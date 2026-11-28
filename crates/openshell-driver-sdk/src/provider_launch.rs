// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File, OpenOptions, TryLockError};
use std::future::Future;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};

use openshell_core::driver_utils::PROVIDER_LAUNCH_DRAIN_GRACE;
use openshell_core::proto::compute::v1::{
    OrderedStart, OrderedStartResult, StartSandboxRequest, StartSandboxResponse,
    StopSandboxResponse,
};
use openshell_core::sandbox_generation::SandboxGenerationId;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tonic::{Code, Response, Status};
use tracing::Instrument as _;

const LOCK_FILE: &str = "provider-launch.lock";
const JOURNAL_FILE: &str = "launch.json";
const LEGACY_REVISION_FILE: &str = "provider-launch.revision";
const RESTART_STOP_DIR: &str = "restart-stop";
const STOP_MUTATION_FILE: &str = "stop-mutation.json";
const CONTAINMENT_PENDING_FILE: &str = "containment.pending";
const JOURNAL_VERSION: u32 = 1;
const MAX_JOURNAL_BYTES: u64 = 256 * 1024;
static ACTIVE_LAUNCHES: LazyLock<watch::Sender<usize>> = LazyLock::new(|| watch::channel(0).0);
static CLOSING_PROVIDER_LAUNCH_WORK: AtomicBool = AtomicBool::new(false);

/// Checkpoint for an ordered Stop that is about to change compute.
pub struct ProviderStopMutation {
    path: PathBuf,
    operation: OrderedStart,
}

impl ProviderStopMutation {
    /// Record the first possible effect after the driver finishes preflight.
    pub async fn begin(&self) -> Result<(), Status> {
        write_journal(&self.path, &self.operation, None).await
    }
}

struct ActiveLaunch;

impl ActiveLaunch {
    fn begin() -> Self {
        ACTIVE_LAUNCHES.send_modify(|count| *count += 1);
        Self
    }
}

impl Drop for ActiveLaunch {
    fn drop(&mut self) {
        ACTIVE_LAUNCHES.send_modify(|count| *count -= 1);
    }
}

/// Retain an admitted driver operation through caller cancellation and shutdown.
pub async fn own_provider_launch_work<T: Send + 'static>(
    work: impl Future<Output = T> + Send + 'static,
) -> Result<T, Status> {
    let active = ActiveLaunch::begin();
    if CLOSING_PROVIDER_LAUNCH_WORK.load(Ordering::SeqCst) {
        return Err(Status::unavailable("provider launch work is draining"));
    }
    tokio::spawn(
        async move {
            let _active = active;
            work.await
        }
        .in_current_span(),
    )
    .await
    .map_err(|error| Status::unavailable(format!("provider launch task ended: {error}")))
}

/// Give detached launch callbacks time to finish after the RPC server stops.
///
/// Call this after the server stops accepting and serving requests. A driver
/// that exits during an unfinished launch leaves its journal available for replay.
pub async fn drain_provider_launches() {
    CLOSING_PROVIDER_LAUNCH_WORK.store(true, Ordering::SeqCst);
    wait_for_active_provider_work().await;
}

async fn wait_for_active_provider_work() {
    let mut active = ACTIVE_LAUNCHES.subscribe();
    if tokio::time::timeout(
        PROVIDER_LAUNCH_DRAIN_GRACE,
        active.wait_for(|count| *count == 0),
    )
    .await
    .is_err()
    {
        tracing::warn!("provider launch drain expired");
    }
}

#[cfg(unix)]
pub fn provider_launches_active() -> bool {
    *ACTIVE_LAUNCHES.borrow() > 0
}

/// What the driver should do for the requested operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderLaunchReplay {
    /// Carry out a newly accepted launch operation.
    Start,
    /// Reconcile a previously accepted launch whose outcome is unknown.
    Resume,
    /// Settle an accepted, expired operation without starting resources.
    Settle,
    /// Check whether the exact launch from a recorded success remains active.
    ObserveCompleted,
}

/// Settle a launch whose runtime is retired so the gateway can replace it.
///
/// Return this through `replay_provider_launch` after confirming the old
/// operation can no longer start resources.
pub fn provider_launch_retired() -> StartSandboxResponse {
    StartSandboxResponse {
        ordered_start_result: Some(OrderedStartResult {
            requires_replacement: true,
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Try to lock the same sandbox journal that guards provider launch callbacks.
///
/// Hold the file through the mutation. When another process has the lock,
/// defer work that could alter the resources it is reconciling.
pub async fn try_provider_launch_lock(journal_dir: PathBuf) -> Result<Option<File>, Status> {
    let file = journal_io(move || open_lock(&journal_dir, true)).await?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(error)) => Err(journal_error(&error)),
    }
}

/// Lock any existing launch journal before a direct Start.
pub async fn lock_existing_provider_launch(journal_dir: PathBuf) -> Result<Option<File>, Status> {
    journal_io(move || {
        let lock = match open_lock(&journal_dir, false) {
            Ok(lock) => lock,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if containment_pending(&journal_dir.join(CONTAINMENT_PENDING_FILE))? {
                    return Ok(Err(unknown_containment()));
                }
                return Ok(Ok(None));
            }
            Err(error) => return Err(error),
        };
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Ok(Err(Status::unavailable(
                    "another provider launch owns the journal",
                )));
            }
            Err(TryLockError::Error(error)) => return Err(error),
        }
        if containment_pending(&journal_dir.join(CONTAINMENT_PENDING_FILE))? {
            return Ok(Err(unknown_containment()));
        }
        Ok(Ok(Some(lock)))
    })
    .await?
}

/// Stop the verified workload under its launch lock.
///
/// Revalidate the observed launch before calling. The stop future must confirm
/// the outcome of each engine request before returning true. An unconfirmed
/// stop fences replacement because its engine request might still take effect
/// after a later stop finishes.
pub async fn run_provider_containment(
    journal_dir: PathBuf,
    lock: File,
    stop: impl Future<Output = bool> + Send + 'static,
) -> Result<bool, Status> {
    own_provider_launch_work(async move {
        let _lock = lock;
        let marker = journal_dir.join(CONTAINMENT_PENDING_FILE);
        let path = marker.clone();
        let was_pending = journal_io(move || {
            let pending = containment_pending(&path)?;
            if !pending {
                durable_replace(&path, b"pending\n")?;
            }
            Ok(pending)
        })
        .await?;
        if !stop.await {
            return Ok(false);
        }
        if !was_pending {
            journal_io(move || {
                fs::remove_file(marker)?;
                File::open(journal_dir)?.sync_all()
            })
            .await?;
        }
        Ok(true)
    })
    .await?
}

fn containment_pending(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn unknown_containment() -> Status {
    Status::unavailable("previous provider containment stop has an unknown engine outcome")
}

/// Read a terminal receipt under the launch lock.
/// Only the matching sandbox operation can use the recorded result.
pub async fn lookup_provider_launch_receipt(
    journal_dir: PathBuf,
    request: StartSandboxRequest,
) -> Result<Response<StartSandboxResponse>, Status> {
    if !request.ordered_start_receipt_only || request.settle_only {
        return Err(Status::invalid_argument(
            "invalid provider launch receipt lookup",
        ));
    }
    let operation = request
        .ordered_start
        .ok_or_else(|| Status::invalid_argument("provider launch receipt requires an operation"))?;
    if request.provider_launch_revision != 0
        && request.provider_launch_revision != operation.revision
    {
        return Err(Status::invalid_argument(
            "provider launch revisions do not match",
        ));
    }
    validate_operation(&operation.operation_id, operation.revision)?;
    let (recorded, legacy_revision) = journal_io(move || {
        let lock = open_lock(&journal_dir, false)?;
        lock.try_lock()?;
        Ok((
            read_journal(&journal_dir.join(JOURNAL_FILE))?,
            read_legacy_revision(&journal_dir.join(LEGACY_REVISION_FILE))?,
        ))
    })
    .await?;
    if operation.revision < legacy_revision {
        return Err(Status::aborted("provider launch operation was superseded"));
    }
    let recorded =
        recorded.ok_or_else(|| Status::unavailable("provider launch receipt is unavailable"))?;
    if operation.revision < recorded.revision
        || (operation.revision == recorded.revision
            && operation.operation_id != recorded.operation_id)
    {
        return Err(Status::aborted("provider launch operation was superseded"));
    }
    let outcome = recorded
        .outcome
        .filter(|_| operation.revision == recorded.revision)
        .ok_or_else(|| Status::unavailable("provider launch receipt is unavailable"))?;
    Ok(outcome.response(operation, true, false))
}

/// Use the decoded launch SPIFFE ID to bind an ordered Start to the journal.
///
/// The boolean indicates whether the gateway sent only the scalar revision
/// and expects the legacy response.
pub fn ordered_provider_launch_operation(
    request: &StartSandboxRequest,
    decoded_id: Option<&str>,
) -> Result<Option<(OrderedStart, bool)>, Status> {
    if request.ordered_start_receipt_only {
        return Err(Status::invalid_argument(
            "provider launch receipt requires lookup",
        ));
    }
    let revision = request.provider_launch_revision;
    let envelope = request.ordered_start.as_ref();
    let Some(decoded_id) = decoded_id else {
        if revision != 0 || envelope.is_some() || request.settle_only {
            return Err(Status::invalid_argument(
                "provider launch ordering requires verified provider identity",
            ));
        }
        return Ok(None);
    };
    let id = decoded_id.rsplit('/').next().unwrap_or_default();
    let (operation, legacy_response) = if let Some(operation) = envelope {
        if operation.operation_id != id || (revision != 0 && operation.revision != revision) {
            return Err(Status::failed_precondition(
                "provider launch bundle and operation do not match",
            ));
        }
        (operation.clone(), false)
    } else {
        if revision == 0 || request.settle_only {
            return Err(Status::failed_precondition(
                "verified provider start requires a launch revision",
            ));
        }
        (
            OrderedStart {
                operation_id: id.to_owned(),
                revision,
            },
            true,
        )
    };
    validate_operation(&operation.operation_id, operation.revision)?;
    Ok(Some((operation, legacy_response)))
}

/// Convert a journal receipt to the response expected by a scalar-only Start.
pub fn legacy_provider_launch_outcome(
    mut response: Response<StartSandboxResponse>,
) -> Result<Response<StartSandboxResponse>, Status> {
    let outcome = response
        .get_mut()
        .ordered_start_result
        .take()
        .ok_or_else(|| Status::unavailable("missing provider launch acknowledgment"))?;
    if outcome.requires_replacement {
        return Err(Status::failed_precondition(
            "provider launch is retired and must be replaced",
        ));
    }
    let code = Code::from(outcome.code);
    if code != Code::Ok {
        return Err(Status::new(code, outcome.message));
    }
    Ok(response)
}

#[derive(Serialize, Deserialize)]
struct Journal {
    version: u32,
    #[serde(rename = "id")]
    operation_id: String,
    revision: u64,
    outcome: Option<RecordedOutcome>,
}

#[derive(Clone, Serialize, Deserialize)]
struct RecordedOutcome {
    status_code: i32,
    message: String,
    runtime_identity: String,
    #[serde(default)]
    requires_replacement: bool,
}

impl RecordedOutcome {
    fn from_result(result: Result<StartSandboxResponse, Status>) -> Self {
        match result {
            Ok(response) => Self {
                status_code: i32::from(Code::Ok),
                message: String::new(),
                runtime_identity: response.runtime_identity,
                requires_replacement: response
                    .ordered_start_result
                    .is_some_and(|outcome| outcome.requires_replacement),
            },
            Err(status) => Self {
                status_code: i32::from(status.code()),
                message: status.message().to_owned(),
                runtime_identity: String::new(),
                requires_replacement: false,
            },
        }
    }

    fn response(
        self,
        operation: OrderedStart,
        replayed: bool,
        requires_replacement: bool,
    ) -> Response<StartSandboxResponse> {
        Response::new(StartSandboxResponse {
            runtime_identity: self.runtime_identity,
            ordered_start_result: Some(OrderedStartResult {
                operation: Some(operation),
                code: self.status_code,
                message: self.message,
                replayed,
                requires_replacement: self.requires_replacement || requires_replacement,
            }),
        })
    }
}

/// Accept or replay a launch under a durable per-sandbox journal.
///
/// Use one private host directory for the life of the sandbox. Every process
/// must share it. If a callback loses its process, the next callback must
/// reconcile its backend effects, including requests that may still complete.
///
/// Return an outer error while effects are uncertain. The inner result
/// becomes the durable terminal acknowledgment. During `ObserveCompleted`,
/// use an inner `NotFound` to report that the recorded launch needs
/// replacement. Any other error leaves the outcome unresolved at the gateway.
pub async fn replay_provider_launch<F, Fut>(
    journal_dir: PathBuf,
    operation: OrderedStart,
    settle_only: bool,
    start: F,
) -> Result<Response<StartSandboxResponse>, Status>
where
    F: FnOnce(ProviderLaunchReplay) -> Fut + Send + 'static,
    Fut: Future<Output = Result<Result<StartSandboxResponse, Status>, Status>> + Send + 'static,
{
    validate_operation(&operation.operation_id, operation.revision)?;
    // A dropped RPC cannot interrupt mutation or its terminal checkpoint.
    own_provider_launch_work(replay(journal_dir, operation, settle_only, start)).await?
}

/// Finish or replay an ordered stop. In an automatic restart, the stop and
/// start share a revision and operation ID.
pub async fn replay_provider_stop<F, Fut>(
    journal_dir: PathBuf,
    operation: OrderedStart,
    stop: F,
) -> Result<Response<StopSandboxResponse>, Status>
where
    F: FnOnce(ProviderStopMutation) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), Status>> + Send + 'static,
{
    validate_operation(&operation.operation_id, operation.revision)?;
    // Lock in the same order as Start. A stale Stop must never write a
    // pending child journal while a newer Start owns the parent.
    let parent_lock = try_provider_launch_lock(journal_dir.clone())
        .await?
        .ok_or_else(|| Status::unavailable("another provider launch owns the journal"))?;
    let stop_dir = journal_dir.join(RESTART_STOP_DIR);
    let child_journal = stop_dir.join(JOURNAL_FILE);
    let (start_revision, recorded_stop) = journal_io(move || {
        let revision = read_journal(&journal_dir.join(JOURNAL_FILE))?
            .map_or(0, |journal| journal.revision)
            .max(read_legacy_revision(
                &journal_dir.join(LEGACY_REVISION_FILE),
            )?);
        Ok((revision, read_journal(&child_journal)?))
    })
    .await?;
    if start_revision >= operation.revision {
        let (outcome, replayed) = if let Some(recorded) = recorded_stop.filter(|recorded| {
            recorded.operation_id == operation.operation_id
                && recorded.revision == operation.revision
        }) {
            (
                recorded.outcome.ok_or_else(|| {
                    Status::unavailable("previous provider stop outcome is unknown")
                })?,
                true,
            )
        } else {
            (
                RecordedOutcome::from_result(Err(Status::aborted("provider stop was superseded"))),
                false,
            )
        };
        return Ok(Response::new(StopSandboxResponse {
            ordered_stop_result: outcome
                .response(operation, replayed, false)
                .into_inner()
                .ordered_start_result,
        }));
    }
    let marker = stop_dir.join(STOP_MUTATION_FILE);
    let owned = operation.clone();
    let response = replay_provider_launch(stop_dir, operation, false, move |action| async move {
        let _parent_lock = parent_lock;
        if action == ProviderLaunchReplay::ObserveCompleted {
            return Ok(Ok(StartSandboxResponse::default()));
        }
        let read_marker = marker.clone();
        let attempted = journal_io(move || read_journal(&read_marker)).await?;
        if attempted.is_some_and(|journal| {
            journal.operation_id == owned.operation_id && journal.revision == owned.revision
        }) {
            return Err(Status::unavailable(
                "previous provider stop outcome is unknown",
            ));
        }
        let mutation = ProviderStopMutation {
            path: marker,
            operation: owned,
        };
        match stop(mutation).await {
            Ok(()) => Ok(Ok(StartSandboxResponse::default())),
            Err(status) if status.code() == Code::NotFound => Ok(Err(status)),
            Err(status) => Err(status),
        }
    })
    .await?;
    Ok(Response::new(StopSandboxResponse {
        ordered_stop_result: response.into_inner().ordered_start_result,
    }))
}

async fn replay<F, Fut>(
    journal_dir: PathBuf,
    operation: OrderedStart,
    settle_only: bool,
    start: F,
) -> Result<Response<StartSandboxResponse>, Status>
where
    F: FnOnce(ProviderLaunchReplay) -> Fut,
    Fut: Future<Output = Result<Result<StartSandboxResponse, Status>, Status>>,
{
    let _lock = try_provider_launch_lock(journal_dir.clone())
        .await?
        .ok_or_else(|| Status::unavailable("another provider launch owns the journal"))?;

    let containment = journal_dir.join(CONTAINMENT_PENDING_FILE);
    if journal_io(move || containment_pending(&containment)).await? {
        return Err(unknown_containment());
    }

    let path = journal_dir.join(JOURNAL_FILE);
    let read_path = path.clone();
    let revision_path = journal_dir.join(LEGACY_REVISION_FILE);
    let read_revision_path = revision_path.clone();
    let stop_path = journal_dir.join(RESTART_STOP_DIR).join(JOURNAL_FILE);
    let (recorded, legacy_revision, stop) = journal_io(move || {
        Ok((
            read_journal(&read_path)?,
            read_legacy_revision(&read_revision_path)?,
            read_journal(&stop_path)?,
        ))
    })
    .await?;
    let revision = operation.revision;
    if let Some(stop) = stop {
        if stop.revision > revision {
            return Err(Status::aborted("provider start predates an ordered stop"));
        }
        if stop.outcome.is_none() {
            return Err(Status::unavailable("an ordered provider stop is unsettled"));
        }
        if stop.revision == revision
            && (stop.operation_id != operation.operation_id
                || stop
                    .outcome
                    .is_some_and(|outcome| outcome.status_code != i32::from(Code::Ok)))
        {
            return Err(Status::failed_precondition(
                "provider stop did not complete",
            ));
        }
    }
    if revision < legacy_revision
        || (revision == legacy_revision
            && recorded
                .as_ref()
                .is_none_or(|journal| journal.revision < revision))
    {
        return Err(Status::aborted(
            "provider launch revision is already claimed by an earlier driver",
        ));
    }
    if let Some(recorded) = recorded {
        let same_revision = revision == recorded.revision;
        let same_id = operation.operation_id == recorded.operation_id;
        if revision < recorded.revision || same_revision != same_id {
            return Err(Status::aborted("provider launch operation was superseded"));
        }
        if same_revision {
            if legacy_revision < revision {
                write_legacy_revision(revision_path, revision).await?;
            }
            if let Some(outcome) = recorded.outcome {
                return observe_completed(operation, outcome, start).await;
            }
            let action = if settle_only {
                ProviderLaunchReplay::Settle
            } else {
                ProviderLaunchReplay::Resume
            };
            let outcome = RecordedOutcome::from_result(start(action).await?);
            return persist_outcome(path, operation, outcome).await;
        }
        if recorded.outcome.is_none() {
            return Err(Status::unavailable(
                "an earlier provider launch is unsettled",
            ));
        }
    }

    if settle_only {
        let outcome = RecordedOutcome::from_result(Err(Status::failed_precondition(
            "provider launch expired before driver acceptance",
        )));
        let response = persist_outcome(path, operation, outcome).await?;
        write_legacy_revision(revision_path, revision).await?;
        return Ok(response);
    }
    write_journal(&path, &operation, None).await?;
    write_legacy_revision(revision_path, revision).await?;
    let outcome = RecordedOutcome::from_result(start(ProviderLaunchReplay::Start).await?);
    persist_outcome(path, operation, outcome).await
}

async fn observe_completed<F, Fut>(
    operation: OrderedStart,
    outcome: RecordedOutcome,
    start: F,
) -> Result<Response<StartSandboxResponse>, Status>
where
    F: FnOnce(ProviderLaunchReplay) -> Fut,
    Fut: Future<Output = Result<Result<StartSandboxResponse, Status>, Status>>,
{
    let requires_replacement =
        if outcome.status_code == i32::from(Code::Ok) && !outcome.requires_replacement {
            match start(ProviderLaunchReplay::ObserveCompleted).await? {
                Ok(_) => false,
                Err(status) if status.code() == Code::NotFound => true,
                Err(status) => return Err(status),
            }
        } else {
            false
        };
    Ok(outcome.response(operation, true, requires_replacement))
}

async fn persist_outcome(
    path: PathBuf,
    operation: OrderedStart,
    outcome: RecordedOutcome,
) -> Result<Response<StartSandboxResponse>, Status> {
    write_journal(&path, &operation, Some(&outcome)).await?;
    Ok(outcome.response(operation, false, false))
}

fn validate_operation(id: &str, revision: u64) -> Result<(), Status> {
    if revision == 0 {
        return Err(Status::invalid_argument(
            "provider launch revision is required",
        ));
    }
    SandboxGenerationId::parse(id).map_err(|error| Status::invalid_argument(error.to_string()))?;
    Ok(())
}

fn open_lock(directory: &Path, create: bool) -> io::Result<File> {
    if create {
        create_private_directory(directory)?;
    } else if !fs::symlink_metadata(directory)?.is_dir() {
        return Err(io::Error::other(
            "provider launch journal is not a directory",
        ));
    }
    let mut options = OpenOptions::new();
    options
        .create(create)
        .truncate(false)
        .read(true)
        .write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(directory.join(LOCK_FILE))?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other(
            "provider launch lock is not a regular file",
        ));
    }
    Ok(file)
}

fn create_private_directory(directory: &Path) -> io::Result<()> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => {
            return Err(io::Error::other(
                "provider launch journal is not a directory",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let parent = directory
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| io::Error::other("provider launch journal needs a parent directory"))?;
    create_private_directory(parent)?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    match builder.create(directory) {
        Ok(()) => File::open(parent)?.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if fs::symlink_metadata(directory)?.is_dir() {
                File::open(parent)?.sync_all()
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

fn read_journal(path: &Path) -> io::Result<Option<Journal>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_JOURNAL_BYTES {
        return Err(io::Error::other(
            "provider launch journal is not a bounded regular file",
        ));
    }
    let journal: Journal =
        serde_json::from_reader(file.take(MAX_JOURNAL_BYTES)).map_err(io::Error::other)?;
    if journal.version != JOURNAL_VERSION
        || validate_operation(&journal.operation_id, journal.revision).is_err()
        || journal.outcome.as_ref().is_some_and(|outcome| {
            i32::from(Code::from(outcome.status_code)) != outcome.status_code
        })
    {
        return Err(io::Error::other("provider launch journal is invalid"));
    }
    Ok(Some(journal))
}

fn read_legacy_revision(path: &Path) -> io::Result<u64> {
    match fs::read_to_string(path) {
        Ok(value) => value.parse().map_err(io::Error::other),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error),
    }
}

async fn write_legacy_revision(path: PathBuf, revision: u64) -> Result<(), Status> {
    // An older driver using this inode must see the same revision floor.
    journal_io(move || durable_replace(&path, revision.to_string().as_bytes())).await
}

async fn write_journal(
    path: &Path,
    operation: &OrderedStart,
    outcome: Option<&RecordedOutcome>,
) -> Result<(), Status> {
    let bytes = serde_json::to_vec(&Journal {
        version: JOURNAL_VERSION,
        operation_id: operation.operation_id.clone(),
        revision: operation.revision,
        outcome: outcome.cloned(),
    })
    .map_err(|error| Status::internal(format!("encode provider launch journal: {error}")))?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(Status::internal(
            "provider launch journal exceeds its size limit",
        ));
    }
    let path = path.to_path_buf();
    journal_io(move || durable_replace(&path, &bytes)).await
}

fn durable_replace(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("provider launch file has no parent"))?;
    let mut tempfile = tempfile::NamedTempFile::new_in(parent)?;
    tempfile.write_all(contents)?;
    tempfile.as_file().sync_all()?;
    tempfile.persist(path).map_err(|error| error.error)?;
    File::open(parent)?.sync_all()
}

async fn journal_io<T: Send + 'static>(
    work: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> Result<T, Status> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| {
            Status::unavailable(format!("provider launch journal task ended: {error}"))
        })?
        .map_err(|error| journal_error(&error))
}

fn journal_error(error: &io::Error) -> Status {
    Status::unavailable(format!("access provider launch journal: {error}"))
}

#[cfg(test)]
mod tests {
    use tokio::sync::oneshot;

    use super::*;

    fn operation(id: &str, revision: u64) -> OrderedStart {
        OrderedStart {
            operation_id: id.to_owned(),
            revision,
        }
    }

    #[tokio::test]
    async fn ordered_stop_receipt_survives_start_and_rejects_delayed_stop() {
        let directory = tempfile::tempdir().unwrap();
        let journal = directory.path().join("sandbox");
        let restart = operation("restart", 2);
        let preflight = replay_provider_stop(journal.clone(), restart.clone(), |_| async {
            Err(Status::unavailable("engine lookup failed"))
        })
        .await
        .unwrap_err();
        assert_eq!(preflight.code(), Code::Unavailable);
        let stop = replay_provider_stop(journal.clone(), restart.clone(), |mutation| async move {
            mutation.begin().await
        })
        .await
        .unwrap()
        .into_inner()
        .ordered_stop_result
        .unwrap();
        assert_eq!(stop.code, i32::from(Code::Ok));
        replay_provider_launch(journal.clone(), restart.clone(), false, |_| async {
            Ok(Ok(StartSandboxResponse::default()))
        })
        .await
        .unwrap();
        let replayed = replay_provider_stop(journal.clone(), restart, |_| async {
            panic!("replaying the stop must leave the replacement running");
        })
        .await
        .unwrap()
        .into_inner()
        .ordered_stop_result
        .unwrap();
        assert!(replayed.replayed);
        assert_eq!(replayed.code, i32::from(Code::Ok));

        let manual_stop = operation("manual-stop", 3);
        let stopped = replay_provider_stop(
            journal.clone(),
            manual_stop.clone(),
            |mutation| async move { mutation.begin().await },
        )
        .await
        .unwrap()
        .into_inner()
        .ordered_stop_result
        .unwrap();
        assert_eq!(stopped.operation.as_ref(), Some(&manual_stop));
        assert_eq!(stopped.code, i32::from(Code::Ok));
        assert!(!stopped.replayed);

        replay_provider_launch(
            journal.clone(),
            operation("successor", 4),
            false,
            |_| async { Ok(Ok(StartSandboxResponse::default())) },
        )
        .await
        .unwrap();
        let replayed = replay_provider_stop(journal.clone(), manual_stop, |_| async {
            panic!("replaying the explicit stop must leave the later start running");
        })
        .await
        .unwrap()
        .into_inner()
        .ordered_stop_result
        .unwrap();
        assert!(replayed.replayed);
        assert_eq!(replayed.code, i32::from(Code::Ok));

        let stale = replay_provider_stop(journal, operation("delayed", 3), |_| async {
            panic!("an unseen superseded stop must leave the newer launch running");
        })
        .await
        .unwrap()
        .into_inner()
        .ordered_stop_result
        .unwrap();
        assert_eq!(stale.code, i32::from(Code::Aborted));
    }

    #[tokio::test]
    async fn containment_blocks_new_starts_until_the_engine_confirms_stop() {
        for confirmed in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let journal = directory.path().join("sandbox");
            assert!(
                lock_existing_provider_launch(journal.clone())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(!journal.exists());
            let lock = try_provider_launch_lock(journal.clone())
                .await
                .unwrap()
                .unwrap();
            let (started, waiting) = oneshot::channel();
            let (finish, finishing) = oneshot::channel();
            let stop = tokio::spawn(run_provider_containment(
                journal.clone(),
                lock,
                async move {
                    started.send(()).unwrap();
                    finishing.await.unwrap();
                    confirmed
                },
            ));

            waiting.await.unwrap();
            assert_eq!(
                lock_existing_provider_launch(journal.clone())
                    .await
                    .unwrap_err()
                    .code(),
                Code::Unavailable,
            );
            let launch = operation("launch-1", 1);
            let error = replay_provider_launch(journal.clone(), launch.clone(), false, |_| async {
                panic!("a pending stop still owns the launch lock");
            })
            .await
            .unwrap_err();
            assert_eq!(error.code(), Code::Unavailable);

            finish.send(()).unwrap();
            assert_eq!(stop.await.unwrap().unwrap(), confirmed);
            if confirmed {
                assert!(
                    lock_existing_provider_launch(journal.clone())
                        .await
                        .unwrap()
                        .is_some()
                );
                replay_provider_launch(journal, launch, false, |_| async {
                    Ok(Ok(StartSandboxResponse::default()))
                })
                .await
                .unwrap();
            } else {
                let lock = try_provider_launch_lock(journal.clone())
                    .await
                    .unwrap()
                    .unwrap();
                assert!(
                    run_provider_containment(journal.clone(), lock, async { true })
                        .await
                        .unwrap()
                );
                let stop_receipt =
                    replay_provider_stop(journal.clone(), operation("stop-1", 1), |_| async {
                        Ok(())
                    })
                    .await
                    .unwrap()
                    .into_inner();
                assert_eq!(
                    stop_receipt.ordered_stop_result.unwrap().code,
                    Code::Ok as i32
                );
                assert_eq!(
                    lock_existing_provider_launch(journal.clone())
                        .await
                        .unwrap_err()
                        .message(),
                    unknown_containment().message(),
                );
                let error =
                    replay_provider_launch(journal, operation("launch-2", 2), false, |_| async {
                        panic!("an unknown stop must fence later launches");
                    })
                    .await
                    .unwrap_err();
                assert_eq!(error.message(), unknown_containment().message());
            }
        }
    }

    #[tokio::test]
    async fn receipt_only_lookup_returns_the_exact_terminal_outcome() {
        let directory = tempfile::tempdir().unwrap();
        let journal = directory.path().join("sandbox");
        let launch = operation("launch-1", 1);
        let lookup = |launch: &OrderedStart| StartSandboxRequest {
            ordered_start: Some(launch.clone()),
            ordered_start_receipt_only: true,
            ..Default::default()
        };
        let missing = lookup_provider_launch_receipt(journal.clone(), lookup(&launch))
            .await
            .unwrap_err();
        assert_eq!(missing.code(), Code::Unavailable);
        assert!(!journal.exists());

        replay_provider_launch(
            journal.clone(),
            launch.clone(),
            false,
            |replay| async move {
                assert_eq!(replay, ProviderLaunchReplay::Start);
                Err(Status::unavailable("native outcome is unknown"))
            },
        )
        .await
        .unwrap_err();
        let pending = fs::read(journal.join(JOURNAL_FILE)).unwrap();
        let unfinished = lookup_provider_launch_receipt(journal.clone(), lookup(&launch))
            .await
            .unwrap_err();
        assert_eq!(unfinished.code(), Code::Unavailable);
        assert_eq!(fs::read(journal.join(JOURNAL_FILE)).unwrap(), pending);

        replay_provider_launch(
            journal.clone(),
            launch.clone(),
            false,
            |replay| async move {
                assert_eq!(replay, ProviderLaunchReplay::Resume);
                Ok(Ok(StartSandboxResponse {
                    runtime_identity: "actual-runtime".into(),
                    ..Default::default()
                }))
            },
        )
        .await
        .unwrap();
        let response = lookup_provider_launch_receipt(journal.clone(), lookup(&launch))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.runtime_identity, "actual-runtime");
        let receipt = response.ordered_start_result.unwrap();
        assert_eq!(receipt.operation, Some(launch));
        assert_eq!(receipt.code, i32::from(Code::Ok));
        assert!(receipt.replayed);

        let wrong_id = lookup_provider_launch_receipt(journal, lookup(&operation("other", 1)))
            .await
            .unwrap_err();
        assert_eq!(wrong_id.code(), Code::Aborted);
    }

    #[tokio::test]
    async fn dropped_rpc_retains_the_launch_and_replays_its_acknowledgment() {
        let directory = tempfile::tempdir().unwrap();
        let launch = operation("launch-1", 1);
        let (started, waiting) = oneshot::channel();
        let (finish, finishing) = oneshot::channel();
        let rpc = tokio::spawn(replay_provider_launch(
            directory.path().to_path_buf(),
            launch.clone(),
            false,
            move |replay| async move {
                assert_eq!(replay, ProviderLaunchReplay::Start);
                started.send(()).unwrap();
                finishing.await.unwrap();
                Ok(Ok(StartSandboxResponse {
                    runtime_identity: "actual-runtime".to_owned(),
                    ..Default::default()
                }))
            },
        ));
        waiting.await.unwrap();
        rpc.abort();
        assert!(rpc.await.unwrap_err().is_cancelled());
        let contender = replay_provider_launch(
            directory.path().to_path_buf(),
            launch.clone(),
            false,
            |_| async { panic!("the first callback still owns the provider launch") },
        )
        .await
        .unwrap_err();
        assert_eq!(contender.code(), Code::Unavailable);
        let draining = tokio::spawn(wait_for_active_provider_work());
        tokio::task::yield_now().await;
        assert!(!draining.is_finished());
        finish.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), draining)
            .await
            .unwrap()
            .unwrap();

        let response = replay_provider_launch(
            directory.path().to_path_buf(),
            launch.clone(),
            false,
            |replay| async move {
                assert_eq!(replay, ProviderLaunchReplay::ObserveCompleted);
                Ok(Err(Status::not_found("the host supervisor exited")))
            },
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(response.runtime_identity, "actual-runtime");
        let outcome = response.ordered_start_result.unwrap();
        assert_eq!(outcome.operation, Some(launch));
        assert_eq!(outcome.code, i32::from(Code::Ok));
        assert!(outcome.requires_replacement);
    }

    #[tokio::test]
    async fn unknown_outcome_fences_other_revisions_until_exact_settlement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().to_path_buf();
        let legacy_revision = path.join(LEGACY_REVISION_FILE);
        fs::write(&legacy_revision, "2").unwrap();
        let stale =
            replay_provider_launch(path.clone(), operation("legacy-2", 2), false, |_| async {
                panic!("a revision already accepted by an earlier driver ran again")
            })
            .await
            .unwrap_err();
        assert_eq!(stale.code(), Code::Aborted);

        let launch = operation("launch-3", 3);
        let pending =
            replay_provider_launch(path.clone(), launch.clone(), false, |replay| async move {
                assert_eq!(replay, ProviderLaunchReplay::Start);
                Err(Status::unavailable("backend response lost"))
            })
            .await
            .unwrap_err();
        assert_eq!(pending.code(), Code::Unavailable);

        for (request, code) in [
            (operation("prior-launch", 2), Code::Aborted),
            (operation("conflicting-launch", 3), Code::Aborted),
            (operation("later-launch", 4), Code::Unavailable),
        ] {
            let error = replay_provider_launch(path.clone(), request, false, |_| async {
                panic!("a conflicting operation reached the backend")
            })
            .await
            .unwrap_err();
            assert_eq!(error.code(), code);
        }

        let mut exited =
            replay_provider_launch(path.clone(), launch.clone(), true, |replay| async move {
                assert_eq!(replay, ProviderLaunchReplay::Settle);
                Ok(Err(Status::deadline_exceeded("launch is inactive")))
            })
            .await
            .unwrap()
            .into_inner();
        let repeated = replay_provider_launch(path.clone(), launch, false, |_| async {
            panic!("a terminal rejection reached the backend")
        })
        .await
        .unwrap()
        .into_inner();
        let original = exited.ordered_start_result.as_mut().unwrap();
        assert!(!original.replayed);
        original.replayed = true;
        assert_eq!(exited, repeated);
        assert_eq!(
            repeated.ordered_start_result.unwrap().code,
            i32::from(Code::DeadlineExceeded),
        );

        let replacement = operation("launch-4", 4);
        let mut retired = replay_provider_launch(
            path.clone(),
            replacement.clone(),
            false,
            |replay| async move {
                assert_eq!(replay, ProviderLaunchReplay::Start);
                Ok(Ok(provider_launch_retired()))
            },
        )
        .await
        .unwrap()
        .into_inner();
        let replayed = replay_provider_launch(path, replacement, false, |_| async {
            panic!("a durably retired launch reached the backend")
        })
        .await
        .unwrap()
        .into_inner();
        let original = retired.ordered_start_result.as_mut().unwrap();
        assert!(!original.replayed);
        original.replayed = true;
        assert_eq!(retired, replayed);
        assert!(replayed.ordered_start_result.unwrap().requires_replacement);
        assert_eq!(fs::read_to_string(legacy_revision).unwrap(), "4");
    }
}
