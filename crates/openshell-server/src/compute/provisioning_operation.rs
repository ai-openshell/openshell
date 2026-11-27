// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Retain ownership of submitted driver work until its outcome is known.
//!
//! Local cancellation and backend absence cannot prove that an external create
//! stopped. A durable claim prevents another replica from declaring cleanup
//! complete, retrying, or deleting the only record of an unresolved request.

use std::future::Future;
use std::time::Duration;

use openshell_core::{
    ObjectId,
    proto::compute::v1::OrderedStart,
    proto::{Sandbox, SandboxPhase},
};
use tonic::Status;
use tracing::Instrument as _;

use super::{
    ComputeRuntime, ProviderLaunchReplacement, RESTART_READINESS_TIMEOUT_MS,
    ensure_supervisor_not_ready_status, is_automatic_restart_transition,
    is_recoverable_error_reason, provisioning_deadline, sandbox_phase_should_be_running,
    sandbox_provisioning_attempt_id, sandbox_resource_version, sandbox_runtime_generation,
    set_next_restart_at_ms, set_sandbox_error,
};
use crate::auth::sandbox_session::PersistedSandboxIdentity;
use crate::persistence::PersistenceError;

const PROVIDER_LAUNCH_REVISION: &str = "internal.openshell.ai/provider-launch-recovery-revision";
const PROVIDER_MANUAL_STOP: &str = "internal.openshell.ai/provider-manual-stop";
const PROVIDER_RESTART_STOP: &str = "internal.openshell.ai/provider-restart-stop";
const PROVIDER_RECREATE_ON_MISSING: &str = "internal.openshell.ai/provider-recreate-on-missing";

pub(super) fn pending_provider_restart_stop(sandbox: &Sandbox) -> bool {
    has_operation_marker(sandbox, PROVIDER_RESTART_STOP)
}

pub(super) fn has_provider_manual_stop(sandbox: &Sandbox) -> bool {
    has_operation_marker(sandbox, PROVIDER_MANUAL_STOP)
}

pub(super) fn pending_provider_manual_stop(
    sandbox: &Sandbox,
) -> Result<Option<OrderedStart>, Status> {
    let Some(revision) = sandbox
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.annotations.get(PROVIDER_MANUAL_STOP))
    else {
        return Ok(None);
    };
    let invalid = || Status::failed_precondition("invalid pending manual provider stop");
    if sandbox.phase() != i32::from(SandboxPhase::Stopping)
        || !provisioning_deadline::driver_operation_pending(sandbox)
    {
        return Err(invalid());
    }
    let revision = revision
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(invalid)?;
    let operation_id = operation_id(sandbox)
        .and_then(|id| uuid::Uuid::parse_str(id).ok())
        .ok_or_else(invalid)?
        .to_string();
    Ok(Some(OrderedStart {
        operation_id,
        revision,
    }))
}

pub(super) fn claim_provider_manual_stop(
    sandbox: &mut Sandbox,
    revision: u64,
    repair_window_ms: i64,
) {
    claim_provider_launch(sandbox, repair_window_ms);
    if let Some(metadata) = sandbox.metadata.as_mut() {
        metadata
            .annotations
            .insert(PROVIDER_MANUAL_STOP.to_string(), revision.to_string());
    }
}

pub(super) fn clear_provider_manual_stop(sandbox: &mut Sandbox) {
    if let Some(metadata) = sandbox.metadata.as_mut() {
        metadata.annotations.remove(PROVIDER_MANUAL_STOP);
    }
    if let Some(record) = sandbox
        .status
        .as_mut()
        .and_then(|status| status.provisioning.as_mut())
    {
        record.driver_operation_pending = false;
    }
}

pub(super) fn provider_recreate_on_missing(sandbox: &Sandbox) -> bool {
    has_operation_marker(sandbox, PROVIDER_RECREATE_ON_MISSING)
}

pub(super) fn record_provider_recreate_intent(sandbox: &mut Sandbox) {
    if let Some(metadata) = sandbox.metadata.as_mut() {
        metadata
            .annotations
            .insert(PROVIDER_RECREATE_ON_MISSING.to_string(), "true".to_string());
    }
}

fn has_operation_marker(sandbox: &Sandbox, marker: &str) -> bool {
    sandbox
        .metadata
        .as_ref()
        .is_some_and(|metadata| metadata.annotations.contains_key(marker))
}

pub(super) fn record_provider_restart_stop(sandbox: &mut Sandbox, revision: u64) {
    record_provider_launch_revision(sandbox, revision);
    if let Some(metadata) = sandbox.metadata.as_mut() {
        metadata
            .annotations
            .insert(PROVIDER_RESTART_STOP.to_string(), revision.to_string());
    }
}

pub(super) fn clear_provider_restart_stop(sandbox: &mut Sandbox) {
    if let Some(metadata) = sandbox.metadata.as_mut() {
        metadata.annotations.remove(PROVIDER_RESTART_STOP);
    }
}

pub(super) fn pending_provider_launch(sandbox: &Sandbox) -> Result<Option<OrderedStart>, Status> {
    let Some(revision) = sandbox
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.annotations.get(PROVIDER_LAUNCH_REVISION))
    else {
        return Ok(None);
    };
    let revision = revision
        .parse::<u64>()
        .ok()
        .filter(|revision| *revision != 0)
        .ok_or_else(|| Status::failed_precondition("invalid provider launch recovery revision"))?;
    let id = provider_launch_id(sandbox)
        .ok_or_else(|| Status::failed_precondition("missing pending provider launch ID"))?
        .to_string();
    Ok(Some(OrderedStart {
        operation_id: id,
        revision,
    }))
}

pub(super) fn record_provider_launch_revision(sandbox: &mut Sandbox, revision: u64) {
    if let Some(metadata) = sandbox.metadata.as_mut() {
        metadata
            .annotations
            .insert(PROVIDER_LAUNCH_REVISION.to_string(), revision.to_string());
    }
}

/// An attempt may contain several recovery operations on the same generation.
/// Keep the last operation ID after settlement so a delayed callback cannot
/// adopt a newer operation merely because it has already finished.
pub(super) fn same_operation(left: &Sandbox, right: &Sandbox) -> bool {
    sandbox_provisioning_attempt_id(left) == sandbox_provisioning_attempt_id(right)
        && operation_id(left) == operation_id(right)
}

fn operation_id(sandbox: &Sandbox) -> Option<&str> {
    sandbox
        .status
        .as_ref()?
        .provisioning
        .as_ref()
        .map(|record| record.driver_operation_id.as_str())
}

fn provider_launch_id(sandbox: &Sandbox) -> Option<uuid::Uuid> {
    let metadata = sandbox.metadata.as_ref()?;
    PersistedSandboxIdentity::read(&metadata.annotations)
        .ok()?
        .provider_launch_id
}

pub(super) fn same_result_owner(current: &Sandbox, owned: &Sandbox) -> bool {
    same_operation(current, owned) && provider_launch_id(current) == provider_launch_id(owned)
}

/// Track an opted-in launch on older rows before dispatching driver I/O.
pub(super) fn claim_provider_launch(sandbox: &mut Sandbox, repair_window_ms: i64) {
    let needs_deadline = matches!(
        SandboxPhase::try_from(sandbox.phase()),
        Ok(SandboxPhase::Provisioning | SandboxPhase::Starting)
    );
    sandbox
        .status
        .get_or_insert_with(Default::default)
        .provisioning
        .get_or_insert_with(|| {
            let mut record =
                provisioning_deadline::new_record(openshell_core::time::now_ms(), repair_window_ms);
            if !needs_deadline {
                record.deadline = None;
            }
            record
        });
    claim_record(sandbox);
}

/// Called only inside a CAS that has checked the prior operation is settled.
/// Legacy rows without an attempt retain their existing lifecycle contract.
pub(super) fn claim_record(sandbox: &mut Sandbox) {
    if let Some(record) = sandbox
        .status
        .as_mut()
        .and_then(|status| status.provisioning.as_mut())
    {
        record.driver_operation_pending = true;
        record.driver_operation_id = uuid::Uuid::new_v4().to_string();
    }
}

pub(super) fn ensure_current_result(current: &Sandbox, owned: &Sandbox) -> Result<(), Status> {
    if !same_result_owner(current, owned)
        || sandbox_runtime_generation(current) != sandbox_runtime_generation(owned)
    {
        return Err(Status::aborted(
            "sandbox driver operation changed before result handling",
        ));
    }
    if provisioning_deadline::timed_out(current) {
        return Err(Status::deadline_exceeded("provisioning deadline expired"));
    }
    ensure_operation_settled(current)
}

pub(super) fn ensure_operation_settled(sandbox: &Sandbox) -> Result<(), Status> {
    if provisioning_deadline::driver_operation_pending(sandbox) {
        return Err(Status::failed_precondition(
            "previous driver operation is still pending; retry and deletion are blocked",
        ));
    }
    Ok(())
}

/// Keep monitor interruption separate from an actual driver response. Only
/// the latter may enter the caller's existing failure recovery path.
#[derive(Debug, thiserror::Error)]
pub(super) enum ProvisioningOperationError {
    #[error("{status}")]
    Driver {
        status: Status,
        settled: Box<Sandbox>,
    },
    #[error("{0}")]
    Monitor(Status),
    #[error("{0}")]
    Unsettled(Status),
    #[error("provider launch is inactive; replacement is pending")]
    ProviderLaunchReplacementPending,
}

impl From<ProvisioningOperationError> for Status {
    fn from(error: ProvisioningOperationError) -> Self {
        match error {
            ProvisioningOperationError::Driver { status, .. }
            | ProvisioningOperationError::Monitor(status)
            | ProvisioningOperationError::Unsettled(status) => status,
            ProvisioningOperationError::ProviderLaunchReplacementPending => {
                Self::aborted(error.to_string())
            }
        }
    }
}

pub(super) enum DriverOutcome<T> {
    Completed(Result<T, Status>, Option<Box<Sandbox>>),
    ProviderLaunchRetired(OrderedStart),
}

#[derive(Clone, Copy)]
enum DriverSettlement<'a> {
    Completed(Option<&'a str>),
    Retired(&'a OrderedStart),
}

impl ComputeRuntime {
    /// Claim before polling the operation, then retain its task even when the
    /// caller or deadline monitor leaves. Pending describes the owned future,
    /// not backend cancellation: transport-error ambiguity remains governed by
    /// the compute driver's existing error contract.
    pub(super) async fn await_provisioning_operation<T: Send + 'static>(
        &self,
        starting: &Sandbox,
        operation: impl Future<Output = Result<T, Status>> + Send + 'static,
    ) -> Result<(T, Box<Sandbox>), ProvisioningOperationError> {
        self.await_provisioning_operation_with_replacement(starting, None, |_| operation)
            .await
    }

    pub(super) async fn await_provisioning_operation_with_replacement<T: Send + 'static, F>(
        &self,
        starting: &Sandbox,
        replacement: Option<&ProviderLaunchReplacement>,
        operation: impl FnOnce(&Sandbox) -> F + Send,
    ) -> Result<(T, Box<Sandbox>), ProvisioningOperationError>
    where
        F: Future<Output = Result<T, Status>> + Send + 'static,
    {
        let claimed = self
            .claim_provisioning_operation(starting, replacement, false)
            .await
            .map_err(ProvisioningOperationError::Monitor)?;
        let claimed =
            if replacement.is_some() && sandbox_provisioning_attempt_id(&claimed).is_none() {
                // The first CAS reserves credentials without dispatching anything.
                // A crash there can be recovered by replacing the reservation.
                // Claim the exact reservation before the driver future is polled.
                self.claim_provisioning_operation(&claimed, None, true)
                    .await
                    .map_err(ProvisioningOperationError::Monitor)?
            } else {
                claimed
            };
        self.await_claimed_provisioning_operation(&claimed, operation(&claimed))
            .await
    }

    /// The caller has atomically claimed both its lifecycle transition and the
    /// operation. The detached worker owns I/O, not the caller's local gate.
    pub(super) async fn await_claimed_provisioning_operation<T: Send + 'static>(
        &self,
        starting: &Sandbox,
        operation: impl Future<Output = Result<T, Status>> + Send + 'static,
    ) -> Result<(T, Box<Sandbox>), ProvisioningOperationError> {
        self.await_claimed_driver_outcome(starting, async { Ok(operation.await) })
            .await
    }

    pub(super) async fn await_claimed_driver_outcome<T: Send + 'static>(
        &self,
        starting: &Sandbox,
        operation: impl Future<Output = Result<Result<T, Status>, Status>> + Send + 'static,
    ) -> Result<(T, Box<Sandbox>), ProvisioningOperationError> {
        self.await_claimed_driver_outcome_with_transition(starting, async {
            operation
                .await
                .map(|result| DriverOutcome::Completed(result, None))
        })
        .await
    }

    pub(super) async fn await_claimed_driver_outcome_with_transition<T: Send + 'static>(
        &self,
        starting: &Sandbox,
        operation: impl Future<Output = Result<DriverOutcome<T>, Status>> + Send + 'static,
    ) -> Result<(T, Box<Sandbox>), ProvisioningOperationError> {
        let tracked = sandbox_provisioning_attempt_id(starting).is_some();
        let runtime = self.clone();
        let owned_attempt = starting.clone();
        // Dropping a JoinHandle detaches its task. Do not abort it on a monitor
        // error or deadline: the remote side may still commit the request.
        let worker = async move {
            let outcome = operation
                .await
                .map_err(ProvisioningOperationError::Unsettled)?;
            let (result, transition) = match outcome {
                DriverOutcome::Completed(result, transition) => (result, transition),
                DriverOutcome::ProviderLaunchRetired(operation) => {
                    let updated = runtime
                        .settle_driver_operation(
                            &owned_attempt,
                            DriverSettlement::Retired(&operation),
                        )
                        .await
                        .map_err(ProvisioningOperationError::Monitor)?;
                    return Err(
                        if provisioning_deadline::driver_operation_pending(&updated) {
                            ProvisioningOperationError::ProviderLaunchReplacementPending
                        } else {
                            ProvisioningOperationError::Monitor(Status::aborted(
                                "provider launch retired after sandbox stopped expecting a start",
                            ))
                        },
                    );
                }
            };
            let owned_attempt = transition.map_or(owned_attempt, |sandbox| *sandbox);
            let settled = if tracked {
                let settled = runtime
                    .settle_provisioning_operation(&owned_attempt, None)
                    .await
                    .map_err(ProvisioningOperationError::Monitor)?;
                // Settlement records a known response even if another writer
                // rotated identity. That response cannot bind or compensate
                // against the replacement generation in its returned snapshot.
                if sandbox_runtime_generation(&settled)
                    != sandbox_runtime_generation(&owned_attempt)
                    || provider_launch_id(&settled) != provider_launch_id(&owned_attempt)
                {
                    return Err(ProvisioningOperationError::Monitor(Status::aborted(
                        "sandbox launch changed during driver operation",
                    )));
                }
                settled
            } else if runtime.provider_workload_identity().is_some() {
                // Untracked recovery uses the driver's idempotent start and
                // the persisted launch to fence responses across recoveries.
                let current = runtime
                    .store
                    .get_message::<Sandbox>(owned_attempt.object_id())
                    .await
                    .map_err(|error| {
                        ProvisioningOperationError::Monitor(Status::internal(format!(
                            "read sandbox after startup recovery: {error}"
                        )))
                    })?
                    .ok_or_else(|| {
                        ProvisioningOperationError::Monitor(Status::aborted(
                            "sandbox removed during startup recovery",
                        ))
                    })?;
                ensure_current_result(&current, &owned_attempt)
                    .map_err(ProvisioningOperationError::Monitor)?;
                // A same-launch supervisor may update readiness before Start
                // returns. Let a success bind against the latest running phase.
                if current.phase() != owned_attempt.phase()
                    && (result.is_err()
                        || !matches!(
                            SandboxPhase::try_from(current.phase()),
                            Ok(SandboxPhase::Provisioning | SandboxPhase::Ready)
                        ))
                {
                    return Err(ProvisioningOperationError::Monitor(Status::aborted(
                        "sandbox phase changed during startup recovery",
                    )));
                }
                owned_attempt
            } else {
                owned_attempt
            };
            match result {
                Ok(response) => Ok((response, Box::new(settled))),
                Err(status) => Err(ProvisioningOperationError::Driver {
                    status,
                    settled: Box::new(settled),
                }),
            }
        };
        // Retain the request span so detaching ownership preserves the driver
        // call's parent trace, including when the caller stops waiting.
        let mut worker = tokio::spawn(worker.in_current_span());
        loop {
            tokio::select! {
                result = &mut worker => return result.map_err(|error| {
                    ProvisioningOperationError::Unsettled(Status::internal(format!(
                        "driver operation owner terminated; outcome remains unknown: {error}"
                    )))
                })?,
                () = tokio::time::sleep(Duration::from_secs(1)) => {
                    let current = self.store.get_message::<Sandbox>(starting.object_id())
                        .await.map_err(|error| ProvisioningOperationError::Monitor(
                            Status::internal(format!("monitor provisioning: {error}"))
                        ))?
                        .ok_or_else(|| ProvisioningOperationError::Monitor(
                            Status::not_found("sandbox removed during startup")
                        ))?;
                    if !same_result_owner(&current, starting)
                        || sandbox_runtime_generation(&current) != sandbox_runtime_generation(starting) {
                        return Err(ProvisioningOperationError::Monitor(Status::aborted(
                            "sandbox provisioning attempt changed while waiting for compute"
                        )));
                    }
                    if provisioning_deadline::timed_out(&current) {
                        return Err(ProvisioningOperationError::Monitor(Status::deadline_exceeded(
                            "provisioning deadline expired; driver settlement may still be pending"
                        )));
                    }
                }
            }
        }
    }

    pub(super) async fn claim_provisioning_operation(
        &self,
        starting: &Sandbox,
        provider_launch: Option<&ProviderLaunchReplacement>,
        track_legacy_dispatch: bool,
    ) -> Result<Sandbox, Status> {
        self.claim_driver_operation(starting, provider_launch, track_legacy_dispatch, false)
            .await
    }

    pub(super) async fn claim_provider_launch_recovery(
        &self,
        starting: &Sandbox,
        replacement: Option<&ProviderLaunchReplacement>,
    ) -> Result<Sandbox, Status> {
        self.claim_driver_operation(starting, replacement, true, true)
            .await
    }

    /// Only the first owner of an exact `NotFound` receipt can issue fallback
    /// Create. Keep the existing Create interlock while its result is unknown.
    pub(super) async fn claim_provider_timeout_recreate(
        &self,
        starting: &Sandbox,
        operation: &OrderedStart,
    ) -> Result<Sandbox, Status> {
        for _ in 0..super::START_PHASE_CAS_RETRY_LIMIT {
            let current = self
                .store
                .get_message::<Sandbox>(starting.object_id())
                .await
                .map_err(|error| Status::unavailable(error.to_string()))?
                .ok_or_else(|| Status::aborted("sandbox removed before timeout recreation"))?;
            if !same_result_owner(&current, starting)
                || pending_provider_launch(&current)?.as_ref() != Some(operation)
                || !provider_recreate_on_missing(&current)
            {
                return Err(Status::aborted(
                    "sandbox timeout recreation already claimed or superseded",
                ));
            }
            if provisioning_deadline::timed_out(&current)
                || provisioning_deadline::pending_error_preparation_overdue(
                    &current,
                    openshell_core::time::now_ms(),
                )
            {
                return Err(Status::deadline_exceeded(
                    "provisioning deadline expired before recreation",
                ));
            }
            match self
                .store
                .update_message_cas::<Sandbox, _>(
                    starting.object_id(),
                    sandbox_resource_version(&current),
                    |sandbox| {
                        if let Some(metadata) = sandbox.metadata.as_mut() {
                            metadata.annotations.remove(PROVIDER_LAUNCH_REVISION);
                            metadata.annotations.remove(PROVIDER_RECREATE_ON_MISSING);
                        }
                    },
                )
                .await
            {
                Ok(claimed) => return Ok(claimed),
                Err(PersistenceError::Conflict { .. }) => {}
                Err(error) => return Err(Status::unavailable(error.to_string())),
            }
        }
        Err(Status::aborted(
            "sandbox kept changing before timeout recreation",
        ))
    }

    async fn claim_driver_operation(
        &self,
        starting: &Sandbox,
        provider_launch: Option<&ProviderLaunchReplacement>,
        track_legacy_dispatch: bool,
        replayable: bool,
    ) -> Result<Sandbox, Status> {
        match sandbox_provisioning_attempt_id(starting) {
            None if provider_launch.is_none() && !track_legacy_dispatch => {
                return Ok(starting.clone());
            }
            Some("") => return Err(Status::failed_precondition("provisioning attempt is empty")),
            _ => {}
        }
        for _ in 0..super::START_PHASE_CAS_RETRY_LIMIT {
            let current = self
                .store
                .get_message::<Sandbox>(starting.object_id())
                .await
                .map_err(|error| Status::internal(error.to_string()))?
                .ok_or_else(|| Status::not_found("sandbox removed before driver dispatch"))?;
            if provisioning_deadline::timed_out(&current) {
                return Err(Status::deadline_exceeded(
                    "provisioning deadline already expired",
                ));
            }
            if provisioning_deadline::driver_operation_pending(&current) {
                return Err(Status::failed_precondition(
                    "previous driver operation may still complete; retry and deletion are blocked",
                ));
            }
            // The provisioning deadline worker can adopt an untracked row
            // between reservation and dispatch without taking driver ownership.
            let adopted_deadline = track_legacy_dispatch
                && sandbox_provisioning_attempt_id(starting).is_none()
                && operation_id(&current) == Some("");
            if (!same_operation(&current, starting) && !adopted_deadline)
                || provider_launch_id(&current) != provider_launch_id(starting)
                || sandbox_runtime_generation(&current) != sandbox_runtime_generation(starting)
            {
                return Err(Status::aborted(
                    "provisioning operation changed before driver dispatch",
                ));
            }
            if current.phase() != starting.phase() {
                return Err(Status::aborted(
                    "sandbox phase changed before driver dispatch",
                ));
            }
            if let Some(replacement) = provider_launch {
                let previous = &replacement.previous;
                let unchanged = current
                    .metadata
                    .as_ref()
                    .and_then(|metadata| PersistedSandboxIdentity::read(&metadata.annotations).ok())
                    .is_some_and(|identity| {
                        identity.runtime_generation == previous.runtime_generation
                            && identity.auth_epoch == previous.auth_epoch
                            && identity.provider_launch_id == previous.provider_launch_id
                    });
                if !unchanged {
                    return Err(Status::aborted(
                        "sandbox launch authorization changed before driver dispatch",
                    ));
                }
            }
            let current_version = sandbox_resource_version(&current);
            let revision = current_version
                .checked_add(1)
                .ok_or_else(|| Status::failed_precondition("sandbox resource version overflow"))?;
            match self
                .store
                .update_message_cas::<Sandbox, _>(
                    starting.object_id(),
                    current_version,
                    |sandbox| {
                        if let (Some(replacement), Some(metadata)) =
                            (provider_launch, sandbox.metadata.as_mut())
                        {
                            replacement.next.write(&mut metadata.annotations);
                        }
                        if replayable {
                            record_provider_launch_revision(sandbox, revision);
                        }
                        if track_legacy_dispatch {
                            claim_provider_launch(sandbox, self.provisioning_repair_window_ms);
                        } else {
                            claim_record(sandbox);
                        }
                    },
                )
                .await
            {
                Ok(updated) => {
                    self.sandbox_index.update_from_sandbox(&updated);
                    self.sandbox_watch_bus.notify(starting.object_id());
                    return Ok(updated);
                }
                Err(PersistenceError::Conflict { .. }) => {}
                Err(error) => return Err(Status::internal(error.to_string())),
            }
        }
        Err(Status::aborted(
            "sandbox kept changing before driver dispatch",
        ))
    }

    pub(super) async fn settle_provisioning_operation(
        &self,
        starting: &Sandbox,
        admission_denial: Option<&str>,
    ) -> Result<Sandbox, Status> {
        self.settle_driver_operation(starting, DriverSettlement::Completed(admission_denial))
            .await
    }

    async fn settle_driver_operation(
        &self,
        starting: &Sandbox,
        settlement: DriverSettlement<'_>,
    ) -> Result<Sandbox, Status> {
        // Keep the observed response in this task across transient persistence
        // failures. A process crash still leaves the durable claim intact;
        // neither lease expiry nor backend absence can safely clear it.
        loop {
            let result = self
                .try_settle_provisioning_operation(starting, settlement)
                .await;
            match result {
                Ok(settled) => return Ok(settled),
                Err(error) if error.code() == tonic::Code::Aborted => return Err(error),
                Err(error) => {
                    tracing::warn!(sandbox_id = starting.object_id(), %error,
                        "Retaining driver response until operation ownership can be persisted");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    async fn try_settle_provisioning_operation(
        &self,
        starting: &Sandbox,
        settlement: DriverSettlement<'_>,
    ) -> Result<Sandbox, Status> {
        let current = self
            .store
            .get_message::<Sandbox>(starting.object_id())
            .await
            .map_err(|error| Status::internal(error.to_string()))?
            .ok_or_else(|| Status::aborted("sandbox removed before driver settlement"))?;
        if !same_operation(&current, starting) {
            return Err(Status::aborted(
                "provisioning attempt changed before driver settlement",
            ));
        }
        let launch = pending_provider_launch(starting)?;
        let current_launch = pending_provider_launch(&current)?;
        if launch.is_some() && launch != current_launch {
            return Err(Status::aborted(
                "provider launch recovery already settled or replaced",
            ));
        }
        if current_launch.is_some() && !same_result_owner(&current, starting) {
            return Err(Status::aborted("provider launch changed before settlement"));
        }
        if provisioning_deadline::pending_error_preparation_overdue(
            &current,
            openshell_core::time::now_ms(),
        ) {
            return Err(Status::deadline_exceeded(
                "provider launch deadline elapsed; waiting for timeout reconciliation",
            ));
        }
        let version = sandbox_resource_version(&current);
        let phase = SandboxPhase::try_from(current.phase()).unwrap_or_default();
        let replacement = if let DriverSettlement::Retired(operation) = settlement {
            if current_launch.as_ref() != Some(operation)
                || pending_provider_restart_stop(&current)
                || !provisioning_deadline::driver_operation_pending(&current)
                || sandbox_runtime_generation(&current) != sandbox_runtime_generation(starting)
            {
                return Err(Status::aborted("retired provider launch was superseded"));
            }
            if !provisioning_deadline::timed_out(&current)
                && (sandbox_phase_should_be_running(phase)
                    || (phase == SandboxPhase::Error && is_recoverable_error_reason(&current)))
            {
                let metadata = current.metadata.as_ref().ok_or_else(|| {
                    Status::aborted("sandbox metadata missing at launch retirement")
                })?;
                let identity = PersistedSandboxIdentity::read(&metadata.annotations)
                    .map_err(|error| Status::aborted(error.to_string()))?;
                let revision = version
                    .checked_add(1)
                    .ok_or_else(|| Status::aborted("sandbox resource version overflow"))?;
                Some((identity.replace_provider_launch(), revision))
            } else {
                None
            }
        } else {
            None
        };
        let updated = self
            .store
            .update_message_cas::<Sandbox, _>(
                starting.object_id(),
                sandbox_resource_version(&current),
                |sandbox| {
                    if let Some((identity, revision)) = &replacement
                        && let Some(metadata) = sandbox.metadata.as_mut()
                    {
                        // Publish the successor with the same CAS that retires
                        // the old receipt. Other replicas can only replay it.
                        identity.write(&mut metadata.annotations);
                        record_provider_launch_revision(sandbox, *revision);
                        if matches!(
                            phase,
                            SandboxPhase::Ready | SandboxPhase::Provisioning | SandboxPhase::Error
                        ) && let Some(status) = sandbox.status.as_mut()
                            && status
                                .provisioning
                                .as_ref()
                                .is_some_and(|record| record.deadline.is_none())
                        {
                            // The predecessor has no active deadline. Give the
                            // successor time to register and report readiness.
                            status.provisioning =
                                Some(provisioning_deadline::new_preparation_record(
                                    openshell_core::time::now_ms(),
                                    self.image_preparation_timeout_seconds,
                                    self.provisioning_repair_window_ms,
                                ));
                        }
                        claim_provider_launch(sandbox, self.provisioning_repair_window_ms);
                        if phase == SandboxPhase::Ready {
                            sandbox.set_phase(SandboxPhase::Provisioning as i32);
                            ensure_supervisor_not_ready_status(&mut sandbox.status);
                        } else if is_automatic_restart_transition(sandbox)
                            && let Some(status) = sandbox.status.as_mut()
                        {
                            let deadline = openshell_core::time::now_ms()
                                .saturating_add(RESTART_READINESS_TIMEOUT_MS);
                            set_next_restart_at_ms(status, deadline);
                        }
                        return;
                    }
                    if current_launch.is_some()
                        && let Some(metadata) = sandbox.metadata.as_mut()
                    {
                        metadata.annotations.remove(PROVIDER_LAUNCH_REVISION);
                        metadata.annotations.remove(PROVIDER_RESTART_STOP);
                        metadata.annotations.remove(PROVIDER_RECREATE_ON_MISSING);
                    }
                    if let Some(record) = sandbox
                        .status
                        .as_mut()
                        .and_then(|status| status.provisioning.as_mut())
                    {
                        record.driver_operation_pending = false;
                        // Any stop before this response may have seen absence before
                        // the late create committed. Require another cleanup pass.
                        record.cleanup_completed_time = None;
                        // The retry timestamp may be another replica's active
                        // STOP lease. Preserve it through driver settlement.
                    }
                    if let DriverSettlement::Completed(Some(message)) = settlement
                        && current_launch.is_some()
                        && sandbox_runtime_generation(sandbox)
                            == sandbox_runtime_generation(starting)
                        && !provisioning_deadline::timed_out(sandbox)
                        && (sandbox_phase_should_be_running(phase)
                            || (phase == SandboxPhase::Error
                                && is_recoverable_error_reason(sandbox)))
                    {
                        set_sandbox_error(sandbox, "ResourceAdmissionDenied", message);
                    }
                },
            )
            .await
            .map_err(|error| Status::internal(error.to_string()))?;
        self.sandbox_index.update_from_sandbox(&updated);
        self.sandbox_watch_bus.notify(starting.object_id());
        Ok(updated)
    }
}
