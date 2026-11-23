// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generic launcher for compute drivers that run as gateway-managed
//! subprocesses.
//!
//! The launcher resolves a driver binary, prepares a private run directory,
//! starts the driver in `serve` mode, waits for its Unix domain socket, sends
//! `Configure`, and returns a gRPC `Channel` plus a [`ManagedDriverProcess`]
//! handle that reaps the subprocess and cleans up the socket on drop. Each
//! driver supplies its own name and binary; the driver owns and validates its
//! configuration, which the gateway passes through as an opaque table.

#[cfg(unix)]
use hyper_util::rt::TokioIo;
use openshell_core::{Error, Result};
use openshell_driver_launch::proto::ConfigureRequest;
#[cfg(unix)]
use openshell_driver_launch::proto::{
    GetLaunchInfoRequest, driver_launch_client::DriverLaunchClient,
};
#[cfg(unix)]
use openshell_otel::TraceContextInterceptor;
use openshell_server::AcquiredRemoteDriverEndpoint;
use openshell_server::config_file::OtlpConfig;
#[cfg(unix)]
use openshell_server::{DriverProcessState, ManagedDriverProcess};
#[cfg(unix)]
use std::future::Future;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::path::PathBuf;
#[cfg(unix)]
use std::{io::ErrorKind, process::Stdio, sync::Arc, time::Duration};
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
use tokio::process::Command;
use tonic::transport::Channel;
#[cfg(unix)]
use tonic::transport::Endpoint;
#[cfg(unix)]
use tower::service_fn;

const COMPUTE_DRIVER_SOCKET_RUN_DIR: &str = "run";
const COMPUTE_DRIVER_SOCKET_NAME: &str = "compute-driver.sock";

/// A driver binary the gateway launches and where it keeps its private run
/// directory.
#[derive(Debug, Clone, Copy)]
pub struct DriverProcess<'a> {
    /// Short driver name used in messages and telemetry, such as `vm`.
    pub name: &'a str,
    /// File name of the driver binary, such as `openshell-driver-vm`.
    pub binary_name: &'a str,
    /// Operator-configured directory to search before the conventional ones.
    pub driver_dir: Option<&'a Path>,
    /// Config key that sets `driver_dir`, named in the not-found message.
    pub driver_dir_key: Option<&'a str>,
    /// Directory whose `run/` subdirectory holds the socket.
    pub state_dir: &'a Path,
}

/// Resolve the driver binary path.
///
/// Resolution order:
/// 1. `{driver_dir}/{binary_name}`, when the operator configures a `driver_dir`.
/// 2. Conventional install directories:
///    `~/.local/libexec/openshell`, `/usr/libexec/openshell`,
///    `/usr/local/libexec/openshell`, `/usr/local/libexec`.
/// 3. Sibling of the gateway's own executable (last-resort fallback so
///    local development builds still work out of the box).
pub fn resolve_driver_bin(driver: &DriverProcess<'_>) -> Result<PathBuf> {
    let mut searched: Vec<PathBuf> = Vec::new();

    // 1. Configured driver directory, or the conventional install locations
    // when no explicit override is configured.
    for dir in resolve_driver_search_dirs(driver.driver_dir) {
        let candidate = dir.join(driver.binary_name);
        if candidate.is_file() {
            return Ok(candidate);
        }
        push_unique_path(&mut searched, candidate);
    }

    // 2. Sibling-of-gateway fallback.
    let current_exe = std::env::current_exe()
        .map_err(|e| Error::config(format!("failed to resolve current executable: {e}")))?;
    let Some(parent) = current_exe.parent() else {
        return Err(Error::config(format!(
            "current executable '{}' has no parent directory",
            current_exe.display()
        )));
    };
    let sibling = parent.join(driver.binary_name);
    if sibling.is_file() {
        return Ok(sibling);
    }
    push_unique_path(&mut searched, sibling);

    let searched_display = searched
        .iter()
        .map(|p| format!("'{}'", p.display()))
        .collect::<Vec<_>>()
        .join(", ");
    let name = driver.name;
    let configured = driver
        .driver_dir_key
        .map_or_else(String::new, |key| format!("under {key}, "));
    Err(Error::config(format!(
        "{name} compute driver binary not found (searched {searched_display}); install it {configured}in a conventional libexec path such as ~/.local/libexec/openshell, /usr/libexec/openshell, or /usr/local/libexec{{,/openshell}}, or place it next to the gateway binary"
    )))
}

fn resolve_driver_search_dirs(driver_dir: Option<&Path>) -> Vec<PathBuf> {
    driver_dir.map(Path::to_path_buf).map_or_else(
        || {
            let mut dirs = Vec::new();
            if let Ok(current_exe) = std::env::current_exe()
                && let Some(prefix) = current_exe.parent().and_then(Path::parent)
            {
                push_unique_path(&mut dirs, prefix.join("libexec"));
                push_unique_path(&mut dirs, prefix.join("libexec").join("openshell"));
            }
            for dir in default_driver_search_dirs(std::env::var_os("HOME").map(PathBuf::from)) {
                push_unique_path(&mut dirs, dir);
            }
            dirs
        },
        |dir| vec![dir],
    )
}

fn default_driver_search_dirs(home: Option<PathBuf>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(home) = home {
        dirs.push(home.join(".local").join("libexec").join("openshell"));
    }
    push_unique_path(&mut dirs, PathBuf::from("/usr/libexec/openshell"));
    push_unique_path(&mut dirs, PathBuf::from("/usr/local/libexec/openshell"));
    push_unique_path(&mut dirs, PathBuf::from("/usr/local/libexec"));
    dirs
}

fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

/// Path of the Unix domain socket the driver will listen on.
pub fn socket_path(driver: &DriverProcess<'_>) -> PathBuf {
    driver
        .state_dir
        .join(COMPUTE_DRIVER_SOCKET_RUN_DIR)
        .join(COMPUTE_DRIVER_SOCKET_NAME)
}

#[cfg(unix)]
fn prepare_socket_path(driver: &DriverProcess<'_>, socket_path: &Path) -> Result<()> {
    let expected_uid = current_euid();
    prepare_state_dir(driver.state_dir, expected_uid)?;
    let parent = socket_path.parent().ok_or_else(|| {
        Error::execution(format!(
            "compute driver socket path '{}' has no parent directory",
            socket_path.display()
        ))
    })?;
    prepare_private_socket_dir(parent, expected_uid)?;
    remove_stale_socket(socket_path, expected_uid)
}

#[cfg(unix)]
fn current_euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(unix)]
fn prepare_state_dir(state_dir: &Path, expected_uid: u32) -> Result<()> {
    std::fs::create_dir_all(state_dir).map_err(|err| {
        Error::execution(format!(
            "failed to create driver state dir '{}': {err}",
            state_dir.display()
        ))
    })?;
    let metadata = checked_directory_metadata(state_dir, expected_uid, "driver state dir")?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o700 {
        std::fs::set_permissions(state_dir, std::fs::Permissions::from_mode(0o700)).map_err(
            |err| {
                Error::execution(format!(
                    "failed to restrict driver state dir '{}': {err}",
                    state_dir.display()
                ))
            },
        )?;
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_private_socket_dir(socket_dir: &Path, expected_uid: u32) -> Result<()> {
    std::fs::create_dir_all(socket_dir).map_err(|err| {
        Error::execution(format!(
            "failed to create compute driver socket dir '{}': {err}",
            socket_dir.display()
        ))
    })?;
    let _ = checked_directory_metadata(socket_dir, expected_uid, "compute driver socket dir")?;
    std::fs::set_permissions(socket_dir, std::fs::Permissions::from_mode(0o700)).map_err(|err| {
        Error::execution(format!(
            "failed to restrict compute driver socket dir '{}': {err}",
            socket_dir.display()
        ))
    })
}

#[cfg(unix)]
fn checked_directory_metadata(
    path: &Path,
    expected_uid: u32,
    label: &str,
) -> Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path).map_err(|err| {
        Error::execution(format!(
            "failed to stat {label} '{}': {err}",
            path.display()
        ))
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(Error::execution(format!(
            "{label} '{}' is a symlink; refusing to use it",
            path.display()
        )));
    }
    if !file_type.is_dir() {
        return Err(Error::execution(format!(
            "{label} '{}' is not a directory",
            path.display()
        )));
    }
    if metadata.uid() != expected_uid {
        return Err(Error::execution(format!(
            "{label} '{}' is owned by uid {} but current euid is {}",
            path.display(),
            metadata.uid(),
            expected_uid
        )));
    }
    Ok(metadata)
}

#[cfg(unix)]
fn remove_stale_socket(socket_path: &Path, expected_uid: u32) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(Error::execution(format!(
                "failed to stat compute driver socket '{}': {err}",
                socket_path.display()
            )));
        }
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(Error::execution(format!(
            "compute driver socket '{}' is a symlink; refusing to remove it",
            socket_path.display()
        )));
    }
    if metadata.uid() != expected_uid {
        return Err(Error::execution(format!(
            "compute driver socket '{}' is owned by uid {} but current euid is {}",
            socket_path.display(),
            metadata.uid(),
            expected_uid
        )));
    }
    if !file_type.is_socket() {
        return Err(Error::execution(format!(
            "compute driver socket path '{}' exists but is not a Unix socket",
            socket_path.display()
        )));
    }
    std::fs::remove_file(socket_path).map_err(|err| {
        Error::execution(format!(
            "failed to remove stale compute driver socket '{}': {err}",
            socket_path.display()
        ))
    })
}

/// How long the gateway waits for `Configure`, which builds the driver and
/// contacts its backend.
#[cfg(unix)]
pub const CONFIGURE_TIMEOUT: Duration = Duration::from_mins(2);

/// Launch a driver in `serve` mode, negotiate the launch protocol, send
/// `Configure`, and return a managed endpoint once the driver is configured.
#[cfg(unix)]
pub async fn launch_configured(
    driver: &DriverProcess<'_>,
    log_level: &str,
    shutdown: tokio::sync::watch::Receiver<bool>,
    request: ConfigureRequest,
) -> Result<AcquiredRemoteDriverEndpoint> {
    let name = driver.name;
    let driver_bin = resolve_driver_bin(driver)?;
    check_driver_binary_trust(&driver_bin, current_euid())?;
    let socket_path = socket_path(driver);
    prepare_socket_path(driver, &socket_path)?;

    let mut command = Command::new(&driver_bin);
    command
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .arg("serve")
        .arg("--bind-socket")
        .arg(&socket_path)
        .arg("--expected-peer-pid")
        .arg(std::process::id().to_string())
        .arg("--log-level")
        .arg(log_level);

    let mut child = command.spawn().map_err(|e| {
        Error::execution(format!(
            "failed to launch {name} compute driver '{}': {e}",
            driver_bin.display()
        ))
    })?;
    let channel = wait_for_launch_service(name, &socket_path, &mut child).await?;
    configure_driver(name, channel.clone(), &mut child, request).await?;
    let process = Arc::new(ManagedDriverProcess::new(child, socket_path));
    watch_for_exit(
        Arc::downgrade(&process),
        name.to_string(),
        EXIT_POLL_INTERVAL,
        shutdown,
        SHUTDOWN_GRACE,
        |message| {
            tracing::error!("{message}");
            std::process::exit(1);
        },
    );
    Ok(AcquiredRemoteDriverEndpoint::managed(
        name, channel, process,
    ))
}

#[cfg(unix)]
async fn configure_driver(
    name: &str,
    channel: Channel,
    child: &mut tokio::process::Child,
    request: ConfigureRequest,
) -> Result<()> {
    let mut client = DriverLaunchClient::with_interceptor(channel, TraceContextInterceptor);
    tokio::select! {
        result = tokio::time::timeout(CONFIGURE_TIMEOUT, client.configure(request)) => match result {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(status)) => {
                let message = format!(
                    "{name} compute driver failed to configure: {}",
                    status.message()
                );
                Err(match status.code() {
                    tonic::Code::InvalidArgument | tonic::Code::FailedPrecondition => {
                        Error::config(message)
                    }
                    _ => Error::execution(message),
                })
            }
            Err(_) => Err(Error::execution(format!(
                "{name} compute driver did not finish Configure within {}s",
                CONFIGURE_TIMEOUT.as_secs()
            ))),
        },
        status = child.wait() => Err(Error::execution(format!(
            "{name} compute driver exited during Configure with status {}",
            status.map_or_else(|error| error.to_string(), |status| status.to_string())
        ))),
    }
}

/// What the gateway knows about itself and a driver when it builds the
/// driver's `Configure` request.
pub struct ConfigureContext<'a> {
    pub driver_name: &'a str,
    pub gateway_name: &'a str,
    pub gateway_port: u16,
    /// The gateway's `guest_tls_ca`, when it serves TLS.
    pub tls_ca: Option<&'a Path>,
    pub otlp_config: Option<&'a OtlpConfig>,
    pub network_trust: Option<&'a openshell_core::NetworkSupervisorTrustBundle>,
    /// The operator's driver table, passed through unchanged.
    pub driver_config: &'a toml::Table,
    pub image_overrides: Option<openshell_driver_launch::proto::ImageOverrides>,
}

/// The `Configure` request for a launched driver. The driver's table travels
/// as opaque TOML; the gateway adds only its own context.
///
/// # Errors
///
/// Returns an error when the table cannot be encoded or a path is not UTF-8.
pub fn configure_request(context: &ConfigureContext<'_>) -> Result<ConfigureRequest> {
    use openshell_driver_launch::proto::{GatewayContext, NetworkTrust};

    let driver_config_toml = toml::to_string(context.driver_config).map_err(|error| {
        Error::config(format!(
            "failed to encode [openshell.drivers.{}]: {error}",
            context.driver_name
        ))
    })?;
    let tls_ca_path = context
        .tls_ca
        .map(|path| {
            path.to_str().map(str::to_string).ok_or_else(|| {
                Error::config(format!(
                    "guest TLS CA path is not UTF-8: {}",
                    path.display()
                ))
            })
        })
        .transpose()?
        .unwrap_or_default();
    let network_trust = context
        .network_trust
        .map(|bundle| -> Result<NetworkTrust> {
            Ok(NetworkTrust {
                digest: bundle.digest().to_string(),
                certificate_count: u32::try_from(bundle.certificate_count())
                    .map_err(|_| Error::config("network trust bundle has too many certificates"))?,
                artifact_path: bundle
                    .artifact_path()
                    .to_str()
                    .ok_or_else(|| Error::config("network trust artifact path is not UTF-8"))?
                    .to_string(),
            })
        })
        .transpose()?;
    Ok(ConfigureRequest {
        protocol_version: openshell_driver_launch::PROTOCOL_VERSION,
        required_features: Vec::new(),
        gateway: Some(GatewayContext {
            gateway_port: u32::from(context.gateway_port),
            tls_ca_path,
            gateway_name: context.gateway_name.to_string(),
        }),
        network_trust,
        driver_config_toml,
        image_overrides: context.image_overrides.clone(),
        telemetry: context.otlp_config.map(telemetry),
    })
}

/// The gateway's OTLP settings for the driver's own export and its supervisors.
fn telemetry(otlp: &OtlpConfig) -> openshell_driver_launch::proto::Telemetry {
    use openshell_driver_launch::proto::{CollectorTls, OtlpExport, Telemetry};

    let exports = otlp.supervisor_otlp();
    let export = |export: Option<openshell_core::sandbox_env::OtlpExport>| {
        export.map(|export| OtlpExport {
            endpoint: export.endpoint,
            protocol: export.protocol.as_str().to_string(),
        })
    };
    let path = |path: Option<&Path>| {
        path.map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    Telemetry {
        traces: export(exports.traces),
        ocsf: export(exports.ocsf),
        agent: export(exports.agent),
        collector: otlp.traces.as_ref().map(|traces| CollectorTls {
            ca_file: path(traces.collector.ca_file()),
            cert_file: path(traces.collector.cert_file()),
            key_file: path(traces.collector.key_file()),
        }),
        trace_headers: openshell_server::gateway_trace_headers(Some(otlp))
            .map(|headers| headers.expose_secret().to_string())
            .unwrap_or_default(),
    }
}

/// How long auto-detection waits for a driver's `probe` before it counts the
/// driver as not available.
#[cfg(unix)]
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Run `<binary> <args>` with no input and return its standard output.
///
/// The command gets `timeout` to exit successfully and may print at most
/// `max_output` bytes. A command that fails, runs out of time, or prints more
/// than that returns an error message.
#[cfg(unix)]
fn run_bounded(
    binary: &Path,
    args: &[&std::ffi::OsStr],
    timeout: Duration,
    max_output: usize,
) -> std::result::Result<Vec<u8>, String> {
    run_bounded_with_input(binary, args, None, timeout, max_output)
}

/// [`run_bounded`], writing `input` to the command's stdin when given.
#[cfg(unix)]
fn run_bounded_with_input(
    binary: &Path,
    args: &[&std::ffi::OsStr],
    input: Option<Vec<u8>>,
    timeout: Duration,
    max_output: usize,
) -> std::result::Result<Vec<u8>, String> {
    use std::io::{Read as _, Write as _};

    let mut child = std::process::Command::new(binary)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("failed to run '{}': {error}", binary.display()))?;
    // Write from a thread so a driver that does not read its input cannot
    // block the gateway; the pipe closes when the thread finishes.
    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        std::thread::spawn(move || {
            let _ = stdin.write_all(&input);
        });
    }
    // Read while the process runs, so output beyond the pipe buffer cannot
    // block it. Reading stops one byte past the limit, which closes the pipe.
    let reader = child.stdout.take().map(|stdout| {
        std::thread::spawn(move || {
            let mut output = Vec::new();
            stdout
                .take(max_output as u64 + 1)
                .read_to_end(&mut output)
                .map(|_| output)
        })
    });
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("timed out after {}s", timeout.as_secs()));
            }
            Err(error) => return Err(format!("failed to wait for the process: {error}")),
        }
    };
    let output = match reader {
        Some(reader) => reader
            .join()
            .map_err(|_| "output reader panicked".to_string())?
            .map_err(|error| format!("failed to read output: {error}"))?,
        None => Vec::new(),
    };
    // Output past the limit closes the pipe on the process, which then ends
    // with SIGPIPE. Hand it back so the caller reports the size, not the signal.
    if output.len() > max_output {
        return Ok(output);
    }
    if !status.success() {
        return Err(format!("exited with {status}"));
    }
    Ok(output)
}

/// Have a driver launched in `serve` mode validate the `Configure` request it
/// would receive, without starting it. The request goes to `preflight` on
/// stdin, so no file is written.
///
/// # Errors
///
/// Returns an error naming the driver when it cannot be run, fails, times out,
/// prints unusable output, or rejects the configuration.
#[cfg(unix)]
pub fn preflight_configured(
    driver: &DriverProcess<'_>,
    timeout: Duration,
    request: &ConfigureRequest,
) -> Result<()> {
    use openshell_driver_sdk::preflight::{MAX_PREFLIGHT_OUTPUT_BYTES, PreflightResult};

    let name = driver.name;
    let binary = trusted_driver_bin(driver)?;
    let output = run_bounded_with_input(
        &binary,
        &["preflight".as_ref()],
        Some(openshell_driver_launch::encode_configure_request(request)),
        timeout,
        MAX_PREFLIGHT_OUTPUT_BYTES,
    )
    .map_err(|error| Error::config(format!("{name} compute driver preflight {error}")))?;
    let result = PreflightResult::parse(&output)
        .map_err(|error| Error::config(format!("{name} compute driver: {error}")))?;
    if result.ok {
        Ok(())
    } else {
        Err(Error::config(result.error.unwrap_or_else(|| {
            format!("{name} compute driver rejected its configuration")
        })))
    }
}

/// Resolve the driver binary and check that the gateway can trust it.
#[cfg(unix)]
fn trusted_driver_bin(driver: &DriverProcess<'_>) -> Result<PathBuf> {
    let binary = resolve_driver_bin(driver)?;
    check_driver_binary_trust(&binary, current_euid())?;
    Ok(binary)
}

/// Run `<binary> probe` and report whether the driver is usable here.
///
/// A missing or untrusted binary, a failed or timed-out probe, and oversized or
/// malformed output all count as not available, and the reason names the
/// driver, so detection never hangs on or trusts one broken driver.
#[cfg(unix)]
pub fn probe(
    driver: &DriverProcess<'_>,
    timeout: Duration,
) -> openshell_driver_sdk::probe::ProbeResult {
    use openshell_driver_sdk::probe::{MAX_PROBE_OUTPUT_BYTES, ProbeResult};

    let name = driver.name;
    let unavailable = |reason: String| ProbeResult::unavailable(format!("{name} driver: {reason}"));
    let binary = match trusted_driver_bin(driver) {
        Ok(binary) => binary,
        Err(error) => return unavailable(error.to_string()),
    };
    let output = match run_bounded(
        &binary,
        &["probe".as_ref()],
        timeout,
        MAX_PROBE_OUTPUT_BYTES,
    ) {
        Ok(output) => output,
        Err(error) => return unavailable(format!("probe {error}")),
    };
    ProbeResult::parse(&output).unwrap_or_else(unavailable)
}

/// How long `preflight` may take before the driver counts as failed.
#[cfg(unix)]
pub const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(unix)]
const EXIT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// How long the watcher waits for the gateway's own shutdown to begin after a
/// driver exits. A stop signal reaches the driver and the gateway together, so
/// the driver can end a moment before the gateway notices it must shut down.
#[cfg(unix)]
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Call `on_exit` with a message naming the driver if the process ends while
/// the gateway still holds it and is not shutting down. The gateway cannot
/// serve sandboxes without its driver, so the caller exits and leaves a
/// restart to the init system.
#[cfg(unix)]
fn watch_for_exit(
    process: std::sync::Weak<ManagedDriverProcess>,
    name: String,
    interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    grace: Duration,
    on_exit: impl FnOnce(String) + Send + 'static,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            if *shutdown.borrow() {
                return;
            }
            let Some(process) = process.upgrade() else {
                return;
            };
            match process.poll_exit() {
                DriverProcessState::Running => {}
                DriverProcessState::Released => return,
                DriverProcessState::Exited(status) => {
                    drop(process);
                    if tokio::time::timeout(grace, shutdown.wait_for(|stopping| *stopping))
                        .await
                        .is_ok()
                    {
                        return;
                    }
                    on_exit(format!(
                        "{name} compute driver exited unexpectedly with status {status}"
                    ));
                    return;
                }
            }
        }
    });
}

/// Refuse a driver binary, or the directory that holds it, that another user
/// could replace: it must be owned by the gateway's effective user or root and
/// must not be group- or world-writable.
#[cfg(unix)]
fn check_driver_binary_trust(binary: &Path, expected_uid: u32) -> Result<()> {
    let binary = binary.canonicalize().map_err(|error| {
        Error::config(format!(
            "failed to resolve compute driver binary '{}': {error}",
            binary.display()
        ))
    })?;
    let directory = binary.parent().ok_or_else(|| {
        Error::config(format!(
            "compute driver binary '{}' has no parent directory",
            binary.display()
        ))
    })?;
    for (label, path) in [("binary", binary.as_path()), ("directory", directory)] {
        let metadata = std::fs::metadata(path).map_err(|error| {
            Error::config(format!(
                "failed to inspect compute driver {label} '{}': {error}",
                path.display()
            ))
        })?;
        if metadata.uid() != expected_uid && metadata.uid() != 0 {
            return Err(Error::config(format!(
                "compute driver {label} '{}' is owned by uid {}, not root or the gateway's uid {expected_uid}",
                path.display(),
                metadata.uid()
            )));
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            return Err(Error::config(format!(
                "compute driver {label} '{}' is group- or world-writable (mode {mode:o})",
                path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub async fn launch_configured(
    _driver: &DriverProcess<'_>,
    _log_level: &str,
    _shutdown: tokio::sync::watch::Receiver<bool>,
    _request: ConfigureRequest,
) -> Result<AcquiredRemoteDriverEndpoint> {
    Err(Error::config(
        "launched compute drivers require unix domain socket support",
    ))
}

/// Readiness polls, 100 ms apart. The Podman driver retries its API ping for
/// about ten seconds before it binds its socket, so the wait is longer.
#[cfg(unix)]
const READY_POLLS: u32 = 300;

/// Wait for a driver launched in `serve` mode to answer `GetLaunchInfo`, and
/// check that it speaks this gateway's launch protocol version.
#[cfg(unix)]
#[tracing::instrument(
    name = "driver.wait_for_launch_service",
    skip_all,
    fields(
        otel.name = "driver.wait_for_launch_service",
        otel.status_code = tracing::field::Empty,
        driver.name = %name,
    )
)]
async fn wait_for_launch_service(
    name: &str,
    socket_path: &Path,
    child: &mut tokio::process::Child,
) -> Result<Channel> {
    let (channel, versions) = wait_for_socket(name, socket_path, child, |channel| async move {
        let mut client = DriverLaunchClient::with_interceptor(channel, TraceContextInterceptor);
        client
            .get_launch_info(tonic::Request::new(GetLaunchInfoRequest {}))
            .await
            .map(|info| info.into_inner().protocol_versions)
            .map_err(|status| status.to_string())
    })
    .await?;
    if !versions.contains(&openshell_driver_launch::PROTOCOL_VERSION) {
        return Err(Error::config(format!(
            "{name} compute driver supports launch protocol versions {versions:?}, but this gateway needs {}",
            openshell_driver_launch::PROTOCOL_VERSION
        )));
    }
    Ok(channel)
}

/// Poll until the driver's socket accepts a connection and `ready` succeeds on
/// it, failing early if the driver exits.
#[cfg(unix)]
async fn wait_for_socket<T, F, Fut>(
    name: &str,
    socket_path: &Path,
    child: &mut tokio::process::Child,
    mut ready: F,
) -> Result<(Channel, T)>
where
    F: FnMut(Channel) -> Fut,
    Fut: Future<Output = std::result::Result<T, String>>,
{
    let mut last_error: Option<String> = None;
    for _ in 0..READY_POLLS {
        let try_wait_result = child.try_wait().map_err(|e| {
            Error::execution(format!("failed to poll {name} compute driver process: {e}"))
        })?;
        if let Some(status) = try_wait_result {
            return Err(Error::execution(format!(
                "{name} compute driver exited before becoming ready with status {status}"
            )));
        }

        match connect_compute_driver(name, socket_path).await {
            Ok(channel) => match ready(channel.clone()).await {
                Ok(value) => return Ok((channel, value)),
                Err(error) => last_error = Some(error),
            },
            Err(err) => last_error = Some(err.to_string()),
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(Error::execution(format!(
        "timed out waiting for {name} compute driver socket '{}': {}",
        socket_path.display(),
        last_error.unwrap_or_else(|| "unknown error".to_string())
    )))
}

#[cfg(unix)]
async fn connect_compute_driver(name: &str, socket_path: &Path) -> Result<Channel> {
    let socket_path = socket_path.to_path_buf();
    let display_path = socket_path.clone();
    Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
            let socket_path = socket_path.clone();
            async move { UnixStream::connect(socket_path).await.map(TokioIo::new) }
        }))
        .await
        .map_err(|e| {
            Error::execution(format!(
                "failed to connect to {name} compute driver socket '{}': {e}",
                display_path.display()
            ))
        })
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        ConfigureContext, DriverProcess, check_driver_binary_trust, configure_request,
        current_euid, prepare_socket_path, prepare_state_dir, resolve_driver_bin,
        resolve_driver_search_dirs, socket_path, watch_for_exit,
    };
    use openshell_server::ManagedDriverProcess;
    use openshell_server::config_file::OtlpConfig;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener as StdUnixListener;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::tempdir;

    /// Owned inputs for a [`DriverProcess`] in tests.
    #[derive(Default)]
    struct TestDriver {
        driver_dir: Option<PathBuf>,
        state_dir: Option<PathBuf>,
    }

    impl TestDriver {
        fn state_dir(&self) -> PathBuf {
            self.state_dir.clone().unwrap_or_default()
        }

        fn process(&self) -> DriverProcess<'_> {
            DriverProcess {
                name: "test",
                binary_name: "openshell-driver-test",
                driver_dir: self.driver_dir.as_deref(),
                driver_dir_key: Some("[openshell.drivers.test].driver_dir"),
                state_dir: self.state_dir.as_deref().unwrap_or_else(|| Path::new("")),
            }
        }
    }

    #[test]
    fn configure_carries_trace_headers_and_the_driver_table() {
        crate::test_environment::Environment::new()
            .remove("OTEL_EXPORTER_OTLP_HEADERS")
            .remove("OTEL_EXPORTER_OTLP_TRACES_HEADERS")
            .run(|| {
                let otlp: OtlpConfig = toml::from_str(
                    "endpoint = 'http://collector.internal:4318'\n\
                 headers = { authorization = 'Bearer secret-token' }\n",
                )
                .unwrap();
                let table: toml::Table = toml::from_str("vcpus = 4\n").unwrap();
                let request = configure_request(&ConfigureContext {
                    driver_name: "test",
                    gateway_name: "g",
                    gateway_port: 8080,
                    tls_ca: None,
                    otlp_config: Some(&otlp),
                    network_trust: None,
                    driver_config: &table,
                    image_overrides: None,
                })
                .unwrap();
                assert_eq!(
                    request.protocol_version,
                    openshell_driver_launch::PROTOCOL_VERSION
                );
                assert_eq!(
                    toml::from_str::<toml::Table>(&request.driver_config_toml).unwrap(),
                    table
                );
                assert_eq!(
                    request.telemetry.unwrap().trace_headers,
                    "authorization=Bearer%20secret-token"
                );
            });
    }

    #[test]
    fn resolve_driver_bin_uses_driver_dir_when_binary_present() {
        let dir = tempdir().unwrap();
        let bin = dir.path().join("openshell-driver-test");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let vm_config = TestDriver {
            driver_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        assert_eq!(resolve_driver_bin(&vm_config.process()).unwrap(), bin);
    }

    #[test]
    fn resolve_driver_bin_error_mentions_driver_dir_hint() {
        let dir = tempdir().unwrap(); // empty — no driver binary present

        let vm_config = TestDriver {
            driver_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let err = resolve_driver_bin(&vm_config.process())
            .unwrap_err()
            .to_string();
        assert!(err.contains("[openshell.drivers.test].driver_dir"));
        assert!(err.contains("openshell-driver-test"));
    }

    #[test]
    fn resolve_driver_search_dirs_include_libexec_fallbacks() {
        let dirs = resolve_driver_search_dirs(None);

        assert!(dirs.contains(&PathBuf::from("/usr/libexec/openshell")));
        assert!(dirs.contains(&PathBuf::from("/usr/local/libexec/openshell")));
        assert!(dirs.contains(&PathBuf::from("/usr/local/libexec")));
    }

    #[test]
    fn compute_driver_socket_path_uses_private_run_dir() {
        let state_dir = PathBuf::from("/tmp/openshell-vm-state");
        let vm_config = TestDriver {
            state_dir: Some(state_dir.clone()),
            ..Default::default()
        };

        assert_eq!(
            socket_path(&vm_config.process()),
            state_dir.join("run").join("compute-driver.sock")
        );
    }

    #[test]
    fn prepare_compute_driver_socket_path_creates_private_run_dir() {
        let dir = tempdir().unwrap();
        let vm_config = TestDriver {
            state_dir: Some(dir.path().join("state")),
            ..Default::default()
        };
        let socket_path = socket_path(&vm_config.process());

        prepare_socket_path(&vm_config.process(), &socket_path).unwrap();

        let mode = std::fs::metadata(vm_config.state_dir().join("run"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn prepare_compute_driver_socket_path_restricts_existing_run_dir() {
        let dir = tempdir().unwrap();
        let vm_config = TestDriver {
            state_dir: Some(dir.path().join("state")),
            ..Default::default()
        };
        let run_dir = vm_config.state_dir().join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let socket_path = socket_path(&vm_config.process());

        prepare_socket_path(&vm_config.process(), &socket_path).unwrap();

        let mode = std::fs::metadata(run_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn prepare_compute_driver_socket_path_restricts_existing_state_dir() {
        let dir = tempdir().unwrap();
        let vm_config = TestDriver {
            state_dir: Some(dir.path().join("state")),
            ..Default::default()
        };
        std::fs::create_dir_all(vm_config.state_dir()).unwrap();
        std::fs::set_permissions(
            vm_config.state_dir(),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        let socket_path = socket_path(&vm_config.process());

        prepare_socket_path(&vm_config.process(), &socket_path).unwrap();

        let mode = std::fs::metadata(vm_config.state_dir())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn prepare_compute_driver_socket_path_rejects_symlinked_state_dir() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target");
        let state_link = dir.path().join("state-link");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, &state_link).unwrap();
        let vm_config = TestDriver {
            state_dir: Some(state_link),
            ..Default::default()
        };
        let socket_path = socket_path(&vm_config.process());

        let err = prepare_socket_path(&vm_config.process(), &socket_path)
            .expect_err("symlinked state dir should be rejected")
            .to_string();
        assert!(err.contains("is a symlink"));
    }

    #[test]
    fn prepare_compute_driver_socket_path_rejects_symlinked_run_dir() {
        let dir = tempdir().unwrap();
        let vm_config = TestDriver {
            state_dir: Some(dir.path().join("state")),
            ..Default::default()
        };
        let target = dir.path().join("run-target");
        std::fs::create_dir_all(vm_config.state_dir()).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, vm_config.state_dir().join("run")).unwrap();
        let socket_path = socket_path(&vm_config.process());

        let err = prepare_socket_path(&vm_config.process(), &socket_path)
            .expect_err("symlinked run dir should be rejected")
            .to_string();
        assert!(err.contains("is a symlink"));
    }

    #[test]
    fn prepare_vm_state_dir_rejects_wrong_owner() {
        let dir = tempdir().unwrap();
        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let wrong_uid = if current_euid() == u32::MAX {
            u32::MAX - 1
        } else {
            current_euid() + 1
        };

        let err = prepare_state_dir(&state_dir, wrong_uid)
            .expect_err("wrong owner should be rejected")
            .to_string();
        assert!(err.contains("is owned by uid"));
    }

    #[test]
    fn prepare_compute_driver_socket_path_rejects_symlinked_socket() {
        let dir = tempdir().unwrap();
        let vm_config = TestDriver {
            state_dir: Some(dir.path().join("state")),
            ..Default::default()
        };
        let socket_path = socket_path(&vm_config.process());
        std::fs::create_dir_all(socket_path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink("/tmp/not-a-socket", &socket_path).unwrap();

        let err = prepare_socket_path(&vm_config.process(), &socket_path)
            .expect_err("symlinked socket should be rejected")
            .to_string();
        assert!(err.contains("is a symlink"));
    }

    #[test]
    fn prepare_compute_driver_socket_path_rejects_non_socket_stale_path() {
        let dir = tempdir().unwrap();
        let vm_config = TestDriver {
            state_dir: Some(dir.path().join("state")),
            ..Default::default()
        };
        let socket_path = socket_path(&vm_config.process());
        std::fs::create_dir_all(socket_path.parent().unwrap()).unwrap();
        std::fs::write(&socket_path, "not a socket").unwrap();

        let err = prepare_socket_path(&vm_config.process(), &socket_path)
            .expect_err("regular file should be rejected")
            .to_string();
        assert!(err.contains("is not a Unix socket"));
    }

    #[test]
    fn prepare_compute_driver_socket_path_removes_same_owner_stale_socket() {
        let dir = tempdir().unwrap();
        let vm_config = TestDriver {
            state_dir: Some(dir.path().join("state")),
            ..Default::default()
        };
        let socket_path = socket_path(&vm_config.process());
        std::fs::create_dir_all(socket_path.parent().unwrap()).unwrap();
        let listener = StdUnixListener::bind(&socket_path).unwrap();

        prepare_socket_path(&vm_config.process(), &socket_path).unwrap();

        drop(listener);
        assert!(!socket_path.exists());
    }

    fn driver_binary(dir: &Path, binary_mode: u32, dir_mode: u32) -> PathBuf {
        let binary = dir.join("openshell-driver-test");
        std::fs::write(&binary, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(binary_mode)).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(dir_mode)).unwrap();
        binary
    }

    #[test]
    fn a_driver_binary_owned_by_the_gateway_user_is_trusted() {
        let dir = tempdir().unwrap();
        let binary = driver_binary(dir.path(), 0o755, 0o755);
        check_driver_binary_trust(&binary, current_euid()).unwrap();
    }

    #[test]
    fn a_writable_driver_binary_or_directory_is_refused() {
        let dir = tempdir().unwrap();
        for (binary_mode, dir_mode, what) in [(0o775, 0o755, "binary"), (0o757, 0o755, "binary")] {
            let binary = driver_binary(dir.path(), binary_mode, dir_mode);
            let error = check_driver_binary_trust(&binary, current_euid()).unwrap_err();
            assert!(error.to_string().contains(what), "{error}");
            assert!(error.to_string().contains("writable"), "{error}");
        }
        let binary = driver_binary(dir.path(), 0o755, 0o777);
        let error = check_driver_binary_trust(&binary, current_euid()).unwrap_err();
        assert!(error.to_string().contains("directory"), "{error}");
        assert!(error.to_string().contains("writable"), "{error}");
    }

    #[test]
    fn a_driver_binary_owned_by_another_user_is_refused() {
        let dir = tempdir().unwrap();
        let binary = driver_binary(dir.path(), 0o755, 0o755);
        // The binary is owned by the test user, so pretend the gateway runs as
        // someone else. Root-owned files remain acceptable, so skip as root.
        if current_euid() == 0 {
            return;
        }
        let error = check_driver_binary_trust(&binary, current_euid() + 1).unwrap_err();
        assert!(error.to_string().contains("owned by uid"), "{error}");
    }

    fn spawn_sleeper(seconds: &str) -> tokio::process::Child {
        tokio::process::Command::new("sleep")
            .arg(seconds)
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    }

    #[tokio::test]
    async fn a_driver_that_exits_after_it_was_ready_is_reported_by_name() {
        let dir = tempdir().unwrap();
        let child = tokio::process::Command::new("sh")
            .args(["-c", "exit 3"])
            .spawn()
            .unwrap();
        let process = Arc::new(ManagedDriverProcess::new(child, dir.path().join("d.sock")));
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let (_shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
        watch_for_exit(
            Arc::downgrade(&process),
            "vm".to_string(),
            Duration::from_millis(10),
            shutdown,
            Duration::from_millis(50),
            move |message| {
                let _ = sender.send(message);
            },
        );
        let message = tokio::time::timeout(Duration::from_secs(5), receiver)
            .await
            .unwrap()
            .unwrap();
        assert!(
            message.contains("vm compute driver exited unexpectedly"),
            "{message}"
        );
        assert!(message.contains("exit status: 3"), "{message}");
    }

    #[tokio::test]
    async fn a_running_driver_is_not_reported() {
        let dir = tempdir().unwrap();
        let process = Arc::new(ManagedDriverProcess::new(
            spawn_sleeper("30"),
            dir.path().join("d.sock"),
        ));
        let (sender, mut receiver) = tokio::sync::oneshot::channel::<String>();
        let (_shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
        watch_for_exit(
            Arc::downgrade(&process),
            "vm".to_string(),
            Duration::from_millis(10),
            shutdown,
            Duration::from_millis(50),
            move |message| {
                let _ = sender.send(message);
            },
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(receiver.try_recv().is_err());
        drop(process);
    }

    /// A stop signal reaches the driver and the gateway together. A driver that
    /// ends while the gateway is shutting down is not a failure.
    #[tokio::test]
    async fn a_driver_that_exits_during_gateway_shutdown_is_not_reported() {
        let dir = tempdir().unwrap();
        let child = tokio::process::Command::new("sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        let process = Arc::new(ManagedDriverProcess::new(child, dir.path().join("d.sock")));
        let (sender, mut receiver) = tokio::sync::oneshot::channel::<String>();
        let (shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
        watch_for_exit(
            Arc::downgrade(&process),
            "vm".to_string(),
            Duration::from_millis(10),
            shutdown,
            Duration::from_secs(5),
            move |message| {
                let _ = sender.send(message);
            },
        );
        // The driver has exited by the time the watcher notices. The gateway
        // begins its own shutdown inside the grace period.
        tokio::time::sleep(Duration::from_millis(100)).await;
        shutdown_tx.send_replace(true);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn output_beyond_the_limit_is_not_mistaken_for_a_timeout() {
        let dir = tempdir().unwrap();
        let binary = probe_script(dir.path(), "head -c 300000 /dev/zero | tr '\\0' x");
        let output = super::run_bounded(&binary, &[], Duration::from_secs(5), 4096).unwrap();
        assert_eq!(output.len(), 4097);
    }

    fn probe_script(dir: &Path, body: &str) -> PathBuf {
        let binary = driver_binary(dir, 0o755, 0o755);
        std::fs::write(&binary, format!("#!/bin/sh\n{body}\n")).unwrap();
        binary
    }

    fn run_probe(body: &str, timeout: Duration) -> openshell_driver_sdk::probe::ProbeResult {
        let dir = tempdir().unwrap();
        probe_script(dir.path(), body);
        let state = dir.path().join("state");
        let driver = DriverProcess {
            name: "test",
            binary_name: "openshell-driver-test",
            driver_dir: Some(dir.path()),
            driver_dir_key: None,
            state_dir: &state,
        };
        super::probe(&driver, timeout)
    }

    #[test]
    fn a_probe_reports_availability() {
        let result = run_probe("echo '{\"available\":true}'", Duration::from_secs(5));
        assert!(result.available, "{result:?}");
        let result = run_probe(
            "echo '{\"available\":false,\"reason\":\"no socket\"}'",
            Duration::from_secs(5),
        );
        assert!(!result.available);
        assert_eq!(result.reason.as_deref(), Some("no socket"));
    }

    #[test]
    fn a_broken_probe_counts_as_unavailable_and_names_the_driver() {
        for body in [
            "exit 1",
            "echo not-json",
            "head -c 100000 /dev/zero | tr '\\0' ' '",
            "sleep 30",
        ] {
            let result = run_probe(body, Duration::from_millis(300));
            assert!(!result.available, "{body}");
            assert!(result.reason.unwrap().starts_with("test driver:"), "{body}");
        }
    }

    #[test]
    fn a_missing_driver_is_unavailable() {
        let dir = tempdir().unwrap();
        let state = dir.path().join("state");
        let driver = DriverProcess {
            name: "test",
            binary_name: "openshell-driver-absent",
            driver_dir: Some(dir.path()),
            driver_dir_key: None,
            state_dir: &state,
        };
        assert!(!super::probe(&driver, Duration::from_secs(1)).available);
    }

    fn run_preflight(body: &str, timeout: Duration) -> openshell_core::Result<()> {
        let dir = tempdir().unwrap();
        probe_script(dir.path(), body);
        let state = dir.path().join("state");
        let driver = DriverProcess {
            name: "test",
            binary_name: "openshell-driver-test",
            driver_dir: Some(dir.path()),
            driver_dir_key: None,
            state_dir: &state,
        };
        let request = openshell_driver_launch::proto::ConfigureRequest {
            protocol_version: openshell_driver_launch::PROTOCOL_VERSION,
            ..Default::default()
        };
        let result = super::preflight_configured(&driver, timeout, &request);
        assert!(!state.exists(), "preflight must not create driver state");
        result
    }

    #[test]
    fn preflight_reports_the_drivers_verdict() {
        run_preflight("echo '{\"ok\":true}'", Duration::from_secs(10)).unwrap();

        let error = run_preflight(
            "echo '{\"ok\":false,\"error\":\"vcpus must be positive\"}'",
            Duration::from_secs(10),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("vcpus must be positive"),
            "{error}"
        );
    }

    #[test]
    fn a_configured_preflight_receives_the_request_on_stdin() {
        let dir = tempdir().unwrap();
        // The script checks it was run as `preflight` with no arguments and
        // got the encoded request on stdin.
        probe_script(
            dir.path(),
            "test \"$1\" = preflight && test $# -eq 1 && test \"$(wc -c)\" -gt 0 && echo '{\"ok\":true}'",
        );
        let state = dir.path().join("state");
        let driver = DriverProcess {
            name: "test",
            binary_name: "openshell-driver-test",
            driver_dir: Some(dir.path()),
            driver_dir_key: None,
            state_dir: &state,
        };
        let request = openshell_driver_launch::proto::ConfigureRequest {
            protocol_version: openshell_driver_launch::PROTOCOL_VERSION,
            driver_config_toml: "network_name = \"n\"".to_string(),
            ..Default::default()
        };
        super::preflight_configured(&driver, Duration::from_secs(10), &request).unwrap();
        assert!(!state.exists(), "preflight must not create driver state");
    }

    #[test]
    fn a_broken_preflight_fails_and_names_the_driver() {
        for body in ["exit 1", "echo nope", "sleep 30"] {
            let error = run_preflight(body, Duration::from_millis(500))
                .unwrap_err()
                .to_string();
            assert!(error.contains("test compute driver"), "{body}: {error}");
        }
    }
}
