// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use futures::Stream;
use miette::{IntoDiagnostic, Result};
use openshell_core::VERSION;
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
use openshell_core::sandbox_env::SupervisorOtlpArgs;
use openshell_driver_vm::startup_config::VmComputeConfig;
#[cfg(target_os = "macos")]
use openshell_driver_vm::{VM_RUNTIME_DIR_ENV, configured_runtime_dir};
use openshell_driver_vm::{
    VmBackend, VmDriver, VmDriverConfig, VmLaunchConfig, VmMount, VsockPortMap, procguard, run_vm,
};
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use tokio::net::{UnixListener, UnixStream};
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "openshell-driver-vm")]
#[command(version = VERSION)]
#[allow(clippy::struct_excessive_bools)]
struct Args {
    /// Operator-owned JSON policy; omitted means driver config disabled and labels required.
    #[arg(
        long,
        env = "OPENSHELL_DRIVER_ADMISSION_CONFIG_JSON",
        default_value = "{}"
    )]
    admission_config_json: openshell_core::resource_admission::DriverAdmissionConfig,
    #[arg(long, hide = true, default_value_t = false)]
    internal_run_vm: bool,

    #[arg(long, hide = true)]
    internal_prepare_image: Option<PathBuf>,

    #[arg(long = "vm-root-disk", hide = true, alias = "vm-rootfs")]
    vm_root_disk: Option<PathBuf>,

    #[arg(long = "vm-overlay-disk", hide = true)]
    vm_overlay_disk: Option<PathBuf>,

    #[arg(long = "vm-image-disk", hide = true)]
    vm_image_disk: Option<PathBuf>,

    #[arg(long = "vm-kernel-image", hide = true)]
    vm_kernel_image: Option<PathBuf>,

    #[arg(long, hide = true)]
    vm_exec: Option<String>,

    #[arg(long, hide = true, default_value = "/")]
    vm_workdir: String,

    #[arg(long, hide = true)]
    vm_env: Vec<String>,

    #[arg(long, hide = true)]
    vm_console_output: Option<PathBuf>,

    #[arg(long, hide = true, default_value_t = 2)]
    vm_vcpus: u8,

    #[arg(long, hide = true, default_value_t = 2048)]
    vm_mem_mib: u32,

    #[arg(long, hide = true, default_value_t = 1)]
    vm_krun_log_level: u32,

    #[arg(long, env = "OPENSHELL_COMPUTE_DRIVER_BIND")]
    bind_address: Option<SocketAddr>,

    #[arg(long, env = "OPENSHELL_COMPUTE_DRIVER_SOCKET")]
    bind_socket: Option<PathBuf>,

    #[arg(long, hide = true)]
    expected_peer_pid: Option<u32>,

    #[arg(
        long,
        env = "OPENSHELL_COMPUTE_DRIVER_ALLOW_UNAUTHENTICATED_TCP",
        default_value_t = false
    )]
    allow_unauthenticated_tcp: bool,

    #[arg(
        long,
        env = "OPENSHELL_COMPUTE_DRIVER_ALLOW_SAME_UID_PEER",
        default_value_t = false
    )]
    allow_same_uid_peer: bool,

    #[arg(long, env = "OPENSHELL_LOG_LEVEL", default_value = "info")]
    log_level: String,

    #[command(flatten)]
    otlp: SupervisorOtlpArgs,

    #[arg(long, env = "OPENSHELL_GATEWAY_NAME")]
    gateway_name: Option<String>,

    #[arg(long = "grpc-endpoint", env = "OPENSHELL_GRPC_ENDPOINT")]
    grpc_endpoint: Option<String>,

    #[arg(long, env = "OPENSHELL_SANDBOX_IMAGE", default_value = "")]
    default_image: String,

    #[arg(long, env = "OPENSHELL_VM_BOOTSTRAP_IMAGE", default_value = "")]
    bootstrap_image: String,

    #[arg(
        long,
        env = "OPENSHELL_VM_DRIVER_STATE_DIR",
        default_value = "target/openshell-vm-driver"
    )]
    state_dir: PathBuf,

    #[arg(long = "guest-tls-ca", env = "OPENSHELL_VM_TLS_CA")]
    guest_tls_ca: Option<PathBuf>,

    /// Deprecated; client certificates are rejected.
    #[arg(long = "guest-tls-cert", env = "OPENSHELL_VM_TLS_CERT")]
    guest_tls_cert: Option<PathBuf>,

    /// Deprecated; client private keys are rejected.
    #[arg(long = "guest-tls-key", env = "OPENSHELL_VM_TLS_KEY")]
    guest_tls_key: Option<PathBuf>,

    /// Gateway-owned normalized destination trust artifact. This hidden option
    /// is supplied only by the in-process gateway VM factory.
    #[arg(long, hide = true)]
    additional_ca_bundle: Option<PathBuf>,

    /// Expected SHA-256 generation of the gateway-owned destination trust
    /// artifact. Supplied with the path so the child can authenticate its
    /// one-time startup read without receiving CA bytes on argv or in env.
    #[arg(long, hide = true)]
    additional_ca_digest: Option<String>,

    /// Expected certificate count in the gateway-normalized destination trust
    /// artifact.
    #[arg(long, hide = true)]
    additional_ca_certificate_count: Option<usize>,

    /// Corporate forward proxy for supervisor TLS egress.
    #[arg(long, env = "OPENSHELL_VM_UPSTREAM_PROXY")]
    upstream_proxy: Option<String>,

    #[arg(long, env = "OPENSHELL_VM_UPSTREAM_NO_PROXY")]
    upstream_no_proxy: Option<String>,

    /// Root-owned gateway-host file containing `user:pass` proxy credentials.
    #[arg(long, env = "OPENSHELL_VM_UPSTREAM_PROXY_AUTH_FILE")]
    upstream_proxy_auth_file: Option<PathBuf>,

    /// Explicitly acknowledge cleartext Basic authentication to an http proxy.
    #[arg(
        long,
        env = "OPENSHELL_VM_UPSTREAM_PROXY_AUTH_ALLOW_INSECURE",
        default_value_t = false
    )]
    upstream_proxy_auth_allow_insecure: bool,

    #[arg(
        long,
        env = "OPENSHELL_VM_UPSTREAM_PROXY_CONNECT_BY_HOSTNAME",
        default_value_t = false
    )]
    upstream_proxy_connect_by_hostname: bool,

    /// Gateway-host PEM CA bundle trusted for the corporate proxy and for
    /// server certificates re-signed by a TLS-intercepting proxy.
    #[arg(long, env = "OPENSHELL_VM_UPSTREAM_PROXY_CA_BUNDLE")]
    upstream_proxy_ca_bundle: Option<PathBuf>,

    /// Guest-reachable SPIFFE Workload API endpoint (`tcp:IP:port`).
    #[arg(
        long = "provider-spiffe-workload-api-tcp-endpoint",
        env = "OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_TCP_ENDPOINT"
    )]
    provider_spiffe_workload_api_tcp_endpoint: Option<String>,

    /// Explicit acknowledgement that the configured Workload API listener is exposed to VM guests.
    #[arg(
        long,
        env = "OPENSHELL_PROVIDER_SPIFFE_ALLOW_GUEST_TCP",
        default_value_t = false
    )]
    provider_spiffe_allow_guest_tcp: bool,

    #[arg(long, env = "OPENSHELL_VM_KRUN_LOG_LEVEL", default_value_t = 1)]
    krun_log_level: u32,

    #[arg(long, env = "OPENSHELL_VM_DRIVER_VCPUS", default_value_t = 2)]
    vcpus: u8,

    #[arg(long, env = "OPENSHELL_VM_DRIVER_MEM_MIB", default_value_t = 2048)]
    mem_mib: u32,

    #[arg(long, env = "OPENSHELL_VM_OVERLAY_DISK_MIB", default_value_t = 4096)]
    overlay_disk_mib: u64,

    #[arg(long, env = "OPENSHELL_VM_GPU")]
    gpu: bool,

    #[arg(long, env = "OPENSHELL_VM_GPU_MEM_MIB", default_value_t = 8192)]
    gpu_mem_mib: u32,

    #[arg(long, env = "OPENSHELL_VM_GPU_VCPUS", default_value_t = 4)]
    gpu_vcpus: u8,

    #[arg(long, env = "OPENSHELL_VM_SANDBOX_UID")]
    sandbox_uid: Option<u32>,

    #[arg(long, env = "OPENSHELL_VM_SANDBOX_GID")]
    sandbox_gid: Option<u32>,

    // Corporate forward proxy for sandbox egress. Operator-owned: these reach
    // the host supervisor on its argv, which the sandbox image and the
    // user-supplied environment cannot influence.
    #[arg(long, env = "OPENSHELL_VM_HTTPS_PROXY")]
    https_proxy: Option<String>,

    #[arg(long, env = "OPENSHELL_VM_NO_PROXY")]
    no_proxy: Option<String>,

    #[arg(long, env = "OPENSHELL_VM_PROXY_AUTH_FILE")]
    proxy_auth_file: Option<String>,

    // Value-taking rather than a presence flag so an explicit `false` in
    // `[openshell.drivers.vm]` survives the gateway -> driver hop and still
    // trips the "acknowledgement without a credential" check.
    #[arg(long, env = "OPENSHELL_VM_PROXY_AUTH_ALLOW_INSECURE")]
    proxy_auth_allow_insecure: Option<bool>,

    #[arg(long, env = "OPENSHELL_VM_PROXY_CONNECT_BY_HOSTNAME")]
    proxy_connect_by_hostname: Option<bool>,

    #[arg(long, env = "OPENSHELL_VM_PROXY_CA_BUNDLE")]
    proxy_ca_bundle: Option<String>,

    #[arg(long, env = "OPENSHELL_VM_ENABLE_BIND_MOUNTS", default_value_t = false)]
    enable_bind_mounts: bool,

    #[arg(long, env = "OPENSHELL_VM_ROOTFS_TAR_STAGING_DIR")]
    rootfs_tar_staging_dir: Option<PathBuf>,

    #[arg(long, env = "OPENSHELL_VM_ROOTFS_TAR_MAX_BYTES")]
    rootfs_tar_max_bytes: Option<u64>,

    #[arg(long, hide = true)]
    vm_backend: Option<String>,

    #[arg(long, hide = true)]
    vm_gpu_bdf: Option<String>,

    #[arg(long, hide = true)]
    vm_vsock_cid: Option<u32>,

    #[arg(long, hide = true)]
    vm_vsock_control_port: Option<u32>,

    #[arg(long, hide = true)]
    vm_vsock_control_socket: Option<PathBuf>,

    #[arg(long, hide = true)]
    vm_vsock_runtime_initiated: bool,

    #[arg(long, hide = true)]
    vm_mount: Vec<String>,
}

/// `preflight` reads the `Configure` request the gateway would send from
/// stdin, validates it, and reports on stdout. It starts nothing and creates
/// no state.
fn run_preflight(arguments: &[std::ffi::OsString]) -> ! {
    use openshell_driver_sdk::preflight::PreflightResult;
    use std::io::Read as _;

    let result = if arguments.is_empty() {
        let mut input = Vec::new();
        io::stdin()
            .take(openshell_driver_launch::MAX_CONFIGURE_REQUEST_BYTES as u64 + 1)
            .read_to_end(&mut input)
            .map_err(|error| format!("failed to read the configure request: {error}"))
            .and_then(|_| openshell_driver_launch::decode_configure_request(&input))
            .and_then(|request| configured_args(&request, "info".to_string()))
            .and_then(|args| vm_driver_config(&args))
            .map_or_else(PreflightResult::rejected, |_| PreflightResult::ok())
    } else {
        PreflightResult::rejected("usage: preflight < configure-request")
    };
    println!("{}", result.to_json());
    std::process::exit(0);
}

/// Bootstrap flags of `serve`, the mode a gateway launches the driver in.
/// Everything else, telemetry included, arrives in the `Configure` RPC.
#[derive(Parser)]
#[command(name = "openshell-driver-vm serve")]
struct ServeArgs {
    /// Unix socket the gateway connects to.
    #[arg(long)]
    bind_socket: PathBuf,

    /// The launching gateway's PID; only it may connect.
    #[arg(long)]
    expected_peer_pid: u32,

    #[arg(long, default_value = "info")]
    log_level: String,
}

/// Serve `DriverLaunch` at once and build the VM driver when the gateway calls
/// `Configure`.
async fn run_serve(arguments: &[std::ffi::OsString]) -> Result<()> {
    let args = ServeArgs::parse_from(
        std::iter::once(std::ffi::OsString::from("openshell-driver-vm serve"))
            .chain(arguments.iter().cloned()),
    );
    let ansi = openshell_core::color::stdout_ansi();
    let driver_tracing = Arc::new(openshell_otel::install_deferred_driver_tracing(
        openshell_driver_vm::otel_tracing::TRACING,
        &args.log_level,
        ansi,
    ));
    // If the gateway is killed, this driver and its VM launchers must die too.
    if let Err(err) = procguard::die_with_parent() {
        tracing::warn!(
            error = %err,
            "procguard arm failed; gateway crashes may orphan this driver"
        );
    }

    let configured = Arc::new(OnceLock::<VmDriver>::new());
    let slot = configured.clone();
    let log_level = args.log_level.clone();
    let (launch, compute) = openshell_driver_launch::services("vm", VERSION, move |request| {
        openshell_driver_sdk::launch::enable_export(
            &driver_tracing,
            &request,
            &log_level,
            ansi,
            VERSION,
        );
        let config =
            configured_args(&request, log_level.clone()).and_then(|args| vm_driver_config(&args));
        let slot = slot.clone();
        async move {
            let config = config.map_err(tonic::Status::invalid_argument)?;
            let driver = VmDriver::new(config)
                .await
                .map_err(tonic::Status::unavailable)?;
            let _ = slot.set(driver.clone());
            info!("vm compute driver configured");
            Ok(ComputeDriverServer::new(driver))
        }
    });

    let socket_path = args.bind_socket;
    prepare_compute_driver_socket(&socket_path).map_err(|err| miette::miette!("{err}"))?;
    info!(socket = %socket_path.display(), "Starting vm compute driver; waiting for Configure");
    let listener = UnixListener::bind(&socket_path).into_diagnostic()?;
    restrict_socket_permissions(&socket_path).map_err(|err| miette::miette!("{err}"))?;
    let result = tonic::transport::Server::builder()
        .layer(openshell_otel::compute_driver_rpc_layer())
        .add_service(launch)
        .add_service(compute)
        .serve_with_incoming_shutdown(
            AuthenticatedUnixIncoming::new(listener, Some(args.expected_peer_pid)),
            shutdown_signal(),
        )
        .await
        .into_diagnostic();
    let _ = std::fs::remove_file(&socket_path);
    if let Some(driver) = configured.get() {
        driver.remove_socket_root();
    }
    result
}

/// The driver's settings for a `Configure` request: the environment and
/// defaults, overlaid with the gateway's settings.
fn configured_args(
    request: &openshell_driver_launch::proto::ConfigureRequest,
    log_level: String,
) -> std::result::Result<Args, String> {
    let mut args =
        Args::try_parse_from(["openshell-driver-vm"]).map_err(|error| error.to_string())?;
    args.log_level = log_level;
    apply_configure(&mut args, request)?;
    Ok(args)
}

/// Overlay a `Configure` request onto the default flags. The request is
/// authoritative for everything it carries; a driver setting the operator
/// table leaves out keeps its default.
fn apply_configure(
    args: &mut Args,
    request: &openshell_driver_launch::proto::ConfigureRequest,
) -> std::result::Result<(), String> {
    let gateway = request.gateway.clone().unwrap_or_default();
    args.gateway_name = (!gateway.gateway_name.is_empty()).then(|| gateway.gateway_name.clone());
    args.guest_tls_ca =
        (!gateway.tls_ca_path.is_empty()).then(|| PathBuf::from(&gateway.tls_ca_path));
    openshell_driver_sdk::launch::apply_telemetry(request.telemetry.as_ref(), &mut args.otlp)?;
    if let Some(trust) = &request.network_trust {
        args.additional_ca_bundle = Some(PathBuf::from(&trust.artifact_path));
        args.additional_ca_digest = Some(trust.digest.clone());
        args.additional_ca_certificate_count = Some(
            usize::try_from(trust.certificate_count)
                .map_err(|_| "network trust certificate count is too large".to_string())?,
        );
    }
    let config: VmComputeConfig = toml::from_str(&request.driver_config_toml)
        .map_err(|error| format!("invalid driver_config: {error}"))?;
    let gateway_port = u16::try_from(gateway.gateway_port)
        .map_err(|_| format!("gateway port {} is out of range", gateway.gateway_port))?;
    let has_tls_ca = args.guest_tls_ca.is_some();
    apply_vm_config(args, config, gateway_port, has_tls_ca)
}

/// The driver configuration the flags, environment, and any gateway settings
/// applied to `args` describe.
fn vm_driver_config(args: &Args) -> std::result::Result<VmDriverConfig, String> {
    Ok(VmDriverConfig {
        allow_driver_config: args.admission_config_json.allow_driver_config,
        resource_admission: args.admission_config_json.resource_admission.clone(),
        grpc_endpoint: args
            .grpc_endpoint
            .clone()
            .ok_or_else(|| "OPENSHELL_GRPC_ENDPOINT is required".to_string())?,
        supervisor_otlp: args.otlp.supervisor_otlp(),
        supervisor_gateway_name: args.gateway_name.clone(),
        state_dir: args.state_dir.clone(),
        launcher_bin: None,
        default_image: args.default_image.clone(),
        bootstrap_image: args.bootstrap_image.clone(),
        log_level: args.log_level.clone(),
        krun_log_level: args.krun_log_level,
        vcpus: args.vcpus,
        mem_mib: args.mem_mib,
        overlay_disk_mib: args.overlay_disk_mib,
        guest_tls_ca: args.guest_tls_ca.clone(),
        guest_tls_cert: args.guest_tls_cert.clone(),
        guest_tls_key: args.guest_tls_key.clone(),
        additional_ca_bundle: args.additional_ca_bundle.clone(),
        additional_ca_digest: args.additional_ca_digest.clone(),
        additional_ca_certificate_count: args.additional_ca_certificate_count,
        additional_ca_snapshot: None,
        upstream_proxy: openshell_core::UpstreamProxyConfig {
            https_proxy: args.upstream_proxy.clone(),
            no_proxy: args.upstream_no_proxy.clone(),
            proxy_auth_file: args.upstream_proxy_auth_file.clone(),
            proxy_auth_allow_insecure: args.upstream_proxy_auth_allow_insecure.then_some(true),
            proxy_connect_by_hostname: args.upstream_proxy_connect_by_hostname.then_some(true),
        },
        proxy_ca_bundle: args.upstream_proxy_ca_bundle.clone(),
        provider_spiffe_workload_api_tcp_endpoint: args
            .provider_spiffe_workload_api_tcp_endpoint
            .clone(),
        provider_spiffe_allow_guest_tcp: args.provider_spiffe_allow_guest_tcp,
        gpu_enabled: args.gpu,
        gpu_mem_mib: args.gpu_mem_mib,
        gpu_vcpus: args.gpu_vcpus,
        sandbox_uid: args.sandbox_uid,
        sandbox_gid: args.sandbox_gid,
        rootfs_tar_staging_dir: args.rootfs_tar_staging_dir.clone(),
        rootfs_tar_max_bytes: args.rootfs_tar_max_bytes,
        enable_bind_mounts: args.enable_bind_mounts,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.first().is_some_and(|arg| arg == "serve") {
        return run_serve(&arguments[1..]).await;
    }
    if arguments.first().is_some_and(|arg| arg == "preflight") {
        run_preflight(&arguments[1..]);
    }
    let args = Args::parse();
    if let Some(request) = args.internal_prepare_image {
        openshell_driver_vm::driver::run_image_preparation_worker(&request)
            .await
            .map_err(|error| miette::miette!("{error}"))?;
        return Ok(());
    }
    if args.internal_run_vm {
        // The VM launcher arms procguard after resolving its runtime so its
        // libkrun worker cannot outlive the launcher.
        maybe_reexec_internal_vm_with_runtime_env()?;
        let config = build_vm_launch_config(&args).map_err(|err| miette::miette!("{err}"))?;
        run_vm(&config).map_err(|err| miette::miette!("{err}"))?;
        return Ok(());
    }

    let _tracing = openshell_otel::install_driver_tracing(
        openshell_driver_vm::otel_tracing::TRACING,
        openshell_otel::DriverTracingConfig {
            endpoint: args.otlp.endpoint.as_deref(),
            protocol: args.otlp.protocol.into(),
            ca_file: args.otlp.ca_file.as_deref(),
            cert_file: args.otlp.cert_file.as_deref(),
            key_file: args.otlp.key_file.as_deref(),
            gateway_name: args.gateway_name.as_deref(),
            service_version: VERSION,
            log_level: &args.log_level,
            ansi: openshell_core::color::stdout_ansi(),
        },
    );
    args.otlp.warn_deprecated();

    let listen_mode = compute_driver_listen_mode(&args).map_err(|err| miette::miette!("{err}"))?;

    // Arm procguard so that if the gateway is killed (SIGKILL or crash)
    // we also die. Without this the driver is reparented to init and
    // keeps its per-sandbox VM launchers alive forever. Launchers have
    // their own procguards (armed in `run_vm`) which cascade cleanup of
    // the libkrun worker the moment this driver exits.
    if let Err(err) = procguard::die_with_parent() {
        tracing::warn!(
            error = %err,
            "procguard arm failed; gateway crashes may orphan this driver"
        );
    }

    let driver = VmDriver::new(vm_driver_config(&args).map_err(|err| miette::miette!("{err}"))?)
        .await
        .map_err(|err| miette::miette!("{err}"))?;

    let socket_cleanup = driver.clone();
    let result = match listen_mode {
        ComputeDriverListenMode::Unix {
            socket_path,
            expected_peer_pid,
        } => {
            prepare_compute_driver_socket(&socket_path).map_err(|err| miette::miette!("{err}"))?;

            info!(socket = %socket_path.display(), "Starting vm compute driver");
            let listener = UnixListener::bind(&socket_path).into_diagnostic()?;
            restrict_socket_permissions(&socket_path).map_err(|err| miette::miette!("{err}"))?;
            let result = tonic::transport::Server::builder()
                .layer(openshell_otel::compute_driver_rpc_layer())
                .add_service(ComputeDriverServer::new(driver))
                .serve_with_incoming_shutdown(
                    AuthenticatedUnixIncoming::new(listener, expected_peer_pid),
                    shutdown_signal(),
                )
                .await
                .into_diagnostic();
            let _ = std::fs::remove_file(&socket_path);
            result
        }
        ComputeDriverListenMode::Tcp(bind_address) => {
            info!(address = %bind_address, "Starting unauthenticated dev vm compute driver");
            tonic::transport::Server::builder()
                .layer(openshell_otel::compute_driver_rpc_layer())
                .add_service(ComputeDriverServer::new(driver))
                .serve_with_shutdown(bind_address, shutdown_signal())
                .await
                .into_diagnostic()
        }
    };
    socket_cleanup.remove_socket_root();
    result
}

/// Apply the driver's own table on top of the gateway context already set on
/// `args`, defaulting the sandbox endpoint to the gateway's own listener.
fn apply_vm_config(
    args: &mut Args,
    mut config: VmComputeConfig,
    gateway_port: u16,
    has_tls_ca: bool,
) -> std::result::Result<(), String> {
    if config.state_dir.as_os_str().is_empty() {
        config.state_dir = VmComputeConfig::default_state_dir();
    }
    // The gateway's own listener is the default endpoint for sandboxes. It has
    // a gateway CA exactly when it serves TLS.
    if config.grpc_endpoint.trim().is_empty() {
        let scheme = if has_tls_ca { "https" } else { "http" };
        config.grpc_endpoint = format!("{scheme}://127.0.0.1:{gateway_port}");
    }
    config
        .validate_configuration()
        .map_err(|error| error.to_string())?;
    // The CA authenticates the gateway for an https endpoint only.
    if !config.grpc_endpoint.starts_with("https://") {
        args.guest_tls_ca = None;
    }

    args.admission_config_json = openshell_core::resource_admission::DriverAdmissionConfig {
        allow_driver_config: config.allow_driver_config,
        resource_admission: config.resource_admission.clone(),
    };
    args.grpc_endpoint = Some(config.grpc_endpoint);
    let proxy = config.upstream_proxy;
    args.upstream_proxy = proxy.https_proxy;
    args.upstream_no_proxy = proxy.no_proxy;
    args.upstream_proxy_auth_file = proxy.proxy_auth_file;
    args.upstream_proxy_auth_allow_insecure = proxy.proxy_auth_allow_insecure == Some(true);
    args.upstream_proxy_connect_by_hostname = proxy.proxy_connect_by_hostname == Some(true);
    args.upstream_proxy_ca_bundle = config.proxy_ca_bundle;
    args.state_dir = config.state_dir;
    if !config.default_image.trim().is_empty() {
        args.default_image = config.default_image;
    }
    if !config.bootstrap_image.trim().is_empty() {
        args.bootstrap_image = config.bootstrap_image;
    }
    args.krun_log_level = config.krun_log_level;
    args.vcpus = config.vcpus;
    args.mem_mib = config.mem_mib;
    args.overlay_disk_mib = config.overlay_disk_mib;
    args.sandbox_uid = config.sandbox_uid;
    args.sandbox_gid = config.sandbox_gid;
    args.rootfs_tar_staging_dir = config.rootfs_tar_staging_dir;
    args.rootfs_tar_max_bytes = config.rootfs_tar_max_bytes;
    args.enable_bind_mounts = config.enable_bind_mounts;
    args.provider_spiffe_workload_api_tcp_endpoint =
        config.provider_spiffe_workload_api_tcp_endpoint;
    args.provider_spiffe_allow_guest_tcp = config.provider_spiffe_allow_guest_tcp;
    Ok(())
}

async fn shutdown_signal() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                tracing::warn!(%error, "failed to listen for Ctrl-C");
            }
        }
        _ = terminate.recv() => {}
    }
    info!("Shutdown signal received; stopping vm compute driver");
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ComputeDriverListenMode {
    Unix {
        socket_path: PathBuf,
        expected_peer_pid: Option<u32>,
    },
    Tcp(SocketAddr),
}

fn compute_driver_listen_mode(args: &Args) -> std::result::Result<ComputeDriverListenMode, String> {
    if let Some(socket_path) = args.bind_socket.clone() {
        if args.expected_peer_pid.is_none() && !args.allow_same_uid_peer {
            return Err(
                "--expected-peer-pid is required with --bind-socket; use --allow-same-uid-peer only for local development"
                    .to_string(),
            );
        }
        return Ok(ComputeDriverListenMode::Unix {
            socket_path,
            expected_peer_pid: args.expected_peer_pid,
        });
    }

    if !args.allow_unauthenticated_tcp {
        return Err(
            "--bind-socket is required; unauthenticated TCP mode is disabled unless --allow-unauthenticated-tcp is set for local development"
                .to_string(),
        );
    }

    let Some(bind_address) = args.bind_address else {
        return Err("--bind-address is required with --allow-unauthenticated-tcp".to_string());
    };

    Ok(ComputeDriverListenMode::Tcp(bind_address))
}

fn prepare_compute_driver_socket(socket_path: &Path) -> std::result::Result<(), String> {
    let Some(parent) = socket_path.parent() else {
        return Err(format!(
            "vm compute driver socket path '{}' has no parent directory",
            socket_path.display()
        ));
    };
    let expected_uid = current_euid();
    prepare_private_socket_dir(parent, expected_uid)?;
    remove_stale_socket(socket_path, expected_uid)
}

fn current_euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn prepare_private_socket_dir(
    socket_dir: &Path,
    expected_uid: u32,
) -> std::result::Result<(), String> {
    std::fs::create_dir_all(socket_dir)
        .map_err(|err| format!("create socket dir {}: {err}", socket_dir.display()))?;
    let metadata = std::fs::symlink_metadata(socket_dir)
        .map_err(|err| format!("stat socket dir {}: {err}", socket_dir.display()))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(format!(
            "socket dir {} is a symlink; refusing to use it",
            socket_dir.display()
        ));
    }
    if !file_type.is_dir() {
        return Err(format!(
            "socket dir {} is not a directory",
            socket_dir.display()
        ));
    }
    if metadata.uid() != expected_uid {
        return Err(format!(
            "socket dir {} is owned by uid {} but current euid is {}",
            socket_dir.display(),
            metadata.uid(),
            expected_uid
        ));
    }
    std::fs::set_permissions(socket_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|err| format!("chmod socket dir {}: {err}", socket_dir.display()))
}

fn remove_stale_socket(socket_path: &Path, expected_uid: u32) -> std::result::Result<(), String> {
    let metadata = match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("stat socket {}: {err}", socket_path.display())),
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(format!(
            "socket {} is a symlink; refusing to remove it",
            socket_path.display()
        ));
    }
    if metadata.uid() != expected_uid {
        return Err(format!(
            "socket {} is owned by uid {} but current euid is {}",
            socket_path.display(),
            metadata.uid(),
            expected_uid
        ));
    }
    if !file_type.is_socket() {
        return Err(format!(
            "socket path {} exists but is not a Unix socket",
            socket_path.display()
        ));
    }
    std::fs::remove_file(socket_path)
        .map_err(|err| format!("remove stale socket {}: {err}", socket_path.display()))
}

fn restrict_socket_permissions(socket_path: &Path) -> std::result::Result<(), String> {
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("chmod socket {}: {err}", socket_path.display()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerCredentials {
    uid: u32,
    pid: Option<i32>,
}

fn peer_credentials(stream: &UnixStream) -> std::result::Result<PeerCredentials, String> {
    let credentials = stream
        .peer_cred()
        .map_err(|err| format!("read peer credentials: {err}"))?;
    Ok(PeerCredentials {
        uid: credentials.uid(),
        pid: credentials.pid(),
    })
}

fn authorize_peer_credentials(
    peer: PeerCredentials,
    driver_uid: u32,
    gateway_pid: Option<u32>,
) -> std::result::Result<(), String> {
    if peer.uid != driver_uid {
        return Err(format!(
            "peer uid {} does not match current euid {}",
            peer.uid, driver_uid
        ));
    }
    let Some(gateway_pid) = gateway_pid else {
        return Ok(());
    };
    let Some(peer_process_id) = peer.pid.and_then(|pid| u32::try_from(pid).ok()) else {
        return Err(format!(
            "peer pid is unavailable; expected gateway pid {gateway_pid}"
        ));
    };
    if peer_process_id != gateway_pid {
        return Err(format!(
            "peer pid {peer_process_id} does not match expected gateway pid {gateway_pid}"
        ));
    }
    Ok(())
}

struct AuthenticatedUnixIncoming {
    listener: UnixListener,
    expected_uid: u32,
    expected_peer_pid: Option<u32>,
}

impl AuthenticatedUnixIncoming {
    fn new(listener: UnixListener, expected_peer_pid: Option<u32>) -> Self {
        Self {
            listener,
            expected_uid: current_euid(),
            expected_peer_pid,
        }
    }
}

impl Stream for AuthenticatedUnixIncoming {
    type Item = io::Result<UnixStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match this.listener.poll_accept(cx) {
                Poll::Ready(Ok((stream, _addr))) => {
                    let authorized = peer_credentials(&stream).and_then(|peer| {
                        authorize_peer_credentials(peer, this.expected_uid, this.expected_peer_pid)
                    });
                    match authorized {
                        Ok(()) => return Poll::Ready(Some(Ok(stream))),
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                "rejected vm compute driver UDS client"
                            );
                        }
                    }
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Some(Err(err))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn build_vm_launch_config(args: &Args) -> std::result::Result<VmLaunchConfig, String> {
    let root_disk = args
        .vm_root_disk
        .clone()
        .ok_or_else(|| "--vm-root-disk is required in internal VM mode".to_string())?;
    let overlay_disk = args
        .vm_overlay_disk
        .clone()
        .ok_or_else(|| "--vm-overlay-disk is required in internal VM mode".to_string())?;
    let image_disk = args.vm_image_disk.clone();
    let exec_path = args
        .vm_exec
        .clone()
        .ok_or_else(|| "--vm-exec is required in internal VM mode".to_string())?;
    let console_output = args
        .vm_console_output
        .clone()
        .ok_or_else(|| "--vm-console-output is required in internal VM mode".to_string())?;

    let backend = match args.vm_backend.as_deref() {
        Some("qemu") => VmBackend::Qemu,
        Some("libkrun") | None => VmBackend::Libkrun,
        Some(other) => return Err(format!("unknown VM backend: {other}")),
    };

    let mounts = args
        .vm_mount
        .iter()
        .map(|m| parse_vm_mount_arg(m))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(VmLaunchConfig {
        root_disk,
        overlay_disk,
        image_disk,
        kernel_image: args.vm_kernel_image.clone(),
        vcpus: args.vm_vcpus,
        mem_mib: args.vm_mem_mib,
        exec_path,
        args: Vec::new(),
        env: args.vm_env.clone(),
        workdir: args.vm_workdir.clone(),
        log_level: args.vm_krun_log_level,
        console_output,
        backend,
        gpu_bdf: args.vm_gpu_bdf.clone(),
        vsock_cid: args.vm_vsock_cid,
        vsock_port_map: match (
            args.vm_vsock_control_port,
            args.vm_vsock_control_socket.clone(),
        ) {
            (Some(guest_port), Some(host_socket)) => Some(VsockPortMap {
                guest_port,
                host_socket,
                host_initiated: !args.vm_vsock_runtime_initiated,
            }),
            (None, None) => None,
            _ => {
                return Err(
                    "--vm-vsock-control-port and --vm-vsock-control-socket must be set together"
                        .to_string(),
                );
            }
        },
        mounts,
    })
}

fn parse_vm_mount_arg(arg: &str) -> std::result::Result<VmMount, String> {
    // Split from the right: the driver generates the tag and mode, so a tab
    // in the source can never shift them.
    let mut parts = arg.rsplitn(3, '\t');
    let mode = parts
        .next()
        .ok_or_else(|| format!("invalid --vm-mount format: {arg}"))?;
    let tag = parts
        .next()
        .ok_or_else(|| format!("invalid --vm-mount format (missing tag): {arg}"))?;
    let source = parts
        .next()
        .ok_or_else(|| format!("invalid --vm-mount format (missing source): {arg}"))?;
    let read_only = match mode {
        "ro" => true,
        "rw" => false,
        _ => {
            return Err(format!(
                "invalid --vm-mount mode '{mode}': expected 'ro' or 'rw'"
            ));
        }
    };
    Ok(VmMount {
        host_path: PathBuf::from(source),
        tag: tag.to_string(),
        read_only,
    })
}

#[cfg(target_os = "macos")]
fn maybe_reexec_internal_vm_with_runtime_env() -> Result<()> {
    use std::os::unix::process::CommandExt as _;

    const REEXEC_ENV: &str = "__OPENSHELL_DRIVER_VM_REEXEC";

    if std::env::var_os(REEXEC_ENV).is_some() {
        return Ok(());
    }

    let runtime_dir = configured_runtime_dir().map_err(|err| miette::miette!("{err}"))?;
    let runtime_str = runtime_dir.to_string_lossy();
    let needs_reexec = std::env::var_os("DYLD_LIBRARY_PATH")
        .is_none_or(|value| !value.to_string_lossy().contains(runtime_str.as_ref()));
    if !needs_reexec {
        return Ok(());
    }

    let mut dyld_paths = vec![runtime_dir.clone()];
    if let Some(existing) = std::env::var_os("DYLD_LIBRARY_PATH") {
        dyld_paths.extend(std::env::split_paths(&existing));
    }
    let joined = std::env::join_paths(&dyld_paths)
        .map_err(|err| miette::miette!("join DYLD_LIBRARY_PATH: {err}"))?;
    let exe = std::env::current_exe().into_diagnostic()?;
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Use execvp() so the current process is *replaced* by the re-exec'd
    // binary — no wrapper process sits between the compute driver and
    // the actually-running VM launcher. That avoids two problems:
    //   1. An extra process level that survives SIGKILL of the driver
    //      (the wrapper was reparenting the re-exec'd child to init).
    //   2. Signal forwarding: with a wrapper, a SIGTERM to the wrapper
    //      doesn't reach the child unless we hand-roll forwarding.
    // After exec, the child inherits our PID and our procguard arming.
    let err = std::process::Command::new(exe)
        .args(&args)
        .env("DYLD_LIBRARY_PATH", &joined)
        .env(VM_RUNTIME_DIR_ENV, runtime_dir)
        .env(REEXEC_ENV, "1")
        .exec();
    // `exec()` only returns on failure.
    Err(miette::miette!("failed to re-exec with runtime env: {err}"))
}

#[cfg(not(target_os = "macos"))]
// Signature must match the macOS variant which can fail.
#[allow(clippy::unnecessary_wraps)]
fn maybe_reexec_internal_vm_with_runtime_env() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Args, ComputeDriverListenMode, PeerCredentials, authorize_peer_credentials,
        compute_driver_listen_mode, configured_args, parse_vm_mount_arg, vm_driver_config,
    };
    use clap::Parser;
    use std::path::{Path, PathBuf};

    const VM_DRIVER_CONFIG_FIXTURE: &str = include_str!("../tests/fixtures/driver-config-vm.toml");

    /// `Configure` supplies the settings the gateway used to pass as flags.
    #[test]
    fn configure_supplies_the_settings_the_gateway_used_to_pass_as_flags() {
        use openshell_driver_launch::proto::{
            CollectorTls, ConfigureRequest, GatewayContext, NetworkTrust, OtlpExport, Telemetry,
        };

        let export = |endpoint: &str, protocol: &str| {
            Some(OtlpExport {
                endpoint: endpoint.to_string(),
                protocol: protocol.to_string(),
            })
        };
        let request = ConfigureRequest {
            protocol_version: openshell_driver_launch::PROTOCOL_VERSION,
            gateway: Some(GatewayContext {
                gateway_port: 8080,
                tls_ca_path: "/etc/openshell/tls/ca.pem".to_string(),
                gateway_name: "gateway-a".to_string(),
            }),
            network_trust: Some(NetworkTrust {
                artifact_path: "/var/lib/openshell/trust/bundle.pem".to_string(),
                digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
                certificate_count: 3,
            }),
            driver_config_toml: VM_DRIVER_CONFIG_FIXTURE.to_string(),
            telemetry: Some(Telemetry {
                traces: export("https://collector.example:4317", "grpc"),
                ocsf: export("https://collector.example:4318", "http/protobuf"),
                agent: export("https://collector.example:4319", "grpc"),
                collector: Some(CollectorTls {
                    ca_file: "/etc/openshell/otlp/ca.pem".to_string(),
                    cert_file: "/etc/openshell/otlp/cert.pem".to_string(),
                    key_file: "/etc/openshell/otlp/key.pem".to_string(),
                }),
                trace_headers: String::new(),
            }),
            ..ConfigureRequest::default()
        };
        let args = configured_args(&request, "debug".to_string()).unwrap();
        assert!(args.bind_socket.is_none());
        assert!(args.expected_peer_pid.is_none());
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.gateway_name.as_deref(), Some("gateway-a"));
        assert_eq!(
            args.grpc_endpoint.as_deref(),
            Some("https://127.0.0.1:8080")
        );
        assert_eq!(
            args.guest_tls_ca.as_deref(),
            Some(Path::new("/etc/openshell/tls/ca.pem"))
        );
        assert!(args.admission_config_json.allow_driver_config);
        assert_eq!(
            args.otlp.endpoint.as_deref(),
            Some("https://collector.example:4317")
        );
        assert_eq!(
            args.otlp.ocsf_protocol,
            openshell_core::sandbox_env::OtlpProtocol::HttpProtobuf
        );
        assert_eq!(
            args.otlp.agent_endpoint.as_deref(),
            Some("https://collector.example:4319")
        );
        assert_eq!(
            args.otlp.key_file.as_deref(),
            Some(Path::new("/etc/openshell/otlp/key.pem"))
        );
        assert_eq!(
            args.upstream_proxy.as_deref(),
            Some("http://proxy.example:3128")
        );
        assert!(args.upstream_proxy_auth_allow_insecure);
        assert!(args.upstream_proxy_connect_by_hostname);
        assert_eq!(
            args.upstream_proxy_ca_bundle.as_deref(),
            Some(Path::new("/etc/openshell/proxy-ca.pem"))
        );
        assert_eq!(args.additional_ca_certificate_count, Some(3));
        assert_eq!(args.state_dir, Path::new("/var/lib/openshell/vm"));
        assert_eq!(args.vcpus, 4);
        assert_eq!(args.mem_mib, 4096);
        assert_eq!(args.overlay_disk_mib, 8192);
        assert_eq!(args.sandbox_uid, Some(2000));
        assert_eq!(args.rootfs_tar_max_bytes, Some(1_073_741_824));
        assert!(args.enable_bind_mounts);
        assert!(args.provider_spiffe_allow_guest_tcp);
        vm_driver_config(&args).unwrap();
    }

    #[test]
    fn configure_defaults_the_endpoint_to_the_gateway_listener() {
        let request = openshell_driver_launch::proto::ConfigureRequest {
            protocol_version: openshell_driver_launch::PROTOCOL_VERSION,
            gateway: Some(openshell_driver_launch::proto::GatewayContext {
                gateway_port: 9090,
                tls_ca_path: String::new(),
                gateway_name: "g".to_string(),
            }),
            ..Default::default()
        };
        let args = configured_args(&request, "info".to_string()).unwrap();
        assert_eq!(args.grpc_endpoint.as_deref(), Some("http://127.0.0.1:9090"));

        let unknown = openshell_driver_launch::proto::ConfigureRequest {
            driver_config_toml: "surprise = 1".to_string(),
            ..request
        };
        let error = configured_args(&unknown, "info".to_string()).unwrap_err();
        assert!(error.contains("surprise"), "{error}");
    }

    #[test]
    fn corporate_proxy_flags_parse_into_driver_settings() {
        let args = Args::parse_from([
            "openshell-driver-vm",
            "--upstream-proxy",
            "http://proxy.corp.com:8080",
            "--upstream-no-proxy",
            "10.0.0.0/8,.svc.cluster.local",
            "--upstream-proxy-auth-file",
            "/etc/openshell/secrets/proxy-auth",
            "--upstream-proxy-auth-allow-insecure",
            "--upstream-proxy-connect-by-hostname",
            "--upstream-proxy-ca-bundle",
            "/etc/openshell/tls/proxy-ca.pem",
        ]);

        assert_eq!(
            args.upstream_proxy.as_deref(),
            Some("http://proxy.corp.com:8080")
        );
        assert_eq!(
            args.upstream_no_proxy.as_deref(),
            Some("10.0.0.0/8,.svc.cluster.local")
        );
        assert_eq!(
            args.upstream_proxy_auth_file.as_deref(),
            Some(PathBuf::from("/etc/openshell/secrets/proxy-auth").as_path())
        );
        assert!(args.upstream_proxy_auth_allow_insecure);
        assert!(args.upstream_proxy_connect_by_hostname);
        assert_eq!(
            args.upstream_proxy_ca_bundle.as_deref(),
            Some(PathBuf::from("/etc/openshell/tls/proxy-ca.pem").as_path())
        );
    }

    #[test]
    fn corporate_proxy_settings_default_to_unset() {
        let args = Args::parse_from(["openshell-driver-vm"]);
        assert!(args.upstream_proxy.is_none());
        assert!(args.upstream_no_proxy.is_none());
        assert!(args.upstream_proxy_auth_file.is_none());
        assert!(!args.upstream_proxy_auth_allow_insecure);
        assert!(!args.upstream_proxy_connect_by_hostname);
        assert!(args.upstream_proxy_ca_bundle.is_none());
    }

    #[test]
    fn internal_network_trust_options_have_no_environment_aliases() {
        let args = Args::parse_from([
            "openshell-driver-vm",
            "--additional-ca-bundle",
            "/var/lib/openshell/network/additional-ca.crt",
            "--additional-ca-digest",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--additional-ca-certificate-count",
            "2",
        ]);
        assert_eq!(
            args.additional_ca_bundle.as_deref(),
            Some(PathBuf::from("/var/lib/openshell/network/additional-ca.crt").as_path())
        );
        assert_eq!(
            args.additional_ca_digest.as_deref(),
            Some("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(args.additional_ca_certificate_count, Some(2));

        temp_env::with_vars(
            [
                (
                    "OPENSHELL_VM_ADDITIONAL_CA_BUNDLE",
                    Some("/tmp/untrusted.crt"),
                ),
                ("OPENSHELL_VM_ADDITIONAL_CA_DIGEST", Some("sha256:bad")),
                ("OPENSHELL_VM_ADDITIONAL_CA_CERTIFICATE_COUNT", Some("999")),
            ],
            || {
                let args = Args::parse_from(["openshell-driver-vm"]);
                assert!(args.additional_ca_bundle.is_none());
                assert!(args.additional_ca_digest.is_none());
                assert!(args.additional_ca_certificate_count.is_none());
            },
        );
    }

    #[test]
    fn peer_authorization_accepts_matching_uid_and_pid() {
        authorize_peer_credentials(
            PeerCredentials {
                uid: 1000,
                pid: Some(42),
            },
            1000,
            Some(42),
        )
        .unwrap();
    }

    #[test]
    fn peer_authorization_rejects_wrong_pid() {
        let err = authorize_peer_credentials(
            PeerCredentials {
                uid: 1000,
                pid: Some(7),
            },
            1000,
            Some(42),
        )
        .expect_err("wrong pid should be rejected");
        assert!(err.contains("does not match expected gateway pid"));
    }

    #[test]
    fn peer_authorization_rejects_wrong_uid() {
        let err = authorize_peer_credentials(
            PeerCredentials {
                uid: 1001,
                pid: Some(42),
            },
            1000,
            Some(42),
        )
        .expect_err("wrong uid should be rejected");
        assert!(err.contains("does not match current euid"));
    }

    #[test]
    fn peer_authorization_rejects_missing_pid_when_expected() {
        let err = authorize_peer_credentials(
            PeerCredentials {
                uid: 1000,
                pid: None,
            },
            1000,
            Some(42),
        )
        .expect_err("missing pid should be rejected");
        assert!(err.contains("peer pid is unavailable"));
    }

    #[test]
    fn peer_authorization_accepts_matching_uid_without_expected_pid() {
        authorize_peer_credentials(
            PeerCredentials {
                uid: 1000,
                pid: None,
            },
            1000,
            None,
        )
        .unwrap();
    }

    #[test]
    fn listen_mode_rejects_default_tcp() {
        let args = Args::parse_from(["openshell-driver-vm"]);
        let err = compute_driver_listen_mode(&args).expect_err("default TCP should be disabled");
        assert!(err.contains("--bind-socket is required"));
    }

    #[test]
    fn accepts_canonical_grpc_endpoint_flag() {
        let args = Args::try_parse_from([
            "openshell-driver-vm",
            "--grpc-endpoint",
            "http://127.0.0.1:8080",
        ])
        .unwrap();
        assert_eq!(args.grpc_endpoint.as_deref(), Some("http://127.0.0.1:8080"));
    }

    #[test]
    fn rejects_legacy_openshell_endpoint_flag() {
        let error = Args::try_parse_from([
            "openshell-driver-vm",
            "--openshell-endpoint",
            "http://127.0.0.1:8080",
        ])
        .expect_err("legacy --openshell-endpoint must be rejected");
        assert!(error.to_string().contains("--openshell-endpoint"));
    }

    #[test]
    fn accepts_gateway_otlp_configuration() {
        let args = Args::try_parse_from([
            "openshell-driver-vm",
            "--otlp-endpoint",
            "http://127.0.0.1:4317",
            "--gateway-name",
            "production-us-west",
        ]);
        assert!(
            args.is_ok(),
            "VM driver should accept the gateway OTLP endpoint"
        );
    }

    #[test]
    fn listen_mode_rejects_bind_address_without_tcp_opt_in() {
        let args = Args::parse_from(["openshell-driver-vm", "--bind-address", "127.0.0.1:50061"]);
        let err =
            compute_driver_listen_mode(&args).expect_err("TCP bind should require explicit opt-in");
        assert!(err.contains("--allow-unauthenticated-tcp"));
    }

    #[test]
    fn listen_mode_requires_bind_address_with_tcp_opt_in() {
        let args = Args::parse_from(["openshell-driver-vm", "--allow-unauthenticated-tcp"]);
        let err =
            compute_driver_listen_mode(&args).expect_err("TCP opt-in should require an address");
        assert!(err.contains("--bind-address is required"));
    }

    #[test]
    fn listen_mode_accepts_explicit_unauthenticated_tcp() {
        let args = Args::parse_from([
            "openshell-driver-vm",
            "--allow-unauthenticated-tcp",
            "--bind-address",
            "127.0.0.1:50061",
        ]);
        assert_eq!(
            compute_driver_listen_mode(&args).unwrap(),
            ComputeDriverListenMode::Tcp("127.0.0.1:50061".parse().unwrap())
        );
    }

    #[test]
    fn listen_mode_requires_expected_peer_pid_for_uds() {
        let args = Args::parse_from([
            "openshell-driver-vm",
            "--bind-socket",
            "/tmp/compute-driver.sock",
        ]);
        let err = compute_driver_listen_mode(&args)
            .expect_err("UDS should require gateway peer pid by default");
        assert!(err.contains("--expected-peer-pid is required"));
    }

    #[test]
    fn listen_mode_accepts_uds_with_expected_peer_pid() {
        let args = Args::parse_from([
            "openshell-driver-vm",
            "--bind-socket",
            "/tmp/compute-driver.sock",
            "--expected-peer-pid",
            "42",
        ]);
        assert_eq!(
            compute_driver_listen_mode(&args).unwrap(),
            ComputeDriverListenMode::Unix {
                socket_path: PathBuf::from("/tmp/compute-driver.sock"),
                expected_peer_pid: Some(42),
            }
        );
    }

    #[test]
    fn listen_mode_accepts_explicit_same_uid_uds_dev_mode() {
        let args = Args::parse_from([
            "openshell-driver-vm",
            "--bind-socket",
            "/tmp/compute-driver.sock",
            "--allow-same-uid-peer",
        ]);
        assert_eq!(
            compute_driver_listen_mode(&args).unwrap(),
            ComputeDriverListenMode::Unix {
                socket_path: PathBuf::from("/tmp/compute-driver.sock"),
                expected_peer_pid: None,
            }
        );
    }

    #[test]
    fn parse_vm_mount_arg_parses_readonly() {
        let m = parse_vm_mount_arg("/host/src\tosfs0\tro").unwrap();
        assert_eq!(m.host_path, PathBuf::from("/host/src"));
        assert_eq!(m.tag, "osfs0");
        assert!(m.read_only);
    }

    #[test]
    fn parse_vm_mount_arg_parses_readwrite() {
        let m = parse_vm_mount_arg("/host/src\tosfs1\trw").unwrap();
        assert!(!m.read_only);
    }

    #[test]
    fn parse_vm_mount_arg_keeps_tag_and_mode_when_source_has_tab() {
        let m = parse_vm_mount_arg("/host/src\tvfs9\trw\tosfs0\tro").unwrap();
        assert_eq!(m.host_path, PathBuf::from("/host/src\tvfs9\trw"));
        assert_eq!(m.tag, "osfs0");
        assert!(m.read_only);
    }

    #[test]
    fn parse_vm_mount_arg_rejects_unknown_mode() {
        let err = parse_vm_mount_arg("/host/src\tosfs0\treadonly").unwrap_err();
        assert!(err.contains("expected 'ro' or 'rw'"));
    }

    #[test]
    fn parse_vm_mount_arg_rejects_missing_fields() {
        assert!(parse_vm_mount_arg("/host/src\tosfs0").is_err());
        assert!(parse_vm_mount_arg("/host/src").is_err());
    }
}
