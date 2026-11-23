// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Launching the Podman compute driver through the generic launcher.
//!
//! The gateway starts the driver in `serve` mode and passes the operator's
//! `[openshell.drivers.podman]` table through unchanged in `Configure`, which
//! `preflight` also validates. The Podman driver deserializes and validates it.

use crate::launcher::{self, DriverProcess};
use openshell_core::{NetworkSupervisorTrustBundle, Result};
use openshell_driver_launch::proto::{ConfigureRequest, ImageOverrides};
use openshell_server::AcquiredRemoteDriverEndpoint;
use openshell_server::config_file::OtlpConfig;
use std::path::{Path, PathBuf};

const DRIVER_BIN_NAME: &str = "openshell-driver-podman";

/// Everything the gateway supplies to launch the Podman driver.
pub struct PodmanLaunch<'a> {
    pub gateway_log_level: &'a str,
    pub gateway_name: &'a str,
    pub gateway_port: u16,
    /// The gateway's `guest_tls_ca`, when it serves TLS.
    pub tls_ca: Option<&'a Path>,
    pub otlp_config: Option<&'a OtlpConfig>,
    pub network_trust: Option<&'a NetworkSupervisorTrustBundle>,
    /// Becomes true when the gateway begins shutting down.
    pub shutdown: tokio::sync::watch::Receiver<bool>,
    /// The operator's `[openshell.drivers.podman]` table, passed through.
    pub driver_config: toml::Table,
}

/// Directory whose `run/` subdirectory holds the driver socket.
#[must_use]
pub fn default_state_dir() -> PathBuf {
    openshell_core::paths::openshell_state_dir().map_or_else(
        |_| PathBuf::from("target/openshell-podman-driver"),
        |dir| dir.join("podman-driver"),
    )
}

/// Whether the Podman driver reports that Podman is usable on this host.
#[must_use]
pub fn is_available() -> bool {
    let state_dir = default_state_dir();
    let process = DriverProcess {
        name: "podman",
        binary_name: DRIVER_BIN_NAME,
        driver_dir: None,
        driver_dir_key: None,
        state_dir: &state_dir,
    };
    let result = launcher::probe(&process, launcher::PROBE_TIMEOUT);
    if !result.available {
        tracing::debug!(
            reason = result.reason.as_deref().unwrap_or("unknown"),
            "podman compute driver not available"
        );
    }
    result.available
}

/// Have the Podman driver validate the `Configure` request the gateway would
/// send it. Values the gateway only knows once it serves, such as its TLS CA,
/// telemetry, and the staged network trust bundle, are left out.
pub fn preflight(
    gateway_log_level: &str,
    gateway_name: &str,
    gateway_port: u16,
    driver_config: toml::Table,
) -> Result<()> {
    let state_dir = default_state_dir();
    let process = DriverProcess {
        name: "podman",
        binary_name: DRIVER_BIN_NAME,
        driver_dir: None,
        driver_dir_key: None,
        state_dir: &state_dir,
    };
    let request = configure_request(
        &PodmanLaunch {
            gateway_log_level,
            gateway_name,
            gateway_port,
            tls_ca: None,
            otlp_config: None,
            network_trust: None,
            shutdown: tokio::sync::watch::channel(false).1,
            driver_config,
        },
        |name| std::env::var(name).ok(),
    )?;
    launcher::preflight_configured(&process, launcher::PREFLIGHT_TIMEOUT, &request)
}

/// Launch the Podman driver and return a managed endpoint for it.
pub async fn spawn(launch: PodmanLaunch<'_>) -> Result<AcquiredRemoteDriverEndpoint> {
    let state_dir = default_state_dir();
    let process = DriverProcess {
        name: "podman",
        binary_name: DRIVER_BIN_NAME,
        driver_dir: None,
        driver_dir_key: None,
        state_dir: &state_dir,
    };
    let request = configure_request(&launch, |name| std::env::var(name).ok())?;
    launcher::launch_configured(
        &process,
        launch.gateway_log_level,
        launch.shutdown.clone(),
        request,
    )
    .await
}

/// The `Configure` request for the Podman driver. The operator's table travels
/// unchanged; the gateway adds its own context and resolved image overrides.
fn configure_request(
    launch: &PodmanLaunch<'_>,
    environment: impl Fn(&str) -> Option<String>,
) -> Result<ConfigureRequest> {
    launcher::configure_request(&launcher::ConfigureContext {
        driver_name: "podman",
        gateway_name: launch.gateway_name,
        gateway_port: launch.gateway_port,
        tls_ca: launch.tls_ca,
        otlp_config: launch.otlp_config,
        network_trust: launch.network_trust,
        driver_config: &launch.driver_config,
        image_overrides: Some(ImageOverrides {
            sandbox_runtime_image: environment(openshell_core::config::SANDBOX_RUNTIME_IMAGE_ENV),
            supervisor_image: environment(openshell_core::config::SUPERVISOR_IMAGE_ENV),
        }),
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::{PodmanLaunch, configure_request};
    use openshell_core::NetworkSupervisorTrustBundle;
    use std::path::{Path, PathBuf};

    const FIXTURE: &str =
        include_str!("../../openshell-driver-podman/tests/fixtures/driver-config-podman.toml");

    #[test]
    fn configure_passes_the_driver_table_through_and_resolves_image_overrides() {
        let driver_config: toml::Table = toml::from_str(FIXTURE).unwrap();
        let trust = NetworkSupervisorTrustBundle::new(
            b"pem".to_vec(),
            3,
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            PathBuf::from("/var/lib/openshell/trust/bundle.pem"),
        );
        let request = configure_request(
            &PodmanLaunch {
                gateway_log_level: "debug",
                gateway_name: "gateway-a",
                gateway_port: 8080,
                tls_ca: Some(Path::new("/etc/openshell/tls/ca.pem")),
                otlp_config: None,
                network_trust: Some(&trust),
                shutdown: tokio::sync::watch::channel(false).1,
                driver_config: driver_config.clone(),
            },
            |name| {
                (name == openshell_core::config::SUPERVISOR_IMAGE_ENV)
                    .then(|| "supervisor:env".to_string())
            },
        )
        .unwrap();

        let table: toml::Table = toml::from_str(&request.driver_config_toml).unwrap();
        assert_eq!(table, driver_config);
        let gateway = request.gateway.unwrap();
        assert_eq!(gateway.gateway_port, 8080);
        assert_eq!(gateway.gateway_name, "gateway-a");
        assert!(request.telemetry.is_none());
        assert_eq!(gateway.tls_ca_path, "/etc/openshell/tls/ca.pem");
        let overrides = request.image_overrides.unwrap();
        assert_eq!(
            overrides.supervisor_image.as_deref(),
            Some("supervisor:env")
        );
        assert!(overrides.sandbox_runtime_image.is_none());
        let network_trust = request.network_trust.unwrap();
        assert_eq!(network_trust.certificate_count, 3);
        assert_eq!(
            network_trust.artifact_path,
            "/var/lib/openshell/trust/bundle.pem"
        );
    }
}
