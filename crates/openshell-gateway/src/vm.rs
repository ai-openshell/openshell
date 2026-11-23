// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Launching the VM compute driver through the generic launcher.
//!
//! The gateway reads only the launcher's own keys (`driver_dir`, `state_dir`)
//! from the operator's `[openshell.drivers.vm]` table. The VM driver owns and
//! validates the rest of the table, which the gateway passes through in
//! `Configure`.

use crate::launcher::{self, DriverProcess};
use openshell_core::{Error, NetworkSupervisorTrustBundle, Result};
use openshell_driver_launch::proto::ConfigureRequest;
use openshell_server::AcquiredRemoteDriverEndpoint;
use openshell_server::config_file::OtlpConfig;
use std::path::{Path, PathBuf};

const DRIVER_BIN_NAME: &str = "openshell-driver-vm";
const DRIVER_DIR_KEY: &str = "[openshell.drivers.vm].driver_dir";

/// The launcher's view of `[openshell.drivers.vm]`.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct VmLaunchSettings {
    /// Directory to search for compute-driver binaries before the gateway
    /// falls back to its conventional install paths and sibling binary.
    pub driver_dir: Option<PathBuf>,
    /// Working directory for VM driver state, which holds the private run
    /// directory with the driver socket.
    pub state_dir: Option<PathBuf>,
}

impl VmLaunchSettings {
    /// Default working directory for VM driver state.
    #[must_use]
    pub fn default_state_dir() -> PathBuf {
        openshell_core::paths::openshell_state_dir().map_or_else(
            |_| PathBuf::from("target/openshell-vm-driver"),
            |dir| dir.join("vm-driver"),
        )
    }

    /// Read the launcher's keys from the operator's driver table.
    ///
    /// # Errors
    ///
    /// Returns an error when `driver_dir` or `state_dir` has the wrong type.
    pub fn from_table(table: &toml::Table) -> Result<Self> {
        let mut settings: Self =
            toml::Value::Table(table.clone())
                .try_into()
                .map_err(|error: toml::de::Error| {
                    Error::config(format!("invalid [openshell.drivers.vm] table: {error}"))
                })?;
        if settings
            .state_dir
            .as_ref()
            .is_none_or(|dir| dir.as_os_str().is_empty())
        {
            settings.state_dir = Some(Self::default_state_dir());
        }
        Ok(settings)
    }

    fn state_dir(&self) -> PathBuf {
        self.state_dir
            .clone()
            .unwrap_or_else(Self::default_state_dir)
    }
}

/// Everything the gateway supplies to launch the VM driver.
pub struct VmLaunch<'a> {
    pub gateway_log_level: &'a str,
    pub gateway_name: &'a str,
    pub gateway_port: u16,
    /// The gateway's `guest_tls_ca`, when it serves TLS.
    pub tls_ca: Option<&'a Path>,
    pub otlp_config: Option<&'a OtlpConfig>,
    pub network_trust: Option<&'a NetworkSupervisorTrustBundle>,
    /// Becomes true when the gateway begins shutting down.
    pub shutdown: tokio::sync::watch::Receiver<bool>,
    pub settings: &'a VmLaunchSettings,
    /// The operator's `[openshell.drivers.vm]` table, passed through.
    pub driver_config: toml::Table,
}

/// Launch the VM driver and return a managed endpoint for it.
pub async fn spawn(launch: VmLaunch<'_>) -> Result<AcquiredRemoteDriverEndpoint> {
    let settings = launch.settings;
    let state_dir = settings.state_dir();
    let process = DriverProcess {
        name: "vm",
        binary_name: DRIVER_BIN_NAME,
        driver_dir: settings.driver_dir.as_deref(),
        driver_dir_key: Some(DRIVER_DIR_KEY),
        state_dir: &state_dir,
    };
    let request = configure_request(&launch)?;
    launcher::launch_configured(
        &process,
        launch.gateway_log_level,
        launch.shutdown.clone(),
        request,
    )
    .await
}

/// Have the VM driver validate the `Configure` request the gateway would send.
/// Values the gateway only knows once it serves, such as its TLS CA and the
/// staged network trust bundle, are left out.
pub fn preflight(
    gateway_log_level: &str,
    gateway_name: &str,
    gateway_port: u16,
    driver_config: toml::Table,
) -> Result<()> {
    let settings = VmLaunchSettings::from_table(&driver_config)?;
    let state_dir = settings.state_dir();
    let process = DriverProcess {
        name: "vm",
        binary_name: DRIVER_BIN_NAME,
        driver_dir: settings.driver_dir.as_deref(),
        driver_dir_key: Some(DRIVER_DIR_KEY),
        state_dir: &state_dir,
    };
    let request = configure_request(&VmLaunch {
        gateway_log_level,
        gateway_name,
        gateway_port,
        tls_ca: None,
        otlp_config: None,
        network_trust: None,
        shutdown: tokio::sync::watch::channel(false).1,
        settings: &settings,
        driver_config,
    })?;
    launcher::preflight_configured(&process, launcher::PREFLIGHT_TIMEOUT, &request)
}

/// The VM driver's table: the operator's table, passed through,
/// without the launcher-owned `driver_dir`.
fn vm_driver_config_table(mut table: toml::Table) -> toml::Table {
    table.remove("driver_dir");
    table
}

/// The `Configure` request for the VM driver.
fn configure_request(launch: &VmLaunch<'_>) -> Result<ConfigureRequest> {
    let driver_config = vm_driver_config_table(launch.driver_config.clone());
    launcher::configure_request(&launcher::ConfigureContext {
        driver_name: "vm",
        gateway_name: launch.gateway_name,
        gateway_port: launch.gateway_port,
        tls_ca: launch.tls_ca,
        otlp_config: launch.otlp_config,
        network_trust: launch.network_trust,
        driver_config: &driver_config,
        image_overrides: None,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::{VmLaunch, VmLaunchSettings, configure_request, vm_driver_config_table};
    use openshell_core::NetworkSupervisorTrustBundle;
    use std::path::{Path, PathBuf};

    const VM_DRIVER_CONFIG_FIXTURE: &str =
        include_str!("../../openshell-driver-vm/tests/fixtures/driver-config-vm.toml");

    fn fixture_driver_config() -> toml::Table {
        toml::from_str(VM_DRIVER_CONFIG_FIXTURE).unwrap()
    }

    /// The gateway passes the operator's table through unchanged, apart from
    /// the launcher-owned `driver_dir`, and adds its own context.
    #[test]
    fn configure_passes_the_operator_table_through_without_the_driver_dir() {
        let trust = NetworkSupervisorTrustBundle::new(
            b"pem".to_vec(),
            3,
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            PathBuf::from("/var/lib/openshell/trust/bundle.pem"),
        );
        let expected = fixture_driver_config();
        let mut operator_table = expected.clone();
        operator_table.insert("driver_dir".into(), "/usr/libexec/openshell".into());
        let settings = VmLaunchSettings::from_table(&operator_table).unwrap();

        let request = configure_request(&VmLaunch {
            gateway_log_level: "debug",
            gateway_name: "gateway-a",
            gateway_port: 8080,
            tls_ca: Some(Path::new("/etc/openshell/tls/ca.pem")),
            otlp_config: None,
            network_trust: Some(&trust),
            shutdown: tokio::sync::watch::channel(false).1,
            settings: &settings,
            driver_config: operator_table,
        })
        .unwrap();

        let table: toml::Table = toml::from_str(&request.driver_config_toml).unwrap();
        assert_eq!(table, expected);
        let gateway = request.gateway.unwrap();
        assert_eq!(gateway.gateway_port, 8080);
        assert_eq!(gateway.gateway_name, "gateway-a");
        assert_eq!(gateway.tls_ca_path, "/etc/openshell/tls/ca.pem");
        assert!(request.image_overrides.is_none());
        let network_trust = request.network_trust.unwrap();
        assert_eq!(network_trust.certificate_count, 3);
        assert_eq!(
            network_trust.artifact_path,
            "/var/lib/openshell/trust/bundle.pem"
        );
    }

    #[test]
    fn only_the_launcher_owned_key_is_removed_from_the_operator_table() {
        let mut table = fixture_driver_config();
        let before = table.clone();
        table.insert("driver_dir".into(), "/opt/drivers".into());
        assert_eq!(vm_driver_config_table(table), before);
    }

    #[test]
    fn launch_settings_default_the_state_dir_and_read_the_driver_dir() {
        let settings = VmLaunchSettings::from_table(&toml::Table::new()).unwrap();
        assert_eq!(settings.state_dir(), VmLaunchSettings::default_state_dir());
        assert!(settings.driver_dir.is_none());

        let table: toml::Table =
            toml::from_str("driver_dir = '/opt/drivers'\nstate_dir = '/var/lib/vm'\nvcpus = 4\n")
                .unwrap();
        let settings = VmLaunchSettings::from_table(&table).unwrap();
        assert_eq!(
            settings.driver_dir.as_deref(),
            Some(Path::new("/opt/drivers"))
        );
        assert_eq!(settings.state_dir(), PathBuf::from("/var/lib/vm"));
    }
}
