// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Building the Podman driver configuration from the gateway's `Configure`
//! request.
//!
//! The request's `driver_config_toml` is the operator's
//! `[openshell.drivers.podman]` table, passed through unchanged. The driver
//! deserializes it into [`PodmanComputeConfig`], applies the gateway context,
//! and validates the result before it builds the driver.

use openshell_core::NetworkSupervisorTrustBundle;

use crate::PodmanComputeConfig;

/// Environment variable that overrides the Podman API socket path.
pub const PODMAN_SOCKET_ENV: &str = "OPENSHELL_PODMAN_SOCKET";

/// Build and validate the driver configuration and the network trust bundle
/// from the gateway's `Configure` request.
///
/// `driver_config_toml` is the operator's table, opaque to the gateway. The
/// gateway resolves the image overrides; the driver applies them and its own
/// `OPENSHELL_PODMAN_SOCKET` override over the table.
///
/// # Errors
///
/// Returns a message when `driver_config` is invalid, validation fails, or the
/// staged network trust artifact cannot be loaded and verified.
pub fn config_from_configure(
    request: &openshell_driver_launch::proto::ConfigureRequest,
) -> Result<(PodmanComputeConfig, Option<NetworkSupervisorTrustBundle>), String> {
    config_from_configure_with(request, |name| std::env::var(name).ok())
}

fn config_from_configure_with(
    request: &openshell_driver_launch::proto::ConfigureRequest,
    environment: impl Fn(&str) -> Option<String>,
) -> Result<(PodmanComputeConfig, Option<NetworkSupervisorTrustBundle>), String> {
    let mut config: PodmanComputeConfig = toml::from_str(&request.driver_config_toml)
        .map_err(|error: toml::de::Error| format!("invalid driver_config: {error}"))?;
    let gateway = request.gateway.clone().unwrap_or_default();
    config.gateway_port = u16::try_from(gateway.gateway_port)
        .map_err(|_| format!("gateway port {} is out of range", gateway.gateway_port))?;
    config.supervisor_otlp =
        openshell_driver_sdk::launch::supervisor_otlp(request.telemetry.as_ref())?;
    config.supervisor_gateway_name =
        (!gateway.gateway_name.is_empty()).then(|| gateway.gateway_name.clone());
    if config.guest_tls_ca.is_none() && !gateway.tls_ca_path.is_empty() {
        config.guest_tls_ca = Some(gateway.tls_ca_path.into());
    }
    if let Some(overrides) = &request.image_overrides {
        if let Some(image) = &overrides.sandbox_runtime_image {
            config.sandbox_runtime_image.clone_from(image);
        }
        if let Some(image) = &overrides.supervisor_image {
            config.supervisor_image.clone_from(image);
        }
    }
    if let Some(path) = environment(PODMAN_SOCKET_ENV) {
        config.socket_path = Some(path.into());
    }
    config
        .validate_configuration()
        .map_err(|error| error.to_string())?;

    let trust = request
        .network_trust
        .as_ref()
        .map(|trust| {
            let count = usize::try_from(trust.certificate_count)
                .map_err(|_| "network trust certificate count is too large".to_string())?;
            openshell_driver_sdk::network_trust::load_staged_bundle(
                std::path::Path::new(&trust.artifact_path),
                &trust.digest,
                count,
            )
        })
        .transpose()?;
    Ok((config, trust))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_driver_launch::proto::{ConfigureRequest, GatewayContext, OtlpExport, Telemetry};

    const FIXTURE: &str = include_str!("../tests/fixtures/driver-config-podman.toml");

    fn configure_request() -> ConfigureRequest {
        ConfigureRequest {
            protocol_version: openshell_driver_launch::PROTOCOL_VERSION,
            gateway: Some(GatewayContext {
                gateway_port: 8080,
                tls_ca_path: String::new(),
                gateway_name: "gateway-a".to_string(),
            }),
            driver_config_toml: FIXTURE.to_string(),
            telemetry: Some(Telemetry {
                traces: Some(OtlpExport {
                    endpoint: "https://collector.example:4317".to_string(),
                    protocol: "grpc".to_string(),
                }),
                ..Telemetry::default()
            }),
            ..ConfigureRequest::default()
        }
    }

    #[test]
    fn the_fixture_builds_a_validated_configuration() {
        let (config, trust) = config_from_configure_with(&configure_request(), |_| None).unwrap();
        assert!(trust.is_none());
        assert_eq!(config.gateway_port, 8080);
        assert_eq!(config.supervisor_gateway_name.as_deref(), Some("gateway-a"));
        assert_eq!(config.network_name, "openshell-test");
        assert!(config.allow_driver_config);
        assert_eq!(
            config
                .supervisor_otlp
                .traces
                .as_ref()
                .map(|t| t.endpoint.as_str()),
            Some("https://collector.example:4317")
        );
        assert!(config.guest_tls_ca.is_none());
    }

    #[test]
    fn the_gateway_ca_is_used_when_the_driver_table_sets_none() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, "ca").unwrap();
        let mut request = configure_request();
        request.gateway.as_mut().unwrap().tls_ca_path = ca.to_str().unwrap().to_string();
        let (config, _) = config_from_configure_with(&request, |_| None).unwrap();
        assert_eq!(config.guest_tls_ca.as_deref(), Some(ca.as_path()));
    }

    #[test]
    fn configure_applies_gateway_image_overrides_and_the_socket_environment() {
        let mut request = configure_request();
        request.image_overrides = Some(openshell_driver_launch::proto::ImageOverrides {
            sandbox_runtime_image: Some("runtime:gateway".into()),
            supervisor_image: Some("supervisor:gateway".into()),
        });
        let (config, _) = config_from_configure_with(&request, |name| {
            (name == PODMAN_SOCKET_ENV).then(|| "/run/podman.sock".to_string())
        })
        .unwrap();
        assert_eq!(config.sandbox_runtime_image, "runtime:gateway");
        assert_eq!(config.supervisor_image, "supervisor:gateway");
        assert_eq!(
            config.socket_path.as_deref(),
            Some(std::path::Path::new("/run/podman.sock"))
        );
    }

    #[test]
    fn configure_rejects_unknown_driver_config_keys() {
        let mut request = configure_request();
        request.driver_config_toml = "surprise = 1".to_string();
        let error = config_from_configure_with(&request, |_| None).unwrap_err();
        assert!(error.contains("surprise"), "{error}");
    }

    #[test]
    fn an_unknown_export_protocol_is_rejected() {
        let mut request = configure_request();
        request
            .telemetry
            .as_mut()
            .unwrap()
            .traces
            .as_mut()
            .unwrap()
            .protocol = "carrier-pigeon".to_string();
        assert!(config_from_configure_with(&request, |_| None).is_err());
    }
}
