// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reading the gateway's telemetry from a `Configure` request, for drivers the
//! gateway launches in `serve` mode.

use openshell_core::sandbox_env::{OtlpExport, OtlpProtocol, SupervisorOtlp};
use openshell_driver_launch::proto::{ConfigureRequest, Telemetry};

fn export(
    export: Option<&openshell_driver_launch::proto::OtlpExport>,
) -> Result<Option<OtlpExport>, String> {
    export
        .map(|export| {
            let protocol = if export.protocol.is_empty() {
                OtlpProtocol::default()
            } else {
                export.protocol.parse()?
            };
            Ok(OtlpExport {
                endpoint: export.endpoint.clone(),
                protocol,
            })
        })
        .transpose()
}

/// The exports a driver passes to the supervisors it starts.
///
/// # Errors
///
/// Returns a message when an export names an unknown protocol.
pub fn supervisor_otlp(telemetry: Option<&Telemetry>) -> Result<SupervisorOtlp, String> {
    let Some(telemetry) = telemetry else {
        return Ok(SupervisorOtlp::default());
    };
    Ok(SupervisorOtlp {
        traces: export(telemetry.traces.as_ref())?,
        ocsf: export(telemetry.ocsf.as_ref())?,
        agent: export(telemetry.agent.as_ref())?,
    })
}

/// Set a driver's OTLP command-line settings from the request's telemetry.
/// Settings the request leaves out keep their current values.
///
/// # Errors
///
/// Returns a message when an export names an unknown protocol.
#[cfg(feature = "clap")]
pub fn apply_telemetry(
    telemetry: Option<&Telemetry>,
    args: &mut openshell_core::sandbox_env::SupervisorOtlpArgs,
) -> Result<(), String> {
    let Some(telemetry) = telemetry else {
        return Ok(());
    };
    let otlp = supervisor_otlp(Some(telemetry))?;
    if let Some(export) = otlp.traces {
        args.endpoint = Some(export.endpoint);
        args.protocol = export.protocol;
    }
    if let Some(export) = otlp.ocsf {
        args.ocsf_endpoint = Some(export.endpoint);
        args.ocsf_protocol = export.protocol;
    }
    if let Some(export) = otlp.agent {
        args.agent_endpoint = Some(export.endpoint);
        args.agent_protocol = export.protocol;
    }
    if let Some(collector) = &telemetry.collector {
        let path = |path: &str| (!path.is_empty()).then(|| path.into());
        args.ca_file = path(&collector.ca_file);
        args.cert_file = path(&collector.cert_file);
        args.key_file = path(&collector.key_file);
    }
    Ok(())
}

/// Start the driver's own trace export from the request's telemetry. Setup
/// failures are logged, as at standalone startup.
pub fn enable_export(
    tracing: &openshell_otel::DeferredDriverTracing,
    request: &ConfigureRequest,
    log_level: &str,
    ansi: bool,
    service_version: &'static str,
) {
    let Some(telemetry) = request.telemetry.as_ref() else {
        return;
    };
    let Some(traces) = telemetry.traces.as_ref() else {
        return;
    };
    let protocol = match export(Some(traces)) {
        Ok(export) => export.map(|export| export.protocol).unwrap_or_default(),
        Err(error) => {
            tracing::error!(%error, "OTLP exporting could not be started");
            return;
        }
    };
    let collector = telemetry.collector.clone().unwrap_or_default();
    let path = |path: &str| (!path.is_empty()).then(|| std::path::PathBuf::from(path));
    let (ca_file, cert_file, key_file) = (
        path(&collector.ca_file),
        path(&collector.cert_file),
        path(&collector.key_file),
    );
    let gateway_name = request
        .gateway
        .as_ref()
        .map(|gateway| gateway.gateway_name.as_str())
        .filter(|name| !name.is_empty());
    tracing.enable_export(
        openshell_otel::DriverTracingConfig {
            endpoint: Some(&traces.endpoint),
            protocol: protocol.into(),
            ca_file: ca_file.as_deref(),
            cert_file: cert_file.as_deref(),
            key_file: key_file.as_deref(),
            gateway_name,
            service_version,
            log_level,
            ansi,
        },
        openshell_otel::parse_otlp_headers(&telemetry.trace_headers),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_driver_launch::proto::{CollectorTls, OtlpExport as WireExport};

    fn telemetry() -> Telemetry {
        Telemetry {
            traces: Some(WireExport {
                endpoint: "https://collector:4317".into(),
                protocol: String::new(),
            }),
            ocsf: Some(WireExport {
                endpoint: "https://collector:4318".into(),
                protocol: "http/protobuf".into(),
            }),
            agent: None,
            collector: Some(CollectorTls {
                ca_file: "/ca.pem".into(),
                ..CollectorTls::default()
            }),
            trace_headers: String::new(),
        }
    }

    #[test]
    fn supervisor_exports_default_to_grpc_and_reject_unknown_protocols() {
        let otlp = supervisor_otlp(Some(&telemetry())).unwrap();
        assert_eq!(otlp.traces.unwrap().protocol, OtlpProtocol::Grpc);
        assert_eq!(otlp.ocsf.unwrap().protocol, OtlpProtocol::HttpProtobuf);
        assert!(otlp.agent.is_none());

        let mut unknown = telemetry();
        unknown.traces.as_mut().unwrap().protocol = "carrier-pigeon".into();
        assert!(supervisor_otlp(Some(&unknown)).is_err());
        assert_eq!(supervisor_otlp(None).unwrap(), SupervisorOtlp::default());
    }
}
