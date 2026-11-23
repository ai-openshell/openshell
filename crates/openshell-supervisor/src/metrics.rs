// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-owned supervisor metrics export.

use openshell_core::config::DEFAULT_GATEWAY_NAME;
use openshell_core::jwt::{OtlpExportCredentials, OtlpTlsMaterial, SecretOtlpHeaders};
use openshell_core::sandbox_env::OtlpProtocol;
use openshell_otel::{
    CollectorTransport, OtlpExportConfig, OtlpTarget, SdkMeterProvider, ServiceName, SetupError,
};
use opentelemetry::KeyValue;
use opentelemetry::metrics::MeterProvider as _;

const SERVICE_NAME: &str = "openshell-supervisor";

/// The deployment identity of a supervisor, independent of its process.
pub enum SupervisorIdentity<'a> {
    Sandbox(&'a str),
    PoolMember(&'a str),
}

fn resource_attributes(
    gateway_name: Option<&str>,
    identity: Option<SupervisorIdentity<'_>>,
) -> Vec<KeyValue> {
    let mut attributes = openshell_otel::gateway_resource_attributes(gateway_name, None);
    if let Some(identity) = identity {
        let (kind, key, id) = match identity {
            SupervisorIdentity::Sandbox(id) => ("sandbox", "openshell.sandbox.id", id),
            SupervisorIdentity::PoolMember(id) => {
                ("pool", "openshell.supervisor.pool_member.id", id)
            }
        };
        // Keep the components unambiguous when a configured gateway name contains a colon.
        let gateway = gateway_name
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or(DEFAULT_GATEWAY_NAME)
            .replace('%', "%25")
            .replace(':', "%3A");
        attributes.extend([
            KeyValue::new("service.instance.id", format!("{kind}:{gateway}:{id}")),
            KeyValue::new(key, id.to_string()),
        ]);
    }
    attributes
}

/// Create the process's metrics provider inside the runtime driving OTLP.
pub fn start(
    endpoint: &str,
    protocol: OtlpProtocol,
    credentials: OtlpExportCredentials<'_>,
    gateway_name: Option<&str>,
    identity: Option<SupervisorIdentity<'_>>,
    sandbox_count: impl Fn() -> u64 + Send + Sync + 'static,
) -> Result<SdkMeterProvider, SetupError> {
    let config = OtlpExportConfig {
        endpoint,
        service_name: ServiceName::Fixed(SERVICE_NAME),
        service_version: Some(openshell_core::VERSION),
        resource_attributes: resource_attributes(gateway_name, identity),
    };
    let transport = CollectorTransport {
        protocol: protocol.into(),
        headers: credentials
            .headers
            .map(SecretOtlpHeaders::expose_secret)
            .map(openshell_otel::parse_otlp_headers)
            .unwrap_or_default(),
        tls: credentials
            .tls
            .map(OtlpTlsMaterial::otlp_tls)
            .transpose()?
            .unwrap_or_default(),
    };
    let provider = OtlpTarget::new(&config)?
        .with_transport(&transport)
        .meter_provider()?;
    let meter = provider.meter(SERVICE_NAME);
    openshell_supervisor_network::metrics::install(&meter);
    meter
        .u64_observable_gauge("openshell_supervisor_sandboxes_active")
        .with_description("Sandboxes assigned to this supervisor.")
        .with_callback(move |observer| observer.observe(sandbox_count(), &[]))
        .build();
    Ok(provider)
}

/// Flush final metrics with the SDK reader's bounded shutdown wait.
pub fn shutdown(provider: &SdkMeterProvider) {
    if let Err(error) = provider.shutdown() {
        tracing::warn!(%error, "OTLP metrics provider shutdown failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_otel_test_support::{OtlpHttpTestServer, relay::string_attribute};
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::metrics::v1::metric::Data;
    use prost::Message as _;

    #[test]
    fn dedicated_metrics_identify_the_gateway_and_sandbox() {
        let attributes = resource_attributes(
            Some("test:gateway"),
            Some(SupervisorIdentity::Sandbox("sandbox-id")),
        );
        assert!(attributes.contains(&KeyValue::new(
            "service.instance.id",
            "sandbox:test%3Agateway:sandbox-id",
        )));
        assert!(attributes.contains(&KeyValue::new("openshell.sandbox.id", "sandbox-id")));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pushes_supervisor_gauges_and_resource_to_the_collector() {
        let mut collector = OtlpHttpTestServer::start().await;
        let path = format!("{}/receiver", collector.endpoint());
        let headers = SecretOtlpHeaders::new("x-collector-test=metrics".to_string());
        let count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(2));
        let provider = start(
            &path,
            OtlpProtocol::HttpProtobuf,
            OtlpExportCredentials {
                headers: Some(&headers),
                tls: None,
            },
            Some("test-gateway"),
            Some(SupervisorIdentity::PoolMember("member-1")),
            {
                let count = count.clone();
                move || count.load(std::sync::atomic::Ordering::Relaxed)
            },
        )
        .unwrap();

        for assigned in [2, 1, 0] {
            count.store(assigned, std::sync::atomic::Ordering::Relaxed);
            let flush = provider.clone();
            tokio::task::spawn_blocking(move || flush.force_flush().unwrap())
                .await
                .unwrap();
            let received = collector.next_export().await;
            assert_eq!(received.path, "/receiver/v1/metrics");
            assert_eq!(received.headers.get("x-collector-test").unwrap(), "metrics");
            let response = ExportMetricsServiceRequest::decode(received.body).unwrap();
            let resource = &response.resource_metrics[0];
            let attributes = &resource.resource.as_ref().unwrap().attributes;
            assert!(attributes.contains(&string_attribute(
                "service.instance.id",
                "pool:test-gateway:member-1",
            )));
            assert!(attributes.contains(&string_attribute(
                "openshell.supervisor.pool_member.id",
                "member-1",
            )));
            assert!(
                attributes.contains(&string_attribute("openshell.gateway.name", "test-gateway"))
            );
            let instruments = resource
                .scope_metrics
                .iter()
                .flat_map(|scope| &scope.metrics)
                .collect::<Vec<_>>();
            let sandboxes = instruments
                .iter()
                .find(|metric| metric.name == "openshell_supervisor_sandboxes_active")
                .unwrap();
            let Some(Data::Gauge(gauge)) = &sandboxes.data else {
                panic!("Expected the assigned sandbox gauge");
            };
            let sample = &gauge.data_points[0];
            assert_eq!(sample.attributes, []);
            assert_eq!(
                sample.value,
                Some(
                    opentelemetry_proto::tonic::metrics::v1::number_data_point::Value::AsInt(
                        i64::try_from(assigned).unwrap()
                    )
                ),
            );
            assert!(instruments.iter().any(|metric| {
                metric.name == "openshell_supervisor_connections_active"
                    && matches!(metric.data, Some(Data::Gauge(_)))
            }));
        }
        tokio::task::spawn_blocking(move || shutdown(&provider))
            .await
            .unwrap();
    }
}
