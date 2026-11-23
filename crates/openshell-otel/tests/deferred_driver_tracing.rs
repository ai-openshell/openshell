// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Installs process-wide tracing, so it runs in its own test binary.

use openshell_otel::{DriverTracingConfig, Protocol};
use openshell_otel_test_support::OtlpTestServer;

#[tokio::test(flavor = "multi_thread")]
async fn export_enabled_after_install_reaches_the_collector_once() {
    let tracing = openshell_otel::install_deferred_driver_tracing(
        openshell_otel::compute_driver_tracing!(),
        "info",
        false,
    );
    tracing::info_span!("driver.before_export").in_scope(|| {});

    let collector = OtlpTestServer::start().await;
    let config = DriverTracingConfig {
        endpoint: Some(collector.endpoint()),
        protocol: Protocol::Grpc,
        ca_file: None,
        cert_file: None,
        key_file: None,
        gateway_name: Some("test-gateway"),
        service_version: "test",
        log_level: "info",
        ansi: false,
    };
    tracing.enable_export(config, http::HeaderMap::new());
    tracing.enable_export(config, http::HeaderMap::new());
    tracing::info_span!("driver.after_export").in_scope(|| {});
    drop(tracing);
    let received = collector.shutdown().await;

    let names: Vec<_> = received
        .spans
        .iter()
        .map(|span| span.name.as_str())
        .collect();
    assert_eq!(names, ["driver.after_export"]);
    assert_eq!(received.gateway_names, ["test-gateway"]);
}
