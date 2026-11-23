// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded, process-wide supervisor egress metrics.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, Meter, ObservableGauge};

use crate::l7::L7Protocol;

const LATENCY_BUCKETS_SECONDS: [f64; 17] = [
    0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
    5.0, 10.0, 15.0,
];
static METRICS: OnceLock<Metrics> = OnceLock::new();

/// Installs the process's egress instruments before starting any proxies.
pub fn install(meter: &Meter) {
    METRICS.get_or_init(|| Metrics::new(meter));
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Scope {
    Connection,
    Request,
    Message,
}

impl Scope {
    fn label(self) -> &'static str {
        match self {
            Self::Connection => "connection",
            Self::Request => "request",
            Self::Message => "message",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum InspectionType {
    Tcp,
    Http,
    Rest,
    Graphql,
    JsonRpc,
    Mcp,
    Websocket,
    Unknown,
}

impl InspectionType {
    const ALL: [Self; 8] = [
        Self::Tcp,
        Self::Http,
        Self::Rest,
        Self::Graphql,
        Self::JsonRpc,
        Self::Mcp,
        Self::Websocket,
        Self::Unknown,
    ];

    pub(crate) fn from_protocol(protocol: L7Protocol) -> Self {
        match protocol {
            L7Protocol::Rest => Self::Rest,
            L7Protocol::Graphql => Self::Graphql,
            L7Protocol::JsonRpc => Self::JsonRpc,
            L7Protocol::Mcp => Self::Mcp,
            L7Protocol::Websocket => Self::Websocket,
            L7Protocol::Sql => Self::Tcp, // The SQL route uses raw passthrough.
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Http => "http",
            Self::Rest => "rest",
            Self::Graphql => "graphql",
            Self::JsonRpc => "json-rpc",
            Self::Mcp => "mcp",
            Self::Websocket => "websocket",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Outcome {
    Allow,
    Deny,
    Audit,
    FailOpen,
}

impl Outcome {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Audit => "audit",
            Self::FailOpen => "fail_open",
        }
    }

    pub(crate) fn policy(allowed: bool, enforce: bool) -> Self {
        match (allowed, enforce) {
            (true, _) => Self::Allow,
            (false, true) => Self::Deny,
            (false, false) => Self::Audit,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ResultLabel {
    Success,
    Deny,
    Error,
    Timeout,
    Cancelled,
}

impl ResultLabel {
    fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Deny => "deny",
            Self::Error => "error",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
        }
    }

    pub(crate) fn from_io_error(error: &std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::TimedOut => Self::Timeout,
            _ => Self::Error,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Route {
    Direct,
    Proxy,
}

impl Route {
    fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Proxy => "proxy",
        }
    }
}

struct Metrics {
    decisions: Counter<u64>,
    policy_evaluation: Histogram<f64>,
    request_inspection: Histogram<f64>,
    upstream_connect: Histogram<f64>,
    connections: Arc<[AtomicU64; InspectionType::ALL.len()]>,
    _active_connections: ObservableGauge<u64>,
}

impl Metrics {
    fn new(meter: &Meter) -> Self {
        let histogram = |name, description| {
            meter
                .f64_histogram(name)
                .with_description(description)
                .with_unit("s")
                .with_boundaries(LATENCY_BUCKETS_SECONDS.to_vec())
                .build()
        };
        let connections: Arc<[AtomicU64; InspectionType::ALL.len()]> =
            Arc::new(std::array::from_fn(|_| AtomicU64::new(0)));
        let active = Arc::clone(&connections);
        let active_connections = meter
            .u64_observable_gauge("openshell_supervisor_connections_active")
            .with_description("Live proxied connections.")
            .with_callback(move |observer| {
                for inspection in InspectionType::ALL {
                    observer.observe(
                        active[inspection as usize].load(Ordering::Relaxed),
                        &[KeyValue::new("inspection_type", inspection.label())],
                    );
                }
            })
            .build();
        Self {
            decisions: meter
                .u64_counter("openshell_supervisor_egress_decisions_total")
                .with_description("Final egress admission decisions.")
                .build(),
            policy_evaluation: histogram(
                "openshell_supervisor_policy_evaluation_duration_seconds",
                "Time spent evaluating egress policy.",
            ),
            request_inspection: histogram(
                "openshell_supervisor_request_inspection_duration_seconds",
                "Time spent inspecting a request or message before forwarding.",
            ),
            upstream_connect: histogram(
                "openshell_supervisor_upstream_connect_duration_seconds",
                "Time spent establishing an upstream connection.",
            ),
            connections,
            _active_connections: active_connections,
        }
    }
}

pub(crate) fn decision(scope: Scope, outcome: Outcome, inspection: InspectionType) {
    if let Some(metrics) = METRICS.get() {
        metrics.decisions.add(
            1,
            &[
                KeyValue::new("scope", scope.label()),
                KeyValue::new("outcome", outcome.label()),
                KeyValue::new("inspection_type", inspection.label()),
            ],
        );
    }
}

pub(crate) struct ActiveConnection(Option<&'static AtomicU64>);

impl ActiveConnection {
    pub(crate) fn new(inspection: InspectionType) -> Self {
        let count = METRICS
            .get()
            .map(|metrics| &metrics.connections[inspection as usize]);
        if let Some(count) = count {
            count.fetch_add(1, Ordering::Relaxed);
        }
        Self(count)
    }
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        if let Some(count) = self.0 {
            count.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Stage {
    PolicyEvaluation(Scope),
    Inspection(Scope, InspectionType),
    UpstreamConnect(Route),
}

pub(crate) async fn connect<T>(
    route: Route,
    operation: impl Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    let timer = Timer::new(Stage::UpstreamConnect(route));
    let result = operation.await;
    let label = result
        .as_ref()
        .map_or_else(ResultLabel::from_io_error, |_| ResultLabel::Success);
    timer.finish(label);
    result
}

pub(crate) fn evaluate<T, E>(
    scope: Scope,
    operation: impl FnOnce() -> Result<T, E>,
    allowed: impl FnOnce(&T) -> bool,
) -> Result<T, E> {
    let timer = Timer::new(Stage::PolicyEvaluation(scope));
    let decision = operation();
    let result = match decision.as_ref().map(allowed) {
        Ok(true) => ResultLabel::Success,
        Ok(false) => ResultLabel::Deny,
        Err(_) => ResultLabel::Error,
    };
    timer.finish(result);
    decision
}

#[derive(Debug)]
pub(crate) struct Timer {
    stage: Stage,
    start: Option<Instant>,
    pause: Option<Instant>,
    excluded: Duration,
}

impl Timer {
    pub(crate) fn new(stage: Stage) -> Self {
        Self {
            stage,
            start: METRICS.get().map(|_| Instant::now()),
            pause: None,
            excluded: Duration::ZERO,
        }
    }

    pub(crate) fn finish(mut self, result: ResultLabel) {
        self.record(result);
    }

    pub(crate) fn set_stage(&mut self, stage: Stage) {
        self.stage = stage;
    }

    pub(crate) fn pause(&mut self) {
        if self.start.is_some() {
            self.pause = Some(Instant::now());
        }
    }

    pub(crate) fn resume(&mut self) {
        if let Some(paused) = self.pause.take() {
            self.excluded += paused.elapsed();
        }
    }

    fn record(&mut self, result: ResultLabel) {
        let (Some(metrics), Some(started)) = (METRICS.get(), self.start.take()) else {
            return;
        };
        let ended = self.pause.unwrap_or_else(Instant::now);
        let seconds = (ended - started)
            .saturating_sub(self.excluded)
            .as_secs_f64();
        let result = KeyValue::new("result", result.label());
        match self.stage {
            Stage::PolicyEvaluation(scope) => {
                metrics
                    .policy_evaluation
                    .record(seconds, &[KeyValue::new("scope", scope.label()), result]);
            }
            Stage::Inspection(scope, inspection) => metrics.request_inspection.record(
                seconds,
                &[
                    KeyValue::new("scope", scope.label()),
                    KeyValue::new("inspection_type", inspection.label()),
                    result,
                ],
            ),
            Stage::UpstreamConnect(route) => {
                metrics
                    .upstream_connect
                    .record(seconds, &[KeyValue::new("route", route.label()), result]);
            }
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        self.record(ResultLabel::Cancelled);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::metrics::MeterProvider as _;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};

    #[tokio::test]
    async fn histograms_and_decisions_record_without_a_sampled_span() {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        install(&provider.meter("supervisor-metrics-test"));

        let connection = ActiveConnection::new(InspectionType::Unknown);
        Timer::new(Stage::PolicyEvaluation(Scope::Connection)).finish(ResultLabel::Deny);
        Timer::new(Stage::Inspection(Scope::Request, InspectionType::Rest))
            .finish(ResultLabel::Success);
        drop(Timer::new(Stage::UpstreamConnect(Route::Proxy)));
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::TimedOut,
        ] {
            let error = connect(Route::Proxy, async { Err::<(), _>(kind.into()) })
                .await
                .unwrap_err();
            assert_eq!(error.kind(), kind);
        }
        for outcome in [
            Outcome::Allow,
            Outcome::Deny,
            Outcome::Audit,
            Outcome::FailOpen,
        ] {
            decision(Scope::Connection, outcome, InspectionType::Unknown);
        }
        provider.force_flush().unwrap();

        let records = exporter.get_finished_metrics().unwrap();
        let instruments = records[0]
            .scope_metrics()
            .flat_map(|scope| scope.metrics())
            .collect::<Vec<_>>();
        for (name, result) in [
            (
                "openshell_supervisor_policy_evaluation_duration_seconds",
                "deny",
            ),
            (
                "openshell_supervisor_request_inspection_duration_seconds",
                "success",
            ),
            (
                "openshell_supervisor_upstream_connect_duration_seconds",
                "cancelled",
            ),
            (
                "openshell_supervisor_upstream_connect_duration_seconds",
                "error",
            ),
            (
                "openshell_supervisor_upstream_connect_duration_seconds",
                "timeout",
            ),
        ] {
            let histogram = instruments
                .iter()
                .find(|metric| metric.name() == name)
                .unwrap();
            let AggregatedMetrics::F64(MetricData::Histogram(histogram)) = histogram.data() else {
                panic!("{name} should export an explicit histogram");
            };
            assert!(histogram.data_points().any(|point| {
                point.count() > 0
                    && point.bounds().eq(LATENCY_BUCKETS_SECONDS)
                    && point
                        .attributes()
                        .any(|kv| kv.key.as_str() == "result" && kv.value.as_str() == result)
            }));
        }
        let decisions = instruments
            .iter()
            .find(|metric| metric.name() == "openshell_supervisor_egress_decisions_total")
            .unwrap();
        let AggregatedMetrics::U64(MetricData::Sum(decisions)) = decisions.data() else {
            panic!("Decision counter should export a sum");
        };
        assert!(decisions.is_monotonic());
        for outcome in ["allow", "deny", "audit", "fail_open"] {
            let labels = [
                KeyValue::new("scope", "connection"),
                KeyValue::new("outcome", outcome),
                KeyValue::new("inspection_type", "unknown"),
            ];
            assert!(decisions.data_points().any(|point| {
                point.value() > 0
                    && point.attributes().count() == labels.len()
                    && point.attributes().all(|label| labels.contains(label))
            }));
        }

        let active_connections =
            |records: &[opentelemetry_sdk::metrics::data::ResourceMetrics]| {
                let gauge = records
                    .last()
                    .unwrap()
                    .scope_metrics()
                    .flat_map(|scope| scope.metrics())
                    .find(|metric| metric.name() == "openshell_supervisor_connections_active")
                    .unwrap();
                let AggregatedMetrics::U64(MetricData::Gauge(gauge)) = gauge.data() else {
                    panic!("Connection count should export a gauge");
                };
                gauge
                    .data_points()
                    .find(|point| {
                        point.attributes().any(|kv| {
                            kv.key.as_str() == "inspection_type" && kv.value.as_str() == "unknown"
                        })
                    })
                    .unwrap()
                    .value()
            };
        assert_eq!(active_connections(&records), 1);
        drop(connection);
        provider.force_flush().unwrap();
        assert_eq!(
            active_connections(&exporter.get_finished_metrics().unwrap()),
            0
        );
    }
}
