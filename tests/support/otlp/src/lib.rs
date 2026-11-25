// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! What an environment's OTLP collector received, for suites whose gateway
//! exports to it.
//!
//! The environment runs the collector, configures the gateway's
//! `[openshell.gateway.otlp]` endpoint and publishes both in
//! `OPENSHELL_TEST_OTLP_*` variables. The collector appends each trace export
//! to a JSONL log, one OTLP/JSON `ExportTraceServiceRequest` per line, as the
//! OpenTelemetry Collector's file exporter writes it. Under
//! `openshell-test-runner`, the tmachine `<podman base>-otlp` environments do
//! that (`tests/tmachine/ansible/playbooks/otlp.yaml`); against your own
//! deployment, set them yourself:
//!
//! | Variable | Example |
//! |---|---|
//! | `OPENSHELL_TEST_OTLP_LOG` | `/var/lib/openshell-test/otlp/traces.jsonl` |
//! | `OPENSHELL_TEST_OTLP_ENDPOINT` | `http://host.containers.internal:4317` |
//!
//! The log holds every test's spans, and the gateway's, so a test reads only
//! spans it named, with [`testkit::Context::name`]. A missing variable fails
//! the test; it never skips it.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;
use testkit::{Error, Poll, Result, ResultExt as _, poll_until};

pub use openshell_otel_test_support::relay::{
    SANDBOX_ID_KEY, SOURCE_KEY, SOURCE_VALUE, encoded_trace_request,
};

pub const LOG_ENV: &str = "OPENSHELL_TEST_OTLP_LOG";
pub const ENDPOINT_ENV: &str = "OPENSHELL_TEST_OTLP_ENDPOINT";

/// String resource attributes, keyed by name.
pub type Attributes = HashMap<String, String>;

/// One span the collector received.
#[derive(Clone, Debug)]
pub struct Span {
    pub name: String,
    /// The string attributes of the resource the span arrived with. A
    /// duplicated key keeps its last value.
    pub attributes: Attributes,
    /// Keys that resource carried more than once.
    pub duplicate_resource_keys: Vec<String>,
}

/// The environment's collector.
pub struct Collector {
    log: PathBuf,
    endpoint: String,
}

impl Collector {
    /// The collector [`LOG_ENV`] and [`ENDPOINT_ENV`] describe.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            log: PathBuf::from(required(LOG_ENV)?),
            endpoint: required(ENDPOINT_ENV)?,
        })
    }

    /// The endpoint the gateway exports to, such as
    /// `http://host.containers.internal:4317`.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The `host:port` of [`Self::endpoint`].
    pub fn host_port(&self) -> &str {
        let authority = self
            .endpoint
            .split_once("://")
            .map_or(self.endpoint.as_str(), |(_, rest)| rest);
        authority.split('/').next().unwrap_or(authority)
    }

    /// Every span received so far whose name is in `names`, in arrival
    /// order.
    pub fn spans(&self, names: &[&str]) -> Result<Vec<Span>> {
        let log = std::fs::read_to_string(&self.log).context(format!(
            "read the OTLP collector log {}",
            self.log.display()
        ))?;
        // The collector may be part way through writing the last line.
        let complete = log.rfind('\n').map_or("", |end| &log[..end]);
        let mut spans = Vec::new();
        for (index, line) in complete.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let request: Value = serde_json::from_str(line).context(format!(
                "parse line {} of {}",
                index + 1,
                self.log.display()
            ))?;
            collect_spans(&request, names, &mut spans);
        }
        Ok(spans)
    }

    /// Wait up to `within` until every span in `names` has arrived. Returns
    /// each name's spans; a name that arrived more than once has more than
    /// one.
    pub async fn wait_for_spans(
        &self,
        names: &[&str],
        within: Duration,
    ) -> Result<HashMap<String, Vec<Span>>> {
        poll_until(
            &format!("the collector to receive spans {names:?}"),
            within,
            Duration::from_millis(250),
            async || {
                let mut by_name: HashMap<String, Vec<Span>> = HashMap::new();
                for span in self.spans(names)? {
                    by_name.entry(span.name.clone()).or_default().push(span);
                }
                let missing: Vec<&str> = names
                    .iter()
                    .copied()
                    .filter(|name| !by_name.contains_key(*name))
                    .collect();
                Ok(if missing.is_empty() {
                    Poll::Ready(by_name)
                } else {
                    Poll::Pending(format!("spans {missing:?} have not arrived"))
                })
            },
        )
        .await
    }
}

fn collect_spans(request: &Value, names: &[&str], spans: &mut Vec<Span>) {
    for resource_spans in array(&request["resourceSpans"]) {
        let mut attributes = Attributes::new();
        let mut seen = Vec::new();
        let mut duplicate_resource_keys = Vec::new();
        for attribute in array(&resource_spans["resource"]["attributes"]) {
            let Some(key) = attribute["key"].as_str() else {
                continue;
            };
            // Track duplicates for every value type; the map keeps only
            // string values.
            if seen.contains(&key) {
                duplicate_resource_keys.push(key.to_string());
            } else {
                seen.push(key);
            }
            if let Some(value) = attribute["value"]["stringValue"].as_str() {
                attributes.insert(key.to_string(), value.to_string());
            }
        }
        for scope_spans in array(&resource_spans["scopeSpans"]) {
            for span in array(&scope_spans["spans"]) {
                let Some(name) = span["name"].as_str() else {
                    continue;
                };
                if names.contains(&name) {
                    spans.push(Span {
                        name: name.to_string(),
                        attributes: attributes.clone(),
                        duplicate_resource_keys: duplicate_resource_keys.clone(),
                    });
                }
            }
        }
    }
}

fn array(value: &Value) -> &[Value] {
    value.as_array().map_or(&[], Vec::as_slice)
}

fn required(name: &str) -> Result<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            Error::msg(format!(
                "{name} is not set; this suite needs a gateway that exports to the environment's OTLP collector (see the otlp-support crate docs)"
            ))
        })
}
