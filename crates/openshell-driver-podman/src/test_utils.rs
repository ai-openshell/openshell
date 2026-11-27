// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared test helpers for openshell-driver-podman unit tests.

use http_body_util::{BodyExt as _, Full};
use hyper::StatusCode;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UnixListener;

/// A canned HTTP response for the Podman stub server.
#[derive(Clone)]
pub struct StubResponse {
    pub status: StatusCode,
    pub body: Bytes,
    pub delay: Duration,
    pub archive_members: Option<Vec<PathBuf>>,
    container_image: Option<&'static str>,
    container_secret: Option<String>,
    container_spec_fields: Option<serde_json::Value>,
    request_bytes: Option<Bytes>,
}

impl StubResponse {
    pub fn new(status: StatusCode, body: impl Into<Bytes>) -> Self {
        Self {
            status,
            body: body.into(),
            delay: Duration::ZERO,
            archive_members: None,
            container_image: None,
            container_secret: None,
            container_spec_fields: None,
            request_bytes: None,
        }
    }

    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    pub fn with_archive_members(mut self, members: &[&str]) -> Self {
        self.archive_members = Some(members.iter().map(PathBuf::from).collect());
        self
    }

    pub fn with_container_image(mut self, image: &'static str) -> Self {
        self.container_image = Some(image);
        self
    }

    pub fn with_container_secret(mut self, name: String) -> Self {
        self.container_secret = Some(name);
        self
    }

    pub fn with_container_spec_fields(mut self, fields: serde_json::Value) -> Self {
        self.container_spec_fields = Some(fields);
        self
    }

    pub fn with_request_bytes(mut self, body: &'static [u8]) -> Self {
        self.request_bytes = Some(Bytes::from_static(body));
        self
    }
}

/// Generate a unique Unix socket path for a test.
///
/// Uses the current PID and nanosecond timestamp to avoid collisions between
/// concurrent test runs.
pub fn unique_socket_path(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos();
    PathBuf::from(format!(
        "/tmp/openshell-podman-{test_name}-{}-{nanos}.sock",
        std::process::id()
    ))
}

/// Spawn a Unix-socket HTTP stub that serves the given `responses` in order.
///
/// Returns:
/// - the socket path (already bound and listening)
/// - a shared log of `"METHOD /path"` strings, one per request received
/// - a join handle that resolves once all expected requests have been served
pub fn spawn_podman_stub(
    test_name: &str,
    responses: Vec<StubResponse>,
) -> (
    PathBuf,
    Arc<Mutex<Vec<String>>>,
    tokio::task::JoinHandle<()>,
) {
    let socket_path = unique_socket_path(test_name);
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("test socket should bind");
    let request_log = Arc::new(Mutex::new(Vec::new()));
    let response_queue = Arc::new(Mutex::new(VecDeque::from(responses)));
    let expected = response_queue
        .lock()
        .expect("response queue lock should not be poisoned")
        .len();
    let socket_path_for_task = socket_path.clone();
    let log_for_task = request_log.clone();
    let queue_for_task = response_queue;
    let handle = tokio::spawn(async move {
        for _ in 0..expected {
            let (stream, _) = listener.accept().await.expect("test stub should accept");
            let log = log_for_task.clone();
            let queue = queue_for_task.clone();
            let result = http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let log = log.clone();
                        let queue = queue.clone();
                        async move {
                            let path = req.uri().path_and_query().map_or_else(
                                || req.uri().path().to_string(),
                                |pq| pq.as_str().to_string(),
                            );
                            log.lock()
                                .expect("request log lock should not be poisoned")
                                .push(format!("{} {}", req.method(), path));
                            let response = queue
                                .lock()
                                .expect("response queue lock should not be poisoned")
                                .pop_front()
                                .expect("stub response should exist");
                            if let Some(expected_bytes) = &response.request_bytes {
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                assert_eq!(&body, expected_bytes);
                            } else if let Some(expected_members) = &response.archive_members {
                                assert_eq!(req.method(), hyper::Method::PUT);
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                let mut archive = tar::Archive::new(body.as_ref());
                                let members: Vec<_> = archive
                                    .entries()
                                    .unwrap()
                                    .map(|entry| entry.unwrap().path().unwrap().into_owned())
                                    .collect();
                                assert_eq!(&members, expected_members);
                            } else if response.container_image.is_some()
                                || response.container_secret.is_some()
                                || response.container_spec_fields.is_some()
                            {
                                assert_eq!(req.method(), hyper::Method::POST);
                                assert!(req.uri().path().ends_with("/containers/create"));
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                let spec: serde_json::Value =
                                    serde_json::from_slice(&body).unwrap();
                                if let Some(expected_image) = response.container_image {
                                    assert_eq!(spec["image"].as_str(), Some(expected_image));
                                }
                                if let Some(expected_secret) = &response.container_secret {
                                    assert!(spec["secrets"].as_array().unwrap().iter().any(|mount| {
                                        mount["source"].as_str() == Some(expected_secret.as_str())
                                            && mount["target"].as_str() == Some(openshell_core::driver_utils::UPSTREAM_PROXY_AUTH_MOUNT_PATH)
                                    }));
                                }
                                if let Some(fields) = &response.container_spec_fields {
                                    for (field, value) in fields.as_object().unwrap() {
                                        assert_eq!(spec.get(field), Some(value), "{field}");
                                    }
                                }
                            }
                            tokio::time::sleep(response.delay).await;
                            Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .status(response.status)
                                    .body(Full::new(response.body))
                                    .expect("stub response should build"),
                            )
                        }
                    }),
                )
                .await;
            // The one-shot test client can close the Unix socket after the
            // response, which Hyper reports as a shutdown error. Let the
            // request log assertions below decide whether the stub served
            // the expected API calls.
            let _ = result;
        }
        let _ = std::fs::remove_file(&socket_path_for_task);
    });
    (socket_path, request_log, handle)
}
