// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Launch protocol between the gateway and the compute drivers it launches.
//!
//! The gateway starts a driver with a short bootstrap command line (socket,
//! peer PID, log level, OTLP). The driver serves [`proto::driver_launch_server::DriverLaunch`]
//! and its `ComputeDriver` service on that socket at once. `ComputeDriver`
//! RPCs return `UNAVAILABLE` until the gateway calls `Configure`, which builds
//! the driver.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use tonic::{Request, Response, Status};

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    unused_qualifications,
    rust_2018_idioms
)]
pub mod proto {
    tonic::include_proto!("openshell.driver.launch.v1");
}

use proto::driver_launch_server::{DriverLaunch, DriverLaunchServer};
use proto::{ConfigureRequest, ConfigureResponse, GetLaunchInfoRequest, GetLaunchInfoResponse};

/// The launch protocol version this crate implements.
pub const PROTOCOL_VERSION: u32 = 1;

/// Largest encoded `ConfigureRequest` a driver accepts on `preflight` stdin.
pub const MAX_CONFIGURE_REQUEST_BYTES: usize = 1024 * 1024;

/// Encode a request for `preflight`, which reads it from stdin.
#[must_use]
pub fn encode_configure_request(request: &ConfigureRequest) -> Vec<u8> {
    prost::Message::encode_to_vec(request)
}

/// Decode the request `preflight` reads from stdin.
///
/// # Errors
///
/// Returns a message when the input is too large or not a `ConfigureRequest`.
pub fn decode_configure_request(bytes: &[u8]) -> Result<ConfigureRequest, String> {
    if bytes.len() > MAX_CONFIGURE_REQUEST_BYTES {
        return Err(format!(
            "configure request exceeds {MAX_CONFIGURE_REQUEST_BYTES} bytes"
        ));
    }
    <ConfigureRequest as prost::Message>::decode(bytes)
        .map_err(|error| format!("invalid configure request: {error}"))
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;
type ConfigureFn<S> = Arc<dyn Fn(ConfigureRequest) -> BoxFuture<Result<S, Status>> + Send + Sync>;

/// A gRPC service that answers `UNAVAILABLE` until `Configure` fills it.
pub struct Deferred<S> {
    slot: Arc<OnceLock<S>>,
}

impl<S> Clone for Deferred<S> {
    fn clone(&self) -> Self {
        Self {
            slot: self.slot.clone(),
        }
    }
}

impl<S> tower::Service<http::Request<tonic::body::Body>> for Deferred<S>
where
    S: tower::Service<
            http::Request<tonic::body::Body>,
            Response = http::Response<tonic::body::Body>,
            Error = Infallible,
        > + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        let Some(inner) = self.slot.get() else {
            return Box::pin(async {
                Ok(
                    Status::unavailable("compute driver is not configured; call Configure first")
                        .into_http(),
                )
            });
        };
        let mut inner = inner.clone();
        Box::pin(async move {
            std::future::poll_fn(|cx| inner.poll_ready(cx)).await?;
            inner.call(request).await
        })
    }
}

impl<S: tonic::server::NamedService> tonic::server::NamedService for Deferred<S> {
    const NAME: &'static str = S::NAME;
}

/// The driver side of `DriverLaunch`.
pub struct Launch<S> {
    slot: Arc<OnceLock<S>>,
    configuring: tokio::sync::Mutex<()>,
    configure: ConfigureFn<S>,
    info: GetLaunchInfoResponse,
}

#[tonic::async_trait]
impl<S: Send + Sync + 'static> DriverLaunch for Launch<S> {
    async fn get_launch_info(
        &self,
        _request: Request<GetLaunchInfoRequest>,
    ) -> Result<Response<GetLaunchInfoResponse>, Status> {
        Ok(Response::new(self.info.clone()))
    }

    async fn configure(
        &self,
        request: Request<ConfigureRequest>,
    ) -> Result<Response<ConfigureResponse>, Status> {
        let _configuring = self.configuring.lock().await;
        if self.slot.get().is_some() {
            return Err(Status::failed_precondition(
                "compute driver is already configured",
            ));
        }
        let request = request.into_inner();
        if !self
            .info
            .protocol_versions
            .contains(&request.protocol_version)
        {
            return Err(Status::invalid_argument(format!(
                "unsupported launch protocol version {}; this driver supports {:?}",
                request.protocol_version, self.info.protocol_versions
            )));
        }
        if let Some(feature) = request
            .required_features
            .iter()
            .find(|feature| !self.info.features.contains(feature))
        {
            return Err(Status::failed_precondition(format!(
                "compute driver does not support required feature '{feature}'"
            )));
        }
        let service = (self.configure)(request).await?;
        let _ = self.slot.set(service);
        Ok(Response::new(ConfigureResponse {}))
    }
}

/// Build the `DriverLaunch` service and the deferred driver service it fills.
///
/// `configure` runs on each `Configure` call until one succeeds. A failed call
/// leaves the driver unconfigured so the gateway can retry.
pub fn services<S, F, Fut>(
    driver_name: &str,
    driver_version: &str,
    configure: F,
) -> (DriverLaunchServer<Launch<S>>, Deferred<S>)
where
    S: Send + Sync + 'static,
    F: Fn(ConfigureRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<S, Status>> + Send + 'static,
{
    let (launch, deferred) = parts(driver_name, driver_version, configure);
    (DriverLaunchServer::new(launch), deferred)
}

fn parts<S, F, Fut>(
    driver_name: &str,
    driver_version: &str,
    configure: F,
) -> (Launch<S>, Deferred<S>)
where
    S: Send + Sync + 'static,
    F: Fn(ConfigureRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<S, Status>> + Send + 'static,
{
    let slot = Arc::new(OnceLock::new());
    let launch = Launch {
        slot: slot.clone(),
        configuring: tokio::sync::Mutex::new(()),
        configure: Arc::new(move |request| Box::pin(configure(request))),
        info: GetLaunchInfoResponse {
            protocol_versions: vec![PROTOCOL_VERSION],
            features: Vec::new(),
            driver_name: driver_name.to_string(),
            driver_version: driver_version.to_string(),
        },
    };
    (launch, Deferred { slot })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn request(version: u32, features: &[&str]) -> Request<ConfigureRequest> {
        Request::new(ConfigureRequest {
            protocol_version: version,
            required_features: features.iter().map(ToString::to_string).collect(),
            ..ConfigureRequest::default()
        })
    }

    fn launch(fail_first: bool) -> (Launch<u32>, Arc<AtomicU32>) {
        let calls = Arc::new(AtomicU32::new(0));
        let counter = calls.clone();
        let (launch, _deferred) = parts("test", "0", move |_request| {
            let call = counter.fetch_add(1, Ordering::SeqCst);
            async move {
                if fail_first && call == 0 {
                    Err(Status::unavailable("backend down"))
                } else {
                    Ok(7_u32)
                }
            }
        });
        (launch, calls)
    }

    #[tokio::test]
    async fn configure_succeeds_once() {
        let (launch, _) = launch(false);
        launch
            .configure(request(PROTOCOL_VERSION, &[]))
            .await
            .unwrap();
        let error = launch
            .configure(request(PROTOCOL_VERSION, &[]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert_eq!(launch.slot.get(), Some(&7));
    }

    #[tokio::test]
    async fn a_failed_configure_can_be_retried() {
        let (launch, calls) = launch(true);
        let error = launch
            .configure(request(PROTOCOL_VERSION, &[]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert!(launch.slot.get().is_none());
        launch
            .configure(request(PROTOCOL_VERSION, &[]))
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn unknown_versions_and_features_are_refused_before_building() {
        let (launch, calls) = launch(false);
        let error = launch.configure(request(99, &[])).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        let error = launch
            .configure(request(PROTOCOL_VERSION, &["network_trust.v2"]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn configure_requests_round_trip_and_oversized_input_is_refused() {
        let request = ConfigureRequest {
            protocol_version: PROTOCOL_VERSION,
            driver_config_toml: "network_name = \"n\"".to_string(),
            ..ConfigureRequest::default()
        };
        let decoded = decode_configure_request(&encode_configure_request(&request)).unwrap();
        assert_eq!(decoded, request);
        let error =
            decode_configure_request(&vec![0; MAX_CONFIGURE_REQUEST_BYTES + 1]).unwrap_err();
        assert!(error.contains("exceeds"), "{error}");
    }

    fn grpc_status(response: &http::Response<tonic::body::Body>) -> Option<&str> {
        response
            .headers()
            .get("grpc-status")
            .and_then(|value| value.to_str().ok())
    }

    #[tokio::test]
    async fn the_deferred_service_is_unavailable_until_filled() {
        use tower::ServiceExt as _;

        let mut deferred = Deferred {
            slot: Arc::new(OnceLock::new()),
        };
        let response = deferred
            .clone()
            .oneshot(http::Request::new(tonic::body::Body::empty()))
            .await
            .unwrap();
        assert_eq!(grpc_status(&response), Some("14"));

        let inner = tower::service_fn(|_request: http::Request<tonic::body::Body>| async {
            Ok::<_, Infallible>(Status::not_found("from inner").into_http())
        });
        assert!(deferred.slot.set(inner).is_ok());
        let response = tower::Service::call(
            &mut deferred,
            http::Request::new(tonic::body::Body::empty()),
        )
        .await
        .unwrap();
        assert_eq!(grpc_status(&response), Some("5"));
    }
}
