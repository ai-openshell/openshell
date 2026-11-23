// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `serve` mode a gateway launches the Podman driver in: the launch
//! service answers at once, compute RPCs wait for `Configure`, and a failed
//! `Configure` leaves the driver running so the gateway can retry.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use openshell_core::proto::compute::v1::GetCapabilitiesRequest;
use openshell_core::proto::compute::v1::compute_driver_client::ComputeDriverClient;
use openshell_driver_launch::proto::driver_launch_client::DriverLaunchClient;
use openshell_driver_launch::proto::{ConfigureRequest, GatewayContext, GetLaunchInfoRequest};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint};

const FIXTURE: &str = include_str!("fixtures/driver-config-podman.toml");

async fn connect(socket: &Path) -> Channel {
    for _ in 0..100 {
        let path: PathBuf = socket.to_path_buf();
        let connected = Endpoint::from_static("http://[::]:50051")
            .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                let path = path.clone();
                async move { UnixStream::connect(path).await.map(TokioIo::new) }
            }))
            .await;
        if let Ok(channel) = connected {
            return channel;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("driver socket {} never came up", socket.display());
}

#[tokio::test]
async fn serve_waits_for_configure_and_survives_a_failed_one() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("run").join("compute-driver.sock");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_openshell-driver-podman"))
        .arg("serve")
        .arg("--bind-socket")
        .arg(&socket)
        .env("OPENSHELL_PODMAN_SOCKET", dir.path().join("missing.sock"))
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let channel = connect(&socket).await;

    let mut launch = DriverLaunchClient::new(channel.clone());
    let info = launch
        .get_launch_info(GetLaunchInfoRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        info.protocol_versions,
        vec![openshell_driver_launch::PROTOCOL_VERSION]
    );
    assert_eq!(info.driver_name, "podman");

    let mut compute = ComputeDriverClient::new(channel.clone());
    let status = compute
        .get_capabilities(GetCapabilitiesRequest::default())
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable, "{status:?}");

    let invalid = ConfigureRequest {
        protocol_version: openshell_driver_launch::PROTOCOL_VERSION,
        driver_config_toml: "surprise = 1".to_string(),
        ..ConfigureRequest::default()
    };
    let status = launch.configure(invalid).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument, "{status:?}");

    let request = ConfigureRequest {
        protocol_version: openshell_driver_launch::PROTOCOL_VERSION,
        gateway: Some(GatewayContext {
            gateway_port: 8080,
            tls_ca_path: String::new(),
            gateway_name: "gateway-a".to_string(),
        }),
        driver_config_toml: FIXTURE.to_string(),
        ..ConfigureRequest::default()
    };
    // No Podman API behind the socket: building the driver fails, and the
    // driver stays up for another attempt.
    let status = launch.configure(request.clone()).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable, "{status:?}");
    assert!(child.try_wait().unwrap().is_none());
    let status = launch.configure(request).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable, "{status:?}");

    child.kill().await.unwrap();
}

fn preflight(input: &[u8]) -> serde_json::Value {
    use std::io::Write as _;

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_openshell-driver-podman"))
        .arg("preflight")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn preflight_validates_the_configure_request_from_stdin() {
    let valid = ConfigureRequest {
        protocol_version: openshell_driver_launch::PROTOCOL_VERSION,
        gateway: Some(GatewayContext {
            gateway_port: 8080,
            tls_ca_path: String::new(),
            gateway_name: "gateway-a".to_string(),
        }),
        driver_config_toml: FIXTURE.to_string(),
        ..ConfigureRequest::default()
    };
    let result = preflight(&openshell_driver_launch::encode_configure_request(&valid));
    assert_eq!(result["ok"], true, "{result}");

    let invalid = ConfigureRequest {
        driver_config_toml: "surprise = 1".to_string(),
        ..valid
    };
    let result = preflight(&openshell_driver_launch::encode_configure_request(&invalid));
    assert_eq!(result["ok"], false);
    assert!(
        result["error"].as_str().unwrap().contains("surprise"),
        "{result}"
    );

    let result = preflight(b"not a request");
    assert_eq!(result["ok"], false, "{result}");
}
