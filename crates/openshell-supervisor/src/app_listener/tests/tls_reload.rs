// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use http_body_util::BodyExt as _;
use openshell_crypto::pki::{self, Certificate, KeyPair};
use openshell_ocsf::events::{BaseEventData, OcsfEvent};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyUsagePurpose};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

const IO_TIMEOUT: Duration = Duration::from_secs(3);
const CERT_FILE: &str = "tls.crt";
const KEY_FILE: &str = "tls.key";
const MALFORMED_CERT: &str = "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n";

fn project_secret(directory: &Path, revision: &str, certificate: &str, key: &str) {
    let generation = directory.join(revision);
    fs::create_dir(&generation).unwrap();
    fs::write(generation.join(CERT_FILE), certificate).unwrap();
    fs::write(generation.join(KEY_FILE), key).unwrap();

    let data = directory.join("..data");
    let previous = fs::read_link(&data).ok();
    // Kubelet publishes a complete generation by replacing the ..data link.
    symlink(revision, directory.join("..data_tmp")).unwrap();
    fs::rename(directory.join("..data_tmp"), data).unwrap();
    if let Some(previous) = previous {
        fs::remove_dir_all(directory.join(previous)).unwrap();
    }
}

fn ca_params(common_name: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params
}

fn issue_leaf(issuer: &Certificate, key: &KeyPair) -> (Certificate, String) {
    let leaf_key = pki::generate_keypair().unwrap();
    let params = CertificateParams::new(vec!["*.svc.openshell.internal".into()]).unwrap();
    let leaf = pki::signed_by(params, &leaf_key, issuer, key).unwrap();
    (leaf, leaf_key.serialize_pem().unwrap())
}

async fn reload_event(
    capture: &OcsfCapture,
    previous_events: usize,
    state: &str,
    detail: &str,
) -> BaseEventData {
    tokio::time::timeout(TLS_RELOAD_INTERVAL + IO_TIMEOUT, async {
        loop {
            let event = capture
                .events()
                .into_iter()
                .skip(previous_events)
                .find_map(|event| match event {
                    OcsfEvent::DeviceConfigStateChange(event)
                        if event.state_custom_label.as_deref() == Some(state)
                            && event
                                .base
                                .message
                                .as_deref()
                                .is_some_and(|message| message.contains(detail)) =>
                    {
                        Some(event.base)
                    }
                    _ => None,
                });
            if let Some(event) = event {
                return event;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("listener did not report TLS state {state} with {detail}"))
}

type ClientTlsStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

async fn connect(fixture: &Fixture, config: Arc<rustls::ClientConfig>) -> ClientTlsStream {
    tokio::time::timeout(IO_TIMEOUT, async {
        let stream = openshell_core::net::connect_tcp_nodelay_best_effort(fixture.address)
            .await
            .unwrap();
        tokio_rustls::TlsConnector::from(config)
            .connect(
                rustls::pki_types::ServerName::try_from(HOST).unwrap(),
                stream,
            )
            .await
            .unwrap()
    })
    .await
    .expect("TLS handshake timed out")
}

fn leaf(tls: &ClientTlsStream) -> &CertificateDer<'static> {
    &tls.get_ref().1.peer_certificates().unwrap()[0]
}

#[tokio::test]
async fn projected_tls_rotation_rejects_invalid_pairs_and_preserves_active_stream() {
    let capture = OcsfCapture::default();
    let _guard = capture.install();
    let directory = tempfile::tempdir().unwrap();
    let root_key = pki::generate_keypair().unwrap();
    let root = pki::self_signed(ca_params("Application root"), &root_key).unwrap();
    let issuer_key = pki::generate_keypair().unwrap();
    let issuer = pki::signed_by(
        ca_params("Application issuer"),
        &issuer_key,
        &root,
        &root_key,
    )
    .unwrap();
    let (original, original_key) = issue_leaf(&issuer, &issuer_key);
    let (renewed, renewed_key) = issue_leaf(&issuer, &issuer_key);
    let initial_bundle = format!("{}{}{MALFORMED_CERT}", original.pem(), issuer.pem());
    project_secret(
        directory.path(),
        "..initial",
        &initial_bundle,
        &original_key,
    );
    for file in [CERT_FILE, KEY_FILE] {
        symlink(Path::new("..data").join(file), directory.path().join(file)).unwrap();
    }
    let listener = Config {
        address: "127.0.0.1:0".parse().unwrap(),
        domain: "svc.openshell.internal".into(),
        certificate: directory.path().join(CERT_FILE),
        key: directory.path().join(KEY_FILE),
    };
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.der().clone()).unwrap();
    let mut client = openshell_crypto::tls::client_builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.resumption = rustls::client::Resumption::disabled();
    let fixture = start_fixture(directory, listener, client);
    let resume = Arc::new(Notify::new());
    fixture.connector.stream_resume.set(resume.clone()).unwrap();

    let tls = connect(&fixture, fixture.tls.clone()).await;
    // An unused malformed certificate at the tail was tolerated at startup.
    assert_eq!(leaf(&tls), original.der());
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    let mut response = tokio::time::timeout(
        IO_TIMEOUT,
        sender.send_request(
            Request::get("/stream")
                .header(header::HOST, HOST)
                .body(Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("stream response timed out")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let first = tokio::time::timeout(IO_TIMEOUT, response.body_mut().frame())
        .await
        .expect("first stream chunk timed out")
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(first, "before rotation");

    let foreign_key = pki::generate_keypair().unwrap();
    let foreign_issuer = pki::signed_by(
        ca_params("Application issuer"),
        &foreign_key,
        &root,
        &root_key,
    )
    .unwrap();
    let renewed_leaf = renewed.pem();
    let renewed_bundle = format!("{renewed_leaf}{}", issuer.pem());
    let malformed_bundle = format!("{renewed_leaf}{MALFORMED_CERT}");
    let foreign_bundle = format!("{renewed_leaf}{}", foreign_issuer.pem());
    let directory = fixture.directory.path();
    for (revision, bundle, key, detail) in [
        (
            "..mismatched",
            renewed_bundle.as_str(),
            original_key.as_str(),
            "invalid certificate chain or private key",
        ),
        (
            "..missing-issuer",
            renewed_leaf.as_str(),
            renewed_key.as_str(),
            "invalid application certificate chain",
        ),
        (
            "..foreign-issuer",
            foreign_bundle.as_str(),
            renewed_key.as_str(),
            "invalid application certificate chain",
        ),
        (
            "..malformed-issuer",
            malformed_bundle.as_str(),
            renewed_key.as_str(),
            "invalid application certificate chain",
        ),
    ] {
        let previous_events = capture.events().len();
        project_secret(directory, revision, bundle, key);
        let failed = reload_event(&capture, previous_events, "reload_failed", detail).await;
        assert_eq!(failed.status, Some(StatusId::Failure));
        let message = failed.message.unwrap();
        assert!(message.contains(&format!("Application listener {}", fixture.address)));
        for line in key.lines().filter(|line| !line.is_empty()) {
            assert!(
                !message.contains(line),
                "TLS reload diagnostic contains private key material"
            );
        }
        assert_eq!(
            leaf(&connect(&fixture, fixture.tls.clone()).await),
            original.der()
        );
        fixture.routes.renew();
    }

    let previous_events = capture.events().len();
    project_secret(directory, "..replacement", &renewed_bundle, &renewed_key);
    let reloaded = reload_event(&capture, previous_events, "reloaded", "succeeded").await;
    assert_eq!(reloaded.status, Some(StatusId::Success));
    assert_eq!(
        leaf(&connect(&fixture, fixture.tls.clone()).await),
        renewed.der()
    );
    resume.notify_one();
    let remaining = tokio::time::timeout(IO_TIMEOUT, response.into_body().collect())
        .await
        .expect("stream did not finish after rotation")
        .unwrap()
        .to_bytes();
    assert_eq!(remaining, "after rotation");
    connection.abort();
}
