// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contract fixture shared by Vault and `OpenBao`, exercised through real sandboxes.

use super::*;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::time::Instant;

const LOGIN_LEASE_SECONDS: u64 = 40;

#[derive(Default)]
struct LoginState {
    issued: AtomicUsize,
    targets: AtomicUsize,
    denied: AtomicBool,
    invalid_lease: AtomicBool,
    wrong_audience: AtomicBool,
    tokens: Mutex<HashMap<String, Instant>>,
}

fn fixture_response(request: &str, issuer: bool, state: &LoginState) -> (&'static str, String) {
    if issuer {
        let payload: serde_json::Value = request
            .split_once("\r\n\r\n")
            .and_then(|(_, body)| serde_json::from_str(body).ok())
            .unwrap_or_default();
        let namespace = request
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("x-vault-namespace"))
            .map(|(_, value)| value.trim());
        let valid = request.starts_with("POST /v1/auth/sandbox-jwt/login ")
            && payload["role"] == "sandbox-api"
            && namespace == Some("team/project")
            && payload["jwt"].as_str().is_some_and(|jwt| {
                verifies_jwt_svid(
                    jwt,
                    if state.wrong_audience.load(Ordering::SeqCst) {
                        "b"
                    } else {
                        "a"
                    },
                )
            });
        if valid && !state.denied.load(Ordering::SeqCst) {
            let count = state.issued.fetch_add(1, Ordering::SeqCst);
            let token = format!("inert-vault-token-{count}");
            state.tokens.lock().unwrap().insert(
                token.clone(),
                Instant::now() + Duration::from_secs(LOGIN_LEASE_SECONDS),
            );
            let lease = if state.invalid_lease.load(Ordering::SeqCst) {
                0
            } else {
                LOGIN_LEASE_SECONDS
            };
            (
                "200 OK",
                json!({"auth":{"client_token":token,"lease_duration":lease,"renewable":true}})
                    .to_string(),
            )
        } else {
            // An issuer may echo the assertion; OpenShell must discard it.
            (
                "403 Forbidden",
                json!({"errors":[payload["jwt"]]}).to_string(),
            )
        }
    } else {
        state.targets.fetch_add(1, Ordering::SeqCst);
        let tokens = state.tokens.lock().unwrap();
        let token = request
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("x-vault-token"))
            .map(|(_, value)| value.trim());
        let valid = token
            .and_then(|token| tokens.get(token))
            .is_some_and(|expiry| *expiry > Instant::now());
        if valid {
            ("200 OK", "vault-login-ok".to_owned())
        } else {
            ("401 Unauthorized", "invalid-credential".to_owned())
        }
    }
}

async fn serve_tls_fixture(port: u16, issuer: bool, state: Arc<LoginState>) -> FixtureHandle {
    let ca = PathBuf::from(
        std::env::var("OPENSHELL_E2E_ADDITIONAL_CA_CERT").expect("additional CA fixture"),
    );
    let directory = ca.parent().unwrap();
    let certificates = CertificateDer::pem_file_iter(directory.join("server.crt"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(directory.join("server.key")).unwrap();
    let tls = openshell_crypto::tls::server_builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
        .await
        .unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let _ = stream.set_nodelay(true);
            let acceptor = acceptor.clone();
            let state = state.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let Some(request) = read_http_request(&mut stream).await else {
                    return;
                };
                let (status, body) = fixture_response(&request, issuer, &state);
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    FixtureHandle { task }
}

async fn call(sandbox: &SandboxGuard, port: u16, denied: bool) -> Result<String, String> {
    let script = format!(
        r"import os, urllib.request, urllib.error
assert not any('inert-vault-token-' in value or value.startswith('eyJ') for value in os.environ.values())
request = urllib.request.Request('https://host.openshell.internal:{port}/resource', headers={{'X-Vault-Token':'workload-supplied'}})
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read().decode()
    assert not {denied} and body == 'vault-login-ok'
    print(body)
except urllib.error.HTTPError as error:
    body = error.read().decode()
    assert {denied} and error.code == 502
    assert 'inert-vault-token-' not in body and 'eyJ' not in body
    print('grant-denied')
",
        denied = if denied { "True" } else { "False" }
    );
    exec_within(sandbox, &script).await
}

async fn blocked_call(sandbox: &SandboxGuard, port: u16, path: &str) -> Result<String, String> {
    exec_within(
        sandbox,
        &format!(
            r"import urllib.request, urllib.error
try:
    urllib.request.urlopen('https://host.openshell.internal:{port}{path}', timeout=10)
except (urllib.error.HTTPError, urllib.error.URLError):
    print('destination-blocked')
else:
    raise RuntimeError('unauthorized request succeeded')
"
        ),
    )
    .await
}

#[tokio::test]
async fn podman_vault_jwt_login_isolates_sandboxes_refreshes_and_fails_closed() {
    let _guard = SPIFFE_FIXTURE_LOCK.lock().await;
    assert!(
        std::env::var_os("OPENSHELL_E2E_ADDITIONAL_CA_CERT").is_some(),
        "run the provider_token_exchange Podman lane with OPENSHELL_E2E_ADDITIONAL_CA=1"
    );
    let socket = PathBuf::from(std::env::var("OPENSHELL_E2E_PROVIDER_SPIFFE_SOCKET").unwrap());
    let mut identity = Some(
        start_spiffe_workload_api(
            &socket,
            &format!("spiffe://{TRUST_DOMAIN}/openshell/sandbox/e2e"),
        )
        .await,
    );
    let issuer_port = find_free_port();
    let target_port = find_free_port();
    let state = Arc::new(LoginState::default());
    let issuer = serve_tls_fixture(issuer_port, true, state.clone()).await;
    let target = serve_tls_fixture(target_port, false, state.clone()).await;
    let name = format!("vault-login-{}", std::process::id());
    let mut profile = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
    write!(
        profile,
        r"id: {name}
display_name: Vault JWT Login
credentials:
  - name: client_token
    auth_style: header
    header_name: X-Vault-Token
    token_grant:
      grant_type: vault_jwt_login
      token_endpoint: https://host.openshell.internal:{issuer_port}/v1/auth/sandbox-jwt/login
      jwt_svid_audience: {IDENTITY_JWT_AUDIENCE}/a
      jwt_login_role: sandbox-api
      jwt_login_namespace: team/project
      cache_ttl_seconds: 600
endpoints:
  - host: host.openshell.internal
    port: {target_port}
    path: /resource
    protocol: rest
    access: read-write
    allowed_ips: [10.0.0.0/8, 169.254.0.0/16, 172.0.0.0/8, 192.168.0.0/16]
binaries:
  - /**
"
    )
    .unwrap();
    profile.flush().unwrap();
    run_cli(&["profile", "import", "-f", profile.path().to_str().unwrap()])
        .await
        .unwrap();
    run_cli(&[
        "provider",
        "create",
        "--name",
        &name,
        "--type",
        &name,
        "--runtime-credentials",
    ])
    .await
    .unwrap();
    let mut a = SandboxGuard::create_keep_with_args(
        &["--provider", &name],
        &["sh", "-lc", &sandbox_script()],
        "token-server-ready",
    )
    .await
    .unwrap();
    let mut b = SandboxGuard::create_keep_with_args(
        &["--provider", &name],
        &["sh", "-lc", &sandbox_script()],
        "token-server-ready",
    )
    .await
    .unwrap();
    let mut unauthorized = SandboxGuard::create_keep_with_args(
        &[],
        &["sh", "-lc", &sandbox_script()],
        "token-server-ready",
    )
    .await
    .unwrap();
    let result: Result<(), String> = async {
        call(&a, target_port, false).await?;
        call(&b, target_port, false).await?;
        if state.issued.load(Ordering::SeqCst) != 2 {
            return Err("same provider must have separate sandbox caches".into());
        }
        call(&a, target_port, false).await?;
        if state.issued.load(Ordering::SeqCst) != 2 {
            return Err("cache miss on immediate repeat".into());
        }
        let before = state.targets.load(Ordering::SeqCst);
        blocked_call(&a, target_port, "/unmatched").await?;
        blocked_call(&unauthorized, target_port, "/resource").await?;
        if state.targets.load(Ordering::SeqCst) != before
            || state.issued.load(Ordering::SeqCst) != 2
        {
            return Err("unauthorized sandbox or unmatched destination borrowed a grant".into());
        }
        tokio::time::sleep(Duration::from_millis(10_100)).await;
        call(&a, target_port, false).await?;
        if state.issued.load(Ordering::SeqCst) != 3 {
            return Err("expired cache did not reacquire".into());
        }
        tokio::time::sleep(Duration::from_millis(10_100)).await;
        let before = state.targets.load(Ordering::SeqCst);
        state.invalid_lease.store(true, Ordering::SeqCst);
        call(&a, target_port, true).await?;
        state.invalid_lease.store(false, Ordering::SeqCst);
        state.denied.store(true, Ordering::SeqCst);
        call(&a, target_port, true).await?;
        state.denied.store(false, Ordering::SeqCst);
        state.wrong_audience.store(true, Ordering::SeqCst);
        call(&a, target_port, true).await?;
        state.wrong_audience.store(false, Ordering::SeqCst);
        identity.take().unwrap().shutdown().await;
        identity = Some(
            start_spiffe_workload_api(
                &socket,
                &format!("spiffe://{TRUST_DOMAIN}/openshell/sandbox/unauthorized"),
            )
            .await,
        );
        call(&a, target_port, true).await?;
        if state.targets.load(Ordering::SeqCst) != before {
            return Err("failed login sent a target request".into());
        }
        Ok(())
    }
    .await;
    a.cleanup().await;
    b.cleanup().await;
    unauthorized.cleanup().await;
    run_cli_ignore_error(&["provider", "delete", &name, "--yes"]).await;
    run_cli_ignore_error(&["profile", "delete", &name, "--yes"]).await;
    target.shutdown().await;
    issuer.shutdown().await;
    identity.unwrap().shutdown().await;
    result.expect("Vault-compatible JWT login contract");
}
