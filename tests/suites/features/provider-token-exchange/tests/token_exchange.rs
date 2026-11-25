// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider token grants: the gateway and the supervisor exchange SPIFFE
//! JWT-SVIDs at token endpoints the test runs, and the supervisor injects the
//! results into requests to a protected target.
//!
//! The gateway and supervisors fetch JWT-SVIDs from the environment's
//! Workload APIs ([`spiffe_support`]). The token endpoints and targets are
//! [`HttpRecorder`]s on the test host. The gateway and Podman's host-network
//! supervisors reach the token endpoints on loopback, which the token
//! endpoint transport policy allows over plain HTTP. Sandboxes reach the
//! targets through [`TEST_HOST`]. Tests never print the fixture tokens,
//! though none are real.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use host_server_support::{HttpRecorder, Request, Response, TEST_HOST};
use serde_json::json;
use spiffe_support::{Bundle, ISSUER, SUPERVISOR_SUBJECT};
use testkit::{Context, Error, Poll, Result, ResultExt as _, Sandbox, poll_until};

fn main() -> std::process::ExitCode {
    testkit::main()
}

/// How long the route servers wait for a request before closing the
/// connection.
const ROUTE_READ_TIMEOUT: Duration = Duration::from_secs(30);
const USER_SUBJECT_TOKEN: &str = "stored-user-token";
const INTERMEDIATE_TOKEN: &str = "intermediate-token";
const FINAL_ACCESS_TOKEN: &str = "final-access-token";
const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe";
const IDENTITY_AUDIENCE: &str = "identity-proxy";
const IDENTITY_JWT_AUDIENCE: &str = "https://identity.openshell-e2e.test";
const IDENTITY_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const SUBJECT_TOKEN_ENV: &str = "subject_token";

/// Two sandboxes, each with its own provider, request the same host and
/// port at the same time. Each request carries its provider's bearer token,
/// from a two-stage token exchange, and its own signed JWT-SVID, from a
/// client-credentials grant; the target checks both. Repeat requests use the
/// cached credentials. A failed grant returns 502 and sends the target no
/// bytes, and the other credential stays cached. No credential reaches the
/// workload.
#[testkit::test]
async fn independent_grants_across_sandboxes(cx: &mut Context) -> testkit::Result {
    let bundle = Arc::new(Bundle::from_env()?);
    let observations = Arc::new(GrantObservations::default());
    let token = HttpRecorder::serve({
        let observations = Arc::clone(&observations);
        move |request| exchange_token(request, &observations)
    })
    .await?;
    let identity = HttpRecorder::serve({
        let observations = Arc::clone(&observations);
        let bundle = Arc::clone(&bundle);
        move |request| issue_identity(request, &observations, &bundle)
    })
    .await?;
    let target = HttpRecorder::serve({
        let observations = Arc::clone(&observations);
        let bundle = Arc::clone(&bundle);
        move |request| protected_target(request, &observations, &bundle)
    })
    .await?;
    let target_port = target.port;

    let mut sandboxes = Vec::new();
    for instance in ["a", "b"] {
        let provider = cx.name(&format!("grants-{instance}"));
        let profile = grants_profile(&provider, token.port, identity.port, target_port, instance);
        let subject = format!("{USER_SUBJECT_TOKEN}-{instance}");
        cx.install_provider(&provider, &profile, &[(SUBJECT_TOKEN_ENV, &subject)])
            .await?;
        sandboxes.push(
            cx.sandbox(&format!("pte{instance}"))
                .image(testkit::python_image())
                .providers([provider.as_str()])
                .create_ready()
                .await?,
        );
    }
    let [a, b] = &sandboxes[..] else {
        unreachable!("two sandboxes")
    };

    let mut after_first = None;
    for round in ["first", "cached"] {
        let (from_a, from_b) = tokio::join!(
            probe(a, target_port, "/resource/a", false),
            probe(b, target_port, "/resource/b", false),
        );
        from_a.context(format!("the {round} request from sandbox A"))?;
        from_b.context(format!("the {round} request from sandbox B"))?;
        if round == "first" {
            let issued = observations.issued();
            testkit::ensure!(
                issued
                    .iter()
                    .all(|(service, identity)| *service > 0 && *identity > 0),
                "each provider did not acquire both credentials: {issued:?}"
            );
            after_first = Some(issued);
        }
    }
    testkit::ensure!(
        observations.target_rejected.load(Ordering::SeqCst) == 0,
        "the target rejected a request with mismatched or untrusted credentials, even if a retry then passed"
    );
    let issued = observations.issued();
    testkit::ensure!(
        Some(issued) == after_first,
        "repeat requests acquired credentials again instead of using the caches: {after_first:?} after the first round, {issued:?} after the cached round"
    );

    let target_bytes = target.received();
    // An audience override forces acquisition of only the failing credential;
    // the other stays cached from the successful requests.
    let (from_a, from_b) = tokio::join!(
        probe(a, target_port, "/deny-service/a", true),
        probe(b, target_port, "/deny-identity/b", true),
    );
    from_a.context("the request from sandbox A whose service grant fails")?;
    from_b.context("the request from sandbox B whose identity grant fails")?;
    testkit::ensure!(
        observations.service_denied.load(Ordering::SeqCst) > 0,
        "the token endpoint saw no request for the denied service audience"
    );
    testkit::ensure!(
        observations.identity_denied.load(Ordering::SeqCst) > 0,
        "the identity endpoint saw no request for the denied identity audience"
    );
    testkit::ensure!(
        target.received() == target_bytes,
        "a failed grant forwarded request bytes to the target"
    );
    Ok(())
}

/// A sandbox with two providers, each bound to its own path, reaches one
/// target. A transient grant failure on B returns 502 with a request ID the
/// token endpoint also saw, closes the tunnel, and shows in the sandbox's
/// status as a retryable failure. Then requests to A, B and A on one client
/// connection each carry only their own route's token, over one upstream
/// connection, and the success clears the reported failure. The failed
/// grant sends the target nothing.
#[testkit::test]
async fn routes_recover_and_select_a_b_a_on_one_connection(cx: &mut Context) -> testkit::Result {
    let grants = Arc::new(RouteGrantState::default());
    let token = HttpRecorder::builder()
        .read_timeout(ROUTE_READ_TIMEOUT)
        .serve({
            let grants = Arc::clone(&grants);
            move |request| route_token(request, &grants)
        })
        .await?;
    let target = HttpRecorder::builder()
        .read_timeout(ROUTE_READ_TIMEOUT)
        .serve(route_target)
        .await?;
    let target_port = target.port;

    let mut providers = Vec::new();
    for route in ["a", "b"] {
        let provider = cx.name(&format!("route-{route}"));
        let profile = route_profile(&provider, token.port, target_port, route);
        let stored = format!("stored-{route}");
        cx.install_provider(&provider, &profile, &[(SUBJECT_TOKEN_ENV, &stored)])
            .await?;
        providers.push(provider);
    }
    let sandbox = cx
        .sandbox("pter")
        .image(testkit::python_image())
        .providers(providers.iter().map(String::as_str))
        .create_ready()
        .await?;

    grants.fail_next_b.store(true, Ordering::SeqCst);
    // The supervisor mediates direct workload connections as CONNECT.
    // HTTPConnection keeps one client socket for the A/B/A run.
    let failure_script = format!(
        r#"import http.client, uuid
first = http.client.HTTPConnection({TEST_HOST:?}, {target_port}, timeout=10)
first.request('GET', '/b/failure', headers={{'Authorization': 'Bearer stale-value'}})
failed = first.getresponse()
failed.read()
assert failed.status == 502, 'the controlled grant failure must return 502'
request_id = failed.getheader('x-openshell-request-id', '')
assert str(uuid.UUID(request_id)) == request_id, 'the refusal must carry a canonical request ID'
print('failed-request-id=' + request_id)
assert failed.will_close, 'the failed tunnel must close'
first.close()
"#
    );
    let recovery_script = format!(
        r#"import http.client
recovered = http.client.HTTPConnection({TEST_HOST:?}, {target_port}, timeout=10)
connection = None
for path in ['/a/first', '/b/second', '/a/third']:
    recovered.request('GET', path, headers={{'Authorization': 'Bearer stale-value'}})
    if connection is None:
        connection = recovered.sock
    assert recovered.sock is connection, 'client connection was replaced'
    response = recovered.getresponse()
    response.read()
    assert response.status == 200, 'upstream rejected the selected credential'
    assert recovered.sock is connection and connection.fileno() >= 0, 'keepalive connection closed'
recovered.close()
print('route-recovery-a-b-a-ok')
"#
    );

    let failed = sandbox.run_python(&failure_script, &[]).await?;
    let request_id = failed
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("failed-request-id="))
        .ok_or_else(|| Error::msg("the workload did not print the refusal's request ID"))?
        .to_string();
    // An authorized reader sees the cause of the refused grant.
    let reported = wait_for_grant_failure(&sandbox, true).await?;
    let recovered = sandbox.run_python(&recovery_script, &[]).await?;
    testkit::ensure!(
        recovered.stdout.contains("route-recovery-a-b-a-ok"),
        "the A/B/A requests did not finish: {}",
        recovered.stdout
    );
    // The matching grant's later success clears it.
    wait_for_grant_failure(&sandbox, false).await?;
    sandbox.delete().await?;
    sandbox.wait_absent(Duration::from_secs(60)).await?;
    // Only EOF on every connection proves the byte count includes all that
    // reached the target.
    target
        .wait_closed(Duration::from_secs(35))
        .await
        .context("the route target saw EOF on every accepted connection")?;

    testkit::ensure!(
        grants.failed_request_id.lock().expect("lock").as_deref() == Some(request_id.as_str()),
        "the token endpoint and the refused response named different exchanges"
    );
    let expected_failure = [
        ("request_id", json!(request_id)),
        ("code", json!("unavailable")),
        ("recovery_action", json!("retry")),
        ("stage", json!("token_endpoint")),
        ("upstream_http_status", json!(503)),
        ("provider", json!(providers[1])),
        ("credential_key", json!("access_token")),
    ];
    testkit::ensure!(
        reported["destination_port"] == json!(target_port),
        "the reported failure names destination port {}, not {target_port}",
        reported["destination_port"]
    );
    for (key, expected) in expected_failure {
        testkit::ensure!(
            reported["failure"][key] == expected,
            "the reported failure's {key} is {}, not {expected}",
            reported["failure"][key]
        );
    }

    let requests = target.requests();
    let summary: Vec<(usize, &str)> = requests
        .iter()
        .map(|request| (request.connection, request.path()))
        .collect();
    testkit::ensure!(
        requests.len() == 3,
        "the target saw {summary:?}; the failed grant must not reach it"
    );
    testkit::ensure!(
        target.received() == requests.iter().map(|request| request.size).sum::<usize>(),
        "part of the failed request reached the target"
    );
    for ((request, path), token) in requests
        .iter()
        .zip(["/a/first", "/b/second", "/a/third"])
        .zip(["Bearer final-a", "Bearer final-b", "Bearer final-a"])
    {
        testkit::ensure!(
            request.path() == path && request.connection == requests[0].connection,
            "the target saw {summary:?}; expected the A/B/A paths on one upstream connection"
        );
        testkit::ensure!(
            request.headers("authorization") == [token],
            "{path} did not carry exactly its own route's token"
        );
    }
    let exchanges = grants.supervisor_requests.lock().expect("lock").clone();
    testkit::ensure!(
        exchanges == ["b", "a", "b"],
        "the supervisor exchanged tokens for routes {exchanges:?}; expected B (failed), A, B and A from its cache"
    );
    Ok(())
}

#[derive(Default)]
struct GrantObservations {
    service_issued: [AtomicUsize; 2],
    identity_issued: [AtomicUsize; 2],
    service_denied: AtomicUsize,
    identity_denied: AtomicUsize,
    target_rejected: AtomicUsize,
}

impl GrantObservations {
    fn issued(&self) -> [(usize, usize); 2] {
        std::array::from_fn(|index| {
            (
                self.service_issued[index].load(Ordering::SeqCst),
                self.identity_issued[index].load(Ordering::SeqCst),
            )
        })
    }
}

/// The gateway's and the supervisor's token exchanges. The gateway trades
/// the stored subject token for an intermediate token addressed to the
/// supervisor's SPIFFE ID; the supervisor trades that for the final token.
fn exchange_token(request: &Request, observations: &GrantObservations) -> Response {
    let form = token_form(request);
    let field = |name: &str| form.get(name).map_or("", String::as_str);
    let valid = is_post(request, "/token")
        && field("grant_type") == "urn:ietf:params:oauth:grant-type:token-exchange"
        && field("client_assertion_type") == CLIENT_ASSERTION_TYPE
        && field("subject_token_type") == TOKEN_TYPE_ACCESS_TOKEN
        && field("requested_token_type") == TOKEN_TYPE_ACCESS_TOKEN
        && !field("client_assertion").is_empty();
    let mut access_token = None;
    for (index, instance) in ["a", "b"].into_iter().enumerate() {
        if !valid {
            break;
        }
        if field("subject_token") == format!("{USER_SUBJECT_TOKEN}-{instance}")
            && field("audience") == SUPERVISOR_SUBJECT
            && field("scope").is_empty()
        {
            access_token = Some(format!("{INTERMEDIATE_TOKEN}-{instance}"));
        } else if field("subject_token") == format!("{INTERMEDIATE_TOKEN}-{instance}")
            && field("scope") == "service.read"
        {
            if field("audience") == format!("service-{instance}") {
                observations.service_issued[index].fetch_add(1, Ordering::SeqCst);
                access_token = Some(format!("{FINAL_ACCESS_TOKEN}-{instance}"));
            } else if field("audience") == format!("denied-service-{instance}") {
                observations.service_denied.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    token_response(access_token.as_deref(), 600)
}

/// A client-credentials grant that checks the supervisor's JWT-SVID and
/// returns it as the access token. No new grant type or sandbox-visible
/// credential is needed to exercise custom-header injection.
fn issue_identity(
    request: &Request,
    observations: &GrantObservations,
    bundle: &Bundle,
) -> Response {
    let form = token_form(request);
    let field = |name: &str| form.get(name).map_or("", String::as_str);
    let mut access_token = None;
    for (index, instance) in ["a", "b"].into_iter().enumerate() {
        let valid = is_post(request, "/identity-token")
            && field("grant_type") == "client_credentials"
            && field("client_assertion_type") == IDENTITY_ASSERTION_TYPE
            && field("scope") == "identity.read"
            && bundle.verify_supervisor_svid(
                field("client_assertion"),
                &identity_jwt_audience(instance),
            );
        if valid && field("audience") == format!("{IDENTITY_AUDIENCE}-{instance}") {
            observations.identity_issued[index].fetch_add(1, Ordering::SeqCst);
            access_token = Some(field("client_assertion"));
        } else if valid && field("audience") == format!("denied-identity-{instance}") {
            observations.identity_denied.fetch_add(1, Ordering::SeqCst);
        }
    }
    token_response(access_token, 900)
}

/// Accepts `GET /resource/<instance>` only with exactly one bearer token and
/// one JWT-SVID, both for that instance.
fn protected_target(
    request: &Request,
    observations: &GrantObservations,
    bundle: &Bundle,
) -> Response {
    let bearer = request.headers("authorization");
    let identity = request.headers("x-workload-jwt");
    let ok = ["a", "b"].into_iter().any(|instance| {
        request.method() == "GET"
            && request.path() == format!("/resource/{instance}")
            && bearer == [format!("Bearer {FINAL_ACCESS_TOKEN}-{instance}")]
            && identity.len() == 1
            && bundle.verify_supervisor_svid(&identity[0], &identity_jwt_audience(instance))
    });
    if ok {
        Response::text("independent-grants-ok")
    } else {
        // Keep the rejection even if the workload retries and a later
        // request gets the right credentials.
        observations.target_rejected.fetch_add(1, Ordering::SeqCst);
        Response::text("credential-verification-failed").status(401)
    }
}

fn identity_jwt_audience(instance: &str) -> String {
    format!("{IDENTITY_JWT_AUDIENCE}/{instance}")
}

/// Request `path` from the target with agent-supplied credentials the
/// supervisor must replace, and fail if any credential reaches the workload.
/// `expect_denied` expects the supervisor's 502 refusal with a request ID.
/// Retries while the exec fails, as when a grant is still settling.
async fn probe(sandbox: &Sandbox, target_port: u16, path: &str, expect_denied: bool) -> Result {
    let url = format!("http://{TEST_HOST}:{target_port}{path}");
    let expect_denied_python = if expect_denied { "True" } else { "False" };
    let expected = if expect_denied {
        "grant-denied"
    } else {
        "independent-grants-ok"
    };
    // The script prints fixed markers only, so its output never holds a
    // credential.
    let script = format!(
        r#"import base64, json, os, re, urllib.error, urllib.request, uuid

def contains_credential(value):
    if any(marker in value for marker in (
        "stored-user-token", "intermediate-token", "final-access-token", "openshell:resolve:"
    )):
        return True
    for token in re.findall(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", value):
        try:
            payload = token.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            if claims.get("iss") == "{ISSUER}":
                return True
        except (ValueError, UnicodeError, AttributeError):
            pass
    return False

if any(contains_credential(value) for value in os.environ.values()):
    raise SystemExit("provider credential material reached the workload environment")
request = urllib.request.Request({url:?}, headers={{
    "Authorization": "Bearer agent-supplied",
    "X-Workload-Jwt": "agent-supplied",
}})
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read().decode()
    if contains_credential(body):
        raise SystemExit("provider credential material reached the workload response")
    if {expect_denied_python}:
        raise SystemExit("failed grant unexpectedly reached the target")
    print(body)
except urllib.error.HTTPError as error:
    body = error.read().decode()
    if contains_credential(body):
        raise SystemExit("provider credential material reached the workload error")
    if not {expect_denied_python} or error.code != 502:
        raise SystemExit("unexpected HTTP status " + str(error.code))
    # The refusal names the exchange with an opaque ID and nothing else.
    request_id = error.headers.get("x-openshell-request-id", "")
    if str(uuid.UUID(request_id)) != request_id:
        raise SystemExit("refusal did not carry a canonical request ID")
    print("grant-denied")
"#
    );
    let output = sandbox
        .poll_exec(
            &format!("{path} to answer from sandbox {}", sandbox.name()),
            Duration::from_secs(20),
            ["python3", "-c", &script],
            |output| output.exit_code == 0,
        )
        .await?;
    testkit::ensure!(
        output.stdout.trim() == expected,
        "{path} from sandbox {} printed {:?}, not {expected}",
        sandbox.name(),
        output.stdout.trim()
    );
    Ok(())
}

/// A profile with two grants for one request: a token-exchange bearer token
/// and a client-credentials JWT-SVID header. Each has a path whose audience
/// the token endpoints deny.
fn grants_profile(
    profile_type: &str,
    token_port: u16,
    identity_port: u16,
    target_port: u16,
    instance: &str,
) -> String {
    let token_endpoint = format!("http://127.0.0.1:{token_port}/token");
    let identity_jwt_audience = identity_jwt_audience(instance);
    format!(
        r"id: {profile_type}
display_name: Token exchange test
description: Independent bearer and JWT-SVID grants for one request
category: other
credentials:
  - name: subject_token
    description: Stored user subject token
    required: true
  - name: access_token
    description: Access token obtained through token exchange
    required: false
    auth_style: bearer
    header_name: Authorization
    token_grant:
      grant_type: token_exchange
      token_endpoint: {token_endpoint}
      audience: service-{instance}
      scopes: [service.read]
      jwt_svid_audience: {token_endpoint}
      client_assertion_type: {CLIENT_ASSERTION_TYPE}
      requested_token_type: {TOKEN_TYPE_ACCESS_TOKEN}
      cache_ttl_seconds: 300
      audience_overrides:
        - path: /deny-service/{instance}
          audience: denied-service-{instance}
      subject_token:
        source: provider_credential
        credential: subject_token
        subject_token_type: {TOKEN_TYPE_ACCESS_TOKEN}
  - name: workload_identity
    description: Signed workload identity for the identity proxy
    required: false
    auth_style: header
    header_name: X-Workload-Jwt
    token_grant:
      grant_type: client_credentials
      token_endpoint: http://127.0.0.1:{identity_port}/identity-token
      audience: {IDENTITY_AUDIENCE}-{instance}
      scopes: [identity.read]
      jwt_svid_audience: {identity_jwt_audience}
      client_assertion_type: {IDENTITY_ASSERTION_TYPE}
      cache_ttl_seconds: 600
      audience_overrides:
        - path: /deny-identity/{instance}
          audience: denied-identity-{instance}
{}",
        endpoints(target_port, "/**")
    )
}

/// A profile with one token-exchange bearer grant bound to `/<route>/**`.
/// Each route has its own audience, so the token endpoint can tell which
/// endpoint's grant the supervisor selected.
fn route_profile(profile_type: &str, token_port: u16, target_port: u16, route: &str) -> String {
    let token_endpoint = format!("http://127.0.0.1:{token_port}/token");
    format!(
        r"id: {profile_type}
display_name: Token exchange route test
description: Route-bound bearer grant
category: other
credentials:
  - name: subject_token
    description: Stored user subject token
    required: true
  - name: access_token
    description: Access token obtained through token exchange
    required: false
    auth_style: bearer
    header_name: Authorization
    token_grant:
      grant_type: token_exchange
      token_endpoint: {token_endpoint}
      audience: audience-{route}
      jwt_svid_audience: {token_endpoint}
      client_assertion_type: {CLIENT_ASSERTION_TYPE}
      requested_token_type: {TOKEN_TYPE_ACCESS_TOKEN}
      cache_ttl_seconds: 300
      subject_token:
        source: provider_credential
        credential: subject_token
        subject_token_type: {TOKEN_TYPE_ACCESS_TOKEN}
{}",
        endpoints(target_port, &format!("/{route}/**"))
    )
}

fn endpoints(target_port: u16, path: &str) -> String {
    format!(
        r"endpoints:
  - host: {TEST_HOST}
    port: {target_port}
    path: {path}
    protocol: rest
    access: read-write
    enforcement: enforce
    allowed_ips:
      - 10.0.0.0/8
      - 169.254.0.0/16
      - 172.0.0.0/8
      - 192.168.0.0/16
binaries:
  - /**
"
    )
}

/// Poll the sandbox's status until its last token-grant failure is present
/// or absent, and return it.
async fn wait_for_grant_failure(sandbox: &Sandbox, present: bool) -> Result<serde_json::Value> {
    let what = if present {
        "to report a token-grant failure"
    } else {
        "to clear its token-grant failure"
    };
    poll_until(
        &format!("sandbox {} {what}", sandbox.name()),
        Duration::from_secs(30),
        Duration::from_secs(1),
        async || {
            let failure = sandbox.get_json().await?["last_token_grant_failure"].clone();
            Ok(if failure.is_null() == present {
                Poll::Pending(format!("last_token_grant_failure is {failure}"))
            } else {
                Poll::Ready(failure)
            })
        },
    )
    .await
}

#[derive(Default)]
struct RouteGrantState {
    fail_next_b: AtomicBool,
    supervisor_requests: Mutex<Vec<String>>,
    failed_request_id: Mutex<Option<String>>,
}

/// The route grants' token endpoint. It records each supervisor exchange's
/// route, and fails the next one for B with a 503 when `fail_next_b` is set.
fn route_token(request: &Request, state: &RouteGrantState) -> Response {
    let form = token_form(request);
    let field = |name: &str| form.get(name).map_or("", String::as_str);
    let subject = field("subject_token");
    let route = match subject {
        "stored-a" | "intermediate-a" => "a",
        "stored-b" | "intermediate-b" => "b",
        _ => "",
    };
    let supervisor = subject.starts_with("intermediate-");
    // The gateway's exchange targets the supervisor's SPIFFE ID; the
    // supervisor's targets the route's audience.
    let valid = !route.is_empty()
        && is_post(request, "/token")
        && !field("client_assertion").is_empty()
        && !field("audience").is_empty()
        && (!supervisor || field("audience") == format!("audience-{route}"));
    let fail = if valid && supervisor {
        state
            .supervisor_requests
            .lock()
            .expect("lock")
            .push(route.to_owned());
        route == "b" && state.fail_next_b.swap(false, Ordering::SeqCst)
    } else {
        false
    };
    if fail {
        *state.failed_request_id.lock().expect("lock") = request.header("x-openshell-request-id");
        Response::json(&json!({"error": "temporary_failure"})).status(503)
    } else if valid {
        let stage = if supervisor { "final" } else { "intermediate" };
        Response::json(
            &json!({"access_token": format!("{stage}-{route}"), "token_type": "Bearer", "expires_in": 300}),
        )
    } else {
        Response::json(&json!({"error": "unexpected_route_exchange"})).status(400)
    }
}

/// The route grants' target. It keeps each connection open across requests,
/// and accepts a request only with exactly its route's token.
fn route_target(request: &Request) -> Response {
    let expected = if request.path().starts_with("/a/") {
        "Bearer final-a"
    } else {
        "Bearer final-b"
    };
    let status = if request.headers("authorization") == [expected] {
        200
    } else {
        401
    };
    Response::new(status).keep_alive()
}

fn is_post(request: &Request, path: &str) -> bool {
    request.method() == "POST" && request.path() == path
}

fn token_form(request: &Request) -> HashMap<String, String> {
    url::form_urlencoded::parse(request.body.as_bytes())
        .into_owned()
        .collect()
}

fn token_response(access_token: Option<&str>, ttl: u64) -> Response {
    match access_token {
        Some(access_token) => Response::json(
            &json!({"access_token": access_token, "token_type": "Bearer", "expires_in": ttl}),
        ),
        None => Response::json(&json!({"error": "invalid_grant"})).status(400),
    }
}
