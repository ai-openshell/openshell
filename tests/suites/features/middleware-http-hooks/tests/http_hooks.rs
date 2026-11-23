// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP hooks against an environment with the content-guard service registered:
//! - `WHOLE_BODY` redacts and denies request and response bodies;
//! - a response stage inspects the body of a server that compresses, because
//!   OpenShell asks for an identity-coded response when the workload asks for
//!   gzip;
//! - DUPLEX carries a request body larger than any `WHOLE_BODY` limit;
//! - DUPLEX delivers server-sent events one by one;
//! - a preflight rejection never contacts the upstream;
//! - a policy that mixes HTTP hook versions on one destination, or in which
//!   the guard selects a `tls: skip` endpoint, is rejected at `policy set`.

use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use host_server_support::TEST_HOST as SANDBOX_HOST;
use serde_json::Value;
use testkit::{Context, ResultExt as _, YamlFile};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

const SENSITIVE_BODY: &str = "contains prototype-secret and internal-only";
const CLEAN_BODY: &str = "ordinary public text";
const PRIVATE_ALLOWED_IPS: &str = r#"        allowed_ips:
          - "10.0.0.0/8"
          - "172.0.0.0/8"
          - "192.168.0.0/16"
          - "fc00::/7""#;

fn main() -> std::process::ExitCode {
    testkit::main()
}

/// One request the upstream served.
struct ReceivedRequest {
    target: String,
    accept_encoding: Option<String>,
    body: Vec<u8>,
}

type Received = Arc<Mutex<Vec<ReceivedRequest>>>;

/// Minimal HTTP/1.1 upstream on the host. It accepts `Content-Length` and
/// chunked request bodies, and every response closes its connection.
///
/// - `POST /echo` returns the request body.
/// - `GET /sensitive` and `GET /clean` return fixed text.
/// - `GET /compressible` returns the `/sensitive` text, gzip-coded when the
///   request accepts gzip, as a typical server does.
/// - `GET /events` streams two server-sent events. It sends the second only
///   after `POST /ack`, or marks it `late` after a timeout, so a client that
///   acknowledges the first event proves it arrived on its own.
struct Upstream {
    port: u16,
    received: Received,
    task: JoinHandle<()>,
}

impl Upstream {
    async fn start() -> Self {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .expect("bind upstream");
        let port = listener.local_addr().expect("upstream address").port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let task_received = Arc::clone(&received);
        let acknowledged = Arc::new(Notify::new());
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let received = Arc::clone(&task_received);
                let acknowledged = Arc::clone(&acknowledged);
                tokio::spawn(async move {
                    let _ = serve_one(stream, received, acknowledged).await;
                });
            }
        });
        Self {
            port,
            received,
            task,
        }
    }

    fn targets(&self) -> Vec<String> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.target.clone())
            .collect()
    }

    fn bodies(&self, target: &str) -> Vec<Vec<u8>> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.target == target)
            .map(|request| request.body.clone())
            .collect()
    }

    fn accept_encodings(&self, target: &str) -> Vec<Option<String>> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.target == target)
            .map(|request| request.accept_encoding.clone())
            .collect()
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_request(
    stream: &mut BufReader<TcpStream>,
) -> std::io::Result<Option<ReceivedRequest>> {
    let mut request_line = String::new();
    if stream.read_line(&mut request_line).await? == 0 {
        return Ok(None);
    }
    let target = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    let mut length = 0;
    let mut chunked = false;
    let mut accept_encoding = None;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-length:") {
            length = value.trim().parse().unwrap_or(0);
        }
        if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
        }
        if let Some(value) = lower.strip_prefix("accept-encoding:") {
            accept_encoding = Some(value.trim().to_string());
        }
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            let mut size = String::new();
            stream.read_line(&mut size).await?;
            let size = usize::from_str_radix(size.trim().split(';').next().unwrap_or("0"), 16)
                .unwrap_or(0);
            if size == 0 {
                // Trailer section.
                loop {
                    let mut line = String::new();
                    stream.read_line(&mut line).await?;
                    if line.trim_end().is_empty() {
                        break;
                    }
                }
                break;
            }
            let mut chunk = vec![0; size + 2];
            stream.read_exact(&mut chunk).await?;
            body.extend_from_slice(&chunk[..size]);
        }
    } else {
        body.resize(length, 0);
        stream.read_exact(&mut body).await?;
    }
    Ok(Some(ReceivedRequest {
        target,
        accept_encoding,
        body,
    }))
}

fn accepts_gzip(accept_encoding: Option<&str>) -> bool {
    accept_encoding.is_some_and(|value| {
        value
            .split(',')
            .any(|coding| coding.split(';').next().unwrap_or_default().trim() == "gzip")
    })
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("gzip response body");
    encoder.finish().expect("finish gzip response body")
}

async fn serve_one(
    stream: TcpStream,
    received: Received,
    acknowledged: Arc<Notify>,
) -> std::io::Result<()> {
    let mut stream = BufReader::new(stream);
    let Some(request) = read_request(&mut stream).await? else {
        return Ok(());
    };
    let target = request.target.clone();
    let body = request.body.clone();
    let compress = target == "/compressible" && accepts_gzip(request.accept_encoding.as_deref());
    received.lock().unwrap().push(request);
    let mut stream = stream.into_inner();
    if target == "/events" {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
            .await?;
        write_chunk(&mut stream, b"data: one prototype-secret\n\n").await?;
        let second =
            match tokio::time::timeout(Duration::from_secs(20), acknowledged.notified()).await {
                Ok(()) => &b"data: two\n\n"[..],
                Err(_) => b"data: late\n\n",
            };
        write_chunk(&mut stream, second).await?;
        stream.write_all(b"0\r\n\r\n").await?;
        return stream.shutdown().await;
    }
    if target == "/ack" {
        acknowledged.notify_one();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await?;
        return stream.shutdown().await;
    }
    let (content_type, response_body) = match target.as_str() {
        "/echo" => ("application/octet-stream", body),
        "/sensitive" | "/compressible" => ("text/plain", SENSITIVE_BODY.as_bytes().to_vec()),
        _ => ("text/plain", CLEAN_BODY.as_bytes().to_vec()),
    };
    let (content_encoding, response_body) = if compress {
        ("Content-Encoding: gzip\r\n", gzip(&response_body))
    } else {
        ("", response_body)
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n{content_encoding}Content-Length: {}\r\nConnection: close\r\n\r\n",
        response_body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&response_body).await?;
    stream.shutdown().await
}

async fn write_chunk(stream: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    stream
        .write_all(format!("{:X}\r\n", data.len()).as_bytes())
        .await?;
    stream.write_all(data).await?;
    stream.write_all(b"\r\n").await?;
    stream.flush().await
}

struct PolicyCase<'a> {
    mode: &'a str,
    body_mode: &'a str,
    /// Port of a `tls: skip` endpoint the attachment also selects, which the
    /// gateway rejects.
    tls_skip_port: Option<u16>,
    /// Also attach `openshell/regex` (legacy HTTP hooks) to the same host.
    mixed: bool,
}

fn policy_yaml(registration: &str, upstream_port: u16, case: &PolicyCase<'_>) -> String {
    let replacement = if case.mode == "redact" {
        "      replacement: \"[FILTERED]\"\n"
    } else {
        ""
    };
    let tls_skip_endpoint = case.tls_skip_port.map_or_else(String::new, |port| {
        format!("      - host: {SANDBOX_HOST}\n        port: {port}\n        tls: skip\n{PRIVATE_ALLOWED_IPS}\n")
    });
    let regex = if case.mixed {
        r#"  regex-redactor:
    middleware: openshell/regex
    order: 20
    config:
      mode: redact
    endpoints:
      include: ["*.openshell.internal"]
"#
    } else {
        ""
    };
    format!(
        r#"version: 1

filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /app
    - /etc
    - /var/log
  read_write:
    - /sandbox
    - /tmp
    - /dev/null

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_middlewares:
  content-guard:
    name: Content guard
    middleware: {registration}
    order: 10
    config:
      mode: {mode}
      body_mode: {body_mode}
      terms:
        - prototype-secret
        - internal-only
{replacement}    on_error: fail_closed
    endpoints:
      include: ["{SANDBOX_HOST}"]
{regex}
network_policies:
  guard_upstream:
    name: guard_upstream
    endpoints:
      - host: {SANDBOX_HOST}
        port: {upstream_port}
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: POST
              path: /echo
          - allow:
              method: POST
              path: /ack
          - allow:
              method: GET
              path: /sensitive
          - allow:
              method: GET
              path: /clean
          - allow:
              method: GET
              path: /compressible
          - allow:
              method: GET
              path: /events
{PRIVATE_ALLOWED_IPS}
{tls_skip_endpoint}    binaries:
      - path: "/**"
"#,
        mode = case.mode,
        body_mode = case.body_mode,
    )
}

/// Upload size larger than any `WHOLE_BODY` limit (256 KiB), so only DUPLEX can
/// carry it.
const LARGE_UPLOAD_LINES: usize = 600;

fn workload_script(upstream_port: u16, case: &PolicyCase<'_>) -> String {
    format!(
        r#"
import gzip
import http.client
import json

HOST = "{SANDBOX_HOST}"
PORT = {upstream_port}
DUPLEX = {duplex}

def call(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=60)
    request_headers = {{"Content-Type": "application/octet-stream"}} if body is not None else {{}}
    request_headers.update(headers or {{}})
    conn.request(method, path, body=body, headers=request_headers)
    response = conn.getresponse()
    data = response.read()
    encoding = response.getheader("Content-Encoding", "")
    if encoding == "gzip":
        data = gzip.decompress(data)
    conn.close()
    return {{"status": response.status, "body": data.decode("latin-1"), "encoding": encoding}}

results = {{
    "echo_term": call("POST", "/echo", b'{{"note":"prototype-secret"}}'),
    "sensitive": call("GET", "/sensitive"),
    "clean": call("GET", "/clean"),
    "target_term": call("GET", "/clean?q=prototype-secret"),
    # Ask for gzip by default, as requests, httpx, and fetch do.
    "compressible": call("GET", "/compressible", headers={{"Accept-Encoding": "gzip, deflate"}}),
}}

if DUPLEX:
    upload = (b"x" * 1000 + b" prototype-secret\n") * {LARGE_UPLOAD_LINES}
    echoed = call("POST", "/echo", upload)
    expected = upload.replace(b"prototype-secret", b"[FILTERED]")
    results["large_upload"] = {{
        "status": echoed["status"],
        "sent_bytes": len(upload),
        "redacted": echoed["body"].encode("latin-1") == expected,
    }}

    conn = http.client.HTTPConnection(HOST, PORT, timeout=60)
    conn.request("GET", "/events")
    response = conn.getresponse()
    first = b""
    while not first.endswith(b"\n\n"):
        line = response.readline()
        if not line:
            break
        first += line
    acknowledged = call("POST", "/ack")
    rest = response.read()
    conn.close()
    results["events"] = {{
        "status": response.status,
        "first": first.decode("utf-8"),
        "ack": acknowledged["status"],
        "rest": rest.decode("utf-8"),
    }}

print(json.dumps(results, sort_keys=True))
"#,
        duplex = if case.body_mode == "duplex" {
            "True"
        } else {
            "False"
        },
    )
}

async fn run_workload(
    cx: &mut Context,
    registration: &str,
    upstream: &Upstream,
    case: &PolicyCase<'_>,
) -> testkit::Result<Value> {
    let script = workload_script(upstream.port, case);
    let sandbox = cx
        .cli_sandbox(match (case.body_mode, case.mode) {
            ("duplex", _) => "duplx",
            (_, "redact") => "redct",
            _ => "deny",
        })
        .image(testkit::python_image())
        .policy_yaml(policy_yaml(registration, upstream.port, case))
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;
    sandbox.run_python(&script, &[]).await?.last_json()
}

fn assert_response(result: &Value, name: &str, status: u64, body: &str) {
    assert_eq!(result[name]["status"], status, "{name}: {result}");
    assert_eq!(result[name]["body"], body, "{name}: {result}");
}

fn assert_platform_error(result: &Value, name: &str, status: u64, error: &str) -> Value {
    assert_eq!(result[name]["status"], status, "{name}: {result}");
    let body: Value = serde_json::from_str(result[name]["body"].as_str().unwrap_or_default())
        .unwrap_or_else(|_| panic!("{name} returns a JSON error: {result}"));
    assert_eq!(body["error"], error, "{name}: {body}");
    body
}

/// The registered guard inspects and transforms HTTP traffic in both body
/// modes, and the gateway rejects policies the guard cannot enforce.
#[testkit::test]
async fn http_hook_content_guard_runs_against_the_gateway_and_supervisor(
    cx: &mut Context,
) -> testkit::Result {
    let registration = middleware_support::content_guard_registration()?;
    let upstream = Upstream::start().await;

    // WHOLE_BODY redaction in both directions and a preflight rejection.
    let redact = run_workload(
        cx,
        &registration,
        &upstream,
        &PolicyCase {
            mode: "redact",
            body_mode: "whole_body",
            tls_skip_port: None,
            mixed: false,
        },
    )
    .await?;
    assert_response(&redact, "echo_term", 200, r#"{"note":"[FILTERED]"}"#);
    assert_response(
        &redact,
        "sensitive",
        200,
        "contains [FILTERED] and [FILTERED]",
    );
    assert_response(&redact, "clean", 200, CLEAN_BODY);
    // The workload asked for gzip. A response stage that may inspect bodies
    // makes OpenShell ask for identity instead, so the guard can redact.
    assert_response(
        &redact,
        "compressible",
        200,
        "contains [FILTERED] and [FILTERED]",
    );
    assert_eq!(redact["compressible"]["encoding"], "", "{redact}");
    let codings = upstream.accept_encodings("/compressible");
    assert!(
        !codings.is_empty()
            && codings
                .iter()
                .all(|coding| coding.as_deref() == Some("identity")),
        "OpenShell asks the upstream for an identity-coded response: {codings:?}"
    );
    assert!(
        upstream
            .bodies("/echo")
            .contains(&br#"{"note":"[FILTERED]"}"#.to_vec()),
        "the upstream receives the redacted body"
    );
    let rejected = assert_platform_error(&redact, "target_term", 403, "middleware_denied");
    assert_eq!(rejected["reason_code"], "content_match", "{rejected}");
    assert!(
        upstream
            .targets()
            .iter()
            .all(|target| !target.contains("prototype-secret")),
        "a preflight rejection never contacts the upstream"
    );

    // WHOLE_BODY denial in both directions.
    let echo_bodies_before = upstream.bodies("/echo").len();
    let deny = run_workload(
        cx,
        &registration,
        &upstream,
        &PolicyCase {
            mode: "deny",
            body_mode: "whole_body",
            tls_skip_port: None,
            mixed: false,
        },
    )
    .await?;
    for name in ["echo_term", "sensitive", "compressible"] {
        let body = assert_platform_error(&deny, name, 403, "middleware_denied");
        assert_eq!(body["reason_code"], "content_match", "{name}: {body}");
        assert!(!body.to_string().contains("prototype-secret"), "{body}");
    }
    assert_response(&deny, "clean", 200, CLEAN_BODY);
    assert_eq!(
        upstream.bodies("/echo").len(),
        echo_bodies_before,
        "a denied request body never reaches the upstream"
    );

    // DUPLEX: a large upload and server-sent events one by one.
    let stream = run_workload(
        cx,
        &registration,
        &upstream,
        &PolicyCase {
            mode: "redact",
            body_mode: "duplex",
            tls_skip_port: None,
            mixed: false,
        },
    )
    .await?;
    assert_response(&stream, "echo_term", 200, r#"{"note":"[FILTERED]"}"#);
    assert_eq!(stream["large_upload"]["status"], 200, "{stream}");
    assert_eq!(stream["large_upload"]["redacted"], true, "{stream}");
    let large = upstream
        .bodies("/echo")
        .into_iter()
        .max_by_key(Vec::len)
        .expect("the upstream received the large upload");
    assert!(
        large.len() > 256 * 1024,
        "the large upload exceeds every WHOLE_BODY limit"
    );
    assert!(!String::from_utf8_lossy(&large).contains("prototype-secret"));
    assert_eq!(stream["events"]["status"], 200, "{stream}");
    assert_eq!(
        stream["events"]["first"], "data: one [FILTERED]\n\n",
        "{stream}"
    );
    assert_eq!(stream["events"]["ack"], 204, "{stream}");
    assert_eq!(
        stream["events"]["rest"], "data: two\n\n",
        "the first event reached the sandbox before the second was sent: {stream}"
    );

    // A policy that runs both HTTP hook versions for one destination is rejected.
    let base = policy_yaml(
        &registration,
        upstream.port,
        &PolicyCase {
            mode: "redact",
            body_mode: "whole_body",
            tls_skip_port: None,
            mixed: false,
        },
    );
    let mixed = policy_yaml(
        &registration,
        upstream.port,
        &PolicyCase {
            mode: "redact",
            body_mode: "whole_body",
            tls_skip_port: None,
            mixed: true,
        },
    );
    let sandbox = cx
        .cli_sandbox("guard")
        .image(testkit::python_image())
        .policy_yaml(base)
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;
    assert_policy_rejected(
        cx,
        sandbox.name(),
        &mixed,
        "separate their endpoint selectors",
    )
    .await?;

    // The guard is fail-closed and cannot inspect a `tls: skip` tunnel, so a
    // policy in which it selects one is rejected.
    // The rejected policy is never used to connect; it only needs a
    // different endpoint port from the inspected endpoint.
    let skip_port = if upstream.port == 443 { 8443 } else { 443 };
    let tls_skip = policy_yaml(
        &registration,
        upstream.port,
        &PolicyCase {
            mode: "redact",
            body_mode: "whole_body",
            tls_skip_port: Some(skip_port),
            mixed: false,
        },
    );
    assert_policy_rejected(cx, sandbox.name(), &tls_skip, "tls: skip endpoint").await
}

async fn assert_policy_rejected(
    cx: &Context,
    sandbox: &str,
    policy: &str,
    reason: &str,
) -> testkit::Result {
    let file = YamlFile::new(policy)?;
    let output = cx
        .cli(["policy", "set", sandbox, "--policy", file.path()?])
        .await?
        .failure()
        .context("policy set should reject the middleware attachment")?;
    testkit::ensure!(
        output.report_text().contains(reason),
        "expected policy rejection containing {reason:?}:\nstdout: {}\nstderr: {}",
        output.stdout,
        output.stderr
    );
    Ok(())
}
