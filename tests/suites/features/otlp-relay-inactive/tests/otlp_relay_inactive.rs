// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The supervisor's agent trace relay when the gateway configures no
//! collector. The test needs a gateway without OTLP export or the agent trace
//! relay, such as an environment's default gateway. `features/otlp-relay`
//! tests the relay with a collector.

use testkit::Context;

fn main() -> std::process::ExitCode {
    testkit::main()
}

/// Reports whether an endpoint was injected, then posts to the relay address
/// directly and reports the failure class instead of raising.
const INERT_SCRIPT: &str = r#"
import http.client, os
print("ENDPOINT", os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "unset"))
connection = http.client.HTTPConnection("192.0.0.8", 4318, timeout=3)
try:
    connection.request("POST", "/v1/traces", body=b"", headers={"Content-Type": "application/x-protobuf"})
    print("STATUS", connection.getresponse().status)
except TimeoutError:
    print("ERROR Timeout")
except OSError:
    print("ERROR ConnectionError")
"#;

/// Without a collector, the supervisor injects no relay endpoint, nothing
/// listens on the relay address, and the supervisor logs that the relay is
/// inactive.
#[testkit::test]
async fn relay_is_inert_without_collector(cx: &mut Context) -> testkit::Result {
    testkit::ensure!(
        std::env::var_os("OPENSHELL_TEST_OTLP_ENDPOINT").is_none(),
        "OPENSHELL_TEST_OTLP_ENDPOINT is set; this suite needs a gateway without an OTLP collector"
    );
    let builder = cx
        .cli_sandbox("otlpi")
        .image(testkit::python_image())
        .args(["--no-auto-providers"])
        .command(["python3", "-c", INERT_SCRIPT]);
    let name = builder.name().to_string();
    let run = builder.run().await?.success()?;
    let output = format!("{}{}", run.stdout, run.stderr);
    testkit::ensure!(
        output.contains("ENDPOINT unset"),
        "a relay endpoint was injected while the relay is inactive:\n{output}"
    );
    testkit::ensure!(
        output.contains("ERROR ConnectionError"),
        "the export did not fail with a connection error:\n{output}"
    );

    let sandbox = cx.adopt(&name).await?;
    let logs = sandbox
        .logs_until("that the OTLP agent trace relay is inactive", |logs| {
            logs.contains("OTLP agent trace relay inactive")
        })
        .await?;
    testkit::ensure!(
        !logs.contains("OTLP agent trace relay enabled"),
        "the supervisor also reported the relay enabled:\n{logs}"
    );
    Ok(())
}
