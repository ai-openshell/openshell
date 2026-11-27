// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy enforcement inside the sandbox: the filesystem rules Landlock
//! applies to exec'd processes, and connections the network policy doesn't
//! allow.
//!
//! Ported from `e2e/python/test_sandbox_landlock.py`,
//! `e2e/python/test_sandbox_policy.py` and the Landlock part of
//! `e2e/python/test_sandbox_venv.py`. Which user exec'd processes run as
//! isn't checked here: Docker and Podman take it from the policy, but
//! Kubernetes and the VM driver choose it through driver configuration.

use sandbox_clients_support::connect;
use serde_json::Value;
use testkit::{Context, Sandbox, policy};

/// Create a long-running sandbox from the Python image with `policy`.
async fn python_sandbox(
    cx: &Context,
    suffix: &str,
    policy: testkit::sdk::raw::proto::SandboxPolicy,
) -> testkit::Result<Sandbox> {
    cx.sandbox(suffix)
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .policy(policy)
        .create_ready()
        .await
}

/// Probes the filesystem from inside the sandbox and prints one JSON object
/// mapping each probe to its result. `OK` means allowed; `EACCES`, `EPERM`
/// and `ERROR:<errno>` mean refused.
const FILESYSTEM_PROBES: &str = r#"
import errno, json, os

def outcome(action):
    try:
        action()
        return "OK"
    except OSError as error:
        return errno.errorcode.get(error.errno, f"ERROR:{error.errno}")

def write(directory):
    with open(os.path.join(directory, ".landlock-probe"), "w") as f:
        f.write("probe")

def rename_across_directories():
    os.makedirs("/sandbox/refer-src", exist_ok=True)
    os.makedirs("/sandbox/refer-dst", exist_ok=True)
    with open("/sandbox/refer-src/file", "w") as f:
        f.write("probe")
    os.rename("/sandbox/refer-src/file", "/sandbox/refer-dst/file")

results = {}
for path in ["/usr", "/tmp", "/sandbox", "/home/sandbox"]:
    results[f"write {path}"] = outcome(lambda: write(path))
for path in ["/usr", "/etc", "/opt", "/root"]:
    results[f"read {path}"] = outcome(lambda: os.listdir(path))
results["rename /sandbox"] = outcome(rename_across_directories)
results["owns /home/sandbox"] = (
    os.path.isdir("/home/sandbox") and os.stat("/home/sandbox").st_uid == os.getuid()
)
print(json.dumps(results))
"#;

/// Landlock lets exec'd commands read and write the policy's read-write
/// paths, read but not write its read-only paths, and touch nothing outside
/// the policy, even a directory the user owns. Renames between directories
/// work, which uv and pip rely on (Landlock ABI v2's refer right).
#[testkit::test]
async fn landlock_enforces_filesystem_policy(cx: &mut Context) -> testkit::Result {
    let sandbox = python_sandbox(cx, "ll", policy::base()).await?;
    let output = sandbox
        .run_python(FILESYSTEM_PROBES, &[])
        .await?
        .success()?;
    let probes = output.last_json()?;
    let result = |probe: &str| probes.get(probe).and_then(Value::as_str);
    let refused = |probe: &str| {
        result(probe).is_some_and(|result| {
            matches!(result, "EACCES" | "EPERM") || result.starts_with("ERROR:")
        })
    };

    for allowed in [
        "write /tmp",
        "write /sandbox",
        "read /usr",
        "read /etc",
        "rename /sandbox",
    ] {
        testkit::ensure!(
            result(allowed) == Some("OK"),
            "{allowed} was {:?}; expected OK\n{probes}",
            result(allowed),
        );
    }
    for denied in ["write /usr", "read /opt", "read /root"] {
        testkit::ensure!(
            refused(denied),
            "{denied} was {:?}; expected a refusal\n{probes}",
            result(denied),
        );
    }
    // Not every image has a home directory for the sandbox user. When it
    // does, owning it doesn't get around Landlock.
    if probes.get("owns /home/sandbox") == Some(&Value::Bool(true)) {
        testkit::ensure!(
            refused("write /home/sandbox"),
            "write /home/sandbox was {:?}; Landlock should refuse it although the user owns it\n{probes}",
            result("write /home/sandbox"),
        );
    }
    Ok(())
}

/// A workload's own socket fails fast with a permission error when it
/// connects to a destination no rule allows, to an allowed host on a port
/// the rule doesn't list, or to an allowed endpoint from a binary the rule
/// doesn't list. Nothing leaves the sandbox, so the destinations needn't be
/// reachable.
#[testkit::test]
async fn transparent_tcp_denies_unauthorized_connections(cx: &mut Context) -> testkit::Result {
    let mut policy = policy::base();
    policy::allow(&mut policy, "wrong_port", "1.1.1.1", 80, &["/**"]);
    policy::allow(&mut policy, "wrong_binary", "1.0.0.1", 443, &["/bin/false"]);
    let sandbox = python_sandbox(cx, "tcp", policy).await?;

    // 9.9.9.9 has no rule, 1.1.1.1 is allowed only on port 80, and 1.0.0.1
    // only for /bin/false.
    for host in ["9.9.9.9", "1.1.1.1", "1.0.0.1"] {
        let probe = connect(&sandbox, host, 443).await?;
        testkit::ensure!(
            probe.outcome.is_permission_denied(),
            "connect to {host}:443 ended with {:?}; expected EPERM or EACCES",
            probe.outcome
        );
    }
    Ok(())
}
