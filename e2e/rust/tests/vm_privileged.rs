// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! VM privileged (true guest root + boot-once BPF LSM) workload E2E tests.
//!
//! Exercises real privileged workloads (Chromium and Bubblewrap) alongside
//! BPF LSM shim-seal, filesystem_policy, and network-mediation checks inside a
//! VM sandbox created with `openshell sandbox create --privileged` / `--priv`.

use std::process::Command as StdCommand;

use openshell_e2e::harness::cli::run_cli;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::{SandboxGuard, unique_sandbox_name};

const DEFAULT_PRIV_IMAGE: &str = "openshell-e2e-priv-workload:local";

fn ensure_privileged_workload_image() -> String {
    if let Ok(image) = std::env::var("OPENSHELL_E2E_PRIV_IMAGE")
        && !image.trim().is_empty()
    {
        return image;
    }

    let inspect = StdCommand::new("docker")
        .args(["image", "inspect", DEFAULT_PRIV_IMAGE])
        .output();
    if inspect.is_ok_and(|out| out.status.success()) {
        return DEFAULT_PRIV_IMAGE.to_string();
    }

    let dockerfile = r#"FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    bubblewrap \
    ca-certificates \
    chromium \
    curl \
    iproute2 \
    python3 \
    strace \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /sandbox /etc/priv-ro-test && echo "sealed-content" > /etc/priv-ro-test/sentinel
"#;
    let mut child = StdCommand::new("docker")
        .args(["build", "-t", DEFAULT_PRIV_IMAGE, "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("spawn docker build for privileged workload image");
    {
        use std::io::Write as _;
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(dockerfile.as_bytes())
            .expect("write Dockerfile");
    }
    let status = child.wait().expect("wait for docker build");
    assert!(
        status.success(),
        "failed to build {DEFAULT_PRIV_IMAGE} workload image"
    );
    DEFAULT_PRIV_IMAGE.to_string()
}

fn privileged_policy() -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().expect("temporary privileged policy");
    std::fs::write(
        file.path(),
        r#"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/etc/priv-ro-test]
  read_write: [/sandbox, /tmp, /dev/shm]
landlock:
  compatibility: best_effort
network_policies: {}
"#,
    )
    .expect("write privileged policy");
    file
}

fn hard_landlock_policy() -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().expect("temporary hard-landlock policy");
    std::fs::write(
        file.path(),
        r#"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /etc]
  read_write: [/sandbox, /tmp]
landlock:
  compatibility: hard_requirement
network_policies: {}
"#,
    )
    .expect("write hard-landlock policy");
    file
}

#[tokio::test]
async fn vm_privileged_chrome_and_bubblewrap_workloads() {
    let image = ensure_privileged_workload_image();
    let policy = privileged_policy();
    let policy_path = policy.path().to_str().expect("UTF-8 policy path");
    let name = unique_sandbox_name();

    let mut sandbox = SandboxGuard::create_keep_with_args(
        &[
            "--name",
            &name,
            "--privileged",
            "--from",
            &image,
            "--policy",
            policy_path,
        ],
        &["sh", "-c", "echo priv-vm-ready; exec sleep infinity"],
        "priv-vm-ready",
    )
    .await
    .expect("privileged VM sandbox should start and become ready");

    // 1. Verify true guest root and namespace isolation from the shim.
    let identity_script = concat!(
        "set -eu; ",
        "test \"$(id -u)\" = \"0\"; ",
        "test ! -e /run/openshell/bootstrap; ",
        "! ps -eo comm | grep -qx openshell-sandbox; ",
        "echo identity-isolation-ok",
    );
    let out = sandbox
        .exec(&["sh", "-c", identity_script])
        .await
        .expect("guest root and namespace isolation check should succeed");
    assert!(
        strip_ansi(&out).contains("identity-isolation-ok"),
        "unexpected identity output:\n{out}"
    );

    // 2. Verify Bubblewrap (nested mount + PID + UTS namespaces) works cleanly.
    let bwrap_script = concat!(
        "set -eu; ",
        "bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp ",
        "--unshare-pid --unshare-uts -- /bin/sh -c 'test \"$(id -u)\" = 0 && echo bwrap-ok'",
    );
    let out = sandbox
        .exec(&["sh", "-c", bwrap_script])
        .await
        .expect("bubblewrap should run inside privileged VM sandbox");
    assert!(
        strip_ansi(&out).contains("bwrap-ok"),
        "bubblewrap output missing marker:\n{out}"
    );

    // 3. Verify Chromium starts cleanly both as guest root and as non-root with
    //    Chromium's own Linux namespace/seccomp sandbox enabled.
    let chrome_script = concat!(
        "set -eu; ",
        "mkdir -p /tmp/chrome-root /tmp/chrome-user; ",
        "chmod 1777 /tmp/chrome-root /tmp/chrome-user; ",
        "HOME=/tmp/chrome-root chromium --no-sandbox --headless=new --disable-gpu ",
        "--disable-software-rasterizer --dump-dom 'data:text/html,<h1>chrome-root-ok</h1>' ",
        "| grep -q 'chrome-root-ok'; ",
        "su -s /bin/sh sandbox -c 'HOME=/tmp/chrome-user chromium --headless=new --disable-gpu ",
        "--disable-software-rasterizer --dump-dom \"data:text/html,<h1>chrome-sandbox-ok</h1>\"' ",
        "| grep -q 'chrome-sandbox-ok'; ",
        "echo chrome-both-ok",
    );
    let out = sandbox
        .exec(&["sh", "-c", chrome_script])
        .await
        .expect("chromium should start in privileged VM sandbox");
    assert!(
        strip_ansi(&out).contains("chrome-both-ok"),
        "chromium output missing marker:\n{out}"
    );

    // 4. Verify BPF LSM shim seal, filesystem_policy, and network mediation
    //    hold even against guest UID 0.
    let security_script = r#"
set -eu
python3 - <<'PY'
import ctypes, errno, os, socket, sys

libc = ctypes.CDLL(None, use_errno=True)

# Determine syscall numbers for arch (aarch64 vs x86_64)
import platform
arch = platform.machine()
if arch == "aarch64":
    SYS_BPF = 280
    SYS_IO_URING_SETUP = 425
elif arch == "x86_64":
    SYS_BPF = 321
    SYS_IO_URING_SETUP = 425
else:
    raise RuntimeError(f"unsupported arch {arch}")

# 4a. bpf() syscall must be denied by lsm/bpf even for guest UID 0
buf = ctypes.create_string_buffer(128)
rc = libc.syscall(SYS_BPF, 0, buf, 64)
err = ctypes.get_errno()
assert rc == -1 and err in (errno.EPERM, errno.EACCES), f"expected bpf() denied, got rc={rc} errno={err}"

# 4b. AF_VSOCK must be denied (by seccomp_notify and/or lsm/socket_create)
try:
    s = socket.socket(40, socket.SOCK_STREAM, 0)
    s.close()
    raise AssertionError("AF_VSOCK socket unexpectedly succeeded")
except OSError as exc:
    assert exc.errno in (errno.EPERM, errno.EACCES, errno.EAFNOSUPPORT), f"unexpected AF_VSOCK errno: {exc}"

# 4c. io_uring_setup must be denied by privileged seccomp filter
rc = libc.syscall(SYS_IO_URING_SETUP, 8, buf)
err = ctypes.get_errno()
assert rc == -1 and err in (errno.EPERM, errno.ENOSYS), f"expected io_uring denied, got rc={rc} errno={err}"

# 4d. filesystem_policy read_only path must reject writes from guest UID 0
try:
    with open("/etc/priv-ro-test/sentinel", "w") as f:
        f.write("tampered\n")
    raise AssertionError("write to read_only policy path unexpectedly succeeded")
except OSError as exc:
    assert exc.errno in (errno.EACCES, errno.EPERM), f"unexpected RO write errno: {exc}"

with open("/etc/priv-ro-test/sentinel") as f:
    assert f.read().strip() == "sealed-content", "sentinel content was modified"

# 4e. Writable policy path (/sandbox) must allow writes
with open("/sandbox/priv-rw-check", "w") as f:
    f.write("rw-ok\n")

# 4f. Policy-denied external TCP connection must fail closed
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(("203.0.113.1", 80))
    raise AssertionError("external TCP connect unexpectedly succeeded")
except OSError:
    pass
finally:
    s.close()

print("security-checks-ok")
PY
# 4g. Writable shadow mount over read_only policy path must be denied by lsm/sb_mount
if mount -t tmpfs tmpfs /etc/priv-ro-test 2>/dev/null; then
    echo "ERROR: mount over read_only policy path unexpectedly succeeded" >&2
    exit 1
fi
echo all-security-ok
"#;
    let out = sandbox
        .exec(&["sh", "-c", security_script])
        .await
        .expect("privileged security checks should succeed");
    let clean = strip_ansi(&out);
    assert!(
        clean.contains("security-checks-ok") && clean.contains("all-security-ok"),
        "privileged security assertions failed:\n{clean}"
    );

    sandbox.cleanup().await;
}

#[tokio::test]
async fn vm_privileged_alias_and_hard_landlock_rejection() {
    let policy = hard_landlock_policy();
    let policy_path = policy.path().to_str().expect("UTF-8 policy path");
    let name = unique_sandbox_name();

    // --priv alias with hard_requirement Landlock must fail closed.
    let (output, code) = run_cli(&[
        "sandbox",
        "create",
        "--name",
        &name,
        "--priv",
        "--no-tty",
        "--policy",
        policy_path,
        "--",
        "true",
    ])
    .await;
    assert_ne!(
        code, 0,
        "privileged sandbox with landlock hard_requirement should fail closed:\n{output}"
    );
    let clean = strip_ansi(&output);
    assert!(
        clean.contains("hard_requirement") || clean.contains("BPF LSM"),
        "expected hard_requirement rejection reason, got:\n{clean}"
    );
    let _ = run_cli(&["sandbox", "delete", &name]).await;
}
