// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-podman")]

use openshell_e2e::harness::sandbox::SandboxGuard;

const USERNS_PROBE: &str = r#"
import ctypes
import errno
import sys

libc = ctypes.CDLL(None, use_errno=True)
libc.unshare.argtypes = [ctypes.c_int]
libc.unshare.restype = ctypes.c_int

CLONE_NEWUSER = 0x10000000

result = libc.unshare(CLONE_NEWUSER)
error = ctypes.get_errno()

if result == -1 and error == errno.EPERM:
    print("WORKLOAD_USERNS_DENIED")
else:
    print(f"UNEXPECTED_USERNS_RESULT result={result} errno={error}")
    sys.exit(1)
"#;

#[tokio::test]
async fn existing_workload_rejects_nested_user_namespaces() {
    let mut sandbox = SandboxGuard::create(&[])
        .await
        .expect("create baseline OpenShell sandbox");

    let result = sandbox.exec(&["python3", "-c", USERNS_PROBE]).await;

    sandbox.cleanup().await;

    let output = result.expect("namespace denial must be observable");

    assert!(
        output.contains("WORKLOAD_USERNS_DENIED"),
        "existing workload isolation must remain enforced: {output}"
    );
}
