// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-podman")]

//! Security invariants for the *ordinary agent workload* while Chromium
//! compatibility is developed in a separate execution boundary. This is not a
//! Chromium functionality test; it must stay green when browser support ships.

use openshell_e2e::harness::sandbox::SandboxGuard;

const WORKLOAD_BOUNDARY_PROBE: &str = r#"
import ctypes
import errno
import sys

libc = ctypes.CDLL(None, use_errno=True)
libc.unshare.argtypes = [ctypes.c_int]
libc.unshare.restype = ctypes.c_int
libc.chroot.argtypes = [ctypes.c_char_p]
libc.chroot.restype = ctypes.c_int

with open('/proc/self/status', encoding='utf-8') as status_file:
    fields = dict(line.split(':', 1) for line in status_file if ':' in line)

def field(name):
    return fields.get(name, '').strip().split()[0] if fields.get(name, '').strip() else ''

def require(name, predicate):
    if not predicate:
        print(f'WORKLOAD_INVARIANT_FAILED {name}', flush=True)
        sys.exit(1)
    print(f'WORKLOAD_INVARIANT_OK {name}', flush=True)

require('no_new_privs', field('NoNewPrivs') == '1')
require('no_effective_caps', int(field('CapEff') or '0', 16) == 0)
require('no_bounding_caps', int(field('CapBnd') or '0', 16) == 0)
require('seccomp_filter', field('Seccomp') == '2')

CLONE_NEWUSER = 0x10000000
ctypes.set_errno(0)
result = libc.unshare(CLONE_NEWUSER)
error = ctypes.get_errno()
require('nested_userns_denied', result == -1 and error == errno.EPERM)

# chroot('/') deliberately avoids special paths and cannot be confused with
# a failure to resolve a target executable after a successful chroot.
ctypes.set_errno(0)
result = libc.chroot(b'/')
error = ctypes.get_errno()
require('chroot_denied', result == -1 and error == errno.EPERM)

print('WORKLOAD_BOUNDARY_INTACT', flush=True)
"#;

#[tokio::test]
async fn existing_workload_preserves_browser_boundary_invariants() {
    let mut sandbox = SandboxGuard::create(&[])
        .await
        .expect("create baseline OpenShell sandbox");

    let result = sandbox
        .exec(&["python3", "-c", WORKLOAD_BOUNDARY_PROBE])
        .await;

    sandbox.cleanup().await;

    let output = result.expect("security invariants must be observable");
    assert!(
        output.contains("WORKLOAD_BOUNDARY_INTACT"),
        "existing workload isolation must remain enforced: {output}"
    );
}
