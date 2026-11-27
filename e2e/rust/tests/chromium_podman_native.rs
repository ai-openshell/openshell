// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-podman")]

//! Standalone Podman control for Chromium's native Linux renderer sandbox.
//!
//! This is deliberately NOT an OpenShell browser-integration test. It proves
//! the browser fixture can start with an isolated netns, no_new_privs, runtime
//! seccomp, and a narrowly scoped OCI capability request. The ordinary agent
//! workload must continue to have *no* capabilities (see
//! `chromium_boundary_baseline.rs`).

use openshell_e2e::harness::container::{ContainerEngine, ImageGuard};
use std::path::PathBuf;
use std::process::Output;

const SYS_CHROOT_CAPABILITY_BIT: u64 = 1 << 18;

fn browser_run(engine: &ContainerEngine, image: &str, command: &[&str]) -> Output {
    let mut cmd = engine.command();
    cmd.args([
        "run",
        "--rm",
        "--network=none",
        "--cap-drop=all",
        "--cap-add=SYS_CHROOT",
        "--security-opt=no-new-privileges",
        image,
    ]);
    cmd.args(command);
    cmd.output().expect("execute constrained Podman browser probe")
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
}

fn status_value<'a>(status: &'a str, key: &str) -> &'a str {
    status
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name == key).then_some(value.trim())
        })
        .unwrap_or_else(|| panic!("missing {key} in /proc/self/status"))
}

#[test]
fn chromium_native_renderer_sandbox_starts_in_constrained_podman() {
    let context = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../chromium");
    let image = ImageGuard::build("chromium-native", &context.join("Dockerfile"), &context)
        .expect("build isolated Chromium fixture");
    let engine = ContainerEngine::from_env().expect("resolve Podman engine");
    assert_eq!(engine.name(), "podman", "only Podman is covered by this control");

    // Verify the *outer* browser process before running Chromium. A successful
    // renderer check must not mask broader-than-intended OCI capabilities.
    let status = browser_run(&engine, image.tag(), &["cat", "/proc/self/status"]);
    assert!(
        status.status.success(),
        "read outer browser-process status: {}",
        combined_output(&status)
    );
    let status = String::from_utf8_lossy(&status.stdout);
    assert_eq!(status_value(&status, "NoNewPrivs"), "1");
    assert_eq!(status_value(&status, "Seccomp"), "2");
    for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let mask = u64::from_str_radix(status_value(&status, key), 16)
            .unwrap_or_else(|_| panic!("non-hex {key} in /proc/self/status"));
        assert_eq!(
            mask & !SYS_CHROOT_CAPABILITY_BIT,
            0,
            "{key} contains capabilities beyond CAP_SYS_CHROOT: {mask:#x}"
        );
        if key == "CapBnd" {
            assert_ne!(
                mask & SYS_CHROOT_CAPABILITY_BIT,
                0,
                "Podman did not install the expected CAP_SYS_CHROOT bounding bit"
            );
        }
    }

    // The browser-side control has no default IPv4 route. This is a control
    // for the standalone fixture only, not proof of production egress policy.
    let routes = browser_run(&engine, image.tag(), &["cat", "/proc/net/route"]);
    assert!(
        routes.status.success(),
        "inspect browser network routes: {}",
        combined_output(&routes)
    );
    let routes = String::from_utf8_lossy(&routes.stdout);
    for row in routes.lines().skip(1) {
        let columns = row.split_whitespace().collect::<Vec<_>>();
        if columns.len() >= 2 {
            assert_ne!(
                columns[1], "00000000",
                "unexpected default IPv4 route in --network=none browser: {row}"
            );
        }
    }

    // The script must run Chromium without --no-sandbox and inspect live
    // renderer namespaces, seccomp, no_new_privs, and effective capabilities.
    // chrome://sandbox and end-to-end policy isolation are separate gates.
    let probe = browser_run(&engine, image.tag(), &["/usr/local/bin/verify-sandbox"]);
    let output = combined_output(&probe);
    assert!(probe.status.success(), "native Chromium probe failed:\n{output}");
    assert!(
        output.contains("CHROMIUM_SANDBOX_VERIFIED"),
        "renderer sandbox verification marker absent:\n{output}"
    );
}
