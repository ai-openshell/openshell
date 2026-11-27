// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI binary resolution for e2e tests.
//!
//! Resolves the `openshell` binary from `OPENSHELL_BIN`, or from
//! `<workspace>/target/debug/openshell` for local runs. The local binary must
//! already be built — the E2E mise tasks do this before running the tests.

use std::path::{Path, PathBuf};

/// Locate the workspace root by walking up from the crate's manifest directory.
fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    // e2e/rust/ is two levels below the workspace root.
    manifest_dir
        .ancestors()
        .nth(2)
        .expect("failed to resolve workspace root from CARGO_MANIFEST_DIR")
        .to_path_buf()
}

/// Return the path to the `openshell` CLI binary.
///
/// Uses `OPENSHELL_BIN` when set, otherwise expects the binary at
/// `<workspace>/target/debug/openshell`.
///
/// # Panics
///
/// Panics if the configured or locally-built binary is not found.
pub fn openshell_bin() -> PathBuf {
    let bin = std::env::var_os("OPENSHELL_BIN").map_or_else(
        || workspace_root().join("target/debug/openshell"),
        PathBuf::from,
    );
    assert!(
        bin.is_file(),
        "openshell binary not found at {} — set OPENSHELL_BIN or run `cargo build -p openshell-cli` first",
        bin.display()
    );
    bin
}

/// Create a [`tokio::process::Command`] pre-configured to invoke the
/// `openshell` CLI.
///
/// The command has `kill_on_drop(true)` set so that background child processes
/// are cleaned up when the handle is dropped.
///
/// It also pins `OPENSHELL_EXEC_WAIT_TIMEOUT=0`, so every harness-spawned CLI
/// keeps the pre-wait instant `sandbox exec` failure unless a call site opts in
/// with an explicit `--exec-wait-timeout` (the flag wins over the environment).
/// Otherwise the CLI's default-on bounded wait would re-time suites that probe
/// exec during churn.
pub fn openshell_cmd() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(openshell_bin());
    cmd.kill_on_drop(true);
    cmd.env("OPENSHELL_EXEC_WAIT_TIMEOUT", "0");
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_root_resolves() {
        let root = workspace_root();
        assert!(
            root.join("Cargo.toml").is_file(),
            "workspace root should contain Cargo.toml: {root:?}"
        );
    }
}
