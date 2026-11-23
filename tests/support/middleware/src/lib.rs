// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The environment starts the content-guard example and registers it before
//! the gateway starts. Suites refer to that registration in their policies.

/// Read `OPENSHELL_TEST_CONTENT_GUARD_REGISTRATION`, the gateway registration
/// name for the example. Missing or invalid configuration fails the test.
pub fn content_guard_registration() -> testkit::Result<String> {
    const VAR: &str = "OPENSHELL_TEST_CONTENT_GUARD_REGISTRATION";
    let name = std::env::var(VAR).map_err(|error| {
        testkit::Error::msg(format!("read the registration from {VAR}: {error}"))
    })?;
    testkit::ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "{VAR} must be a non-empty middleware name (letters, digits, '-' or '_')"
    );
    Ok(name)
}
