// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    println!("cargo::rustc-check-cfg=cfg(conformance_bundle)");
    println!("cargo::rerun-if-env-changed=OPENSHELL_CONFORMANCE_BUNDLE");
    println!("cargo::rerun-if-changed=build.rs");
    if std::env::var_os("OPENSHELL_CONFORMANCE_BUNDLE").is_some() {
        println!("cargo::rustc-cfg=conformance_bundle");
    }
}
