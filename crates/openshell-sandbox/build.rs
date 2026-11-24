// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bpf/openshell_lsm.bpf.c");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let src = manifest_dir.join("bpf/openshell_lsm.bpf.c");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let obj = out_dir.join("openshell_lsm.bpf.o");

    let compiled = try_compile_with_zig(&src, &obj) || try_compile_with_clang(&src, &obj);
    assert!(
        compiled,
        "failed to compile {} for BPF LSM: neither `zig cc` nor `clang` succeeded",
        src.display()
    );
}

fn try_compile_with_zig(src: &PathBuf, obj: &PathBuf) -> bool {
    Command::new("zig")
        .args([
            "cc",
            "-target",
            "bpfel-freestanding",
            "-O2",
            "-g",
            "-Wall",
            "-Werror",
            "-c",
        ])
        .arg(src)
        .arg("-o")
        .arg(obj)
        .status()
        .is_ok_and(|status| status.success())
}

fn try_compile_with_clang(src: &PathBuf, obj: &PathBuf) -> bool {
    Command::new("clang")
        .args(["-target", "bpf", "-O2", "-g", "-Wall", "-Werror", "-c"])
        .arg(src)
        .arg("-o")
        .arg(obj)
        .status()
        .is_ok_and(|status| status.success())
}
