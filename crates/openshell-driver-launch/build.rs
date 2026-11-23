// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const PROTO: &str = "../../proto/driver_launch.proto";
    println!("cargo:rerun-if-changed={PROTO}");
    let mut config = tonic_prost_build::Config::new();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    let includes = [
        std::path::PathBuf::from("../../proto"),
        protoc_bin_vendored::include_path()?,
    ];
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_with_config(config, &[std::path::PathBuf::from(PROTO)], &includes)?;
    Ok(())
}
