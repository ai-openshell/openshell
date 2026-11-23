// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for the compute drivers the `OpenShell` gateway launches.
//!
//! The launch protocol itself (`GetLaunchInfo` and `Configure`) is in
//! `openshell-driver-launch`. This crate holds what drivers share on top of
//! it: applying `Configure` telemetry, loading the staged network trust
//! artifact, parent-death handling, and the `probe` and `preflight` results.

pub mod launch;
pub mod network_trust;
pub mod parent;
pub mod preflight;
pub mod probe;
