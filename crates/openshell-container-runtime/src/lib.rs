// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Code shared by the `OpenShell` desktop compute drivers.
//!
//! Everything here is used only by the Docker, Podman, and VM drivers, so the
//! crate moves with them when they leave this repository.

pub mod podman_socket;
