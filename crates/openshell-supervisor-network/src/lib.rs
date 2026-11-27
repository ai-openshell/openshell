// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// The counting test allocator in `test_support::alloc` needs unsafe; production stays forbidden.
#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]

//! Networking component of the `OpenShell` supervisor.
//!
//! Owns the egress proxy, L7 enforcement, policy runtime contracts,
//! identity cache, TLS interception, and credential injection. The denial-event channel is
//! owned by the orchestrator; this crate produces denials but does not
//! aggregate them.

mod binary_resolution;
#[cfg(feature = "test-support")]
pub mod conformance_support;
#[cfg(all(test, feature = "experimental"))]
use openshell_policy_cedar_runtime::cedar_only;
mod google_cloud_metadata;
#[cfg(target_os = "windows")]
pub mod host;
pub mod identity;
pub mod identity_source;
pub mod l7;
mod network_middleware;
pub mod opa;
pub(crate) mod policy_data;
pub(crate) mod policy_dns;
pub mod policy_engine;
pub mod policy_local;
pub mod policy_types;
pub mod policy_validation;
pub mod procfs;
pub mod proxy;
pub mod run;
pub mod sigv4;
mod spiffe_endpoint;
mod telemetry;
mod token_grant;
pub mod upstream_proxy;

#[cfg(test)]
mod test_support;
