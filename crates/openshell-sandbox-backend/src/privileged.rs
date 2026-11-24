// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Privileged (true guest root) VM isolation profile and confirmation evidence.
//!
//! When a VM compute driver boots a hardened `CONFIG_BPF_LSM=y` guest kernel
//! with an outer network fence, it may admit [`PrivilegedGuestProfile`] in both
//! `BoundaryConfig::privileged` and `SandboxRuntimeDescriptor::privileged`.
//! The runtime boots as guest PID 1 from a read-only runtime root, loads a
//! boot-once BPF LSM seal + policy program, and places workload processes as
//! guest `UID 0` inside private mount, PID, cgroup, and loopback-only network
//! namespaces with inherited `seccomp_notify` network mediation.

use openshell_isolation_interface::contract::BackendError;
use serde::{Deserialize, Serialize};

/// Driver-admitted privileged VM guest profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivilegedGuestProfile {
    /// Boot-once BPF LSM enforces shim seal, `filesystem_policy`, `process`
    /// rules, and kernel-sourced telemetry.
    pub bpf_lsm: bool,
}

impl PrivilegedGuestProfile {
    /// Standard privileged VM profile with boot-once BPF LSM enforcement.
    #[must_use]
    pub const fn vm_bpf_lsm() -> Self {
        Self { bpf_lsm: true }
    }

    /// Reject profiles that disable required kernel enforcement.
    pub fn validate(&self) -> Result<(), BackendError> {
        if !self.bpf_lsm {
            return Err(BackendError::Descriptor(
                "privileged guest profile requires bpf_lsm enforcement".to_string(),
            ));
        }
        Ok(())
    }
}

/// Measured enforcement evidence reported on `Confirm` by `openshell-sandbox --privileged`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "audit evidence preserves independently measured security results"
)]
pub struct PrivilegedSandboxAuditEvidence {
    /// Profile the runtime was bootstrapped with.
    pub profile: PrivilegedGuestProfile,
    /// Real, effective, and saved UID of the runtime (guest PID 1 root).
    pub runtime_uid: u32,
    /// Guest UID of workload processes (real guest root: 0).
    pub workload_uid: u32,
    pub sandbox_dumpable: bool,
    pub core_limit_zero: bool,
    pub native_architecture: String,
    pub kernel_release: String,
    /// The workload root is mounted separately from the read-only runtime root
    /// and every workload process pivots into it.
    pub separate_workload_root: bool,
    /// Boot-once BPF LSM seal hooks are attached and the seal config map is frozen.
    pub bpf_lsm_sealed: bool,
    /// Workload `filesystem_policy` and `process` hooks are attached in BPF LSM.
    pub bpf_policy_enforced: bool,
    /// Workload processes run in a dedicated loopback-only network namespace
    /// separate from the shim's initial network namespace.
    pub init_net_isolated: bool,
    /// Unmarked tasks cannot open `AF_VSOCK` sockets.
    pub vsock_blocked: bool,
    /// Networking-only `seccomp_notify` mediation (with `io_uring` blocked) is active.
    pub network_mediation: bool,
    /// `seccomp_notify` + `ADDFD` round trip qualified at startup.
    pub seccomp_addfd_send: bool,
    /// Supervisor loss freezes the runtime-owned workload cgroup (`cgroup.freeze`).
    /// When `false`, supervisor loss terminates the workload instead of freezing it.
    pub standing_freeze: bool,
    /// Privileged mode enforces filesystem policy via BPF LSM rather than Landlock.
    pub landlock_applied: bool,
}

impl PrivilegedSandboxAuditEvidence {
    /// Validate measured evidence against the profile admitted by the supervisor.
    pub fn validate(&self, admitted: PrivilegedGuestProfile) -> Result<(), BackendError> {
        admitted
            .validate()
            .map_err(|error| BackendError::Confirm(error.to_string()))?;
        if self.profile != admitted {
            return Err(BackendError::Confirm(
                "privileged sandbox evidence names a different profile than the admitted one"
                    .to_string(),
            ));
        }
        let complete = self.runtime_uid == 0
            && self.workload_uid == 0
            && !self.sandbox_dumpable
            && self.core_limit_zero
            && !self.native_architecture.is_empty()
            && !self.kernel_release.is_empty()
            && self.separate_workload_root
            && self.bpf_lsm_sealed
            && self.bpf_policy_enforced
            && self.init_net_isolated
            && self.vsock_blocked
            && self.network_mediation
            && self.seccomp_addfd_send
            && !self.landlock_applied;
        if complete {
            Ok(())
        } else {
            Err(BackendError::Confirm(
                "privileged sandbox audit evidence is incomplete".to_string(),
            ))
        }
    }
}
