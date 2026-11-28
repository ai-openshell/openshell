// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The Podman compute driver, launched as a subprocess.
//!
//! The `openshell-driver-podman` subprocess owns its
//! `[openshell.drivers.podman]` table. The gateway reads only the keys it
//! owns and forwards the rest as TOML text on stdin; see
//! [`crate::local_driver`].

use openshell_server::{DriverDetection, DriverDetectionContext};

use crate::local_driver::LocalDriver;

pub const PODMAN: LocalDriver = LocalDriver {
    name: "podman",
    drop_legacy_keys: drop_legacy_gateway_port,
};

/// `main` accepted `gateway_port` and overwrote it with the gateway's
/// listening port. The driver now rejects the key, so the gateway drops it,
/// warning once, and never treats it as an override.
fn drop_legacy_gateway_port(table: &mut toml::map::Map<String, toml::Value>) {
    if table.remove("gateway_port").is_some() {
        tracing::warn!(
            "[openshell.drivers.podman].gateway_port is ignored: the gateway supplies its listening port; remove it"
        );
    }
}

/// Detect Podman by starting its driver with the operator's table, so a
/// configured `socket_path` is honoured.
pub fn detect(context: &DriverDetectionContext<'_>) -> DriverDetection {
    PODMAN.detect(context, &PODMAN.socket_dir())
}

#[cfg(test)]
mod tests;
