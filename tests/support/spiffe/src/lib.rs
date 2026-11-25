// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The environment's SPIFFE Workload APIs, for suites whose gateway and
//! supervisors fetch JWT-SVIDs from them.
//!
//! The environment runs a Workload API for the gateway and one for the
//! supervisors, points the gateway's Workload API socket and the driver's
//! `provider_spiffe_workload_api_socket` at them, and publishes the bundle
//! that verifies their JWT-SVIDs in `OPENSHELL_TEST_SPIFFE_JWKS`. Under
//! `openshell-test-runner`, the tmachine `<podman base>-spiffe` environments
//! do that (`tests/tmachine/ansible/playbooks/spiffe.yaml`); against your own
//! deployment, set it yourself:
//!
//! | Variable | Example |
//! |---|---|
//! | `OPENSHELL_TEST_SPIFFE_JWKS` | `/var/lib/openshell-test/spiffe/jwks.json` |
//!
//! The Workload APIs issue JWT-SVIDs with issuer [`ISSUER`], to
//! [`GATEWAY_SUBJECT`] for the gateway and to [`SUPERVISOR_SUBJECT`] for
//! every supervisor: suites test credential isolation with distinct providers
//! and audiences, not SPIRE attestation. A missing variable fails the test;
//! it never skips it.

use std::path::PathBuf;

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use testkit::{Error, Result, ResultExt as _};

pub const JWKS_ENV: &str = "OPENSHELL_TEST_SPIFFE_JWKS";

pub const TRUST_DOMAIN: &str = "openshell-e2e.test";
/// The `iss` of every JWT-SVID.
pub const ISSUER: &str = "https://spiffe.openshell-e2e.test";
/// The SPIFFE ID the gateway's Workload API issues.
pub const GATEWAY_SUBJECT: &str = "spiffe://openshell-e2e.test/openshell/gateway";
/// The SPIFFE ID the supervisors' Workload API issues.
pub const SUPERVISOR_SUBJECT: &str = "spiffe://openshell-e2e.test/openshell/sandbox/e2e";

/// The key that verifies the Workload APIs' JWT-SVIDs.
pub struct Bundle {
    key_id: String,
    key: DecodingKey,
}

impl Bundle {
    /// The RS256 key in the JWKS [`JWKS_ENV`] names.
    pub fn from_env() -> Result<Self> {
        let path = PathBuf::from(
            std::env::var(JWKS_ENV)
                .ok()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    Error::msg(format!(
                        "{JWKS_ENV} is not set; this suite needs a gateway and supervisors that use the environment's SPIFFE Workload APIs (see the spiffe-support crate docs)"
                    ))
                })?,
        );
        let jwks = std::fs::read(&path).context(format!("read {}", path.display()))?;
        Self::from_jwks(&jwks).context(format!("read the bundle in {}", path.display()))
    }

    fn from_jwks(jwks: &[u8]) -> Result<Self> {
        let jwks: serde_json::Value = serde_json::from_slice(jwks).context("parse the JWKS")?;
        let key = &jwks["keys"][0];
        let component = |name: &str| {
            key[name]
                .as_str()
                .ok_or_else(|| Error::msg(format!("the JWKS key has no {name}")))
        };
        Ok(Self {
            key_id: component("kid")?.to_string(),
            key: DecodingKey::from_rsa_components(component("n")?, component("e")?)
                .map_err(|error| Error::msg(format!("read the JWKS key: {error}")))?,
        })
    }

    /// Whether `token` is a JWT-SVID the Workload APIs issued to a
    /// supervisor for `audience`, with a valid signature and lifetime.
    pub fn verify_supervisor_svid(&self, token: &str, audience: &str) -> bool {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[ISSUER]);
        validation.set_audience(&[audience]);
        validation.sub = Some(SUPERVISOR_SUBJECT.to_string());
        validation.set_required_spec_claims(&["exp", "iat", "iss", "sub", "aud"]);
        openshell_crypto::jwt::decode::<serde_json::Value>(token, &self.key, &validation)
            .is_ok_and(|verified| verified.header.kid.as_deref() == Some(self.key_id.as_str()))
    }
}
