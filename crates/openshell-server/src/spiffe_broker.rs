// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Startup selection of the gateway's sandbox identity provider.
//!
//! The provider broker depends only on
//! [`SandboxIdentityProvider`]; this module chooses the SPIRE adapter when
//! `[openshell.gateway.spiffe_broker]` is configured.
use std::sync::Arc;
use std::time::{Duration, Instant};

use openshell_core::config::{
    Config, GatewayJwtConfig, SpiffeBrokerConfig, SpiffeWorkloadIdentityConfig,
};
use openshell_core::token_grant_failure::TokenGrantFailure;
use openshell_spiffe::{SandboxIdentityProvider, SandboxSpiffeIdPrefix};
use spiffe::{JwtBundleSet, WorkloadApiClient, WorkloadApiError};
use tokio::sync::Mutex;

/// Check the broker settings `config` enables without building them.
///
/// # Errors
///
/// Rejects broker without gateway session JWTs and a positive session
/// TTL, and settings [`SpiffeBrokerConfig::validate`] rejects.
pub fn validate_config(config: &Config) -> Result<(), String> {
    SupervisorWorkloadIdentity::from_config(config)?;
    enabled(config).map(drop)
}

/// Trusted identity settings shared by launch provisioning and the provider broker.
#[derive(Clone)]
pub struct SupervisorWorkloadIdentity {
    prefix: SandboxSpiffeIdPrefix,
    gateway_id: String,
    workload_api_socket_path: std::path::PathBuf,
    jwt_bundles: Arc<Mutex<Option<JwtBundleSnapshot>>>,
}

struct JwtBundleSnapshot {
    fetched_at: Instant,
    bundles: Arc<JwtBundleSet>,
}

impl SupervisorWorkloadIdentity {
    pub(crate) fn from_config(config: &Config) -> Result<Option<Self>, String> {
        Self::from_settings(
            config.spiffe_workload_identity.as_ref(),
            config.gateway_jwt.as_ref(),
            config.spiffe_broker.is_some(),
        )
    }

    pub(crate) fn from_settings(
        workload: Option<&SpiffeWorkloadIdentityConfig>,
        jwt: Option<&GatewayJwtConfig>,
        broker_enabled: bool,
    ) -> Result<Option<Self>, String> {
        let Some(workload) = workload else {
            return Ok(None);
        };
        if broker_enabled {
            return Err("configure either spiffe_workload_identity or spiffe_broker".into());
        }
        let jwt = jwt
            .filter(|jwt| jwt.ttl_secs.is_some())
            .ok_or("spiffe_workload_identity requires a positive gateway_jwt.ttl_secs")?;
        let prefix = SandboxSpiffeIdPrefix::parse(&workload.spiffe_id_prefix).map_err(|_| {
            "spiffe_workload_identity.spiffe_id_prefix must be a SPIFFE ID prefix with a lowercase trust domain and optional path segments"
        })?;
        let uuid = uuid::Uuid::nil().to_string();
        prefix
            .supervisor_launch_spiffe_id(&jwt.gateway_id, &uuid, &uuid)
            .map_err(|reason| format!("spiffe_workload_identity launch SPIFFE ID: {reason}"))?;
        openshell_core::driver_utils::validate_provider_spiffe_unix_socket(
            &workload.workload_api_socket_path,
        )
        .map_err(|reason| format!("spiffe_workload_identity.workload_api_socket_path: {reason}"))?;
        Ok(Some(Self {
            prefix,
            gateway_id: jwt.gateway_id.clone(),
            workload_api_socket_path: workload.workload_api_socket_path.clone(),
            jwt_bundles: Arc::default(),
        }))
    }

    pub(crate) fn sandbox_spiffe_id(&self, sandbox_id: &str) -> Result<String, String> {
        self.prefix.sandbox_spiffe_id(&self.gateway_id, sandbox_id)
    }

    pub(crate) fn launch_spiffe_id(
        &self,
        sandbox_id: &str,
        launch_id: uuid::Uuid,
    ) -> Result<String, String> {
        self.prefix.supervisor_launch_spiffe_id(
            &self.gateway_id,
            sandbox_id,
            &launch_id.to_string(),
        )
    }

    #[cfg(test)]
    pub(crate) async fn seed_test_jwt_bundles(&self, bundles: JwtBundleSet) {
        *self.jwt_bundles.lock().await = Some(JwtBundleSnapshot {
            fetched_at: Instant::now(),
            bundles: Arc::new(bundles),
        });
    }

    pub(crate) async fn jwt_bundles(&self) -> Result<Arc<JwtBundleSet>, WorkloadApiError> {
        // Share a very recent bundle across grants. An expired snapshot never
        // authorizes a request if the Workload API fails during refresh.
        let mut snapshot = self.jwt_bundles.lock().await;
        if let Some(snapshot) = snapshot.as_ref()
            && snapshot.fetched_at.elapsed() < Duration::from_secs(5)
        {
            return Ok(snapshot.bundles.clone());
        }

        let endpoint = openshell_spiffe::workload_api_endpoint(&self.workload_api_socket_path);
        let client = WorkloadApiClient::connect_to(&endpoint).await?;
        let bundles = Arc::new(client.fetch_jwt_bundles().await?);
        *snapshot = Some(JwtBundleSnapshot {
            fetched_at: Instant::now(),
            bundles: bundles.clone(),
        });
        Ok(bundles)
    }
}

/// The sandbox identity provider `config` enables, if any.
///
/// # Errors
///
/// Rejects what [`validate_config`] rejects.
pub fn sandbox_identity_provider(
    config: &Config,
) -> Result<Option<Arc<dyn SandboxIdentityProvider<Error = TokenGrantFailure>>>, String> {
    let Some(broker) = enabled(config)? else {
        return Ok(None);
    };
    let provider = openshell_spire::SpireSandboxIdentity::new(broker)?;
    Ok(Some(Arc::new(provider)))
}

/// Validated broker settings, when broker is enabled.
fn enabled(config: &Config) -> Result<Option<&SpiffeBrokerConfig>, String> {
    let Some(broker) = &config.spiffe_broker else {
        return Ok(None);
    };
    let jwt = config
        .gateway_jwt
        .as_ref()
        .ok_or("spiffe_broker requires gateway session JWTs")?;
    broker.validate(&jwt.gateway_id)?;
    if jwt.ttl_secs.is_none() {
        return Err("spiffe_broker requires a positive gateway_jwt.ttl_secs".into());
    }
    Ok(Some(broker))
}
