// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::{Json, Router, extract::State, routing::post};
use openshell_bootstrap::jwt::generate_jwt_key;
use openshell_core::config::GatewayJwtConfig;
use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::{
    AttachSandboxProviderRequest, DetachSandboxProviderRequest, NetworkAccessPreset,
    NetworkEndpoint, ProviderProfile, ProviderProfileCategory, ProviderProfileCredential,
    SandboxPhase, SandboxSpec, workspace_selector,
};
use tokio::sync::Notify;

use super::{
    Arc, GetSandboxProviderAccessTokenRequest, HashMap, Principal, Provider,
    ProviderCredentialTokenGrant, ProviderCredentialTokenGrantType, Request, Sandbox,
    SandboxIdentityProvider, SandboxJwtSvid, ServerState, TokenGrantFailure, handle,
    insert_dynamic_credentials_for_profile,
};
use crate::auth::principal::{SandboxIdentitySource, SandboxPrincipal};
use crate::auth::sandbox_jwt::SandboxSessionJwtAuthority;
use crate::auth::sandbox_session::PersistedSandboxIdentity;
use crate::grpc::sandbox::{handle_attach_sandbox_provider, handle_detach_sandbox_provider};
use crate::grpc::test_support::{authed_request, test_server_state_with_driver};

const SANDBOX: &str = "sandbox-detach";
const PROVIDER: &str = "grant-provider";
const PROFILE: &str = "grant-profile";
const GATEWAY: &str = "grant-gateway";

#[derive(Debug)]
struct TestSandboxIdentity;

#[async_trait::async_trait]
impl SandboxIdentityProvider for TestSandboxIdentity {
    type Error = TokenGrantFailure;

    async fn fetch_jwt_svid(
        &self,
        gateway_id: &str,
        sandbox_id: &str,
        _audience: &str,
        _runtime_identity: &str,
    ) -> Result<SandboxJwtSvid, Self::Error> {
        Ok(SandboxJwtSvid {
            spiffe_id: format!("spiffe://test.example/gateway/{gateway_id}/sandbox/{sandbox_id}"),
            token: "fixture-assertion".to_string(),
            expires_at: crate::persistence::current_time_ms() / 1000 + 300,
        })
    }
}

#[derive(Default)]
struct Issuer {
    requests: AtomicUsize,
    started: Notify,
    release: Notify,
}

async fn issue(State(issuer): State<Arc<Issuer>>) -> Json<serde_json::Value> {
    let number = issuer.requests.fetch_add(1, Ordering::Relaxed) + 1;
    if number == 1 {
        issuer.started.notify_one();
        issuer.release.notified().await;
    }
    Json(serde_json::json!({
        "access_token": format!("fixture-access-{number}"),
        "token_type": "Bearer",
        "expires_in": 300,
    }))
}

fn metadata(name: &str) -> ObjectMeta {
    ObjectMeta {
        id: name.into(),
        name: name.into(),
        workspace: "default".into(),
        ..Default::default()
    }
}

async fn grant_fixture(endpoint: String) -> (Arc<ServerState>, String, String) {
    let mut state = test_server_state_with_driver("kubernetes").await;
    let server = Arc::get_mut(&mut state).unwrap();
    let key = generate_jwt_key().expect("generate a session signing key");
    let authority = Arc::new(
        SandboxSessionJwtAuthority::from_pem(
            key.signing_key_pem.as_bytes(),
            key.public_key_pem.as_bytes(),
            key.kid,
            GATEWAY,
            Some(Duration::from_mins(5)),
        )
        .expect("configure the session authority"),
    );
    server.config.gateway_jwt = Some(GatewayJwtConfig {
        signing_key_path: PathBuf::default(),
        public_key_path: PathBuf::default(),
        kid_path: PathBuf::default(),
        gateway_id: GATEWAY.into(),
        ttl_secs: NonZeroU64::new(300),
    });
    server.sandbox_session_jwt_authority = Some(authority.clone());
    server.sandbox_identity = Some(Arc::new(TestSandboxIdentity));
    let identity = PersistedSandboxIdentity::new().expect("create a sandbox session");
    let session = authority
        .mint_persisted_launch(SANDBOX, &identity)
        .expect("sign the sandbox session");
    let bearer = session.supervisor.gateway_token.expose_secret().to_string();
    let mut sandbox_meta = metadata(SANDBOX);
    identity.write(&mut sandbox_meta.annotations);
    let mut sandbox = Sandbox {
        metadata: Some(sandbox_meta),
        spec: Some(SandboxSpec {
            providers: vec![PROVIDER.into()],
            provider_attachment_epoch: "first-attachment".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    sandbox.set_phase(SandboxPhase::Ready as i32);
    server.store.put_message(&sandbox).await.unwrap();

    let profile = ProviderProfile {
        id: PROFILE.into(),
        display_name: "Grant test profile".into(),
        category: ProviderProfileCategory::Other as i32,
        endpoints: vec![NetworkEndpoint {
            host: "api.example.test".into(),
            port: 443,
            path: "/**".into(),
            protocol: "rest".into(),
            access: NetworkAccessPreset::Full as i32,
            ..Default::default()
        }],
        credentials: vec![ProviderProfileCredential {
            name: "access".into(),
            auth_style: "bearer".into(),
            header_name: "Authorization".into(),
            token_grant: Some(ProviderCredentialTokenGrant {
                token_endpoint: endpoint,
                grant_type: ProviderCredentialTokenGrantType::ClientCredentials as i32,
                ..Default::default()
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut credentials = HashMap::new();
    insert_dynamic_credentials_for_profile(
        &mut credentials,
        &openshell_providers::ProviderTypeProfile::from_proto(&profile),
        PROVIDER,
        PROVIDER,
    )
    .unwrap();
    let credential_key = credentials.into_keys().next().expect("configured grant");
    server
        .store
        .put_message(&crate::provider_profile_sources::stored_provider_profile(
            profile,
        ))
        .await
        .unwrap();
    server
        .store
        .put_message(&Provider {
            metadata: Some(metadata(PROVIDER)),
            r#type: PROFILE.into(),
            ..Default::default()
        })
        .await
        .unwrap();
    (state, bearer, credential_key)
}

#[tokio::test]
async fn reattaching_provider_during_exchange_rejects_the_in_flight_token() {
    let issuer = Arc::new(Issuer::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/token", post(issue))
        .with_state(issuer.clone());
    let issuer_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (state, bearer, credential_key) = grant_fixture(endpoint).await;
    let request = || {
        let mut request = Request::new(GetSandboxProviderAccessTokenRequest {
            credential_key: credential_key.clone(),
            ..Default::default()
        });
        request
            .extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: SANDBOX.into(),
                source: SandboxIdentitySource::BootstrapJwt {
                    issuer: format!("openshell-gateway:{GATEWAY}"),
                    auth_epoch: None,
                },
                trust_domain: None,
            }));
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {bearer}").parse().unwrap());
        request
    };

    let exchange = handle(&state, request());
    tokio::pin!(exchange);
    let started = tokio::time::timeout(Duration::from_secs(10), issuer.started.notified());
    tokio::select! {
        result = &mut exchange => panic!("the exchange finished before detachment: {result:?}"),
        started = started => started.expect("the issuer received the first exchange"),
    }
    let detached = handle_detach_sandbox_provider(
        &state,
        authed_request(DetachSandboxProviderRequest {
            sandbox: SANDBOX.into(),
            provider: PROVIDER.into(),
            workspace_scope: Some(workspace_selector("default")),
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert!(detached.detached);
    let attached = handle_attach_sandbox_provider(
        &state,
        authed_request(AttachSandboxProviderRequest {
            sandbox: SANDBOX.into(),
            provider: PROVIDER.into(),
            workspace_scope: Some(workspace_selector("default")),
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert!(attached.attached);
    issuer.release.notify_one();

    let error = exchange.await.expect_err("reject the detached grant");
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    let new_token = handle(&state, request()).await.unwrap().into_inner();
    assert_eq!(new_token.access_token, "fixture-access-2");
    issuer_task.abort();
}
