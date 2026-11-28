// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::{Json, Router, extract::Path, extract::State, routing::post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openshell_bootstrap::jwt::generate_jwt_key;
use openshell_core::config::{GatewayJwtConfig, SpiffeWorkloadIdentityConfig};
use openshell_core::extension_protocol::{
    COMPUTE_ORDERED_PROVIDER_START, COMPUTE_PROVIDER_WORKLOAD_IDENTITY,
};
use openshell_core::proto::compute::v1::GetCapabilitiesRequest;
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriver as _;
use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::{
    NetworkAccessPreset, NetworkEndpoint, ProviderCredentialTokenGrantSubjectToken,
    ProviderProfile, ProviderProfileCategory, ProviderProfileCredential, SandboxPhase, SandboxSpec,
};
use rcgen::PublicKeyData as _;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::*;
use crate::auth::principal::{SandboxIdentitySource, SandboxPrincipal};
use crate::auth::sandbox_jwt::SandboxSessionJwtAuthority;
use crate::auth::sandbox_session::PersistedSandboxIdentity;
use crate::compute::ComputeRuntime;
use crate::grpc::test_support::test_server_state_without_provider_profiles;
use crate::persistence::current_time_ms;
use crate::spiffe_broker::SupervisorWorkloadIdentity;
use crate::test_support::FakeComputeDriver;

const GATEWAY_ID: &str = "performance-test-gateway";
const ASSERTION_AUDIENCE: &str = "https://issuer.test/";
const SUBJECT_KEY: &str = "subject_token";

#[derive(Default)]
struct Issuer {
    warm_calls: AtomicUsize,
    cold_calls: AtomicUsize,
    cold_started: Notify,
    release_cold: Notify,
}

async fn issue(
    State(issuer): State<Arc<Issuer>>,
    Path(grant): Path<String>,
) -> Json<serde_json::Value> {
    let count = match grant.as_str() {
        "warm" => issuer.warm_calls.fetch_add(1, Ordering::Relaxed) + 1,
        "cold" => {
            let count = issuer.cold_calls.fetch_add(1, Ordering::Relaxed) + 1;
            if count == 1 {
                issuer.cold_started.notify_one();
                issuer.release_cold.notified().await;
            }
            count
        }
        _ => panic!("unexpected grant route"),
    };
    Json(serde_json::json!({
        "access_token": format!("{grant}-{count}"),
        "token_type": "Bearer",
        "expires_in": 300,
    }))
}

struct Fixture {
    state: Arc<ServerState>,
    issuer: Arc<Issuer>,
    issuer_task: JoinHandle<()>,
    identity: SupervisorWorkloadIdentity,
    bundles: spiffe::JwtBundleSet,
    id: String,
    spiffe_id: String,
    launch_spiffe_id: String,
    launch_audience: String,
    bearer: String,
    assertion_key: jsonwebtoken::EncodingKey,
    assertion_header: jsonwebtoken::Header,
    warm_key: String,
    cold_key: String,
}

impl Fixture {
    #[allow(
        clippy::literal_string_with_formatting_args,
        reason = "Axum routes use braces for path parameters"
    )]
    async fn new(warm_ttl_seconds: i64, warm_subject: Option<&str>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let issuer = Arc::new(Issuer::default());
        let app = Router::new()
            .route("/{grant}", post(issue))
            .with_state(issuer.clone());
        let issuer_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let id = Uuid::new_v4().to_string();
        let provider_name = format!("grant-{id}");
        let mut state = test_server_state_without_provider_profiles().await;
        let server = Arc::get_mut(&mut state).unwrap();
        server.config.gateway_jwt = Some(GatewayJwtConfig {
            gateway_id: GATEWAY_ID.into(),
            ttl_secs: NonZeroU64::new(300),
            signing_key_path: PathBuf::default(),
            public_key_path: PathBuf::default(),
            kid_path: PathBuf::default(),
        });
        server.config.spiffe_workload_identity = Some(SpiffeWorkloadIdentityConfig {
            spiffe_id_prefix: "spiffe://test.example".into(),
            workload_api_socket_path: "/unused/test/workload.sock".into(),
        });

        let identity = SupervisorWorkloadIdentity::from_config(&server.config)
            .unwrap()
            .unwrap();
        let spiffe_id = identity.sandbox_spiffe_id(&id).unwrap();
        let driver = FakeComputeDriver::new();
        let mut capabilities = driver
            .get_capabilities(Request::new(GetCapabilitiesRequest::default()))
            .await
            .unwrap()
            .into_inner();
        capabilities
            .extension
            .as_mut()
            .unwrap()
            .supported_capabilities
            .extend([
                COMPUTE_PROVIDER_WORKLOAD_IDENTITY.into(),
                COMPUTE_ORDERED_PROVIDER_START.into(),
            ]);
        server.compute = ComputeRuntime::from_driver(
            "fake-compute-driver".into(),
            Arc::new(driver.with_capabilities(capabilities)),
            None,
            server.store.clone(),
            server.sandbox_index.clone(),
            server.sandbox_watch_bus.clone(),
            server.tracing_log_bus.clone(),
            server.supervisor_sessions.clone(),
        )
        .await
        .unwrap()
        .with_provider_workload_identity(Some(identity.clone()))
        .unwrap();

        let persisted = PersistedSandboxIdentity::new().unwrap();
        let launch_spiffe_id = identity
            .launch_spiffe_id(&id, persisted.provider_launch_id.unwrap())
            .unwrap();
        let launch_audience = persisted.runtime_generation.provider_spiffe_audience();
        let gateway_key = generate_jwt_key().unwrap();
        let authority = Arc::new(
            SandboxSessionJwtAuthority::from_pem(
                gateway_key.signing_key_pem.as_bytes(),
                gateway_key.public_key_pem.as_bytes(),
                gateway_key.kid,
                GATEWAY_ID,
                Some(Duration::from_mins(5)),
            )
            .unwrap(),
        );
        let bearer = authority
            .mint_persisted_launch(&id, &persisted)
            .unwrap()
            .supervisor
            .gateway_token
            .expose_secret()
            .to_owned();
        server.sandbox_session_jwt_authority = Some(authority);
        let metadata = |name: &str| ObjectMeta {
            id: name.into(),
            name: name.into(),
            workspace: "default".into(),
            ..Default::default()
        };
        let mut sandbox_meta = metadata(&id);
        persisted.write(&mut sandbox_meta.annotations);
        let mut sandbox = Sandbox {
            metadata: Some(sandbox_meta),
            spec: Some(SandboxSpec {
                providers: vec![provider_name.clone()],
                provider_attachment_epoch: "attachment".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        server.store.put_message(&sandbox).await.unwrap();
        let credential = |name: &str, header: &str, ttl_seconds| ProviderProfileCredential {
            name: name.into(),
            auth_style: "header".into(),
            header_name: header.into(),
            token_grant: Some(ProviderCredentialTokenGrant {
                token_endpoint: format!("{base_url}/{name}"),
                jwt_svid_audience: ASSERTION_AUDIENCE.into(),
                grant_type: ProviderCredentialTokenGrantType::ClientCredentials as i32,
                cache_ttl: Some(prost_types::Duration {
                    seconds: ttl_seconds,
                    nanos: 0,
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut warm = credential("warm", "X-Warm-Token", warm_ttl_seconds);
        let mut provider = Provider {
            metadata: Some(metadata(&provider_name)),
            r#type: format!("profile-{id}"),
            ..Default::default()
        };
        let mut subject_credentials = Vec::new();
        if let Some(value) = warm_subject {
            let grant = warm.token_grant.as_mut().unwrap();
            grant.grant_type = ProviderCredentialTokenGrantType::TokenExchange.into();
            grant.subject_token = Some(ProviderCredentialTokenGrantSubjectToken {
                source: "provider_credential".into(),
                credential: SUBJECT_KEY.into(),
                subject_token_type: oauth::ACCESS_TOKEN_TYPE.into(),
            });
            subject_credentials.push(ProviderProfileCredential {
                name: SUBJECT_KEY.into(),
                ..Default::default()
            });
            provider.credential_handles = server
                .credentials
                .store_provider_credentials(
                    &provider_name,
                    "default",
                    &provider_name,
                    &HashMap::from([(SUBJECT_KEY.into(), value.into())]),
                    &HashMap::new(),
                )
                .await
                .unwrap();
        }
        subject_credentials.extend([warm, credential("cold", "X-Cold-Token", 300)]);
        let profile = ProviderProfile {
            id: provider.r#type.clone(),
            display_name: "Grant performance test profile".into(),
            category: ProviderProfileCategory::Other as i32,
            endpoints: vec![NetworkEndpoint {
                host: "api.example.test".into(),
                port: 443,
                path: "/**".into(),
                protocol: "rest".into(),
                access: NetworkAccessPreset::Full as i32,
                ..Default::default()
            }],
            credentials: subject_credentials,
            ..Default::default()
        };
        let mut credentials = HashMap::new();
        insert_dynamic_credentials_for_profile(
            &mut credentials,
            &openshell_providers::ProviderTypeProfile::from_proto(&profile),
            &provider_name,
            &provider_name,
        )
        .unwrap();
        let key = |name| {
            credentials
                .keys()
                .find(|key| key.ends_with(name))
                .unwrap()
                .clone()
        };
        let (warm_key, cold_key) = (key(":warm"), key(":cold"));
        server.store.put_message(&provider).await.unwrap();
        server
            .store
            .put_message(&crate::provider_profile_sources::stored_provider_profile(
                profile,
            ))
            .await
            .unwrap();

        let key =
            openshell_crypto::pki::generate_keypair_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let public_key = key.der_bytes();
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "EC", "crv": "P-256", "alg": "ES256", "kid": "workload-test",
                "x": URL_SAFE_NO_PAD.encode(&public_key[1..33]),
                "y": URL_SAFE_NO_PAD.encode(&public_key[33..65]),
            }]
        });
        let mut bundles = spiffe::JwtBundleSet::new();
        bundles.add_bundle(
            spiffe::JwtBundle::from_jwt_authorities(
                spiffe::TrustDomain::new("test.example").unwrap(),
                &serde_json::to_vec(&jwks).unwrap(),
            )
            .unwrap(),
        );
        let assertion_key =
            jsonwebtoken::EncodingKey::from_ec_pem(key.serialize_pem().unwrap().as_bytes())
                .unwrap();
        let mut assertion_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        assertion_header.kid = Some("workload-test".into());
        identity.seed_test_jwt_bundles(bundles.clone()).await;

        Self {
            state,
            issuer,
            issuer_task,
            identity,
            bundles,
            id,
            spiffe_id,
            launch_spiffe_id,
            launch_audience,
            bearer,
            assertion_key,
            assertion_header,
            warm_key,
            cold_key,
        }
    }

    fn request(&self, key: &str, expires_at: i64) -> Request<GetSandboxProviderAccessTokenRequest> {
        let sign = |subject: &str, audience: &str| {
            openshell_crypto::jwt::encode(
                &self.assertion_header,
                &serde_json::json!({
                    "sub": subject,
                    "aud": [audience],
                    "exp": expires_at,
                }),
                &self.assertion_key,
            )
            .unwrap()
        };
        let mut request = Request::new(GetSandboxProviderAccessTokenRequest {
            credential_key: key.into(),
            jwt_svid: Some(sign(&self.spiffe_id, ASSERTION_AUDIENCE)),
            launch_jwt_svid: Some(sign(&self.launch_spiffe_id, &self.launch_audience)),
        });
        request
            .extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: self.id.clone(),
                source: SandboxIdentitySource::BootstrapJwt {
                    issuer: format!("openshell-gateway:{GATEWAY_ID}"),
                    auth_epoch: None,
                },
                trust_domain: None,
            }));
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", self.bearer).parse().unwrap(),
        );
        request
    }

    async fn fingerprint(&self, key: &str) -> String {
        let (session, sandbox, launch_id) = authorize(&self.state, &self.bearer).await.unwrap();
        let configured = grant_configuration(&self.state, &sandbox, key)
            .await
            .unwrap();
        let subject = resolve_subject(&self.state, &configured).await.unwrap();
        cache_key(
            &session,
            launch_id,
            &configured,
            subject.as_ref().map(|subject| subject.value.as_str()),
            GATEWAY_ID,
        )
        .unwrap()
    }

    fn spawn_request(
        &self,
        key: &str,
        expires_at: i64,
    ) -> JoinHandle<Result<Response<GetSandboxProviderAccessTokenResponse>, Status>> {
        let state = self.state.clone();
        let request = self.request(key, expires_at);
        tokio::spawn(async move { handle(&state, request).await })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.issuer_task.abort();
    }
}

fn registered(fingerprint: &str) -> usize {
    ACQUISITIONS
        .lock()
        .get(fingerprint)
        .map_or(0, |(_, users)| *users)
}

async fn wait_until(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("requests reached acquisition admission");
}

#[tokio::test]
async fn a_one_second_ttl_reuses_a_live_token() {
    let fixture = Fixture::new(1, None).await;
    let expires = current_time_ms() / 1000 + 60;
    let first = handle(&fixture.state, fixture.request(&fixture.warm_key, expires))
        .await
        .unwrap()
        .into_inner();
    let second = handle(&fixture.state, fixture.request(&fixture.warm_key, expires))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(first.access_token, "warm-1");
    assert_eq!(second.access_token, first.access_token);
    assert_eq!(fixture.issuer.warm_calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn dedicated_cold_waiters_leave_capacity_for_warm_grants() {
    let fixture = Fixture::new(300, None).await;
    let expires = current_time_ms() / 1000 + 60;
    let warm = handle(&fixture.state, fixture.request(&fixture.warm_key, expires))
        .await
        .unwrap()
        .into_inner();
    let fingerprint = fixture.fingerprint(&fixture.cold_key).await;
    let leader = fixture.spawn_request(&fixture.cold_key, expires);
    tokio::time::timeout(
        Duration::from_secs(5),
        fixture.issuer.cold_started.notified(),
    )
    .await
    .expect("cold leader started its OAuth request");
    let waiters: Vec<_> = (1..PER_SANDBOX_VERIFIED_REQUEST_LIMIT)
        .map(|_| fixture.spawn_request(&fixture.cold_key, expires))
        .collect();
    wait_until(|| {
        registered(&fingerprint) + waiters.iter().filter(|task| task.is_finished()).count()
            == PER_SANDBOX_VERIFIED_REQUEST_LIMIT
    })
    .await;
    fixture
        .identity
        .seed_test_jwt_bundles(fixture.bundles.clone())
        .await;

    let cached = tokio::time::timeout(
        Duration::from_secs(5),
        handle(&fixture.state, fixture.request(&fixture.warm_key, expires)),
    )
    .await
    .expect("warm request returned while cold leader was blocked")
    .unwrap()
    .into_inner();
    assert_eq!(cached.access_token, warm.access_token);
    assert_eq!(fixture.issuer.warm_calls.load(Ordering::Relaxed), 1);

    fixture.issuer.release_cold.notify_one();
    assert_eq!(
        leader.await.unwrap().unwrap().into_inner().access_token,
        "cold-1"
    );
    let mut refused = 0;
    for waiter in waiters {
        match waiter.await.unwrap() {
            Ok(response) => assert_eq!(response.into_inner().access_token, "cold-1"),
            Err(error) => {
                assert_eq!(error.code(), tonic::Code::ResourceExhausted);
                refused += 1;
            }
        }
    }
    assert!(refused > 0);
    assert_eq!(fixture.issuer.cold_calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_queued_expired_proof_does_not_fail_a_fresh_waiter() {
    let fixture = Fixture::new(300, None).await;
    let fingerprint = fixture.fingerprint(&fixture.warm_key).await;
    let occupied = ACQUISITIONS.turn(&fingerprint).await.unwrap();
    let now = current_time_ms();
    let short_expiry = now / 1000 + 3;
    let short = fixture.spawn_request(&fixture.warm_key, short_expiry);
    wait_until(|| registered(&fingerprint) == 2).await;
    let fresh = fixture.spawn_request(&fixture.warm_key, now / 1000 + 60);
    wait_until(|| registered(&fingerprint) == 3).await;
    let remaining = short_expiry.saturating_mul(1000) - current_time_ms();
    tokio::time::sleep(Duration::from_millis(u64::try_from(remaining).unwrap_or(0))).await;
    drop(occupied);

    let error = short.await.unwrap().unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    let response = fresh.await.unwrap().unwrap().into_inner();
    assert_eq!(response.access_token, "warm-1");
    assert_eq!(fixture.issuer.warm_calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn queued_token_exchange_rejects_a_subject_rotated_under_the_same_handle() {
    let fixture = Fixture::new(300, Some("original-subject")).await;
    let old_fingerprint = fixture.fingerprint(&fixture.warm_key).await;
    let occupied = ACQUISITIONS.turn(&old_fingerprint).await.unwrap();
    let expires_at = current_time_ms() / 1000 + 60;
    let waiter = fixture.spawn_request(&fixture.warm_key, expires_at);
    wait_until(|| registered(&old_fingerprint) == 2).await;

    let provider_id = format!("grant-{}", fixture.id);
    let provider = fixture
        .state
        .store
        .get_message::<Provider>(&provider_id)
        .await
        .unwrap()
        .unwrap();
    let replacement_handles = fixture
        .state
        .credentials
        .store_provider_credentials(
            &provider_id,
            "default",
            &provider_id,
            &HashMap::from([(SUBJECT_KEY.into(), "replacement-subject".into())]),
            &provider.credential_handles,
        )
        .await
        .unwrap();
    assert_eq!(replacement_handles, provider.credential_handles);
    let new_fingerprint = fixture.fingerprint(&fixture.warm_key).await;
    assert_ne!(new_fingerprint, old_fingerprint);

    // Publish the result for the original subject while the request is still
    // waiting for the acquisition that produced it.
    let cache = |fingerprint, token: &str| {
        ACCESS_TOKENS.set(
            fingerprint,
            &oauth::OAuthTokenResponse {
                access_token: token.into(),
                token_type: "Bearer".into(),
                expires_in: 60,
            },
            current_time_ms() + 60_000,
        );
    };
    cache(old_fingerprint, "old-access-token");
    drop(occupied);

    let error = waiter.await.unwrap().unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    cache(new_fingerprint, "new-access-token");
    let response = handle(
        &fixture.state,
        fixture.request(&fixture.warm_key, expires_at),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(response.access_token, "new-access-token");
    assert_eq!(fixture.issuer.warm_calls.load(Ordering::Relaxed), 0);
}
