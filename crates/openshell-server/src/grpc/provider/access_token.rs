// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-owned sandbox identity and provider-token acquisition.
//! The caller selects an attached configured credential, never grant parameters.
use super::{
    Arc, HashMap, IntermediateTokenCache, LazyLock, Message, ObjectId, ObjectName, ObjectWorkspace,
    Principal, Provider, ProviderCredentialTokenGrantType, Request, Response, Sandbox, ServerState,
    Status, TokenExchangeParams, TokenGrantFailure, TokenGrantFailureKind, TokenGrantStage,
    canonical_request_id, effective_jwt_svid_audience, fetch_gateway_jwt_svid_from,
    get_provider_type_profile_for_scope, insert_dynamic_credentials_for_profile, jwt_exp_ms,
    log_token_grant_failure, oauth, perform_intermediate_token_exchange,
    resolve_subject_token_credential, sanitize_token_grant_status, token_exchange_http_client,
    token_grant_authorization_required_status, token_grant_configuration_status,
    token_grant_dependency_status, token_grant_identity_rejected, token_grant_store_status,
};
use openshell_core::jwt::AuthenticatedSandboxSession;
use openshell_core::proto::{
    GetSandboxProviderAccessTokenRequest, GetSandboxProviderAccessTokenResponse,
    ProviderCredentialTokenGrant,
};
use openshell_core::token_grant_failure::{
    BROKERED_TOKEN_GATEWAY_DEADLINE, WORKLOAD_IDENTITY_CALL_TIMEOUT,
};
use openshell_spiffe::{SandboxIdentityProvider, SandboxJwtSvid};
use std::time::Duration;
use uuid::Uuid;

#[cfg(test)]
mod detach_tests;

static ACCESS_TOKENS: LazyLock<IntermediateTokenCache> = LazyLock::new(IntermediateTokenCache::new);
static ACQUISITIONS: LazyLock<Acquisitions> = LazyLock::new(Acquisitions::default);
static REQUEST_ADMISSION: LazyLock<Admission> = LazyLock::new(Admission::default);
static EXCHANGE_ADMISSION: LazyLock<Admission> = LazyLock::new(Admission::default);
static MISS_ADMISSION: LazyLock<Admission> = LazyLock::new(Admission::default);
const PER_SANDBOX_EXCHANGE_LIMIT: usize = 4;
const PER_SANDBOX_VERIFIED_REQUEST_LIMIT: usize = 16;
// Reserve request capacity for warm grants while other grants wait on OAuth.
const PER_SANDBOX_MISS_LIMIT: usize =
    PER_SANDBOX_VERIFIED_REQUEST_LIMIT - PER_SANDBOX_EXCHANGE_LIMIT;

pub(in crate::grpc) async fn handle(
    state: &Arc<ServerState>,
    request: Request<GetSandboxProviderAccessTokenRequest>,
) -> Result<Response<GetSandboxProviderAccessTokenResponse>, Status> {
    let request_id = canonical_request_id(request.metadata());
    // Failures go to the authenticated sandbox's log stream; other callers
    // are logged on the gateway only.
    let log_sandbox_id = match request.extensions().get::<Principal>() {
        Some(Principal::Sandbox(principal)) => Some(principal.sandbox_id.clone()),
        _ => None,
    };
    // The deadline also bounds waiting for a concurrent acquisition.
    let result = tokio::time::timeout(
        BROKERED_TOKEN_GATEWAY_DEADLINE,
        obtain(state, request, request_id.as_deref()),
    )
    .await
    .unwrap_or_else(|_| {
        Err(
            TokenGrantFailure::new(TokenGrantFailureKind::Timeout, TokenGrantStage::GatewayRpc)
                .to_status(),
        )
    });
    result.map_err(|status| {
        let status = sanitize_token_grant_status(status);
        log_token_grant_failure(
            log_sandbox_id.as_deref(),
            request_id.as_deref(),
            TokenGrantFailure::from_status(&status),
        );
        status
    })
}

/// Verify the original bearer again after asynchronous work, including expiry
/// and the persisted generation, epoch, active phase, and current token lineage.
async fn authorize(
    state: &ServerState,
    bearer: &str,
) -> Result<(AuthenticatedSandboxSession, Sandbox, Option<Uuid>), Status> {
    let authority = state
        .sandbox_session_jwt_authority
        .as_ref()
        .ok_or_else(|| token_grant_identity_rejected(tonic::Code::Unauthenticated))?;
    let session = authority
        .verify_gateway_token(bearer)
        .map_err(|error| error.status)?;
    if session.expires_at.saturating_mul(1000) <= crate::persistence::current_time_ms() {
        return Err(token_grant_identity_rejected(tonic::Code::Unauthenticated));
    }
    let (sandbox, persisted) =
        crate::auth::sandbox_session::authorize_persisted_sandbox(&state.store, &session)
            .await
            .map_err(|error| error.status)?;
    Ok((session, sandbox, persisted.provider_launch_id))
}

/// One configured credential of an attached provider.
struct ConfiguredGrant {
    provider: Provider,
    grant: ProviderCredentialTokenGrant,
    /// The gateway's exact key for the credential, including its endpoint owner.
    key: String,
    attachment_epoch: String,
}

#[allow(clippy::result_large_err)]
fn provider_attachment<'a>(sandbox: &'a Sandbox, provider_name: &str) -> Result<&'a str, Status> {
    sandbox
        .spec
        .as_ref()
        .filter(|spec| spec.providers.iter().any(|name| name == provider_name))
        .map(|spec| spec.provider_attachment_epoch.as_str())
        .ok_or_else(|| token_grant_configuration_status(tonic::Code::PermissionDenied))
}

/// Resolve the exact configured credential from the gateway's approved profile.
/// Audience and scopes (including endpoint overrides) never come from the caller.
///
/// The caller's key must name a configured key exactly, apart from the
/// generation a supervisor adds; a different or missing owner matches nothing.
async fn grant_configuration(
    state: &ServerState,
    sandbox: &Sandbox,
    key: &str,
) -> Result<ConfiguredGrant, Status> {
    let invalid = || token_grant_configuration_status(tonic::Code::PermissionDenied);
    let key =
        openshell_core::dynamic_credential_key::unscoped_owned_key(key).ok_or_else(invalid)?;
    let identity =
        openshell_core::dynamic_credential_key::credential_identity(&key).ok_or_else(invalid)?;
    let (provider_name, _) = identity.split_once(':').ok_or_else(invalid)?;
    let attachment_epoch = provider_attachment(sandbox, provider_name)?.to_owned();
    let provider = state
        .store
        .get_message_by_name::<Provider>(sandbox.object_workspace(), provider_name)
        .await
        .map_err(|_| token_grant_store_status())?
        .ok_or_else(invalid)?;
    let catalog = state
        .provider_profile_sources
        .profile_catalog(&state.store, sandbox.object_workspace(), &provider.r#type)
        .await
        .map_err(token_grant_dependency_status)?;
    let profile = get_provider_type_profile_for_scope(
        &catalog,
        &provider.r#type,
        &provider.profile_workspace,
    )
    .ok_or_else(invalid)?;
    let mut configured = HashMap::new();
    insert_dynamic_credentials_for_profile(
        &mut configured,
        &profile,
        provider_name,
        provider.object_id(),
    )?;
    let credential = configured.remove(&key).ok_or_else(invalid)?;
    let grant = credential.token_grant.ok_or_else(invalid)?;
    oauth::parse_token_endpoint_url(&grant.token_endpoint).map_err(TokenGrantFailure::to_status)?;
    Ok(ConfiguredGrant {
        provider,
        grant,
        key,
        attachment_epoch,
    })
}

/// Bind a cached token to its runtime, configured credential, and subject.
///
/// Include the provider revision and resolved subject token. A request
/// that resolves a rotated subject gets a different key. The digest is an
/// in-memory map key and is never exposed.
fn cache_key(
    session: &AuthenticatedSandboxSession,
    provider_launch_id: Option<Uuid>,
    configured: &ConfiguredGrant,
    subject: Option<&str>,
    gateway_id: &str,
) -> Result<String, Status> {
    let resource_version = configured
        .provider
        .metadata
        .as_ref()
        .map_or(0, |metadata| metadata.resource_version);
    let fields: [&[u8]; 13] = [
        b"openshell-provider-access-token-v1",
        gateway_id.as_bytes(),
        session.sandbox_id.as_str().as_bytes(),
        session.runtime_generation.as_str().as_bytes(),
        &session.auth_epoch.get().to_be_bytes(),
        provider_launch_id.as_ref().map_or(&[], |id| id.as_bytes()),
        configured.attachment_epoch.as_bytes(),
        configured.provider.object_id().as_bytes(),
        &resource_version.to_be_bytes(),
        configured.key.as_bytes(),
        &Message::encode_to_vec(&configured.grant),
        &[u8::from(subject.is_some())],
        subject.map_or(&[], str::as_bytes),
    ];
    digest_fields(&fields)
        .map(hex::encode)
        .map_err(|_| token_grant_configuration_status(tonic::Code::Internal))
}

/// SHA-256 of length-prefixed fields, so no two field lists share an encoding.
fn digest_fields(fields: &[&[u8]]) -> Result<[u8; 32], openshell_crypto::CryptoError> {
    let mut digest = openshell_crypto::sha256_digest()?;
    for field in fields {
        digest.update(&u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes())?;
        digest.update(field)?;
    }
    digest.finish()
}

/// The subject token of a token exchange grant, resolved for this request.
struct Subject {
    value: String,
    token_type: String,
    expires_at_ms: Option<i64>,
}

async fn resolve_subject(
    state: &ServerState,
    configured: &ConfiguredGrant,
) -> Result<Option<Subject>, Status> {
    let configuration_failure =
        || token_grant_configuration_status(tonic::Code::FailedPrecondition);
    let grant_type = ProviderCredentialTokenGrantType::try_from(configured.grant.grant_type)
        .map_err(|_| configuration_failure())?;
    if grant_type != ProviderCredentialTokenGrantType::TokenExchange {
        return Ok(None);
    }
    let subject = configured
        .grant
        .subject_token
        .as_ref()
        .filter(|subject| subject.source == "provider_credential")
        .ok_or_else(configuration_failure)?;
    let (value, expires_at_ms) = resolve_subject_token_credential(
        &state.credentials,
        &configured.provider,
        &subject.credential,
    )
    .await?;
    Ok(Some(Subject {
        expires_at_ms,
        value,
        token_type: subject.subject_token_type.clone(),
    }))
}

/// Recheck the authorized grant and session after waits and before exposing
/// credentials to the issuer or returning an access token to the sandbox.
struct GrantAuthorization<'a> {
    state: &'a ServerState,
    bearer: &'a str,
    session: &'a AuthenticatedSandboxSession,
    provider_launch_id: Option<Uuid>,
    key: &'a str,
    gateway_id: &'a str,
    fingerprint: &'a str,
    subject: Option<&'a Subject>,
    revalidate_subject: bool,
}

impl GrantAuthorization<'_> {
    async fn authorize_launch(&self) -> Result<Sandbox, Status> {
        let (_, sandbox, provider_launch_id) = authorize(self.state, self.bearer).await?;
        if provider_launch_id != self.provider_launch_id {
            return Err(token_grant_identity_rejected(tonic::Code::PermissionDenied));
        }
        Ok(sandbox)
    }

    async fn revalidate(&self) -> Result<Option<i64>, Status> {
        let sandbox = self.authorize_launch().await?;
        let current = grant_configuration(self.state, &sandbox, self.key).await?;
        let resolved;
        let subject = if self.revalidate_subject {
            // A driver can replace a subject without changing the Provider row.
            resolved = resolve_subject(self.state, &current).await?;
            resolved.as_ref()
        } else {
            self.subject
        };
        let subject_value = subject.map(|subject| subject.value.as_str());
        if cache_key(
            self.session,
            self.provider_launch_id,
            &current,
            subject_value,
            self.gateway_id,
        )? != self.fingerprint
        {
            return Err(token_grant_configuration_status(
                tonic::Code::FailedPrecondition,
            ));
        }
        // Profile and subject lookup may await storage. Check the attachment
        // and session on the same fresh snapshot afterward.
        let sandbox = self.authorize_launch().await?;
        if provider_attachment(&sandbox, current.provider.object_name())?
            != current.attachment_epoch
        {
            return Err(token_grant_configuration_status(
                tonic::Code::FailedPrecondition,
            ));
        }
        let subject_expiry = [self.subject, subject]
            .into_iter()
            .flatten()
            .filter_map(|subject| subject.expires_at_ms)
            .min();
        if subject_expiry.is_some_and(|expiry| expiry <= crate::persistence::current_time_ms()) {
            return Err(token_grant_authorization_required_status());
        }
        Ok(subject_expiry)
    }
}

#[derive(Clone, Copy)]
enum GrantIdentity<'a> {
    Broker(&'a dyn SandboxIdentityProvider<Error = TokenGrantFailure>),
    Supervisor(&'a SandboxJwtSvid),
}

impl GrantIdentity<'_> {
    #[allow(clippy::result_large_err)]
    fn cache_ttl_override(
        self,
        grant: &ProviderCredentialTokenGrant,
    ) -> Result<Option<Duration>, Status> {
        let ttl = grant
            .cache_ttl
            .as_ref()
            .map(openshell_core::time::duration_to_std)
            .transpose()
            .map_err(|_| token_grant_configuration_status(tonic::Code::InvalidArgument))?;
        if ttl.is_some_and(|ttl| !ttl.is_zero() && ttl < Duration::from_secs(1)) {
            return match self {
                Self::Broker(_) => Err(token_grant_configuration_status(
                    tonic::Code::InvalidArgument,
                )),
                // Direct grants accepted fractional overrides. Keep those
                // grants usable by exchanging without caching.
                Self::Supervisor(_) => Ok(Some(Duration::ZERO)),
            };
        }
        Ok(ttl)
    }
}

async fn validate_workload_assertion(
    identity: &crate::spiffe_broker::SupervisorWorkloadIdentity,
    session: &AuthenticatedSandboxSession,
    provider_launch_id: Uuid,
    grant: &ProviderCredentialTokenGrant,
    token: &str,
    launch_token: &str,
) -> Result<SandboxJwtSvid, Status> {
    let expected_id = identity
        .sandbox_spiffe_id(session.sandbox_id.as_str())
        .map_err(|_| token_grant_configuration_status(tonic::Code::FailedPrecondition))?;
    let expected_launch_id = identity
        .launch_spiffe_id(session.sandbox_id.as_str(), provider_launch_id)
        .map_err(|_| token_grant_configuration_status(tonic::Code::FailedPrecondition))?;
    let audience = effective_jwt_svid_audience(&grant.token_endpoint, &grant.jwt_svid_audience);
    let launch_audience = session.runtime_generation.provider_spiffe_audience();
    let bundles = tokio::time::timeout(WORKLOAD_IDENTITY_CALL_TIMEOUT, identity.jwt_bundles())
        .await
        .map_err(|_| {
            TokenGrantFailure::new(
                TokenGrantFailureKind::Timeout,
                TokenGrantStage::WorkloadIdentity,
            )
            .to_status()
        })?
        .map_err(|error| {
            super::token_grant_workload_api_status(error, tonic::Code::FailedPrecondition)
        })?;
    verify_workload_assertion(
        token,
        launch_token,
        &bundles,
        expected_id,
        &expected_launch_id,
        &audience,
        &launch_audience,
    )
}

fn verify_workload_assertion(
    token: &str,
    launch_token: &str,
    bundles: &spiffe::JwtBundleSet,
    expected_id: String,
    expected_launch_id: &str,
    audience: &str,
    launch_audience: &str,
) -> Result<SandboxJwtSvid, Status> {
    let rejection = || token_grant_identity_rejected(tonic::Code::PermissionDenied);
    openshell_crypto::install_jwt_provider();
    if expected_id == expected_launch_id || audience == launch_audience {
        return Err(rejection());
    }
    let verify = |token: &str, expected_id: &str, audience: &str| {
        let svid = spiffe::JwtSvid::parse_and_validate(token, bundles, &[audience])
            .map_err(|_| rejection())?;
        let expires_at = svid.expiry().unix_timestamp();
        if svid.spiffe_id().to_string() != expected_id
            || svid.audience().len() != 1
            || expires_at.saturating_mul(1000) <= crate::persistence::current_time_ms()
        {
            return Err(rejection());
        }
        Ok(expires_at)
    };
    let expires_at = verify(token, &expected_id, audience)?.min(verify(
        launch_token,
        expected_launch_id,
        launch_audience,
    )?);
    Ok(SandboxJwtSvid {
        spiffe_id: expected_id,
        token: token.to_string(),
        expires_at,
    })
}

#[allow(clippy::too_many_lines)]
async fn obtain(
    state: &Arc<ServerState>,
    request: Request<GetSandboxProviderAccessTokenRequest>,
    request_id: Option<&str>,
) -> Result<Response<GetSandboxProviderAccessTokenResponse>, Status> {
    let Some(Principal::Sandbox(principal)) = request.extensions().get::<Principal>() else {
        return Err(token_grant_identity_rejected(tonic::Code::PermissionDenied));
    };
    let mut values = request.metadata().get_all("authorization").iter();
    let bearer = values
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(openshell_core::auth::strip_bearer_scheme)
        .ok_or_else(|| token_grant_identity_rejected(tonic::Code::Unauthenticated))?
        .to_string();
    if values.next().is_some() {
        return Err(token_grant_identity_rejected(tonic::Code::Unauthenticated));
    }
    let (session, sandbox, provider_launch_id) = authorize(state, &bearer).await?;
    if principal.sandbox_id != session.sandbox_id.as_str() {
        return Err(token_grant_identity_rejected(tonic::Code::PermissionDenied));
    }
    let unavailable = || token_grant_configuration_status(tonic::Code::FailedPrecondition);
    let gateway_jwt = state.config.gateway_jwt.as_ref().ok_or_else(unavailable)?;
    let supplied = request.get_ref().jwt_svid.as_deref();
    let launch_proof = request.get_ref().launch_jwt_svid.as_deref();
    let supervisor_identity = state.compute.provider_workload_identity();
    let broker = state.sandbox_identity.as_deref();
    if supervisor_identity.is_none()
        && (broker.is_none() || state.compute.configured_driver_name() != "kubernetes")
    {
        return Err(unavailable());
    }
    let assertions = match (supervisor_identity, supplied, launch_proof) {
        (Some(identity), Some(provider), Some(launch)) => Some((identity, provider, launch)),
        (None, None, None) => None,
        (Some(_), None, None) | (None, Some(_), Some(_)) => return Err(unavailable()),
        _ => return Err(token_grant_identity_rejected(tonic::Code::PermissionDenied)),
    };
    // Keep grant requests bounded. Verified requests have a separate, lower
    // limit on OAuth exchanges so cache hits do not consume exchange slots.
    let dedicated = supervisor_identity.is_some();
    let request_limit = if dedicated {
        PER_SANDBOX_VERIFIED_REQUEST_LIMIT
    } else {
        PER_SANDBOX_EXCHANGE_LIMIT
    };
    let _request_admission = REQUEST_ADMISSION.enter(session.sandbox_id.as_str(), request_limit)?;
    let gateway_id = gateway_jwt.gateway_id.as_str();
    let key = &request.get_ref().credential_key;
    let configured = grant_configuration(state, &sandbox, key).await?;
    let grant = &configured.grant;
    // Every dedicated request presents a verified assertion, including cache hits.
    let assertion;
    let identity = match assertions {
        Some((identity, token, launch_proof)) => {
            assertion = validate_workload_assertion(
                identity,
                &session,
                provider_launch_id.ok_or_else(unavailable)?,
                grant,
                token,
                launch_proof,
            )
            .await?;
            GrantIdentity::Supervisor(&assertion)
        }
        None => GrantIdentity::Broker(broker.ok_or_else(unavailable)?),
    };
    let ttl_override = identity.cache_ttl_override(grant)?;
    // Resolve the subject before any cache lookup so its value binds the token.
    let subject = resolve_subject(state, &configured).await?;
    let subject_value = subject.as_ref().map(|subject| subject.value.as_str());
    let fingerprint = cache_key(
        &session,
        provider_launch_id,
        &configured,
        subject_value,
        gateway_id,
    )?;
    let authorization = GrantAuthorization {
        state,
        bearer: &bearer,
        session: &session,
        provider_launch_id,
        key,
        gateway_id,
        fingerprint: &fingerprint,
        subject: subject.as_ref(),
        revalidate_subject: dedicated && subject.is_some(),
    };
    // A zero override disables caching, and with it shared acquisition.
    let caching = ttl_override != Some(Duration::ZERO);
    let mut retried_expired_hit = false;
    loop {
        let cached = || {
            caching
                .then(|| ACCESS_TOKENS.get_until(&fingerprint))
                .flatten()
        };
        // A miss holds its fingerprint's turn until its token is cached, so
        // concurrent misses wait and then find it. A miss is cached only after
        // the final validation below, which a hit passes as well.
        let mut turn = None;
        let miss_admission;
        let (response, serve_until_ms, acquired) = if let Some((token, until)) = cached() {
            miss_admission = None;
            (token, until, false)
        } else {
            miss_admission = dedicated
                .then(|| MISS_ADMISSION.enter(session.sandbox_id.as_str(), PER_SANDBOX_MISS_LIMIT))
                .transpose()?;
            let waited = if caching {
                let waited = ACQUISITIONS.turn(&fingerprint).await;
                if let GrantIdentity::Supervisor(svid) = identity {
                    require_live_assertion(svid, crate::persistence::current_time_ms())?;
                }
                Some(waited?)
            } else {
                None
            };
            if let Some((token, until)) = cached() {
                (token, until, false)
            } else {
                turn = waited;
                let _exchange_admission = dedicated
                    .then(|| {
                        EXCHANGE_ADMISSION
                            .enter(session.sandbox_id.as_str(), PER_SANDBOX_EXCHANGE_LIMIT)
                    })
                    .transpose()?;
                let (token, until) =
                    acquire(&authorization, identity, grant, ttl_override, request_id)
                        .await
                        .inspect_err(|status| {
                            if let Some(turn) = turn.as_mut() {
                                turn.record_failure(status);
                            }
                        })?;
                (token, until, true)
            }
        };
        let subject_expiry = authorization.revalidate().await?;
        // The lifetime runs from when the token service answered, so time spent
        // in the final validation counts against it.
        let now_ms = crate::persistence::current_time_ms();
        if subject_expiry.is_some_and(|expiry| expiry <= now_ms) {
            return Err(token_grant_authorization_required_status());
        }
        let serve_until_ms = serve_until_ms.min(subject_expiry.unwrap_or(i64::MAX));
        let request_expires_at_ms = match identity {
            GrantIdentity::Broker(_) => serve_until_ms,
            GrantIdentity::Supervisor(svid) => {
                require_live_assertion(svid, now_ms)?;
                serve_until_ms.min(svid.expires_at.saturating_mul(1000))
            }
        };
        let remaining_ms = request_expires_at_ms.saturating_sub(now_ms);
        if remaining_ms <= 0 && !acquired && !retried_expired_hit {
            // Another request may already have refreshed the expired entry.
            retried_expired_hit = true;
            continue;
        }
        if remaining_ms <= 0 {
            return Err(TokenGrantFailure::new(
                TokenGrantFailureKind::Timeout,
                TokenGrantStage::GatewayRpc,
            )
            .to_status());
        }
        if acquired && caching {
            ACCESS_TOKENS.set(fingerprint, &response, serve_until_ms);
        }
        drop(turn);
        let response = Response::new(GetSandboxProviderAccessTokenResponse {
            access_token: response.access_token,
            token_type: response.token_type,
            expires_after: openshell_core::time::duration_from_std(Duration::from_millis(
                u64::try_from(remaining_ms).unwrap_or_default(),
            ))
            .ok(),
        });
        drop(miss_admission);
        return Ok(response);
    }
}

#[allow(clippy::result_large_err)]
fn require_live_assertion(svid: &SandboxJwtSvid, now_ms: i64) -> Result<(), Status> {
    if svid.expires_at.saturating_mul(1000) <= now_ms {
        return Err(token_grant_identity_rejected(tonic::Code::PermissionDenied));
    }
    Ok(())
}

/// Acquire a final token, rechecking the grant before each OAuth exchange.
/// Returns the token and when to stop serving it.
async fn acquire(
    authorization: &GrantAuthorization<'_>,
    identity: GrantIdentity<'_>,
    grant: &ProviderCredentialTokenGrant,
    ttl_override: Option<Duration>,
    request_id: Option<&str>,
) -> Result<(oauth::OAuthTokenResponse, i64), Status> {
    let GrantAuthorization {
        state,
        bearer,
        session,
        gateway_id,
        subject,
        ..
    } = *authorization;
    let audience = effective_jwt_svid_audience(&grant.token_endpoint, &grant.jwt_svid_audience);
    let issued;
    let svid = match identity {
        GrantIdentity::Broker(provider) => {
            let (_, sandbox, _) = authorize(state, bearer).await?;
            let runtime_identity = sandbox
                .metadata
                .as_ref()
                .and_then(|metadata| {
                    metadata
                        .annotations
                        .get(crate::compute::COMPUTE_RUNTIME_IDENTITY_ANNOTATION)
                })
                .map_or("", String::as_str);
            issued = provider
                .fetch_jwt_svid(
                    gateway_id,
                    session.sandbox_id.as_str(),
                    &audience,
                    runtime_identity,
                )
                .await
                .map_err(TokenGrantFailure::to_status)?;
            &issued
        }
        GrantIdentity::Supervisor(svid) => svid,
    };
    let check_expiry = || require_live_assertion(svid, crate::persistence::current_time_ms());
    check_expiry()?;
    let client = token_exchange_http_client()?;
    let mut subject_expiry = i64::MAX;
    let token = if let Some(subject) = subject {
        if matches!(identity, GrantIdentity::Supervisor(_)) {
            authorization.authorize_launch().await?;
        }
        let component_socket = state
            .config
            .spiffe_workload_identity
            .as_ref()
            .and_then(|identity| identity.workload_api_socket_path.to_str())
            .or_else(|| {
                state
                    .config
                    .spiffe_broker
                    .as_ref()
                    .map(|broker| broker.workload_api_socket_path.as_str())
            });
        let component_svid = fetch_gateway_jwt_svid_from(&audience, component_socket).await?;
        subject_expiry = authorization.revalidate().await?.unwrap_or(i64::MAX);
        check_expiry()?;
        let intermediate = perform_intermediate_token_exchange(
            &grant.token_endpoint,
            &TokenExchangeParams {
                client_assertion: &component_svid,
                client_assertion_type: &grant.client_assertion_type,
                subject_token: &subject.value,
                subject_token_type: &subject.token_type,
                audience: &svid.spiffe_id,
                scopes: &[],
                requested_token_type: &grant.requested_token_type,
            },
            request_id,
        )
        .await?;
        subject_expiry = subject_expiry.min(authorization.revalidate().await?.unwrap_or(i64::MAX));
        check_expiry()?;
        oauth::post_oauth_token_exchange(
            client,
            &grant.token_endpoint,
            &TokenExchangeParams {
                client_assertion: &svid.token,
                client_assertion_type: &grant.client_assertion_type,
                subject_token: &intermediate.access_token,
                subject_token_type: oauth::ACCESS_TOKEN_TYPE,
                audience: &grant.audience,
                scopes: &grant.scopes,
                requested_token_type: &grant.requested_token_type,
            },
            request_id,
        )
        .await
        .map_err(TokenGrantFailure::to_status)?
    } else {
        authorization.revalidate().await?;
        check_expiry()?;
        oauth::post_oauth_token_grant(
            client,
            &grant.token_endpoint,
            &oauth::TokenGrantParams {
                client_assertion: &svid.token,
                client_assertion_type: &grant.client_assertion_type,
                audience: &grant.audience,
                scopes: &grant.scopes,
            },
            request_id,
        )
        .await
        .map_err(TokenGrantFailure::to_status)?
    };
    let obtained_at_ms = crate::persistence::current_time_ms();
    require_live_assertion(svid, obtained_at_ms)?;
    let identity_expires_at_ms = session
        .expires_at
        .saturating_mul(1000)
        .min(svid.expires_at.saturating_mul(1000))
        .min(subject_expiry);
    let serve_until_ms =
        serve_until_ms(&token, ttl_override, obtained_at_ms, identity_expires_at_ms).ok_or_else(
            || {
                TokenGrantFailure::new(
                    TokenGrantFailureKind::Unclassified,
                    TokenGrantStage::TokenEndpoint,
                )
                .to_status()
            },
        )?;
    Ok((token, serve_until_ms))
}

/// When to stop serving a token the token service issued at `obtained_at_ms`,
/// or `None` when it is already expired.
///
/// The issuer's `expires_in`, a parseable JWT `exp` of the access token, and
/// the session, SVID, and subject expiries each bound the token; `exp` can
/// only shorten it. Serving stops the usual skew before the earliest bound,
/// after at least one second, and never later than the default cache lifetime
/// (whose fallback applies when the issuer omits `expires_in`). A configured
/// cache TTL may shorten that lifetime but, unlike a dedicated supervisor's
/// cache, never extends it.
fn serve_until_ms(
    token: &oauth::OAuthTokenResponse,
    ttl_override: Option<Duration>,
    obtained_at_ms: i64,
    identity_expires_at_ms: i64,
) -> Option<i64> {
    let issuer_expires_at_ms = (token.expires_in > 0)
        .then(|| obtained_at_ms.saturating_add(token.expires_in.saturating_mul(1000)));
    let expires_at_ms = [issuer_expires_at_ms, jwt_exp_ms(&token.access_token)]
        .into_iter()
        .flatten()
        .fold(identity_expires_at_ms, i64::min);
    if expires_at_ms <= obtained_at_ms {
        return None;
    }
    let default_ttl = oauth::token_cache_ttl(None, token.expires_in);
    let ttl = ttl_override
        .filter(|ttl| !ttl.is_zero())
        .map_or(default_ttl, |ttl| ttl.min(default_ttl));
    let skewed_expiry_ms = expires_at_ms
        .saturating_sub(oauth::TOKEN_CACHE_EXPIRY_SKEW_SECONDS.saturating_mul(1000))
        .max(obtained_at_ms.saturating_add(1000).min(expires_at_ms));
    Some(
        obtained_at_ms
            .saturating_add(i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX))
            .min(skewed_expiry_ms),
    )
}

type AcquisitionSlots = HashMap<String, (Arc<tokio::sync::Mutex<Option<Status>>>, usize)>;

#[derive(Default)]
struct Admission {
    active: std::sync::Mutex<HashMap<String, usize>>,
}

impl Admission {
    fn enter(&self, sandbox: &str, per_sandbox_limit: usize) -> Result<AdmissionGuard<'_>, Status> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active.values().sum::<usize>() >= 64
            || active.get(sandbox).copied().unwrap_or_default() >= per_sandbox_limit
        {
            return Err(TokenGrantFailure::new(
                TokenGrantFailureKind::Unavailable,
                TokenGrantStage::GatewayRpc,
            )
            .to_status_with_code(tonic::Code::ResourceExhausted));
        }
        *active.entry(sandbox.to_string()).or_default() += 1;
        Ok(AdmissionGuard {
            admission: self,
            sandbox: sandbox.to_string(),
        })
    }
}

struct AdmissionGuard<'a> {
    admission: &'a Admission,
    sandbox: String,
}

impl Drop for AdmissionGuard<'_> {
    fn drop(&mut self) {
        let mut active = self
            .admission
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = active.get_mut(&self.sandbox) {
            *count -= 1;
            if *count == 0 {
                active.remove(&self.sandbox);
            }
        }
    }
}

/// Coordinate token acquisition separately for each cache fingerprint.
///
/// Concurrent misses share a single acquisition without locking unrelated
/// tokens. Current waiters share dependency outages. A caller's authorization
/// failure leaves the turn available to its waiters. Entries live only while
/// held or awaited.
#[derive(Default)]
struct Acquisitions {
    slots: std::sync::Mutex<AcquisitionSlots>,
}

impl Acquisitions {
    async fn turn(&self, key: &str) -> Result<AcquisitionTurn<'_>, Status> {
        let registration = {
            let mut slots = self.lock();
            let (slot, users) = slots.entry(key.to_string()).or_default();
            *users += 1;
            Registration {
                acquisitions: self,
                key: key.to_string(),
                slot: slot.clone(),
            }
        };
        let failure = registration.slot.clone().lock_owned().await;
        if let Some(status) = failure.as_ref() {
            return Err(status.clone());
        }
        Ok(AcquisitionTurn {
            failure,
            _registration: registration,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, AcquisitionSlots> {
        self.slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

struct Registration<'a> {
    acquisitions: &'a Acquisitions,
    key: String,
    slot: Arc<tokio::sync::Mutex<Option<Status>>>,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        let mut slots = self.acquisitions.lock();
        if let Some((_, users)) = slots.get_mut(&self.key) {
            *users -= 1;
            if *users == 0 {
                slots.remove(&self.key);
            }
        }
    }
}

/// Fields drop in order: the turn is released before its registration.
struct AcquisitionTurn<'a> {
    failure: tokio::sync::OwnedMutexGuard<Option<Status>>,
    _registration: Registration<'a>,
}

impl AcquisitionTurn<'_> {
    fn record_failure(&mut self, status: &Status) {
        let failure = TokenGrantFailure::from_status(status);
        if matches!(
            (failure.kind(), failure.upstream_status()),
            (
                TokenGrantFailureKind::Unavailable,
                None | Some(429 | 500..=599)
            ) | (TokenGrantFailureKind::Timeout, None)
        ) && matches!(
            failure.stage(),
            TokenGrantStage::WorkloadIdentity
                | TokenGrantStage::IntermediateExchange
                | TokenGrantStage::TokenEndpoint
        ) {
            *self.failure = Some(status.clone());
        }
    }
}

#[cfg(test)]
mod performance_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::principal::{SandboxIdentitySource, SandboxPrincipal};
    use std::path::PathBuf;

    #[test]
    fn admission_is_bounded_per_sandbox_and_releases_cancelled_work() {
        let admission = Admission::default();
        for limit in [
            PER_SANDBOX_EXCHANGE_LIMIT,
            PER_SANDBOX_VERIFIED_REQUEST_LIMIT,
        ] {
            let guards: Vec<_> = (0..limit)
                .map(|_| admission.enter("busy", limit).unwrap())
                .collect();
            assert_eq!(
                admission.enter("busy", limit).err().unwrap().code(),
                tonic::Code::ResourceExhausted
            );
            let other = admission.enter("other", limit).unwrap();
            drop(guards);
            drop(admission.enter("busy", limit).unwrap());
            drop(other);
            assert!(admission.active.lock().unwrap().is_empty());
        }
        let guards: Vec<_> = (0..64)
            .map(|i| {
                admission
                    .enter(&i.to_string(), PER_SANDBOX_EXCHANGE_LIMIT)
                    .unwrap()
            })
            .collect();
        assert!(
            admission
                .enter("overflow", PER_SANDBOX_EXCHANGE_LIMIT)
                .is_err()
        );
        drop(guards);
        assert!(admission.active.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn broker_requires_a_signed_session_even_with_a_sandbox_principal() {
        let state = crate::grpc::test_support::test_server_state().await;
        for principal in [
            Principal::Anonymous,
            Principal::Sandbox(SandboxPrincipal {
                sandbox_id: Uuid::new_v4().to_string(),
                source: SandboxIdentitySource::BootstrapJwt {
                    issuer: "launch-session".into(),
                    auth_epoch: None,
                },
                trust_domain: Some("openshell".into()),
            }),
        ] {
            let mut request = Request::new(GetSandboxProviderAccessTokenRequest {
                credential_key: "untrusted".into(),
                jwt_svid: None,
                launch_jwt_svid: None,
            });
            request.extensions_mut().insert(principal);
            let error = handle(&state, request).await.unwrap_err();
            assert!(matches!(
                error.code(),
                tonic::Code::Unauthenticated | tonic::Code::PermissionDenied
            ));
        }
    }

    #[tokio::test]
    async fn brokered_token_exchange_cache_hit_resolves_the_subject_once() {
        use crate::auth::sandbox_jwt::SandboxSessionJwtAuthority;
        use crate::auth::sandbox_session::PersistedSandboxIdentity;
        use openshell_core::config::{GatewayJwtConfig, SpiffeBrokerConfig};
        use openshell_core::proto::datamodel::v1::ObjectMeta;
        use openshell_core::proto::{
            NetworkAccessPreset, NetworkEndpoint, ProviderCredentialTokenGrantSubjectToken,
            ProviderProfile, ProviderProfileCategory, ProviderProfileCredential, SandboxPhase,
            SandboxSpec,
        };

        const GATEWAY: &str = "broker-test";
        const PROVIDER: &str = "handle-backed";
        const SUBJECT: &str = "user-token";
        let mut state =
            crate::grpc::test_support::test_server_state_with_driver("kubernetes").await;
        let server = Arc::get_mut(&mut state).unwrap();
        let key = openshell_bootstrap::jwt::generate_jwt_key().unwrap();
        let ttl = std::num::NonZeroU64::new(300).unwrap();
        let authority = Arc::new(
            SandboxSessionJwtAuthority::from_pem(
                key.signing_key_pem.as_bytes(),
                key.public_key_pem.as_bytes(),
                key.kid,
                GATEWAY,
                Some(Duration::from_secs(ttl.get())),
            )
            .unwrap(),
        );
        server.config.gateway_jwt = Some(GatewayJwtConfig {
            signing_key_path: PathBuf::default(),
            public_key_path: PathBuf::default(),
            kid_path: PathBuf::default(),
            gateway_id: GATEWAY.into(),
            ttl_secs: Some(ttl),
        });
        server.sandbox_session_jwt_authority = Some(authority.clone());
        server.sandbox_identity = Some(Arc::new(
            openshell_spire::SpireSandboxIdentity::new(&SpiffeBrokerConfig {
                spiffe_id_prefix: "spiffe://broker.test/openshell".into(),
                endpoint: "https://broker.test:8443".into(),
                node_local_port: None,
                server_spiffe_id: Some("spiffe://broker.test/agent".into()),
                server_spiffe_id_prefix: None,
                workload_api_socket_path: "/nonexistent/broker-test.sock".into(),
            })
            .unwrap(),
        ));
        let sandbox_id = Uuid::new_v4().to_string();
        let metadata = |id: &str, name: &str| ObjectMeta {
            id: id.into(),
            name: name.into(),
            workspace: "default".into(),
            ..Default::default()
        };
        let identity = PersistedSandboxIdentity::new().unwrap();
        let mut sandbox_meta = metadata(&sandbox_id, &sandbox_id);
        identity.write(&mut sandbox_meta.annotations);
        let mut sandbox = Sandbox {
            metadata: Some(sandbox_meta),
            spec: Some(SandboxSpec {
                providers: vec![PROVIDER.into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();

        let profile_proto = ProviderProfile {
            id: "handle-backed-exchange".into(),
            display_name: "Handle-backed token exchange".into(),
            category: ProviderProfileCategory::Other.into(),
            endpoints: vec![NetworkEndpoint {
                host: "api.example.test".into(),
                port: 443,
                protocol: "rest".into(),
                access: NetworkAccessPreset::Full.into(),
                ..Default::default()
            }],
            credentials: vec![
                ProviderProfileCredential {
                    name: "subject_token".into(),
                    ..Default::default()
                },
                ProviderProfileCredential {
                    name: "access_token".into(),
                    auth_style: "bearer".into(),
                    header_name: "Authorization".into(),
                    token_grant: Some(ProviderCredentialTokenGrant {
                        grant_type: ProviderCredentialTokenGrantType::TokenExchange.into(),
                        token_endpoint: "https://issuer.example.test/token".into(),
                        subject_token: Some(ProviderCredentialTokenGrantSubjectToken {
                            source: "provider_credential".into(),
                            credential: "subject_token".into(),
                            subject_token_type: oauth::ACCESS_TOKEN_TYPE.into(),
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let profile = openshell_providers::ProviderTypeProfile::from_proto(&profile_proto);
        let mut provider = Provider {
            metadata: Some(metadata(PROVIDER, PROVIDER)),
            r#type: profile_proto.id.clone(),
            ..Default::default()
        };
        state
            .store
            .put_message(&crate::provider_profile_sources::stored_provider_profile(
                profile_proto,
            ))
            .await
            .unwrap();
        provider.credential_handles = state
            .credentials
            .store_provider_credentials(
                PROVIDER,
                "default",
                PROVIDER,
                &HashMap::from([("subject_token".into(), SUBJECT.into())]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        state.store.put_message(&provider).await.unwrap();

        let mut credentials = HashMap::new();
        insert_dynamic_credentials_for_profile(&mut credentials, &profile, PROVIDER, PROVIDER)
            .unwrap();
        let credential_key = credentials.into_keys().next().unwrap();
        let launch = authority
            .mint_persisted_launch(&sandbox_id, &identity)
            .unwrap();
        let bearer = launch.supervisor.gateway_token.expose_secret();
        let (session, sandbox, provider_launch_id) = authorize(&state, bearer).await.unwrap();
        let configured = grant_configuration(&state, &sandbox, &credential_key)
            .await
            .unwrap();
        let cached = oauth::OAuthTokenResponse {
            access_token: "cached-access-token".into(),
            token_type: "Bearer".into(),
            expires_in: 60,
        };
        ACCESS_TOKENS.set(
            cache_key(
                &session,
                provider_launch_id,
                &configured,
                Some(SUBJECT),
                GATEWAY,
            )
            .unwrap(),
            &cached,
            crate::persistence::current_time_ms() + 60_000,
        );

        let mut request = Request::new(GetSandboxProviderAccessTokenRequest {
            credential_key,
            ..Default::default()
        });
        request
            .extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id,
                source: SandboxIdentitySource::BootstrapJwt {
                    issuer: format!("openshell-gateway:{GATEWAY}"),
                    auth_epoch: None,
                },
                trust_domain: None,
            }));
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {bearer}").parse().unwrap());

        let (first_read, release_first_read) = state.credentials.gate_next_resolve();
        let exchange = handle(&state, request);
        tokio::pin!(exchange);
        tokio::select! {
            result = &mut exchange => panic!("grant finished before resolving the subject: {result:?}"),
            first_read = first_read => first_read.unwrap(),
        }
        let (second_read, _release_second_read) = state.credentials.gate_next_resolve();
        release_first_read.send(()).unwrap();
        let response = tokio::select! {
            result = exchange => result.unwrap().into_inner(),
            _ = second_read => panic!("cache hit resolved the subject again"),
        };
        assert_eq!(response.access_token, cached.access_token);
    }

    #[test]
    fn workload_assertion_requires_the_exact_sandbox_and_supervisor_launch() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use openshell_core::sandbox_generation::SandboxGenerationId;
        use rcgen::PublicKeyData as _;

        let key =
            openshell_crypto::pki::generate_keypair_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let public_key = key.der_bytes();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some("workload-test".into());
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
        let encoding_key =
            jsonwebtoken::EncodingKey::from_ec_pem(key.serialize_pem().unwrap().as_bytes())
                .unwrap();
        let now = crate::persistence::current_time_ms() / 1000;
        let sign_until = |subject: &str, audiences: &[&str], expires_at| {
            openshell_crypto::jwt::encode(
                &header,
                &serde_json::json!({"sub": subject, "aud": audiences, "exp": expires_at}),
                &encoding_key,
            )
            .unwrap()
        };
        let sign = |subject: &str, audiences: &[&str]| sign_until(subject, audiences, now + 120);
        let sandboxes = [
            "spiffe://test.example/gateway/gateway/sandbox/a",
            "spiffe://test.example/gateway/gateway/sandbox/b",
        ];
        let launches = [
            "spiffe://test.example/gateway/gateway/sandbox/a/launch/current",
            "spiffe://test.example/gateway/gateway/sandbox/b/launch/current",
        ];
        let launch = SandboxGenerationId::parse("g2")
            .unwrap()
            .provider_spiffe_audience();
        let older = SandboxGenerationId::parse("g1")
            .unwrap()
            .provider_spiffe_audience();
        let audience = "https://issuer.test/token";
        let verify = |token: &str, launch_token: &str, expected: &str, expected_launch: &str| {
            verify_workload_assertion(
                token,
                launch_token,
                &bundles,
                expected.to_owned(),
                expected_launch,
                audience,
                &launch,
            )
        };
        for (subject, launch_subject) in sandboxes.into_iter().zip(launches) {
            let token = sign(subject, &[audience]);
            let launch_proof = sign(launch_subject, &[&launch]);
            let verified = verify(&token, &launch_proof, subject, launch_subject).unwrap();
            assert_eq!(verified.spiffe_id, subject);
        }
        let token = sign(sandboxes[0], &[audience]);
        let proof = sign(launches[0], &[&launch]);
        let shorter_provider = sign_until(sandboxes[0], &[audience], now + 60);
        let shorter_launch = sign_until(launches[0], &[&launch], now + 60);
        for (provider, launch_proof) in [(&shorter_provider, &proof), (&token, &shorter_launch)] {
            assert_eq!(
                verify(provider, launch_proof, sandboxes[0], launches[0])
                    .unwrap()
                    .expires_at,
                now + 60
            );
        }
        for (token, proof) in [
            (sign(sandboxes[1], &[audience]), proof.clone()),
            (token.clone(), sign(launches[1], &[&launch])),
            (token.clone(), sign(launches[0], &[&older])),
            (
                token.clone(),
                sign(
                    "spiffe://test.example/gateway/gateway/sandbox/a/launch/outgoing",
                    &[&launch],
                ),
            ),
            (token.clone(), sign(sandboxes[0], &[&launch])),
            (token.clone(), token),
            (sign(sandboxes[0], &[audience, &launch]), proof),
        ] {
            assert_eq!(
                verify(&token, &proof, sandboxes[0], launches[0])
                    .unwrap_err()
                    .code(),
                tonic::Code::PermissionDenied
            );
        }
    }

    #[test]
    fn fingerprint_binds_the_runtime_configured_key_and_resolved_subject() {
        use openshell_core::jwt::{CredentialEpoch, SandboxId};
        let session = AuthenticatedSandboxSession {
            sandbox_id: SandboxId::parse(Uuid::new_v4().to_string()).unwrap(),
            runtime_generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
                "g1",
            )
            .unwrap(),
            auth_epoch: CredentialEpoch::new(1).unwrap(),
            token_id: Uuid::new_v4(),
            issued_at: 1,
            expires_at: 2,
        };
        let configured = |key: &str| ConfiguredGrant {
            provider: Provider::default(),
            grant: ProviderCredentialTokenGrant::default(),
            key: key.to_string(),
            attachment_epoch: String::new(),
        };
        let owned = "api.example.com\t443\t/v1/**\towner\tprovider:access";
        let fingerprint = |session, key, subject| {
            cache_key(session, None, &configured(key), subject, "gateway").unwrap()
        };
        let base = fingerprint(&session, owned, Some("subject-a"));
        // A renewed session token of the same runtime shares cached tokens.
        let renewed = AuthenticatedSandboxSession {
            token_id: Uuid::new_v4(),
            expires_at: 3,
            ..session.clone()
        };
        assert_eq!(fingerprint(&renewed, owned, Some("subject-a")), base);
        // A rotated subject, another credential, or another epoch does not.
        assert_ne!(fingerprint(&session, owned, Some("subject-b")), base);
        let mut reattached = configured(owned);
        reattached.attachment_epoch = "new-attachment".into();
        assert_ne!(
            cache_key(&session, None, &reattached, Some("subject-a"), "gateway").unwrap(),
            base
        );
        let for_launch = |launch| {
            cache_key(
                &session,
                Some(launch),
                &configured(owned),
                Some("subject-a"),
                "gateway",
            )
            .unwrap()
        };
        assert_ne!(
            for_launch(Uuid::from_u128(1)),
            for_launch(Uuid::from_u128(2))
        );
        let spoofed = owned.replace("owner", "other");
        assert_ne!(fingerprint(&session, &spoofed, Some("subject-a")), base);
        let rotated = AuthenticatedSandboxSession {
            auth_epoch: CredentialEpoch::new(2).unwrap(),
            ..session.clone()
        };
        assert_ne!(fingerprint(&rotated, owned, Some("subject-a")), base);
        assert_ne!(
            fingerprint(&session, owned, None),
            fingerprint(&session, owned, Some(""))
        );
    }

    #[test]
    fn verified_grants_accept_fractional_overrides_without_caching() {
        const NOW: i64 = 1_700_000_000_000;
        let assertion = SandboxJwtSvid {
            spiffe_id: "spiffe://test.example/sandbox".into(),
            token: "fixture-assertion".into(),
            expires_at: NOW / 1000 + 60,
        };
        let grant = ProviderCredentialTokenGrant {
            cache_ttl: Some(prost_types::Duration {
                seconds: 0,
                nanos: 500_000_000,
            }),
            ..Default::default()
        };
        let ttl = GrantIdentity::Supervisor(&assertion)
            .cache_ttl_override(&grant)
            .unwrap();
        assert_eq!(ttl, Some(Duration::ZERO));

        let token = oauth::OAuthTokenResponse {
            access_token: "fixture-access-token".into(),
            token_type: "Bearer".into(),
            expires_in: 60,
        };
        assert_eq!(
            serve_until_ms(&token, ttl, NOW, assertion.expires_at * 1000),
            Some(NOW + 30_000)
        );
    }

    #[test]
    fn served_lifetime_never_exceeds_the_token_or_identity() {
        const NOW: i64 = 1_700_000_000_000;
        let token = |expires_in, access_token: &str| oauth::OAuthTokenResponse {
            access_token: access_token.to_string(),
            expires_in,
            token_type: String::new(),
        };
        let jwt = |exp_ms: i64| {
            use base64::Engine as _;
            let claims = format!(r#"{{"exp":{}}}"#, exp_ms / 1000);
            let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims);
            format!("e30.{claims}.sig")
        };
        let hour = Some(Duration::from_hours(1));
        let identity = NOW + 86_400_000;
        let serve = |token, ttl, identity| serve_until_ms(&token, ttl, NOW, identity);
        // A longer cache override is capped by the issuer's lifetime and skew.
        assert_eq!(
            serve(token(300, "opaque"), hour, identity),
            Some(NOW + 270_000)
        );
        // A shorter override still applies.
        let minute = Some(Duration::from_mins(1));
        assert_eq!(
            serve(token(300, "opaque"), minute, identity),
            Some(NOW + 60_000)
        );
        // A JWT exp only shortens the lifetime.
        let short = jwt(NOW + 120_000);
        assert_eq!(
            serve(token(300, &short), hour, identity),
            Some(NOW + 90_000)
        );
        let long = jwt(NOW + 7_200_000);
        assert_eq!(
            serve(token(300, &long), None, identity),
            Some(NOW + 270_000)
        );
        // An omitted expires_in keeps the default fallback, even with an override.
        assert_eq!(
            serve(token(0, "opaque"), hour, identity),
            Some(NOW + 270_000)
        );
        // Zero disables caching, not the bound on serving.
        let zero = Some(Duration::ZERO);
        assert_eq!(
            serve(token(300, "opaque"), zero, identity),
            Some(NOW + 270_000)
        );
        // Identity expiry caps the lifetime with skew but still serves briefly.
        assert_eq!(
            serve(token(300, "opaque"), None, NOW + 60_000),
            Some(NOW + 30_000)
        );
        assert_eq!(
            serve(token(300, "opaque"), None, NOW + 10_000),
            Some(NOW + 1_000)
        );
        assert_eq!(
            serve(token(300, "opaque"), None, NOW + 500),
            Some(NOW + 500)
        );
        // An already expired acquisition is never served.
        assert_eq!(serve(token(300, &jwt(NOW)), None, identity), None);
        assert_eq!(serve(token(300, "opaque"), None, NOW), None);
    }

    #[tokio::test]
    async fn concurrent_misses_take_turns_per_fingerprint_and_leave_no_entries() {
        let acquisitions: &'static Acquisitions = Box::leak(Box::default());
        let first = acquisitions.turn("a").await.unwrap();
        // Another fingerprint is independent.
        drop(acquisitions.turn("b").await.unwrap());
        // A waiter for the same fingerprint blocks; cancelling it leaves only
        // the holder's entry.
        let waiting = tokio::time::timeout(Duration::from_millis(50), acquisitions.turn("a"));
        assert!(waiting.await.is_err());
        assert_eq!(
            acquisitions.lock().get("a").map(|(_, users)| *users),
            Some(1)
        );
        assert_eq!(acquisitions.lock().len(), 1);
        let waiter = tokio::spawn(async move { drop(acquisitions.turn("a").await.unwrap()) });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(first);
        waiter.await.unwrap();
        assert!(acquisitions.lock().is_empty());
    }

    #[tokio::test]
    async fn failed_acquisition_is_shared_with_waiters_but_not_later_requests() {
        let acquisitions: &'static Acquisitions = Box::leak(Box::default());
        let mut holder = acquisitions.turn("grant").await.unwrap();
        let waiters: Vec<_> = (0..3)
            .map(|_| tokio::spawn(async move { acquisitions.turn("grant").await }))
            .collect();
        tokio::time::timeout(Duration::from_secs(5), async {
            while acquisitions.lock().get("grant").map(|(_, users)| *users) != Some(4) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all requests should join the in-flight acquisition");
        holder.record_failure(&Status::unauthenticated("superseded bearer"));
        assert!(holder.failure.is_none());
        let rejected_assertion = TokenGrantFailure::new(
            TokenGrantFailureKind::Unclassified,
            TokenGrantStage::TokenEndpoint,
        )
        .with_upstream_status(401);
        holder.record_failure(&rejected_assertion.to_status());
        assert!(holder.failure.is_none());
        let expected = TokenGrantFailure::new(
            TokenGrantFailureKind::Unavailable,
            TokenGrantStage::TokenEndpoint,
        )
        .with_upstream_status(503);
        holder.record_failure(&expected.to_status());
        drop(holder);
        for waiter in waiters {
            let result = tokio::time::timeout(Duration::from_secs(5), waiter)
                .await
                .expect("waiters should fail without another acquisition")
                .unwrap();
            let Err(status) = result else {
                panic!("a waiter started another acquisition after the holder failed");
            };
            assert_eq!(TokenGrantFailure::from_status(&status), expected);
        }
        assert!(acquisitions.lock().is_empty());
        drop(acquisitions.turn("grant").await.unwrap());
        assert!(acquisitions.lock().is_empty());
    }
}
