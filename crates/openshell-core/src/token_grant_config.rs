// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Validation shared by profile authoring and supervisor installation.

use crate::token_grant_failure::{TokenGrantFailure, TokenGrantFailureKind, TokenGrantStage};

/// Validate the protocol-specific configuration before acquiring an identity.
pub fn validate_jwt_login_configuration(
    endpoint: &str,
    audience: &str,
    role: &str,
    namespace: &str,
) -> Result<(), TokenGrantFailure> {
    let invalid = TokenGrantFailure::new(
        TokenGrantFailureKind::Configuration,
        TokenGrantStage::Configuration,
    );
    let url = url::Url::parse(endpoint).map_err(|_| invalid)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || audience.trim().is_empty()
        || role.trim().is_empty()
        || [endpoint, audience, role, namespace]
            .iter()
            .any(|value| value.chars().any(char::is_control))
        || !namespace.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(invalid);
    }
    Ok(())
}

/// Reject unsupported grant protocols and incompatible login fields at runtime.
pub fn validate_token_grant_configuration(
    grant: &crate::proto::ProviderCredentialTokenGrant,
) -> Result<(), TokenGrantFailure> {
    use crate::proto::ProviderCredentialTokenGrantType;
    let invalid = TokenGrantFailure::new(
        TokenGrantFailureKind::Configuration,
        TokenGrantStage::Configuration,
    );
    let kind = ProviderCredentialTokenGrantType::try_from(grant.grant_type).map_err(|_| invalid)?;
    if kind == ProviderCredentialTokenGrantType::VaultJwtLogin {
        validate_jwt_login_configuration(
            &grant.token_endpoint,
            &grant.jwt_svid_audience,
            &grant.jwt_login_role,
            &grant.jwt_login_namespace,
        )?;
        if grant.subject_token.is_some()
            || !grant.requested_token_type.is_empty()
            || !grant.client_assertion_type.is_empty()
            || !grant.audience.is_empty()
            || !grant.scopes.is_empty()
            || !grant.audience_overrides.is_empty()
        {
            return Err(invalid);
        }
    } else if !grant.jwt_login_role.is_empty() || !grant.jwt_login_namespace.is_empty() {
        return Err(invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{ProviderCredentialTokenGrant, ProviderCredentialTokenGrantType};

    #[test]
    fn jwt_login_configuration_rejects_unsafe_or_ambiguous_inputs() {
        for (endpoint, audience, role, namespace) in [
            ("http://localhost/login", "vault", "role", ""),
            ("https://vault.example/login", "", "role", ""),
            ("https://vault.example/login", "vault", " ", ""),
            (
                "https://vault.example/login",
                "vault",
                "role",
                "team\r\nX-Other: value",
            ),
            ("https://vault.example/login", "vault\tother", "role", ""),
            (
                "https://user:password@vault.example/login",
                "vault",
                "role",
                "",
            ),
            ("https://vault.example/login#fragment", "vault", "role", ""),
        ] {
            assert!(validate_jwt_login_configuration(endpoint, audience, role, namespace).is_err());
        }
        assert!(
            validate_jwt_login_configuration(
                "https://vault.example/v1/auth/custom/login",
                "vault",
                "role",
                "team/project"
            )
            .is_ok()
        );
    }

    #[test]
    fn unknown_grants_fail_and_unspecified_preserves_legacy_default() {
        let mut grant = ProviderCredentialTokenGrant::default();
        assert!(validate_token_grant_configuration(&grant).is_ok());
        grant.grant_type = 999;
        assert!(validate_token_grant_configuration(&grant).is_err());
        grant.grant_type = ProviderCredentialTokenGrantType::ClientCredentials as i32;
        grant.jwt_login_role = "role".into();
        assert!(validate_token_grant_configuration(&grant).is_err());
    }
}
