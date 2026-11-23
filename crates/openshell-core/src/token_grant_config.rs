// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pure validation for token-grant identity configuration.

pub const JWT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";

/// A profile field and a credential-free validation diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenGrantIdentityError {
    pub field: &'static str,
    pub message: &'static str,
}

const fn invalid(field: &'static str, message: &'static str) -> TokenGrantIdentityError {
    TokenGrantIdentityError { field, message }
}

/// Validate identity choices before acquiring credentials or serving cached tokens.
pub fn validate_token_grant_identity(
    grant: &crate::proto::ProviderCredentialTokenGrant,
) -> Result<(), TokenGrantIdentityError> {
    use crate::proto::ProviderCredentialTokenGrantType as Grant;
    let kind = Grant::try_from(grant.grant_type)
        .map_err(|_| invalid("grant_type", "unsupported grant_type"))?;
    if let Some(auth) = &grant.client_authentication {
        match auth.mechanism.as_str() {
            "none" => {
                if auth.credential.is_some() {
                    return Err(invalid(
                        "client_authentication.credential",
                        "client_authentication none forbids credential",
                    ));
                }
                if !grant.client_assertion_type.is_empty() {
                    return Err(invalid(
                        "client_assertion_type",
                        "client_assertion_type requires client_assertion authentication",
                    ));
                }
                if kind != Grant::TokenExchange {
                    return Err(invalid(
                        "client_authentication.mechanism",
                        "client_credentials requires client_assertion authentication",
                    ));
                }
            }
            "client_assertion" => {
                if auth
                    .credential
                    .as_ref()
                    .is_none_or(|credential| credential.source != "jwt_svid")
                {
                    return Err(invalid(
                        "client_authentication.credential.source",
                        "client_assertion requires credential.source: jwt_svid",
                    ));
                }
            }
            _ => {
                return Err(invalid(
                    "client_authentication.mechanism",
                    "unsupported client_authentication.mechanism",
                ));
            }
        }
    }
    if kind != Grant::TokenExchange {
        return if grant.subject_token.is_some() {
            Err(invalid(
                "subject_token",
                "subject_token is only valid for token_exchange grants",
            ))
        } else {
            Ok(())
        };
    }
    let subject = grant.subject_token.as_ref().ok_or(invalid(
        "subject_token",
        "token_exchange grants require subject_token",
    ))?;
    match subject.source.as_str() {
        "provider_credential" => {
            if subject.credential.trim().is_empty() {
                return Err(invalid(
                    "subject_token.credential",
                    "subject_token.credential is required",
                ));
            }
        }
        "jwt_svid" => {
            if !subject.credential.is_empty() {
                return Err(invalid(
                    "subject_token.credential",
                    "jwt_svid subject forbids subject_token.credential",
                ));
            }
            if !subject.subject_token_type.is_empty()
                && subject.subject_token_type != JWT_TOKEN_TYPE
            {
                return Err(invalid(
                    "subject_token.subject_token_type",
                    "jwt_svid subject requires the JWT subject_token_type",
                ));
            }
        }
        _ => {
            return Err(invalid(
                "subject_token.source",
                "subject_token.source must be provider_credential or jwt_svid",
            ));
        }
    }
    Ok(())
}
