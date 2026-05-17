// Rust guideline compliant 2026-02-21
//! Deployment-volatile scope-authorizer policies.
//!
//! Concrete event admission adapters live in `trellis-admission-wos` and
//! `trellis-admission-formspec`; they are wired through `crate::composition`,
//! the only Trellis-side module that imports them. After DI-001/DI-002 this
//! file only carries the scope authorizers (`AllowAllScopeAuthorizer`,
//! `ScopedAllowlistScopeAuthorizer`) — they remain here because their
//! posture depends on JWT verifier wiring in `state.rs` rather than on
//! producer-specific admission vocabulary.

use async_trait::async_trait;
use axum::http::StatusCode;
use stack_common_error::{ErrorCode, StackError};
use trellis_server_ports::{ScopeAuthorization, ScopeAuthorizer};

#[derive(Debug, Clone, Copy)]
pub(crate) struct AllowAllScopeAuthorizer;

#[async_trait]
impl ScopeAuthorizer for AllowAllScopeAuthorizer {
    type Error = StackError;

    async fn authorize(&self, _request: &ScopeAuthorization<'_>) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Enforces [`ScopeAuthorization::jwt_scopes`] against the URL path scope (production-like TWREF-022).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ScopedAllowlistScopeAuthorizer;

#[async_trait]
impl ScopeAuthorizer for ScopedAllowlistScopeAuthorizer {
    type Error = StackError;

    async fn authorize(&self, request: &ScopeAuthorization<'_>) -> Result<(), Self::Error> {
        let Some(scopes) = request.jwt_scopes else {
            return Err(StackError::new(
                ErrorCode::new("INFRA-4010").expect("static error code is valid"),
                StatusCode::UNAUTHORIZED,
                "bearer token required for Trellis scope authorization",
            )
            .with_detail(
                "Set Authorization: Bearer with a JWT whose `scopes` claim lists the target scope (TWREF-022).",
            ));
        };
        let scope_str = std::str::from_utf8(request.scope)
            .map_err(|_| StackError::bad_request("scope is not valid UTF-8"))?;
        if scopes.iter().any(|allowed| allowed.as_str() == scope_str) {
            Ok(())
        } else {
            Err(StackError::new(
                ErrorCode::new("INFRA-4030").expect("static error code is valid"),
                StatusCode::FORBIDDEN,
                "scope not authorized for this bearer token",
            )
            .with_detail(format!(
                "JWT `scopes` did not include `{scope_str}` (TWREF-022)."
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trellis_server_ports::ScopeAction;

    /// Given a scope listed in JWT scopes, when scoped authorizer runs, then authorization succeeds.
    #[tokio::test]
    async fn given_scope_in_jwt_scopes_when_scoped_authorizer_runs_then_ok() {
        let auth = ScopedAllowlistScopeAuthorizer;
        let scopes = vec!["case_123".to_string()];
        auth.authorize(&ScopeAuthorization {
            actor: "sub",
            scope: b"case_123",
            action: ScopeAction::Append,
            jwt_scopes: Some(scopes.as_slice()),
        })
        .await
        .expect("scope allowlisted");
    }

    /// Given JWT scopes omitting the request scope, when scoped authorizer runs, then it returns forbidden.
    #[tokio::test]
    async fn given_missing_scope_in_jwt_when_scoped_authorizer_runs_then_forbidden() {
        let auth = ScopedAllowlistScopeAuthorizer;
        let scopes = vec!["other".to_string()];
        let err = auth
            .authorize(&ScopeAuthorization {
                actor: "sub",
                scope: b"case_123",
                action: ScopeAction::Append,
                jwt_scopes: Some(scopes.as_slice()),
            })
            .await
            .expect_err("scope must not match");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    /// Given no JWT scopes slice (anonymous / missing claims), when scoped authorizer runs, then unauthorized.
    #[tokio::test]
    async fn given_no_jwt_scopes_when_scoped_authorizer_runs_then_unauthorized() {
        let auth = ScopedAllowlistScopeAuthorizer;
        let err = auth
            .authorize(&ScopeAuthorization {
                actor: "sub",
                scope: b"case_123",
                action: ScopeAction::Append,
                jwt_scopes: None,
            })
            .await
            .expect_err("bearer scopes required");
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }
}
