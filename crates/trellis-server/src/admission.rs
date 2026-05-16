// Rust guideline compliant 2026-02-21
//! HTTP-edge admission for append dialects and scope authorization helpers.
//!
//! Routed admission lives in [`RoutedEventAdmissionPolicy`], which delegates to
//! [`WosEventAdmissionPolicy`] versus [`FormspecAppendAdmissionPolicy`] based on the
//! admitted `substrate.append.response_submitted` literal (see crate-root
//! [`FORMSPEC_RESPONSE_SUBMITTED`](crate::FORMSPEC_RESPONSE_SUBMITTED)).

use async_trait::async_trait;
use axum::http::StatusCode;
use stack_common_error::{ErrorCode, StackError};
use trellis_server_ports::{
    AdmissionEvent, AdmittedEvent, DirectSubmitPolicy, EventAdmissionPolicy, EventFamilyId,
    ProfileId, SchemaRef, ScopeAuthorization, ScopeAuthorizer,
};
use wos_events::{ProvenanceKind, ProvenanceRecord};

const FORMSPEC_EVENT_FAMILY: &str = "formspec.response";
const WOS_KERNEL_EVENT_FAMILY: &str = "wos.kernel";

fn formspec_admitted_event(event_type: &str) -> Result<AdmittedEvent, StackError> {
    let family = EventFamilyId::new(FORMSPEC_EVENT_FAMILY)
        .map_err(|error| StackError::internal(format!("formspec family invariant: {error}")))?;
    let schema_ref = SchemaRef::new(format!("formspec-events://{event_type}"))
        .map_err(|error| StackError::internal(format!("formspec schema ref invariant: {error}")))?;
    Ok(AdmittedEvent {
        event_type: event_type.to_string(),
        event_family: family,
        schema_ref,
        profile_id: ProfileId::new(integrity_verify::FORMSPEC_PROFILE_ID),
        direct_submit: DirectSubmitPolicy::ServiceOnly,
    })
}

fn wos_admitted_event(event_type: &str) -> Result<AdmittedEvent, StackError> {
    let family = EventFamilyId::new(WOS_KERNEL_EVENT_FAMILY)
        .map_err(|error| StackError::internal(format!("wos family invariant: {error}")))?;
    let schema_ref = SchemaRef::new(format!("wos-events://{event_type}"))
        .map_err(|error| StackError::internal(format!("wos schema ref invariant: {error}")))?;
    Ok(AdmittedEvent {
        event_type: event_type.to_string(),
        event_family: family,
        schema_ref,
        profile_id: ProfileId::new(integrity_verify::WOS_PROFILE_ID),
        direct_submit: DirectSubmitPolicy::ServiceOnly,
    })
}

/// Formspec aggregate admission for intake proof append events.
#[derive(Debug, Clone, Copy)]
pub struct FormspecAppendAdmissionPolicy;

#[async_trait]
impl EventAdmissionPolicy for FormspecAppendAdmissionPolicy {
    type Error = StackError;

    async fn admit(&self, event: &AdmissionEvent<'_>) -> Result<AdmittedEvent, Self::Error> {
        if event.event_type != crate::FORMSPEC_RESPONSE_SUBMITTED {
            return Err(StackError::bad_request(format!(
                "event type `{}` is not a Formspec append literal",
                event.event_type
            )));
        }
        let value: serde_json::Value = serde_json::from_slice(event.payload).map_err(|error| {
            StackError::bad_request(format!("payload is not valid JSON: {error}"))
        })?;
        let map = value.as_object().ok_or_else(|| {
            StackError::bad_request("Formspec append payload must be a JSON object")
        })?;
        for key in ["aggregateType", "aggregateId", "payload"] {
            if !map.contains_key(key) {
                return Err(StackError::bad_request(format!(
                    "Formspec append payload is missing `{key}`"
                )));
            }
        }
        formspec_admitted_event(event.event_type)
    }
}

/// Routes admission to WOS provenance or Formspec aggregate dialects.
#[derive(Debug, Clone, Copy)]
pub struct RoutedEventAdmissionPolicy {
    pub(crate) wos: WosEventAdmissionPolicy,
    pub(crate) formspec: FormspecAppendAdmissionPolicy,
}

#[async_trait]
impl EventAdmissionPolicy for RoutedEventAdmissionPolicy {
    type Error = StackError;

    async fn admit(&self, event: &AdmissionEvent<'_>) -> Result<AdmittedEvent, Self::Error> {
        if event.event_type == crate::FORMSPEC_RESPONSE_SUBMITTED {
            self.formspec.admit(event).await
        } else {
            self.wos.admit(event).await
        }
    }
}

/// WOS-aware admission policy loaded at the server boundary.
#[derive(Debug, Clone, Copy)]
pub struct WosEventAdmissionPolicy;

#[async_trait]
impl EventAdmissionPolicy for WosEventAdmissionPolicy {
    type Error = StackError;

    async fn admit(&self, event: &AdmissionEvent<'_>) -> Result<AdmittedEvent, Self::Error> {
        let expected_kind = ProvenanceKind::from_canonical_event_literal(event.event_type)
            .ok_or_else(|| {
                StackError::bad_request(format!(
                    "event type `{}` is not registered for WOS admission",
                    event.event_type
                ))
            })?;
        let record: ProvenanceRecord = serde_json::from_slice(event.payload).map_err(|error| {
            StackError::bad_request(format!("payload is not a WOS provenance record: {error}"))
        })?;
        if record.record_kind != expected_kind {
            return Err(StackError::bad_request(format!(
                "payload recordKind does not match event type `{}`",
                event.event_type
            )));
        }
        let record_event = record
            .event
            .as_deref()
            .or_else(|| record.record_kind.canonical_event_literal());
        if record_event != Some(event.event_type) {
            return Err(StackError::bad_request(format!(
                "payload event literal does not match `{}`",
                event.event_type
            )));
        }
        wos_admitted_event(event.event_type)
    }
}

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

    /// Given a Formspec append payload with required keys, when routed admission runs, then it
    /// returns Formspec-profile admitted metadata.
    #[tokio::test]
    async fn given_valid_formspec_payload_when_routed_admits_then_formspec_metadata() {
        let policy = RoutedEventAdmissionPolicy {
            wos: WosEventAdmissionPolicy,
            formspec: FormspecAppendAdmissionPolicy,
        };
        let payload = br#"{"aggregateType":"t","aggregateId":"i","payload":{}}"#;
        let event = AdmissionEvent {
            scope: b"any",
            event_type: crate::FORMSPEC_RESPONSE_SUBMITTED,
            payload,
        };
        let admitted = policy.admit(&event).await.expect("formspec branch admits");
        assert_eq!(admitted.event_type, crate::FORMSPEC_RESPONSE_SUBMITTED);
        assert_eq!(admitted.event_family.as_str(), "formspec.response");
        assert_eq!(
            admitted.profile_id.get(),
            integrity_verify::FORMSPEC_PROFILE_ID
        );
        assert_eq!(admitted.direct_submit, trellis_server_ports::DirectSubmitPolicy::ServiceOnly);
        assert!(admitted.schema_ref.as_str().starts_with("formspec-events://"));
    }

    /// Given a Formspec append payload missing `aggregateType`, when admission runs, then the
    /// server rejects the event before coordinator work.
    #[tokio::test]
    async fn given_formspec_response_submitted_when_payload_missing_aggregate_type_then_admission_rejects(
    ) {
        let policy = FormspecAppendAdmissionPolicy;
        let payload = serde_json::json!({
            "aggregateId": "urn:example:agg",
            "payload": {"k": "v"}
        })
        .to_string();
        let event = AdmissionEvent {
            scope: b"s",
            event_type: crate::FORMSPEC_RESPONSE_SUBMITTED,
            payload: payload.as_bytes(),
        };
        let err = policy
            .admit(&event)
            .await
            .expect_err("missing aggregateType must fail admission");
        assert!(
            err.to_string().contains("aggregateType"),
            "error should name the missing field: {err}"
        );
    }

    /// Given a wrong literal for Formspec-only policy, when admission runs, then the policy
    /// rejects before JSON shape checks.
    #[tokio::test]
    async fn given_non_formspec_literal_when_formspec_policy_admits_then_rejects() {
        let policy = FormspecAppendAdmissionPolicy;
        let payload = serde_json::json!({
            "aggregateType": "t",
            "aggregateId": "urn:x",
            "payload": {}
        })
        .to_string();
        let event = AdmissionEvent {
            scope: b"s",
            event_type: "wos.case.created",
            payload: payload.as_bytes(),
        };
        let err = policy
            .admit(&event)
            .await
            .expect_err("non-Formspec literal must fail Formspec-only policy");
        assert!(
            err.to_string().contains("not a Formspec append literal"),
            "unexpected error: {err}"
        );
    }

    /// Given a WOS case_created payload aligned to its literal, when WOS admission runs, then it
    /// returns the WOS profile id and family without re-parsing the event type.
    #[tokio::test]
    async fn given_matching_wos_provenance_when_wos_admits_then_wos_metadata() {
        let literal = "wos.kernel.case_created";
        let mut record = ProvenanceRecord::blank(ProvenanceKind::CaseCreated);
        record.id = "prov-admission-boundary".to_string();
        let payload = serde_json::to_vec(&record).expect("serialize provenance");
        let event = AdmissionEvent {
            scope: b"case_123",
            event_type: literal,
            payload: payload.as_slice(),
        };
        let admitted = WosEventAdmissionPolicy
            .admit(&event)
            .await
            .expect("WOS admission accepts aligned payload");
        assert_eq!(admitted.event_type, literal);
        assert_eq!(admitted.event_family.as_str(), "wos.kernel");
        assert_eq!(admitted.profile_id.get(), integrity_verify::WOS_PROFILE_ID);
        assert_eq!(
            admitted.schema_ref.as_str(),
            "wos-events://wos.kernel.case_created"
        );
    }

    /// Given a scope listed in JWT scopes, when scoped authorizer runs, then authorization succeeds.
    #[tokio::test]
    async fn given_scope_in_jwt_scopes_when_scoped_authorizer_runs_then_ok() {
        let auth = ScopedAllowlistScopeAuthorizer;
        let scopes = vec!["case_123".to_string()];
        auth
            .authorize(&ScopeAuthorization {
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
