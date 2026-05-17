// Rust guideline compliant 2026-02-21
//! Formspec aggregate ingress admission for Trellis.
//!
//! Validates the Formspec intake proof append payload shape
//! (`substrate.append.response_submitted`) and emits neutral
//! [`AdmittedEvent`] metadata. Direct-client submission is rejected until ADR
//! 0103 / TWREF-0103 lands; this adapter always returns
//! [`DirectSubmitPolicy::ServiceOnly`].
//!
//! Generic Trellis service modules must not depend on this crate; only the
//! Trellis composition root wires it in.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use stack_common_error::StackError;
use trellis_server_ports::{
    AdmissionEvent, AdmittedEvent, BudgetReviewRecord, DirectSubmitPolicy, EventAdmissionPolicy,
    EventFamilyId, EventTypeSpec, SchemaRef,
};
use trellis_types::ArtifactType;

/// Logical event family for Formspec aggregate append events.
pub const FORMSPEC_EVENT_FAMILY: &str = "formspec.response";

/// Canonical Formspec aggregate append literal admitted by this adapter.
pub const FORMSPEC_RESPONSE_SUBMITTED: &str = "substrate.append.response_submitted";

/// Returns the schema reference used by [`AdmittedEvent`] entries this adapter emits.
#[must_use]
pub fn formspec_schema_ref(event_type: &str) -> String {
    format!("formspec-events://{event_type}")
}

/// Builds the event-type specifications a Trellis composition root may register
/// against [`trellis_server_ports::EventTypeRegistry`] at startup.
///
/// Each entry carries the full neutral metadata (`event_family`,
/// `artifact_type`, `direct_submit`) so the registry remains the catalog's
/// source of truth. `artifact_type` is the substrate structural-role contract.
#[must_use]
pub fn formspec_event_type_specs() -> Vec<EventTypeSpec> {
    vec![EventTypeSpec {
        event_type: FORMSPEC_RESPONSE_SUBMITTED.to_string(),
        event_family: EventFamilyId::new(FORMSPEC_EVENT_FAMILY)
            .expect("formspec family slug is non-empty by construction"),
        schema_ref: SchemaRef::new(formspec_schema_ref(FORMSPEC_RESPONSE_SUBMITTED))
            .expect("formspec schema refs are URI-like by construction"),
        artifact_type: ArtifactType::Event,
        direct_submit: DirectSubmitPolicy::ServiceOnly,
        budget_review: BudgetReviewRecord {
            reviewer: "trellis-admission-formspec::FORMSPEC_RESPONSE_SUBMITTED".to_string(),
            plaintext_fields: vec!["eventType".to_string()],
            considered: true,
        },
    }]
}

/// Formspec aggregate admission for intake proof append events.
#[derive(Debug, Clone, Copy, Default)]
pub struct FormspecAppendAdmissionPolicy;

impl FormspecAppendAdmissionPolicy {
    /// Constructs the adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn admitted_event_for(event_type: &str) -> Result<AdmittedEvent, StackError> {
        let family = EventFamilyId::new(FORMSPEC_EVENT_FAMILY)
            .map_err(|error| StackError::internal(format!("formspec family invariant: {error}")))?;
        let schema_ref = SchemaRef::new(formspec_schema_ref(event_type)).map_err(|error| {
            StackError::internal(format!("formspec schema ref invariant: {error}"))
        })?;
        Ok(AdmittedEvent {
            event_type: event_type.to_string(),
            event_family: family,
            schema_ref,
            artifact_type: ArtifactType::Event,
            direct_submit: DirectSubmitPolicy::ServiceOnly,
        })
    }
}

#[async_trait]
impl EventAdmissionPolicy for FormspecAppendAdmissionPolicy {
    type Error = StackError;

    async fn admit(&self, event: &AdmissionEvent<'_>) -> Result<AdmittedEvent, Self::Error> {
        if event.event_type != FORMSPEC_RESPONSE_SUBMITTED {
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
        Self::admitted_event_for(event.event_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trellis_server_ports::{EventTypeRegistry, ReviewGateEventTypeRegistry};

    #[tokio::test]
    async fn given_well_formed_payload_when_admits_then_returns_formspec_metadata() {
        let payload = serde_json::json!({
            "aggregateType": "formspec.response",
            "aggregateId": "resp-001",
            "payload": { "status": "submitted" }
        });
        let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");
        let event = AdmissionEvent {
            scope: b"formspec.prod-mvp",
            event_type: FORMSPEC_RESPONSE_SUBMITTED,
            payload: payload_bytes.as_slice(),
        };
        let admitted = FormspecAppendAdmissionPolicy::new()
            .admit(&event)
            .await
            .expect("well-formed payload admits");
        assert_eq!(admitted.event_type, FORMSPEC_RESPONSE_SUBMITTED);
        assert_eq!(admitted.event_family.as_str(), FORMSPEC_EVENT_FAMILY);
        assert_eq!(admitted.artifact_type, ArtifactType::Event);
        assert_eq!(admitted.direct_submit, DirectSubmitPolicy::ServiceOnly);
        assert!(
            admitted
                .schema_ref
                .as_str()
                .starts_with("formspec-events://")
        );
    }

    #[tokio::test]
    async fn given_wrong_literal_when_admits_then_rejects_before_payload_parse() {
        let event = AdmissionEvent {
            scope: b"formspec.prod-mvp",
            event_type: "wos.kernel.case_created",
            payload: b"{}",
        };
        let err = FormspecAppendAdmissionPolicy::new()
            .admit(&event)
            .await
            .expect_err("non-Formspec literal must reject");
        assert!(
            err.to_string().contains("not a Formspec append literal"),
            "error should name literal failure: {err}"
        );
    }

    #[tokio::test]
    async fn given_payload_missing_aggregate_type_when_admits_then_rejects() {
        let payload = serde_json::json!({
            "aggregateId": "resp-missing",
            "payload": { "status": "submitted" }
        });
        let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");
        let event = AdmissionEvent {
            scope: b"formspec.prod-mvp",
            event_type: FORMSPEC_RESPONSE_SUBMITTED,
            payload: payload_bytes.as_slice(),
        };
        let err = FormspecAppendAdmissionPolicy::new()
            .admit(&event)
            .await
            .expect_err("missing aggregateType must reject");
        assert!(
            err.to_string().contains("aggregateType"),
            "error should name the missing key: {err}"
        );
    }

    #[tokio::test]
    async fn given_malformed_payload_when_admits_then_rejects() {
        let event = AdmissionEvent {
            scope: b"formspec.prod-mvp",
            event_type: FORMSPEC_RESPONSE_SUBMITTED,
            payload: b"not-json",
        };
        let err = FormspecAppendAdmissionPolicy::new()
            .admit(&event)
            .await
            .expect_err("non-JSON must reject");
        assert!(
            err.to_string().contains("not valid JSON"),
            "error should name parse failure: {err}"
        );
    }

    #[test]
    fn given_formspec_event_type_specs_when_registered_then_review_gate_accepts_all() {
        let specs = formspec_event_type_specs();
        assert_eq!(specs.len(), 1);
        let mut registry = ReviewGateEventTypeRegistry::default();
        for spec in specs {
            registry
                .register(spec)
                .expect("formspec admission spec satisfies budget review");
        }
    }
}
