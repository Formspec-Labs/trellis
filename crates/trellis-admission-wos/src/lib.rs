// Rust guideline compliant 2026-02-21
//! WOS-aware ingress admission for Trellis.
//!
//! Validates WOS provenance payloads against canonical event literals owned by
//! [`wos_events`] and emits neutral [`AdmittedEvent`] metadata downstream
//! consumers (receipts, event-type catalog projection, dispatch) consult.
//!
//! Generic Trellis service modules must not depend on this crate; only the
//! Trellis composition root wires it in.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use stack_common_error::StackError;
use trellis_server_ports::{
    AdmissionEvent, AdmittedEvent, DirectSubmitPolicy, EventAdmissionPolicy, EventFamilyId,
    EventTypeSpec, BudgetReviewRecord, ProfileId, SchemaRef,
};
use wos_events::{
    ProvenanceKind, ProvenanceRecord, SUBSTRATE_CANONICAL_EVENT_LITERALS,
};

/// URI scheme used in [`AdmittedEvent::schema_ref`] entries emitted by this adapter.
pub const WOS_SCHEMA_SCHEME: &str = "wos-events";

/// Canonical WOS event literals admitted by this adapter.
///
/// The literals are sourced from [`wos_events::SUBSTRATE_CANONICAL_EVENT_LITERALS`]
/// so adding a new WOS event family in `wos-events` does not require a Trellis
/// admission edit.
pub const WOS_CANONICAL_EVENT_LITERALS: &[&str] = SUBSTRATE_CANONICAL_EVENT_LITERALS;

/// Returns the schema reference used by [`AdmittedEvent`] entries this adapter emits.
#[must_use]
pub fn wos_schema_ref(event_type: &str) -> String {
    format!("{WOS_SCHEMA_SCHEME}://{event_type}")
}

/// Derives the logical event family from a WOS event literal.
///
/// Family is the literal's first two dotted segments under the `wos.` root
/// (`wos.kernel`, `wos.governance`, `wos.ai`, `wos.assurance`, …) so
/// downstream consumers can route on family without re-parsing each literal.
/// Returns `None` for literals not rooted at `wos.` or missing a second
/// dotted segment — generic catalog projection must dispatch those through
/// the owning admission adapter rather than falling back here.
#[must_use]
pub fn wos_event_family(event_type: &str) -> Option<&str> {
    let after_first = event_type.find('.')? + 1;
    if !event_type[..after_first].eq_ignore_ascii_case("wos.") {
        return None;
    }
    let rest = &event_type[after_first..];
    let second = rest.find('.')?;
    Some(&event_type[..after_first + second])
}

/// Builds the event-type specifications a Trellis composition root may register
/// against [`trellis_server_ports::EventTypeRegistry`] at startup.
///
/// Each entry carries a non-empty reviewer to satisfy the registry budget gate.
#[must_use]
pub fn wos_event_type_specs() -> Vec<EventTypeSpec> {
    WOS_CANONICAL_EVENT_LITERALS
        .iter()
        .map(|event_type| EventTypeSpec {
            event_type: (*event_type).to_string(),
            schema_ref: SchemaRef::new(wos_schema_ref(event_type))
                .expect("wos-events schema refs are URI-like by construction"),
            budget_review: BudgetReviewRecord {
                reviewer: "wos-events::SUBSTRATE_CANONICAL_EVENT_LITERALS".to_string(),
                plaintext_fields: vec!["eventType".to_string()],
                considered: true,
            },
        })
        .collect()
}

/// WOS-aware admission policy: validates submitted payloads and emits neutral metadata.
#[derive(Debug, Clone, Copy, Default)]
pub struct WosEventAdmissionPolicy;

impl WosEventAdmissionPolicy {
    /// Constructs the adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn admitted_event_for(event_type: &str) -> Result<AdmittedEvent, StackError> {
        let family_slice = wos_event_family(event_type).ok_or_else(|| {
            StackError::internal(format!(
                "WOS literal `{event_type}` is missing the `<root>.<family>.` prefix"
            ))
        })?;
        let family = EventFamilyId::new(family_slice)
            .map_err(|error| StackError::internal(format!("wos family invariant: {error}")))?;
        let schema_ref = SchemaRef::new(wos_schema_ref(event_type)).map_err(|error| {
            StackError::internal(format!("wos schema ref invariant: {error}"))
        })?;
        Ok(AdmittedEvent {
            event_type: event_type.to_string(),
            event_family: family,
            schema_ref,
            profile_id: ProfileId::new(integrity_verify::WOS_PROFILE_ID),
            direct_submit: DirectSubmitPolicy::ServiceOnly,
        })
    }
}

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
        Self::admitted_event_for(event.event_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trellis_server_ports::{EventTypeRegistry, ReviewGateEventTypeRegistry};

    fn provenance_payload(kind: ProvenanceKind, id: &str) -> Vec<u8> {
        let mut record = ProvenanceRecord::blank(kind);
        record.id = id.to_string();
        serde_json::to_vec(&record).expect("encode provenance record")
    }

    #[tokio::test]
    async fn given_aligned_wos_provenance_when_admits_then_returns_neutral_metadata() {
        let payload = provenance_payload(ProvenanceKind::CaseCreated, "prov-aligned");
        let event = AdmissionEvent {
            scope: b"case-1",
            event_type: "wos.kernel.case_created",
            payload: payload.as_slice(),
        };
        let admitted = WosEventAdmissionPolicy::new()
            .admit(&event)
            .await
            .expect("aligned wos event admits");
        assert_eq!(admitted.event_type, "wos.kernel.case_created");
        assert_eq!(admitted.event_family.as_str(), "wos.kernel");
        assert_eq!(
            admitted.schema_ref.as_str(),
            "wos-events://wos.kernel.case_created"
        );
        assert_eq!(admitted.profile_id.get(), integrity_verify::WOS_PROFILE_ID);
        assert_eq!(admitted.direct_submit, DirectSubmitPolicy::ServiceOnly);
    }

    #[tokio::test]
    async fn given_governance_literal_when_admits_then_family_distinguishes_namespace() {
        let payload = provenance_payload(
            ProvenanceKind::AmendmentAuthorized,
            "prov-governance-family",
        );
        let event = AdmissionEvent {
            scope: b"case-1",
            event_type: "wos.governance.amendment_authorized",
            payload: payload.as_slice(),
        };
        let admitted = WosEventAdmissionPolicy::new()
            .admit(&event)
            .await
            .expect("governance event admits");
        assert_eq!(admitted.event_family.as_str(), "wos.governance");
        assert_ne!(
            admitted.event_family.as_str(),
            "wos.kernel",
            "governance events must not be classified as kernel"
        );
    }

    #[test]
    fn given_wos_literals_when_family_derived_then_namespaces_separate() {
        assert_eq!(wos_event_family("wos.kernel.case_created"), Some("wos.kernel"));
        assert_eq!(
            wos_event_family("wos.governance.amendment_authorized"),
            Some("wos.governance")
        );
        assert_eq!(
            wos_event_family("wos.ai.capability_invocation"),
            Some("wos.ai")
        );
        assert_eq!(
            wos_event_family("wos.assurance.identity_attestation"),
            Some("wos.assurance")
        );
        assert_eq!(wos_event_family("two_segments_only"), None);
        assert_eq!(wos_event_family("wos.only_one"), None);
    }

    #[test]
    fn given_non_wos_literal_when_family_derived_then_returns_none() {
        // Family inference is strictly bounded to the `wos.` root so a future
        // adapter (c2pa, did, etc.) does not silently inherit a misleading
        // family slug from this helper.
        assert_eq!(wos_event_family("c2pa.assertion.created"), None);
        assert_eq!(
            wos_event_family("substrate.append.response_submitted"),
            None
        );
        assert_eq!(wos_event_family("formspec.event.something"), None);
    }

    #[tokio::test]
    async fn given_unknown_wos_event_when_admits_then_rejects_before_payload_parse() {
        let event = AdmissionEvent {
            scope: b"case-1",
            event_type: "wos.kernel.unknown_literal",
            payload: b"{}",
        };
        let err = WosEventAdmissionPolicy::new()
            .admit(&event)
            .await
            .expect_err("unknown literal must reject");
        assert!(
            err.to_string().contains("not registered for WOS admission"),
            "error should name registration gap: {err}"
        );
    }

    #[tokio::test]
    async fn given_malformed_payload_when_admits_then_rejects() {
        let event = AdmissionEvent {
            scope: b"case-1",
            event_type: "wos.kernel.case_created",
            payload: b"not-json",
        };
        let err = WosEventAdmissionPolicy::new()
            .admit(&event)
            .await
            .expect_err("non-JSON payload must reject");
        assert!(
            err.to_string().contains("not a WOS provenance record"),
            "error should name shape failure: {err}"
        );
    }

    #[tokio::test]
    async fn given_payload_record_kind_mismatch_when_admits_then_rejects() {
        // CaseCreated payload posted under a different registered literal: same family, wrong kind.
        let payload = provenance_payload(ProvenanceKind::CaseCreated, "prov-mismatch");
        let event = AdmissionEvent {
            scope: b"case-1",
            event_type: "wos.kernel.commit_attempt_failure",
            payload: payload.as_slice(),
        };
        let err = WosEventAdmissionPolicy::new()
            .admit(&event)
            .await
            .expect_err("recordKind mismatch must reject");
        assert!(
            err.to_string().contains("recordKind does not match"),
            "error should name recordKind: {err}"
        );
    }

    #[test]
    fn given_wos_event_type_specs_when_registered_then_review_gate_accepts_all() {
        let specs = wos_event_type_specs();
        assert!(!specs.is_empty(), "WOS event-type spec set must not be empty");
        let mut registry = ReviewGateEventTypeRegistry::default();
        for spec in specs {
            registry
                .register(spec)
                .expect("WOS admission specs satisfy budget review");
        }
    }

    #[test]
    fn given_wos_event_literals_when_resolved_via_provenance_kind_then_all_resolve() {
        for literal in WOS_CANONICAL_EVENT_LITERALS {
            assert!(
                ProvenanceKind::from_canonical_event_literal(literal).is_some(),
                "WOS literal `{literal}` must resolve through ProvenanceKind"
            );
        }
    }
}
