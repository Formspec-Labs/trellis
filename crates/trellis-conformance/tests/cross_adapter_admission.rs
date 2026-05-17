//! Cross-adapter admission contract tests (TRELLIS-DI-TOPOLOGY-TODO Gate 17).
//!
//! These tests assert that the two domain admission adapters in this stack
//! (`trellis-admission-wos`, `trellis-admission-formspec`) agree on the
//! neutral [`AdmittedEvent`] contract. Known literals must return the
//! expected artifact type + family + URI-like schema ref; unknown literals
//! must reject before append; payloads validated by one adapter must not
//! be accepted by the other.

use stack_common_error::StackError;
use trellis_admission_formspec::{FORMSPEC_RESPONSE_SUBMITTED, FormspecAppendAdmissionPolicy};
use trellis_admission_wos::WosEventAdmissionPolicy;
use trellis_server_ports::{
    AdmissionEvent, AdmittedEvent, DirectSubmitPolicy, EventAdmissionPolicy,
};
use trellis_types::ArtifactType;
use wos_events::{ProvenanceKind, ProvenanceRecord, WOS_CANONICAL_EVENT_LITERALS};

fn wos_payload(kind: ProvenanceKind, id: &str) -> Vec<u8> {
    let mut record = ProvenanceRecord::blank(kind);
    record.id = id.to_string();
    serde_json::to_vec(&record).expect("serialize wos record")
}

fn formspec_payload() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "aggregateType": "formspec.response",
        "aggregateId": "resp-cross-adapter",
        "payload": { "status": "submitted" }
    }))
    .expect("serialize formspec payload")
}

async fn admit_wos(event_type: &str, payload: &[u8]) -> Result<AdmittedEvent, StackError> {
    WosEventAdmissionPolicy::new()
        .admit(&AdmissionEvent {
            scope: b"case-cross-adapter",
            event_type,
            payload,
        })
        .await
}

async fn admit_formspec(event_type: &str, payload: &[u8]) -> Result<AdmittedEvent, StackError> {
    FormspecAppendAdmissionPolicy::new()
        .admit(&AdmissionEvent {
            scope: b"formspec.cross-adapter",
            event_type,
            payload,
        })
        .await
}

#[tokio::test]
async fn given_known_wos_literal_when_wos_admits_then_returns_event_artifact_and_family() {
    let payload = wos_payload(ProvenanceKind::CaseCreated, "prov-wos-known");
    let admitted = admit_wos("wos.kernel.case_created", &payload)
        .await
        .expect("known WOS literal admits");
    assert_eq!(admitted.event_type, "wos.kernel.case_created");
    assert_eq!(admitted.event_family.as_str(), "wos.kernel");
    assert_eq!(admitted.artifact_type, ArtifactType::Event);
    assert_eq!(admitted.direct_submit, DirectSubmitPolicy::ServiceOnly);
    assert!(
        admitted.schema_ref.as_str().starts_with("wos-events://"),
        "WOS schema ref must use wos-events scheme; got {}",
        admitted.schema_ref
    );
}

#[tokio::test]
async fn given_known_formspec_literal_when_formspec_admits_then_returns_event_artifact() {
    let payload = formspec_payload();
    let admitted = admit_formspec(FORMSPEC_RESPONSE_SUBMITTED, &payload)
        .await
        .expect("formspec literal admits");
    assert_eq!(admitted.event_type, FORMSPEC_RESPONSE_SUBMITTED);
    assert_eq!(admitted.event_family.as_str(), "formspec.response");
    assert_eq!(admitted.artifact_type, ArtifactType::Event);
    assert_eq!(admitted.direct_submit, DirectSubmitPolicy::ServiceOnly);
    assert!(
        admitted
            .schema_ref
            .as_str()
            .starts_with("formspec-events://"),
        "Formspec schema ref must use formspec-events scheme; got {}",
        admitted.schema_ref
    );
}

#[tokio::test]
async fn given_unknown_literal_when_wos_admits_then_rejects_before_append() {
    let err = admit_wos("c2pa.assertion.created", b"{}")
        .await
        .expect_err("unknown literal must reject");
    assert!(
        err.to_string().contains("not registered"),
        "WOS adapter must reject unknown literals before append; got {err}"
    );
}

#[tokio::test]
async fn given_unknown_literal_when_formspec_admits_then_rejects_before_append() {
    let err = admit_formspec("wos.kernel.case_created", b"{}")
        .await
        .expect_err("non-Formspec literal must reject");
    assert!(
        err.to_string().contains("not a Formspec append literal"),
        "Formspec adapter must reject non-Formspec literals; got {err}"
    );
}

#[tokio::test]
async fn given_wos_payload_when_formspec_admits_then_rejects() {
    let payload = wos_payload(ProvenanceKind::CaseCreated, "prov-cross-domain");
    let err = admit_formspec(FORMSPEC_RESPONSE_SUBMITTED, &payload)
        .await
        .expect_err("WOS payload must not satisfy Formspec admission");
    let message = err.to_string();
    assert!(
        message.contains("aggregateType")
            || message.contains("aggregateId")
            || message.contains("payload"),
        "Formspec admission should reject missing aggregate keys; got {message}"
    );
}

#[tokio::test]
async fn given_formspec_payload_when_wos_admits_then_rejects() {
    let payload = formspec_payload();
    let err = admit_wos("wos.kernel.case_created", &payload)
        .await
        .expect_err("Formspec aggregate payload must not satisfy WOS admission");
    assert!(
        err.to_string().contains("not a WOS provenance record"),
        "WOS admission should reject non-provenance JSON; got {err}"
    );
}

#[tokio::test]
async fn given_governance_wos_literal_when_admits_then_family_distinguishes_namespace() {
    let payload = wos_payload(ProvenanceKind::AmendmentAuthorized, "prov-governance-cross");
    let admitted = admit_wos("wos.governance.amendment_authorized", &payload)
        .await
        .expect("governance literal admits");
    assert_eq!(admitted.event_family.as_str(), "wos.governance");
    assert_ne!(admitted.event_family.as_str(), "wos.kernel");
}

#[test]
fn given_wos_admission_literal_table_when_aliased_then_matches_substrate_export() {
    // Phase-1 sanity: trellis-admission-wos re-exports the slice from wos-events
    // verbatim. If they diverge by any byte, governance literals or fixtures will
    // silently disagree with admission registration at startup.
    assert_eq!(
        WOS_CANONICAL_EVENT_LITERALS.len(),
        wos_events::WOS_CANONICAL_EVENT_LITERALS.len(),
        "WOS_CANONICAL_EVENT_LITERALS must alias wos-events WOS_CANONICAL_EVENT_LITERALS"
    );
    assert!(
        std::ptr::eq(
            WOS_CANONICAL_EVENT_LITERALS.as_ptr(),
            wos_events::WOS_CANONICAL_EVENT_LITERALS.as_ptr()
        ),
        "alias must point at the same slice"
    );
}
