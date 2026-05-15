// Rust guideline compliant 2026-02-21
//! WOS validator unit tests.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use ciborium::Value;
use integrity_verify::trellis::{
    DomainEvent, DomainExport, RecordValidator, Severity, TrellisTimestamp,
};

use crate::records::parse_signature_affirmation_record;
use crate::event_types::{
    OPEN_CLOCKS_EXPORT_EXTENSION, WOS_CASE_CREATED_EVENT_TYPE,
    WOS_GOVERNANCE_CLOCK_RESOLVED_EVENT_TYPE, WOS_GOVERNANCE_CLOCK_STARTED_EVENT_TYPE,
    WOS_GOVERNANCE_DETERMINATION_RESCINDED_EVENT_TYPE, WOS_GOVERNANCE_REINSTATED_EVENT_TYPE,
    WOS_IDENTITY_ATTESTATION_EVENT_TYPE, WOS_INTAKE_ACCEPTED_EVENT_TYPE,
    WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE,
};
use crate::validator::WosRecordValidator;

fn event(event_type: &str, hash_byte: u8, payload: Option<Vec<u8>>) -> DomainEvent {
    DomainEvent {
        event_type: event_type.to_string(),
        payload,
        canonical_event_hash: [hash_byte; 32],
        authored_at: TrellisTimestamp {
            seconds: u64::from(hash_byte),
            nanos: 0,
        },
    }
}

fn clock_started(clock_id: &str, clock_kind: &str, calendar_ref: Option<&str>) -> Vec<u8> {
    let mut data = vec![
        (
            Value::Text("clockId".into()),
            Value::Text(clock_id.to_string()),
        ),
        (
            Value::Text("clockKind".into()),
            Value::Text(clock_kind.to_string()),
        ),
    ];
    if let Some(calendar_ref) = calendar_ref {
        data.push((
            Value::Text("calendarRef".into()),
            Value::Text(calendar_ref.to_string()),
        ));
    }
    encode_record(WOS_GOVERNANCE_CLOCK_STARTED_EVENT_TYPE, data)
}

fn clock_paused(clock_id: &str) -> Vec<u8> {
    encode_record(
        WOS_GOVERNANCE_CLOCK_RESOLVED_EVENT_TYPE,
        vec![
            (
                Value::Text("clockId".into()),
                Value::Text(clock_id.to_string()),
            ),
            (
                Value::Text("resolution".into()),
                Value::Text("paused".into()),
            ),
        ],
    )
}

fn encode_record(event_type: &str, data: Vec<(Value, Value)>) -> Vec<u8> {
    let value = Value::Map(vec![
        (
            Value::Text("event".into()),
            Value::Text(event_type.to_string()),
        ),
        (Value::Text("data".into()), Value::Map(data)),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes).unwrap();
    bytes
}

const DOC_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PRESENTATION_HASH: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// Given a signature affirmation payload with distinct K-2 fields, when parsed,
/// then signingActId and presentationHash are extracted separately from
/// sourceSignatureId and documentHash (TWREF-050).
#[test]
fn given_distinct_k2_fields_when_parsed_then_signing_act_and_presentation_hash_preserved() {
    let payload = encode_record(
        WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE,
        vec![
            (Value::Text("signerId".into()), Value::Text("signer-1".into())),
            (Value::Text("roleId".into()), Value::Text("role-1".into())),
            (Value::Text("role".into()), Value::Text("applicant".into())),
            (Value::Text("documentId".into()), Value::Text("application".into())),
            (
                Value::Text("signingActId".into()),
                Value::Text("signing-act-777".into()),
            ),
            (Value::Text("documentHash".into()), Value::Text(DOC_HASH.into())),
            (
                Value::Text("presentationHash".into()),
                Value::Text(PRESENTATION_HASH.into()),
            ),
            (
                Value::Text("documentHashAlgorithm".into()),
                Value::Text("sha-256".into()),
            ),
            (
                Value::Text("sourceSignatureSystem".into()),
                Value::Text("formspec".into()),
            ),
            (
                Value::Text("sourceSignatureId".into()),
                Value::Text("source-sig-001".into()),
            ),
            (
                Value::Text("signedPayloadDigest".into()),
                Value::Text(DOC_HASH.into()),
            ),
            (
                Value::Text("signedPayloadDigestAlgorithm".into()),
                Value::Text("sha-256".into()),
            ),
            (
                Value::Text("signingIntent".into()),
                Value::Text("urn:wos:signing-intent:applicant-signature".into()),
            ),
            (
                Value::Text("signedAt".into()),
                Value::Text("2026-05-15T12:00:00Z".into()),
            ),
            (Value::Text("identityBinding".into()), Value::Map(vec![])),
            (Value::Text("consentReference".into()), Value::Map(vec![])),
            (
                Value::Text("signatureProvider".into()),
                Value::Text("formspec".into()),
            ),
            (Value::Text("ceremonyId".into()), Value::Text("ceremony-1".into())),
            (
                Value::Text("formspecResponseRef".into()),
                Value::Text("urn:test:response:1".into()),
            ),
        ],
    );
    let parsed =
        parse_signature_affirmation_record(&payload, WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE)
            .expect("parse signature affirmation");
    assert_eq!(parsed.signing_act_id, "signing-act-777");
    assert_eq!(parsed.source_signature_id.as_deref(), Some("source-sig-001"));
    assert_eq!(parsed.document_hash, DOC_HASH);
    assert_eq!(parsed.presentation_hash, PRESENTATION_HASH);
}

/// Given catalog and record disagree on presentationHash, when matched,
/// then the stranger test reports a mismatch (TWREF-050 / WOS-TV-005).
#[test]
fn given_wrong_presentation_hash_when_catalog_compared_then_entry_does_not_match() {
    use crate::catalog::signature_entry_matches_record;
    use crate::records::{SignatureAffirmationRecordDetails, SignatureManifestEntry};

    let entry = SignatureManifestEntry {
        canonical_event_hash: [0u8; 32],
        signer_id: "signer-1".to_string(),
        role_id: "role-1".to_string(),
        role: "applicant".to_string(),
        document_id: "application".to_string(),
        document_hash: DOC_HASH.to_string(),
        document_hash_algorithm: "sha-256".to_string(),
        signed_at: "2026-05-15T12:00:00Z".to_string(),
        identity_binding: Value::Map(vec![]),
        consent_reference: Value::Map(vec![]),
        signature_provider: "formspec".to_string(),
        ceremony_id: "ceremony-1".to_string(),
        source_signature_system: Some("formspec".to_string()),
        source_signature_id: Some("source-sig-001".to_string()),
        signed_payload_digest: Some(DOC_HASH.to_string()),
        signed_payload_digest_algorithm: Some("sha-256".to_string()),
        signing_intent: Some("urn:wos:signing-intent:applicant-signature".into()),
        profile_ref: None,
        profile_key: None,
        formspec_response_ref: "urn:test:response:1".to_string(),
        signing_act_id: "signing-act-777".to_string(),
        presentation_hash: PRESENTATION_HASH.to_string(),
        witnessed_signature_ref: None,
    };
    let record = SignatureAffirmationRecordDetails {
        signer_id: entry.signer_id.clone(),
        role_id: entry.role_id.clone(),
        role: entry.role.clone(),
        document_id: entry.document_id.clone(),
        document_hash: entry.document_hash.clone(),
        document_hash_algorithm: entry.document_hash_algorithm.clone(),
        signed_at: entry.signed_at.clone(),
        identity_binding: entry.identity_binding.clone(),
        consent_reference: entry.consent_reference.clone(),
        signature_provider: entry.signature_provider.clone(),
        ceremony_id: entry.ceremony_id.clone(),
        source_signature_system: entry.source_signature_system.clone(),
        source_signature_id: entry.source_signature_id.clone(),
        signed_payload_digest: entry.signed_payload_digest.clone(),
        signed_payload_digest_algorithm: entry.signed_payload_digest_algorithm.clone(),
        signing_intent: entry.signing_intent.clone(),
        profile_ref: entry.profile_ref.clone(),
        profile_key: entry.profile_key.clone(),
        formspec_response_ref: entry.formspec_response_ref.clone(),
        signing_act_id: entry.signing_act_id.clone(),
        presentation_hash: DOC_HASH.to_string(),
        witnessed_signature_ref: None,
    };
    assert!(!signature_entry_matches_record(&entry, &record));
}

/// Given export/006 with a tampered signature catalog row, when verify_export_zip
/// runs, then stranger verification reports failure (TWREF-050 / WOS-TV-005).
#[test]
fn given_tampered_signature_catalog_export_when_verify_export_zip_then_stranger_fails() {
    let zip_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../fixtures/vectors/verify/014-export-006-signature-row-mismatch/input-export.zip",
    );
    let bytes = std::fs::read(&zip_path).unwrap_or_else(|error| {
        panic!(
            "fixture input-export.zip must exist at {}: {error}",
            zip_path.display()
        );
    });
    let report = crate::verify_export_zip(&bytes);
    let stranger_passed = report.trellis.structure_verified
        && report.trellis.integrity_verified
        && report
            .wos_findings
            .iter()
            .all(|finding| finding.severity != Severity::Failure);
    assert!(
        !stranger_passed,
        "tampered signature catalog must fail stranger verification: {report:#?}"
    );
}

#[test]
fn validator_admits_wos_identity_attestation_event_type() {
    assert!(
        WosRecordValidator
            .admits_identity_attestation_event_type(WOS_IDENTITY_ATTESTATION_EVENT_TYPE)
    );
    assert!(
        !WosRecordValidator
            .admits_identity_attestation_event_type("wos.identity.authentication_method")
    );
}

#[test]
fn given_wos_event_type_constants_when_checked_against_provenance_kind_then_literals_match() {
    use wos_events::ProvenanceKind;

    assert_eq!(
        WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE,
        ProvenanceKind::SignatureAffirmation
            .canonical_event_literal()
            .expect("canonical literal")
    );
    assert_eq!(
        WOS_INTAKE_ACCEPTED_EVENT_TYPE,
        ProvenanceKind::IntakeAccepted
            .canonical_event_literal()
            .expect("canonical literal")
    );
    assert_eq!(
        WOS_CASE_CREATED_EVENT_TYPE,
        ProvenanceKind::CaseCreated
            .canonical_event_literal()
            .expect("canonical literal")
    );
    assert_eq!(
        WOS_IDENTITY_ATTESTATION_EVENT_TYPE,
        ProvenanceKind::IdentityAttestation
            .canonical_event_literal()
            .expect("canonical literal")
    );
    assert_eq!(
        WOS_GOVERNANCE_DETERMINATION_RESCINDED_EVENT_TYPE,
        ProvenanceKind::DeterminationRescinded
            .canonical_event_literal()
            .expect("canonical literal")
    );
}

#[test]
fn validator_reports_rescission_terminality_as_wos_finding() {
    let findings = WosRecordValidator.validate_events(&[
        event(WOS_GOVERNANCE_DETERMINATION_RESCINDED_EVENT_TYPE, 1, None),
        event("wos.governance.determination_denied", 2, None),
    ]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, "rescission_terminality_violation");
    assert_eq!(findings[0].event_hash, Some([2; 32]));
}

#[test]
fn validator_allows_determination_after_reinstatement() {
    let findings = WosRecordValidator.validate_events(&[
        event(WOS_GOVERNANCE_DETERMINATION_RESCINDED_EVENT_TYPE, 1, None),
        event(WOS_GOVERNANCE_REINSTATED_EVENT_TYPE, 2, None),
        event("wos.governance.determination_denied", 3, None),
    ]);
    assert!(findings.is_empty());
}

#[test]
fn validator_ignores_clock_shaped_payload_on_non_clock_event_type() {
    // Spec contract (`trellis/specs/wos-trellis-verification.md` §3):
    // clock semantics are gated by `event_type`. A non-clock event whose
    // payload happens to deserialize as a clock record MUST NOT participate
    // in segment validation, even when followed by a real conflicting
    // clock_started — there is no "paused" segment to mismatch against.
    let findings = WosRecordValidator.validate_events(&[
        event(
            "wos.kernel.case_created",
            1,
            Some(clock_started("clock-1", "review", Some("fed-calendar"))),
        ),
        event(
            "wos.governance.clock_started",
            2,
            Some(clock_started("clock-1", "review", Some("state-calendar"))),
        ),
    ]);
    assert!(
        findings.is_empty(),
        "non-clock event_type must not trigger clock_calendar_mismatch, got: {findings:?}"
    );
}

#[test]
fn validator_reports_clock_calendar_mismatch_as_wos_finding() {
    let findings = WosRecordValidator.validate_events(&[
        event(
            "wos.governance.clock_started",
            1,
            Some(clock_started("clock-1", "review", Some("fed-calendar"))),
        ),
        event(
            "wos.governance.clock_resolved",
            2,
            Some(clock_paused("clock-1")),
        ),
        event(
            "wos.governance.clock_started",
            3,
            Some(clock_started("clock-1", "review", Some("state-calendar"))),
        ),
    ]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, "clock_calendar_mismatch");
    assert_eq!(findings[0].event_hash, Some([3; 32]));
}

#[test]
fn validator_reports_open_clock_overdue_as_advisory() {
    let mut members = BTreeMap::new();
    members.insert(
        "open-clocks.json".to_string(),
        br#"{"open_clocks":[{"clock_id":"appeal-response-clock","clock_kind":"appeal-response","computed_deadline":[10,0],"origin_event_hash":"0101010101010101010101010101010101010101010101010101010101010101"}],"sealed_at":[11,0]}
"#
        .to_vec(),
    );
    let mut manifest_extensions = BTreeMap::new();
    manifest_extensions.insert(OPEN_CLOCKS_EXPORT_EXTENSION.to_string(), Vec::new());

    let findings = WosRecordValidator.validate_export(DomainExport {
        events: &[],
        members: &members,
        manifest_extensions: &manifest_extensions,
    });

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Advisory);
    assert_eq!(
        findings[0].kind,
        "open_clock_overdue:appeal-response-clock:0101010101010101010101010101010101010101010101010101010101010101"
    );
    assert_eq!(findings[0].event_hash, Some([1; 32]));
}
