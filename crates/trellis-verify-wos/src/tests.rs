// Rust guideline compliant 2026-02-21
//! WOS validator unit tests.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use ciborium::Value;
use trellis_verify::{DomainEvent, DomainExport, RecordValidator, Severity, TrellisTimestamp};

use crate::event_types::{
    OPEN_CLOCKS_EXPORT_EXTENSION, WOS_CASE_CREATED_EVENT_TYPE,
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
    encode_record("clockStarted", data)
}

fn clock_paused(clock_id: &str) -> Vec<u8> {
    encode_record(
        "clockResolved",
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

fn encode_record(kind: &str, data: Vec<(Value, Value)>) -> Vec<u8> {
    let value = Value::Map(vec![
        (
            Value::Text("recordKind".into()),
            Value::Text(kind.to_string()),
        ),
        (Value::Text("data".into()), Value::Map(data)),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes).unwrap();
    bytes
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
fn wos_event_type_constants_use_f13_snake_case_literals() {
    assert_eq!(
        WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE,
        "wos.kernel.signature_affirmation"
    );
    assert_eq!(WOS_INTAKE_ACCEPTED_EVENT_TYPE, "wos.kernel.intake_accepted");
    assert_eq!(WOS_CASE_CREATED_EVENT_TYPE, "wos.kernel.case_created");
    assert_eq!(
        WOS_IDENTITY_ATTESTATION_EVENT_TYPE,
        "wos.assurance.identity_attestation"
    );
    assert_eq!(
        WOS_GOVERNANCE_DETERMINATION_RESCINDED_EVENT_TYPE,
        "wos.governance.determination_rescinded"
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
