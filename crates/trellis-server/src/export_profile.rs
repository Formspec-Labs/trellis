// Rust guideline compliant 2026-02-21
//! WOS/Formspec export-profile members composed by the Trellis server.
//!
//! `trellis-export-writer` binds opaque member bytes and stays substrate-only.
//! This module is the server composition seam that derives WOS/Formspec
//! verifier-facing members from the closed event snapshot before the writer
//! signs the export manifest.

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use integrity_cbor::{
    Value, decode_cbor_value, map_lookup_bytes, map_lookup_map, map_lookup_optional_text,
    map_lookup_optional_value, map_lookup_text, map_lookup_value,
};
use stack_common_error::StackError;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use trellis_export_writer::{PolicyClosureMember, SignedActsCatalogMember, TrellisTimestamp};
use trellis_types::StoredEvent;

use crate::composition::{
    wos_signature_admission_failed_event_type, wos_signature_affirmation_event_type,
};

const SIGNED_ACTS_DERIVATION_RULE: &str = "signed-act-projection-wos-formspec-v1";
const POLICY_CLOSURE_VERSION: &str = "wos-formspec-signature-policy-closure-2026-05-16";

/// Optional export-profile members supplied to `trellis-export-writer`.
#[derive(Debug, Default)]
pub(crate) struct ExportProfileMembers {
    pub(crate) signed_acts_catalog: Option<SignedActsCatalogMember>,
    pub(crate) policy_closure: Option<PolicyClosureMember>,
}

impl ExportProfileMembers {
    /// Returns true when domain verification must run before publication.
    #[must_use]
    pub(crate) fn requires_profile_validation(&self) -> bool {
        self.signed_acts_catalog.is_some() || self.policy_closure.is_some()
    }
}

/// One policy-evidence artifact row carried in `067-policy-closure.cbor`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyClosureArtifact {
    pub(crate) owner: &'static str,
    pub(crate) kind: &'static str,
    pub(crate) version: &'static str,
    pub(crate) reference: &'static str,
    pub(crate) digest: [u8; 32],
    pub(crate) valid_from: &'static str,
    pub(crate) valid_to: Option<&'static str>,
}

#[derive(Clone, Debug)]
struct ProjectedAct {
    act_id: String,
    signed_at: String,
    first_source_ref: Vec<u8>,
    value: Value,
}

struct CorrelatedAct {
    act: ProjectedAct,
    compatibility_key: Vec<u8>,
    source_refs: BTreeMap<Vec<u8>, Value>,
}

#[derive(Clone, Debug)]
struct SignedActsDerivation {
    bytes: Vec<u8>,
    policy_closure_eligible: bool,
}

#[derive(Clone, Debug)]
struct SignatureAffirmationRecordDetails {
    signer_id: String,
    role_id: String,
    role: String,
    document_id: String,
    document_ref: Option<Value>,
    document_hash: String,
    document_hash_algorithm: String,
    signed_at: String,
    consent_reference: Value,
    signature_provider: String,
    ceremony_id: String,
    source_signature_system: Option<String>,
    source_signature_id: Option<String>,
    signed_payload_digest: Option<String>,
    signed_payload_digest_algorithm: Option<String>,
    signing_intent: Option<String>,
    profile_ref: Option<String>,
    profile_key: Option<String>,
    formspec_response_ref: String,
    signing_act_id: String,
    presentation_hash: String,
    witnessed_signature_ref: Option<String>,
    primitive_verification: Value,
}

#[derive(Clone, Debug)]
struct SignatureAdmissionFailedRecordDetails {
    reason: String,
    response_id: String,
    signed_payload_digest: String,
    signature_id: String,
    signing_intent: String,
    signer_id: Option<String>,
    emitted_at: String,
}

/// Builds optional WOS/Formspec export-profile members for a closed event set.
///
/// # Errors
/// Returns an error if a signature source event is unreadable or malformed.
pub(crate) fn build_export_profile_members(
    scope: &[u8],
    events: &[StoredEvent],
    generated_at: TrellisTimestamp,
    policy_artifacts: &[PolicyClosureArtifact],
) -> Result<ExportProfileMembers, StackError> {
    let Some(signed_acts) = signed_acts_catalog(scope, events)? else {
        return Ok(ExportProfileMembers::default());
    };
    let policy_closure = if signed_acts.policy_closure_eligible {
        Some(PolicyClosureMember {
            bytes: policy_closure(scope, generated_at, policy_artifacts)?,
            closure_version: POLICY_CLOSURE_VERSION.to_string(),
        })
    } else {
        None
    };
    Ok(ExportProfileMembers {
        signed_acts_catalog: Some(SignedActsCatalogMember {
            bytes: signed_acts.bytes,
            derivation_rule: SIGNED_ACTS_DERIVATION_RULE.to_string(),
        }),
        policy_closure,
    })
}

fn signed_acts_catalog(
    scope: &[u8],
    events: &[StoredEvent],
) -> Result<Option<SignedActsDerivation>, StackError> {
    let mut acts = Vec::new();
    let mut policy_closure_eligible = true;
    let signature_affirmation = wos_signature_affirmation_event_type();
    let signature_admission_failed = wos_signature_admission_failed_event_type();
    for event in events {
        let event_type = event_type(event)?;
        if event_type == signature_affirmation {
            let payload = inline_payload_bytes(event)?.ok_or_else(|| {
                StackError::bad_request(
                    "signature affirmation projection requires inline payload bytes",
                )
            })?;
            let record = parse_signature_affirmation_record(&payload, signature_affirmation)?;
            let canonical_event_hash = crate::event_hash(scope, event)?;
            policy_closure_eligible &= signature_affirmation_policy_covered(&record);
            acts.push(project_admitted_act(canonical_event_hash, &record)?);
        } else if event_type == signature_admission_failed {
            let payload = inline_payload_bytes(event)?.ok_or_else(|| {
                StackError::bad_request(
                    "signature admission-failed projection requires inline payload bytes",
                )
            })?;
            let record =
                parse_signature_admission_failed_record(&payload, signature_admission_failed)?;
            let canonical_event_hash = crate::event_hash(scope, event)?;
            policy_closure_eligible &= signature_admission_failed_policy_covered(&record);
            acts.push(project_rejected_act(canonical_event_hash, &record)?);
        }
    }
    if acts.is_empty() {
        return Ok(None);
    }
    let mut acts = correlate_projected_acts(acts)?;
    acts.sort_by(compare_projected_acts);
    let catalog = crate::text_map(vec![
        ("projection_schema_version", crate::uint(1)),
        (
            "derivation_rule_id",
            Value::Text(SIGNED_ACTS_DERIVATION_RULE.to_string()),
        ),
        (
            "acts",
            Value::Array(acts.into_iter().map(|act| act.value).collect()),
        ),
    ])?;
    Ok(Some(SignedActsDerivation {
        bytes: crate::encode_value(&catalog)?,
        policy_closure_eligible,
    }))
}

fn correlate_projected_acts(acts: Vec<ProjectedAct>) -> Result<Vec<ProjectedAct>, StackError> {
    let mut by_act_id: BTreeMap<String, CorrelatedAct> = BTreeMap::new();
    let mut seen_source_refs = BTreeSet::new();
    for act in acts {
        let compatibility_key = act_without_source_refs_key(&act.value)?;
        let source_refs = source_refs_from_act(&act.value)?;
        let mut refs = BTreeMap::new();
        for source_ref in source_refs {
            let duplicate_key = crate::encode_value(&source_ref)?;
            let key = source_ref_sort_key(&source_ref)?;
            if !seen_source_refs.insert(duplicate_key) {
                return Err(StackError::bad_request(
                    "signed acts projection repeats a source_ref",
                ));
            }
            if refs.insert(key, source_ref).is_some() {
                return Err(StackError::bad_request(
                    "signed acts projection repeats a source_ref",
                ));
            }
        }
        match by_act_id.get_mut(&act.act_id) {
            Some(existing) if existing.compatibility_key != compatibility_key => {
                return Err(StackError::bad_request(format!(
                    "act_correlation_conflict: act_id `{}` has incompatible projection fields",
                    act.act_id
                )));
            }
            Some(existing) => {
                existing.source_refs.extend(refs);
            }
            None => {
                by_act_id.insert(
                    act.act_id.clone(),
                    CorrelatedAct {
                        act,
                        compatibility_key,
                        source_refs: refs,
                    },
                );
            }
        }
    }

    by_act_id
        .into_values()
        .map(|correlated| {
            let source_refs = correlated.source_refs.into_values().collect::<Vec<_>>();
            let first_source_ref = source_refs
                .first()
                .ok_or_else(|| StackError::internal("projected act source_refs missing"))?;
            let first_source_ref = crate::encode_value(first_source_ref)?;
            let value = replace_source_refs(&correlated.act.value, Value::Array(source_refs))?;
            Ok(ProjectedAct {
                act_id: correlated.act.act_id,
                signed_at: correlated.act.signed_at,
                first_source_ref,
                value,
            })
        })
        .collect()
}

fn act_without_source_refs_key(value: &Value) -> Result<Vec<u8>, StackError> {
    let map = value
        .as_map()
        .ok_or_else(|| StackError::internal("projected act is not a map"))?;
    let filtered = map
        .iter()
        .filter(|(key, _)| key.as_text() != Some("source_refs"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    crate::encode_value(&Value::Map(filtered))
}

fn source_refs_from_act(value: &Value) -> Result<Vec<Value>, StackError> {
    let source_refs = value
        .as_map()
        .and_then(|map| map_lookup_optional_value(map, "source_refs"))
        .and_then(Value::as_array)
        .ok_or_else(|| StackError::internal("projected act source_refs missing"))
        .cloned()?;
    if source_refs.is_empty() {
        return Err(StackError::internal("projected act source_refs missing"));
    }
    Ok(source_refs)
}

fn replace_source_refs(value: &Value, source_refs: Value) -> Result<Value, StackError> {
    let map = value
        .as_map()
        .ok_or_else(|| StackError::internal("projected act is not a map"))?;
    let mut found = false;
    let replaced = map
        .iter()
        .map(|(key, value)| {
            if key.as_text() == Some("source_refs") {
                found = true;
                (key.clone(), source_refs.clone())
            } else {
                (key.clone(), value.clone())
            }
        })
        .collect();
    if !found {
        return Err(StackError::internal("projected act source_refs missing"));
    }
    Ok(Value::Map(replaced))
}

fn signature_affirmation_policy_covered(record: &SignatureAffirmationRecordDetails) -> bool {
    record
        .signing_intent
        .as_deref()
        .is_some_and(is_default_wos_signing_intent)
        && record.profile_ref.is_none()
        && record.profile_key.is_none()
}

fn signature_admission_failed_policy_covered(
    record: &SignatureAdmissionFailedRecordDetails,
) -> bool {
    is_default_wos_signing_intent(&record.signing_intent)
        && is_default_policy_admission_failure_reason(&record.reason)
}

fn is_default_wos_signing_intent(value: &str) -> bool {
    matches!(
        value,
        "urn:wos:signing-intent:applicant-signature"
            | "urn:wos:signing-intent:counter-signature"
            | "urn:wos:signing-intent:witness-attestation"
            | "urn:wos:signing-intent:notarial-attestation"
            | "urn:wos:signing-intent:consent"
            | "urn:wos:signing-intent:attestation-of-fact"
            | "urn:wos:signing-intent:agent-as-attorney-in-fact"
            | "urn:wos:signing-intent:agent-as-officer"
            | "urn:wos:signing-intent:approval"
            | "urn:wos:signing-intent:certified-receipt"
    )
}

fn is_default_policy_admission_failure_reason(value: &str) -> bool {
    matches!(
        value,
        "primitive_verification_failed"
            | "method_unregistered"
            | "evidence_divergence"
            | "registry_unrecognized_method"
    )
}

fn event_type(event: &StoredEvent) -> Result<String, StackError> {
    let value = decode_cbor_value(event.canonical_event()).map_err(cbor_bad_request)?;
    let map = value
        .as_map()
        .ok_or_else(|| StackError::bad_request("canonical event is not a map"))?;
    let header = map_lookup_map(map, "header").map_err(cbor_bad_request)?;
    String::from_utf8(map_lookup_bytes(header, "event_type").map_err(cbor_bad_request)?)
        .map_err(|_| StackError::bad_request("event_type is not UTF-8"))
}

fn inline_payload_bytes(event: &StoredEvent) -> Result<Option<Vec<u8>>, StackError> {
    let value = decode_cbor_value(event.canonical_event()).map_err(cbor_bad_request)?;
    let map = value
        .as_map()
        .ok_or_else(|| StackError::bad_request("canonical event is not a map"))?;
    let payload_ref = map_lookup_map(map, "payload_ref").map_err(cbor_bad_request)?;
    let ref_type = map_lookup_text(payload_ref, "ref_type").map_err(cbor_bad_request)?;
    if ref_type != "inline" {
        return Ok(None);
    }
    map_lookup_bytes(payload_ref, "ciphertext")
        .map(Some)
        .map_err(cbor_bad_request)
}

fn parse_signature_affirmation_record(
    payload_bytes: &[u8],
    expected_event: &str,
) -> Result<SignatureAffirmationRecordDetails, StackError> {
    let value = decode_cbor_value(payload_bytes).map_err(cbor_bad_request)?;
    let map = value.as_map().ok_or_else(|| {
        StackError::bad_request("signature affirmation payload root is not a map")
    })?;
    require_event(map, expected_event, "signature affirmation")?;
    let data = map_lookup_map(map, "data").map_err(cbor_bad_request)?;
    map_lookup_value(data, "identityBinding").map_err(cbor_bad_request)?;
    Ok(SignatureAffirmationRecordDetails {
        signer_id: map_lookup_text(data, "signerId").map_err(cbor_bad_request)?,
        role_id: map_lookup_text(data, "roleId").map_err(cbor_bad_request)?,
        role: map_lookup_text(data, "role").map_err(cbor_bad_request)?,
        document_id: map_lookup_text(data, "documentId").map_err(cbor_bad_request)?,
        document_ref: map_lookup_optional_value(data, "documentRef").cloned(),
        document_hash: map_lookup_text(data, "documentHash").map_err(cbor_bad_request)?,
        document_hash_algorithm: map_lookup_text(data, "documentHashAlgorithm")
            .map_err(cbor_bad_request)?,
        signed_at: map_lookup_text(data, "signedAt").map_err(cbor_bad_request)?,
        consent_reference: map_lookup_value(data, "consentReference")
            .map_err(cbor_bad_request)?
            .clone(),
        signature_provider: map_lookup_text(data, "signatureProvider").map_err(cbor_bad_request)?,
        ceremony_id: map_lookup_text(data, "ceremonyId").map_err(cbor_bad_request)?,
        source_signature_system: map_lookup_optional_text(data, "sourceSignatureSystem")
            .map_err(cbor_bad_request)?,
        source_signature_id: map_lookup_optional_text(data, "sourceSignatureId")
            .map_err(cbor_bad_request)?,
        signed_payload_digest: map_lookup_optional_text(data, "signedPayloadDigest")
            .map_err(cbor_bad_request)?,
        signed_payload_digest_algorithm: map_lookup_optional_text(
            data,
            "signedPayloadDigestAlgorithm",
        )
        .map_err(cbor_bad_request)?,
        signing_intent: map_lookup_optional_text(data, "signingIntent")
            .map_err(cbor_bad_request)?,
        profile_ref: map_lookup_optional_text(data, "profileRef").map_err(cbor_bad_request)?,
        profile_key: map_lookup_optional_text(data, "profileKey").map_err(cbor_bad_request)?,
        formspec_response_ref: map_lookup_text_alias(
            data,
            "sourceResponseRef",
            "formspecResponseRef",
        )?,
        signing_act_id: map_lookup_text(data, "signingActId").map_err(cbor_bad_request)?,
        presentation_hash: map_lookup_text(data, "presentationHash").map_err(cbor_bad_request)?,
        witnessed_signature_ref: map_lookup_optional_text(data, "witnessedSignatureRef")
            .map_err(cbor_bad_request)?,
        primitive_verification: map_lookup_optional_value(data, "primitiveVerification")
            .cloned()
            .unwrap_or(Value::Null),
    })
}

fn parse_signature_admission_failed_record(
    payload_bytes: &[u8],
    expected_event: &str,
) -> Result<SignatureAdmissionFailedRecordDetails, StackError> {
    let value = decode_cbor_value(payload_bytes).map_err(cbor_bad_request)?;
    let map = value.as_map().ok_or_else(|| {
        StackError::bad_request("signature admission-failed payload root is not a map")
    })?;
    require_event(map, expected_event, "signature admission failed")?;
    let data = map_lookup_map(map, "data").map_err(cbor_bad_request)?;
    let evidence = map_lookup_map(data, "evidenceBindings").map_err(cbor_bad_request)?;
    Ok(SignatureAdmissionFailedRecordDetails {
        reason: map_lookup_text(data, "reason").map_err(cbor_bad_request)?,
        response_id: map_lookup_text(evidence, "responseId").map_err(cbor_bad_request)?,
        signed_payload_digest: map_lookup_text(evidence, "signedPayloadDigest")
            .map_err(cbor_bad_request)?,
        signature_id: map_lookup_text(evidence, "signatureId").map_err(cbor_bad_request)?,
        signing_intent: map_lookup_text(evidence, "signingIntent").map_err(cbor_bad_request)?,
        signer_id: map_lookup_optional_text(data, "signerId").map_err(cbor_bad_request)?,
        emitted_at: map_lookup_text(data, "emittedAt").map_err(cbor_bad_request)?,
    })
}

fn project_admitted_act(
    canonical_event_hash: [u8; 32],
    record: &SignatureAffirmationRecordDetails,
) -> Result<ProjectedAct, StackError> {
    let source_ref = source_ref(canonical_event_hash, "signature-affirmation")?;
    let source_refs = sorted_source_refs(vec![source_ref.clone()])?;
    let signing_intent = record
        .signing_intent
        .as_deref()
        .ok_or_else(|| StackError::bad_request("signature affirmation missing signingIntent"))?;
    let signer = crate::text_map(vec![
        ("id", Value::Text(record.signer_id.clone())),
        ("role", Value::Text(record.role.clone())),
        ("role_ref", Value::Text(record.role_id.clone())),
        ("identity_evidence_refs", Value::Array(Vec::new())),
    ])?;
    let bound = crate::text_map(vec![
        ("subject_kind", Value::Text("formspec-response".to_string())),
        (
            "subject_hash",
            option_text(record.signed_payload_digest.as_deref()),
        ),
        (
            "subject_hash_algorithm",
            option_text(record.signed_payload_digest_algorithm.as_deref()),
        ),
        (
            "presentation_hash",
            Value::Text(record.presentation_hash.clone()),
        ),
        ("document_id", Value::Text(record.document_id.clone())),
        (
            "document_ref",
            record.document_ref.clone().unwrap_or(Value::Null),
        ),
        ("content_hash", Value::Text(record.document_hash.clone())),
        (
            "content_hash_algorithm",
            Value::Text(record.document_hash_algorithm.clone()),
        ),
    ])?;
    let admission = crate::text_map(vec![
        ("outcome", Value::Text("admitted".to_string())),
        (
            "source_response_ref",
            Value::Text(record.formspec_response_ref.clone()),
        ),
        (
            "source_signature_system",
            option_text(record.source_signature_system.as_deref()),
        ),
        (
            "source_signature_id",
            option_text(record.source_signature_id.as_deref()),
        ),
        (
            "signature_provider",
            Value::Text(record.signature_provider.clone()),
        ),
        ("ceremony_id", Value::Text(record.ceremony_id.clone())),
        ("profile_ref", option_text(record.profile_ref.as_deref())),
        ("profile_key", option_text(record.profile_key.as_deref())),
        (
            "signed_payload_digest",
            option_text(record.signed_payload_digest.as_deref()),
        ),
        (
            "signed_payload_digest_algorithm",
            option_text(record.signed_payload_digest_algorithm.as_deref()),
        ),
        (
            "primitive_verification",
            record.primitive_verification.clone(),
        ),
        ("failure_reason", Value::Null),
    ])?;
    let value = crate::text_map(vec![
        ("act_id", Value::Text(record.signing_act_id.clone())),
        ("signer", signer),
        ("bound", bound),
        ("intent", Value::Text(signing_intent.to_string())),
        ("consent", record.consent_reference.clone()),
        ("admission", admission),
        (
            "witness_of",
            option_text(record.witnessed_signature_ref.as_deref()),
        ),
        ("signed_at", Value::Text(record.signed_at.clone())),
        ("source_refs", source_refs),
    ])?;
    Ok(ProjectedAct {
        act_id: record.signing_act_id.clone(),
        signed_at: record.signed_at.clone(),
        first_source_ref: crate::encode_value(&source_ref)?,
        value,
    })
}

fn project_rejected_act(
    canonical_event_hash: [u8; 32],
    record: &SignatureAdmissionFailedRecordDetails,
) -> Result<ProjectedAct, StackError> {
    let source_ref = source_ref(canonical_event_hash, "signature-admission-failed")?;
    let source_refs = sorted_source_refs(vec![source_ref.clone()])?;
    let signer = crate::text_map(vec![
        ("id", option_text(record.signer_id.as_deref())),
        ("role", Value::Null),
        ("role_ref", Value::Null),
        ("identity_evidence_refs", Value::Array(Vec::new())),
    ])?;
    let bound = crate::text_map(vec![
        ("subject_kind", Value::Text("formspec-response".to_string())),
        (
            "subject_hash",
            Value::Text(record.signed_payload_digest.clone()),
        ),
        ("subject_hash_algorithm", Value::Null),
        ("presentation_hash", Value::Null),
        ("document_id", Value::Null),
        ("document_ref", Value::Null),
        (
            "content_hash",
            Value::Text(record.signed_payload_digest.clone()),
        ),
        ("content_hash_algorithm", Value::Null),
    ])?;
    let admission = crate::text_map(vec![
        ("outcome", Value::Text("rejected".to_string())),
        (
            "source_response_ref",
            Value::Text(record.response_id.clone()),
        ),
        ("source_signature_system", Value::Null),
        (
            "source_signature_id",
            Value::Text(record.signature_id.clone()),
        ),
        ("signature_provider", Value::Null),
        ("ceremony_id", Value::Null),
        ("profile_ref", Value::Null),
        ("profile_key", Value::Null),
        (
            "signed_payload_digest",
            Value::Text(record.signed_payload_digest.clone()),
        ),
        ("signed_payload_digest_algorithm", Value::Null),
        ("primitive_verification", Value::Null),
        ("failure_reason", Value::Text(record.reason.clone())),
    ])?;
    let value = crate::text_map(vec![
        ("act_id", Value::Text(record.signature_id.clone())),
        ("signer", signer),
        ("bound", bound),
        ("intent", Value::Text(record.signing_intent.clone())),
        ("consent", Value::Null),
        ("admission", admission),
        ("witness_of", Value::Null),
        ("signed_at", Value::Text(record.emitted_at.clone())),
        ("source_refs", source_refs),
    ])?;
    Ok(ProjectedAct {
        act_id: record.signature_id.clone(),
        signed_at: record.emitted_at.clone(),
        first_source_ref: crate::encode_value(&source_ref)?,
        value,
    })
}

fn source_ref(canonical_event_hash: [u8; 32], kind: &str) -> Result<Value, StackError> {
    crate::text_map(vec![
        ("layer", Value::Text("wos".to_string())),
        ("kind", Value::Text(kind.to_string())),
        ("ref", Value::Bytes(canonical_event_hash.to_vec())),
    ])
}

fn sorted_source_refs(source_refs: Vec<Value>) -> Result<Value, StackError> {
    let mut refs = source_refs
        .into_iter()
        .map(|source_ref| {
            let sort_key = source_ref_sort_key(&source_ref)?;
            Ok((sort_key, source_ref))
        })
        .collect::<Result<Vec<_>, StackError>>()?;
    refs.sort_by(|(left, _), (right, _)| left.cmp(right));
    Ok(Value::Array(
        refs.into_iter().map(|(_, source_ref)| source_ref).collect(),
    ))
}

fn source_ref_sort_key(source_ref: &Value) -> Result<Vec<u8>, StackError> {
    let map = source_ref
        .as_map()
        .ok_or_else(|| StackError::internal("source_ref is not a map"))?;
    let layer = map_lookup_optional_value(map, "layer")
        .and_then(Value::as_text)
        .ok_or_else(|| StackError::internal("source_ref layer missing"))?;
    let kind = map_lookup_optional_value(map, "kind")
        .and_then(Value::as_text)
        .ok_or_else(|| StackError::internal("source_ref kind missing"))?;
    let reference = map_lookup_optional_value(map, "ref")
        .ok_or_else(|| StackError::internal("source_ref ref missing"))?;
    let mut key = Vec::new();
    key.extend_from_slice(layer.as_bytes());
    key.push(0);
    key.extend_from_slice(kind.as_bytes());
    key.push(0);
    key.extend_from_slice(&crate::encode_value(reference)?);
    Ok(key)
}

fn compare_projected_acts(left: &ProjectedAct, right: &ProjectedAct) -> Ordering {
    left.act_id
        .cmp(&right.act_id)
        .then_with(|| left.signed_at.cmp(&right.signed_at))
        .then_with(|| left.first_source_ref.cmp(&right.first_source_ref))
}

fn policy_closure(
    scope: &[u8],
    generated_at: TrellisTimestamp,
    policy_artifacts: &[PolicyClosureArtifact],
) -> Result<Vec<u8>, StackError> {
    let artifacts = policy_artifacts
        .iter()
        .map(policy_artifact_value)
        .collect::<Result<Vec<_>, StackError>>()?;
    let closure = crate::text_map(vec![
        ("closure_schema_version", crate::uint(1)),
        (
            "closure_version",
            Value::Text(POLICY_CLOSURE_VERSION.to_string()),
        ),
        ("sealed_at", Value::Text(timestamp_rfc3339(generated_at)?)),
        (
            "owner_scope",
            Value::Text(String::from_utf8_lossy(scope).into_owned()),
        ),
        (
            "verifier_boundary",
            crate::text_map(vec![
                ("bundle_admission_policy_evidence", Value::Bool(true)),
                ("bundle_trust_roots_authoritative", Value::Bool(false)),
                ("verifier_supplied_trust_roots_required", Value::Bool(true)),
                (
                    "verifier_supplied_adapter_allowlists_required",
                    Value::Bool(true),
                ),
                ("server_operational_config_included", Value::Bool(false)),
            ])?,
        ),
        ("artifacts", Value::Array(artifacts)),
    ])?;
    crate::encode_value(&closure)
}

fn policy_artifact_value(artifact: &PolicyClosureArtifact) -> Result<Value, StackError> {
    crate::text_map(vec![
        ("owner", Value::Text(artifact.owner.to_string())),
        ("kind", Value::Text(artifact.kind.to_string())),
        ("version", Value::Text(artifact.version.to_string())),
        ("ref", Value::Text(artifact.reference.to_string())),
        ("digest_algorithm", Value::Text("sha-256".to_string())),
        ("digest", Value::Bytes(artifact.digest.to_vec())),
        ("valid_from", Value::Text(artifact.valid_from.to_string())),
        ("valid_to", option_text(artifact.valid_to)),
    ])
}

fn timestamp_rfc3339(timestamp: TrellisTimestamp) -> Result<String, StackError> {
    let seconds = i64::try_from(timestamp.unix_secs)
        .map_err(|_| StackError::internal("timestamp seconds exceed i64"))?;
    OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|error| StackError::internal(format!("invalid export timestamp: {error}")))?
        .replace_nanosecond(timestamp.subsec_nanos)
        .map_err(|error| StackError::internal(format!("invalid export nanoseconds: {error}")))?
        .format(&Rfc3339)
        .map_err(|error| {
            StackError::internal(format!("failed to format export timestamp: {error}"))
        })
}

fn option_text(value: Option<&str>) -> Value {
    value.map_or(Value::Null, |value| Value::Text(value.to_string()))
}

fn map_lookup_text_alias(
    map: &[(Value, Value)],
    preferred: &str,
    legacy: &str,
) -> Result<String, StackError> {
    if let Some(value) = map_lookup_optional_value(map, preferred) {
        return value
            .as_text()
            .map(str::to_string)
            .ok_or_else(|| StackError::bad_request(format!("{preferred} must be text")));
    }
    map_lookup_text(map, legacy).map_err(cbor_bad_request)
}

fn require_event(
    map: &[(Value, Value)],
    expected_event: &str,
    label: &str,
) -> Result<(), StackError> {
    let event = map_lookup_text(map, "event").map_err(cbor_bad_request)?;
    if event == expected_event {
        Ok(())
    } else {
        Err(StackError::bad_request(format!(
            "{label} payload event is not {expected_event}"
        )))
    }
}

fn cbor_bad_request(error: integrity_cbor::CborHelperError) -> StackError {
    StackError::bad_request(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn act_correlation_merges_compatible_source_refs() {
        let acts = correlate_projected_acts(vec![
            projected_act("act-1", "signer-1", 0x22),
            projected_act("act-1", "signer-1", 0x11),
        ])
        .expect("correlate acts");

        assert_eq!(acts.len(), 1);
        let source_refs = source_refs_from_act(&acts[0].value).expect("source refs");
        assert_eq!(source_refs.len(), 2);
        assert_eq!(
            encode_source_ref(0x11),
            crate::encode_value(&source_refs[0]).unwrap()
        );
        assert_eq!(
            encode_source_ref(0x22),
            crate::encode_value(&source_refs[1]).unwrap()
        );
    }

    #[test]
    fn act_correlation_rejects_incompatible_duplicate_act_id() {
        let error = correlate_projected_acts(vec![
            projected_act("act-1", "signer-1", 0x11),
            projected_act("act-1", "signer-2", 0x22),
        ])
        .expect_err("incompatible act ids must conflict");

        assert_eq!(error.code().as_str(), "INFRA-4000");
        assert!(error.to_string().contains("act_correlation_conflict"));
    }

    #[test]
    fn act_correlation_rejects_duplicate_source_ref_across_act_ids() {
        let error = correlate_projected_acts(vec![
            projected_act("act-1", "signer-1", 0x11),
            projected_act("act-2", "signer-1", 0x11),
        ])
        .expect_err("duplicate source refs must conflict");

        assert_eq!(error.code().as_str(), "INFRA-4000");
        assert!(
            error
                .to_string()
                .contains("signed acts projection repeats a source_ref")
        );
    }

    fn encode_source_ref(source_byte: u8) -> Vec<u8> {
        let source_ref =
            source_ref([source_byte; 32], "signature-affirmation").expect("source ref");
        crate::encode_value(&source_ref).expect("source ref bytes")
    }

    fn projected_act(act_id: &str, signer: &str, source_byte: u8) -> ProjectedAct {
        let source_ref =
            source_ref([source_byte; 32], "signature-affirmation").expect("source ref");
        let value = crate::text_map(vec![
            ("act_id", Value::Text(act_id.to_string())),
            ("signer", Value::Text(signer.to_string())),
            ("signed_at", Value::Text("2026-05-17T00:00:00Z".to_string())),
            (
                "source_refs",
                sorted_source_refs(vec![source_ref.clone()]).expect("source refs"),
            ),
        ])
        .expect("act value");
        ProjectedAct {
            act_id: act_id.to_string(),
            signed_at: "2026-05-17T00:00:00Z".to_string(),
            first_source_ref: crate::encode_value(&source_ref).expect("source ref key"),
            value,
        }
    }
}
