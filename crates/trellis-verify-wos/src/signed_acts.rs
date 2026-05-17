// Rust guideline compliant 2026-02-21
//! SignedAct projection validation for WOS/Formspec exports.

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use ciborium::Value;
use integrity_verify::trellis::{DomainEvent, DomainExport, DomainFinding, Severity};
use trellis_types::{
    encode_canonical_cbor_value, map_lookup_fixed_bytes, map_lookup_text, sha256_bytes,
};

use crate::event_types::{
    wos_signature_admission_failed_event_type, wos_signature_affirmation_event_type,
};
use crate::records::{
    SignatureAdmissionFailedRecordDetails, SignatureAffirmationRecordDetails, hex_string,
    parse_signature_admission_failed_record, parse_signature_affirmation_record,
};

const SIGNED_ACTS_EXPORT_EXTENSION: &str = "trellis.export.signed-acts.v1";
const SIGNED_ACTS_MEMBER: &str = "066-signed-acts.cbor";
const SIGNED_ACTS_DERIVATION_RULE: &str = "signed-act-projection-wos-formspec-v1";

type SignedActsDeriver = fn(&[DomainEvent]) -> Result<Vec<u8>, String>;

#[derive(Clone, Copy)]
struct SignedActsDerivationRule {
    id: &'static str,
    derive: SignedActsDeriver,
}

#[derive(Clone, Debug)]
struct SignedActsExportExtension {
    catalog_ref: String,
    catalog_digest: [u8; 32],
    derivation_rule: String,
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

pub(crate) fn validate_signed_acts_projection(export: &DomainExport<'_>) -> Vec<DomainFinding> {
    let extension_bytes = export.manifest_extensions.get(SIGNED_ACTS_EXPORT_EXTENSION);
    let member_bytes = export.members.get(SIGNED_ACTS_MEMBER);
    match (extension_bytes, member_bytes) {
        (None, None) => Vec::new(),
        (None, Some(_)) => vec![finding(
            "signed_acts_catalog_unbound",
            None,
            "066-signed-acts.cbor is present without trellis.export.signed-acts.v1",
        )],
        (Some(_), None) => vec![finding(
            "missing_signed_acts_catalog",
            None,
            "export is missing 066-signed-acts.cbor",
        )],
        (Some(extension_bytes), Some(member_bytes)) => {
            validate_bound_signed_acts_projection(export, extension_bytes, member_bytes)
        }
    }
}

fn validate_bound_signed_acts_projection(
    export: &DomainExport<'_>,
    extension_bytes: &[u8],
    member_bytes: &[u8],
) -> Vec<DomainFinding> {
    let mut findings = Vec::new();
    let extension = match parse_signed_acts_export_extension(extension_bytes) {
        Ok(extension) => extension,
        Err(error) => {
            return vec![finding(
                "signed_acts_catalog_invalid",
                None,
                format!("signed acts export extension is invalid: {error}"),
            )];
        }
    };
    if extension.catalog_ref != SIGNED_ACTS_MEMBER {
        findings.push(finding(
            "signed_acts_catalog_invalid",
            None,
            format!(
                "signed acts catalog_ref must be {SIGNED_ACTS_MEMBER}, got {}",
                extension.catalog_ref
            ),
        ));
    }
    if sha256_bytes(member_bytes) != extension.catalog_digest {
        findings.push(finding(
            "signed_acts_catalog_digest_mismatch",
            None,
            "signed acts catalog digest does not match manifest extension",
        ));
    }
    if let Err(error) = decode_value(member_bytes) {
        findings.push(finding(
            "signed_acts_catalog_invalid",
            None,
            format!("066-signed-acts.cbor is invalid CBOR: {error}"),
        ));
        return findings;
    }
    let derivation_rule = match signed_acts_derivation_rule(&extension.derivation_rule) {
        Some(rule) => rule,
        None => {
            findings.push(finding(
                "signed_acts_catalog_invalid",
                None,
                format!(
                    "unsupported signed acts derivation_rule {}; supported rules: {}",
                    extension.derivation_rule,
                    supported_signed_acts_derivation_rules().join(", ")
                ),
            ));
            return findings;
        }
    };

    let derived = match (derivation_rule.derive)(export.events) {
        Ok(bytes) => bytes,
        Err(error) => {
            findings.push(finding("signed_acts_catalog_invalid", None, error));
            return findings;
        }
    };
    if derived != member_bytes {
        findings.push(finding(
            "signed_acts_projection_mismatch",
            None,
            "signed acts catalog does not match deterministic WOS/Formspec derivation",
        ));
    }
    findings
}

fn signed_acts_derivation_rule(rule_id: &str) -> Option<SignedActsDerivationRule> {
    signed_acts_derivation_rules()
        .into_iter()
        .find(|rule| rule.id == rule_id)
}

fn supported_signed_acts_derivation_rules() -> Vec<&'static str> {
    signed_acts_derivation_rules()
        .into_iter()
        .map(|rule| rule.id)
        .collect()
}

fn signed_acts_derivation_rules() -> [SignedActsDerivationRule; 1] {
    [SignedActsDerivationRule {
        id: SIGNED_ACTS_DERIVATION_RULE,
        derive: derive_signed_acts_catalog,
    }]
}

fn parse_signed_acts_export_extension(bytes: &[u8]) -> Result<SignedActsExportExtension, String> {
    let value = decode_value(bytes)?;
    let map = value
        .as_map()
        .ok_or_else(|| "signed acts export extension is not a map".to_string())?;
    Ok(SignedActsExportExtension {
        catalog_ref: map_lookup_text(map, "catalog_ref").map_err(|error| error.to_string())?,
        catalog_digest: map_lookup_fixed_bytes(map, "catalog_digest", 32)
            .map_err(|error| error.to_string())?
            .as_slice()
            .try_into()
            .expect("fixed bytes length checked"),
        derivation_rule: map_lookup_text(map, "derivation_rule")
            .map_err(|error| error.to_string())?,
    })
}

fn derive_signed_acts_catalog(events: &[DomainEvent]) -> Result<Vec<u8>, String> {
    let mut acts = Vec::new();
    for event in events {
        if event.event_type == wos_signature_affirmation_event_type() {
            let payload = event.payload.as_deref().ok_or_else(|| {
                format!(
                    "signature affirmation payload unreadable for {}",
                    hex_string(&event.canonical_event_hash)
                )
            })?;
            let record =
                parse_signature_affirmation_record(payload, wos_signature_affirmation_event_type())
                    .map_err(|error| error.to_string())?;
            acts.push(project_admitted_act(event, &record)?);
        } else if event.event_type == wos_signature_admission_failed_event_type() {
            let payload = event.payload.as_deref().ok_or_else(|| {
                format!(
                    "signature admission-failed payload unreadable for {}",
                    hex_string(&event.canonical_event_hash)
                )
            })?;
            let record = parse_signature_admission_failed_record(
                payload,
                wos_signature_admission_failed_event_type(),
            )
            .map_err(|error| error.to_string())?;
            acts.push(project_rejected_act(event, &record)?);
        }
    }
    let mut acts = correlate_projected_acts(acts)?;
    acts.sort_by(compare_projected_acts);
    let catalog = text_map(vec![
        ("projection_schema_version", uint(1)),
        (
            "derivation_rule_id",
            Value::Text(SIGNED_ACTS_DERIVATION_RULE.to_string()),
        ),
        (
            "acts",
            Value::Array(acts.into_iter().map(|act| act.value).collect()),
        ),
    ])?;
    encode_value(&catalog)
}

fn correlate_projected_acts(acts: Vec<ProjectedAct>) -> Result<Vec<ProjectedAct>, String> {
    let mut by_act_id: BTreeMap<String, CorrelatedAct> = BTreeMap::new();
    let mut seen_source_refs = BTreeSet::new();
    for act in acts {
        let compatibility_key = act_without_source_refs_key(&act.value)?;
        let source_refs = source_refs_from_act(&act.value)?;
        let mut refs = BTreeMap::new();
        for source_ref in source_refs {
            let duplicate_key = encode_value(&source_ref)?;
            let key = source_ref_sort_key(&source_ref)?;
            if !seen_source_refs.insert(duplicate_key) {
                return Err("signed acts projection repeats a source_ref".to_string());
            }
            if refs.insert(key, source_ref).is_some() {
                return Err("signed acts projection repeats a source_ref".to_string());
            }
        }
        match by_act_id.get_mut(&act.act_id) {
            Some(existing) if existing.compatibility_key != compatibility_key => {
                return Err(format!(
                    "act_correlation_conflict: act_id `{}` has incompatible projection fields",
                    act.act_id
                ));
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
                .ok_or_else(|| "projected act source_refs missing".to_string())?;
            let first_source_ref = encode_value(first_source_ref)?;
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

fn act_without_source_refs_key(value: &Value) -> Result<Vec<u8>, String> {
    let map = value
        .as_map()
        .ok_or_else(|| "projected act is not a map".to_string())?;
    let filtered = map
        .iter()
        .filter(|(key, _)| key.as_text() != Some("source_refs"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    encode_value(&Value::Map(filtered))
}

fn source_refs_from_act(value: &Value) -> Result<Vec<Value>, String> {
    let source_refs = value
        .as_map()
        .and_then(|map| map_lookup_value(map, "source_refs"))
        .and_then(Value::as_array)
        .ok_or_else(|| "projected act source_refs missing".to_string())
        .cloned()?;
    if source_refs.is_empty() {
        return Err("projected act source_refs missing".to_string());
    }
    Ok(source_refs)
}

fn replace_source_refs(value: &Value, source_refs: Value) -> Result<Value, String> {
    let map = value
        .as_map()
        .ok_or_else(|| "projected act is not a map".to_string())?;
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
        return Err("projected act source_refs missing".to_string());
    }
    Ok(Value::Map(replaced))
}

fn project_admitted_act(
    event: &DomainEvent,
    record: &SignatureAffirmationRecordDetails,
) -> Result<ProjectedAct, String> {
    let source_ref = source_ref(event, "signature-affirmation")?;
    let source_refs = sorted_source_refs(vec![source_ref.clone()])?;
    let witness_of = option_text(record.witnessed_signature_ref.as_deref());
    let signing_intent = record
        .signing_intent
        .as_deref()
        .ok_or_else(|| "signature affirmation missing signingIntent".to_string())?;
    let signer = text_map(vec![
        ("id", Value::Text(record.signer_id.clone())),
        ("role", Value::Text(record.role.clone())),
        ("role_ref", Value::Text(record.role_id.clone())),
        ("identity_evidence_refs", Value::Array(Vec::new())),
    ])?;
    let bound = text_map(vec![
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
    let admission = text_map(vec![
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
    let value = text_map(vec![
        ("act_id", Value::Text(record.signing_act_id.clone())),
        ("signer", signer),
        ("bound", bound),
        ("intent", Value::Text(signing_intent.to_string())),
        ("consent", record.consent_reference.clone()),
        ("admission", admission),
        ("witness_of", witness_of),
        ("signed_at", Value::Text(record.signed_at.clone())),
        ("source_refs", source_refs),
    ])?;
    Ok(ProjectedAct {
        act_id: record.signing_act_id.clone(),
        signed_at: record.signed_at.clone(),
        first_source_ref: encode_value(&source_ref)?,
        value,
    })
}

fn project_rejected_act(
    event: &DomainEvent,
    record: &SignatureAdmissionFailedRecordDetails,
) -> Result<ProjectedAct, String> {
    let source_ref = source_ref(event, "signature-admission-failed")?;
    let source_refs = sorted_source_refs(vec![source_ref.clone()])?;
    let signer = text_map(vec![
        ("id", option_text(record.signer_id.as_deref())),
        ("role", Value::Null),
        ("role_ref", Value::Null),
        ("identity_evidence_refs", Value::Array(Vec::new())),
    ])?;
    let bound = text_map(vec![
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
    let admission = text_map(vec![
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
    let value = text_map(vec![
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
        first_source_ref: encode_value(&source_ref)?,
        value,
    })
}

fn source_ref(event: &DomainEvent, kind: &str) -> Result<Value, String> {
    text_map(vec![
        ("layer", Value::Text("wos".to_string())),
        ("kind", Value::Text(kind.to_string())),
        ("ref", Value::Bytes(event.canonical_event_hash.to_vec())),
    ])
}

fn sorted_source_refs(source_refs: Vec<Value>) -> Result<Value, String> {
    let mut refs = source_refs
        .into_iter()
        .map(|source_ref| {
            let sort_key = source_ref_sort_key(&source_ref)?;
            Ok((sort_key, source_ref))
        })
        .collect::<Result<Vec<_>, String>>()?;
    refs.sort_by(|(left, _), (right, _)| left.cmp(right));
    Ok(Value::Array(
        refs.into_iter().map(|(_, source_ref)| source_ref).collect(),
    ))
}

fn source_ref_sort_key(source_ref: &Value) -> Result<Vec<u8>, String> {
    let map = source_ref
        .as_map()
        .ok_or_else(|| "source_ref is not a map".to_string())?;
    let layer = map_lookup_value(map, "layer")
        .and_then(Value::as_text)
        .ok_or_else(|| "source_ref layer missing".to_string())?;
    let kind = map_lookup_value(map, "kind")
        .and_then(Value::as_text)
        .ok_or_else(|| "source_ref kind missing".to_string())?;
    let reference =
        map_lookup_value(map, "ref").ok_or_else(|| "source_ref ref missing".to_string())?;
    let mut key = Vec::new();
    key.extend_from_slice(layer.as_bytes());
    key.push(0);
    key.extend_from_slice(kind.as_bytes());
    key.push(0);
    key.extend_from_slice(&encode_value(reference)?);
    Ok(key)
}

fn compare_projected_acts(left: &ProjectedAct, right: &ProjectedAct) -> Ordering {
    left.act_id
        .cmp(&right.act_id)
        .then_with(|| left.signed_at.cmp(&right.signed_at))
        .then_with(|| left.first_source_ref.cmp(&right.first_source_ref))
}

fn text_map(fields: Vec<(&str, Value)>) -> Result<Value, String> {
    canonical_map(
        fields
            .into_iter()
            .map(|(key, value)| (Value::Text(key.to_string()), value))
            .collect(),
    )
}

fn canonical_map(fields: Vec<(Value, Value)>) -> Result<Value, String> {
    let mut fields = fields
        .into_iter()
        .map(|(key, value)| {
            let encoded = encode_value(&key)?;
            Ok((encoded, key, value))
        })
        .collect::<Result<Vec<_>, String>>()?;
    fields.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(Value::Map(
        fields
            .into_iter()
            .map(|(_, key, value)| (key, value))
            .collect(),
    ))
}

fn map_lookup_value<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(candidate, _)| candidate.as_text() == Some(key))
        .map(|(_, value)| value)
}

fn option_text(value: Option<&str>) -> Value {
    value.map_or(Value::Null, |value| Value::Text(value.to_string()))
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn decode_value(bytes: &[u8]) -> Result<Value, String> {
    ciborium::from_reader(bytes).map_err(|error| error.to_string())
}

fn encode_value(value: &Value) -> Result<Vec<u8>, String> {
    encode_canonical_cbor_value(value).map_err(|error| error.to_string())
}

fn finding(
    kind: impl Into<String>,
    event_hash: Option<[u8; 32]>,
    message: impl Into<String>,
) -> DomainFinding {
    DomainFinding::new(kind, event_hash, Severity::Failure, message)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use integrity_verify::trellis::{DomainEvent, DomainExport, RecordValidator, TrellisTimestamp};

    use super::*;
    use crate::validator::WosRecordValidator;

    #[test]
    fn signed_acts_projection_validates_when_catalog_matches_derivation() {
        let event = signature_event();
        let catalog = derive_signed_acts_catalog(std::slice::from_ref(&event)).expect("derive");
        let extension = extension_for(&catalog);
        let mut members = BTreeMap::new();
        members.insert(SIGNED_ACTS_MEMBER.to_string(), catalog);
        let mut manifest_extensions = BTreeMap::new();
        manifest_extensions.insert(SIGNED_ACTS_EXPORT_EXTENSION.to_string(), extension);

        let findings = WosRecordValidator.validate_export(DomainExport {
            events: &[event],
            members: &members,
            manifest_extensions: &manifest_extensions,
        });

        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn signed_acts_invalid_catalog_cbor_is_failure() {
        let event = signature_event();
        let catalog = vec![0xff];
        let extension = extension_for(&catalog);
        let mut members = BTreeMap::new();
        members.insert(SIGNED_ACTS_MEMBER.to_string(), catalog);
        let mut manifest_extensions = BTreeMap::new();
        manifest_extensions.insert(SIGNED_ACTS_EXPORT_EXTENSION.to_string(), extension);

        let findings = WosRecordValidator.validate_export(DomainExport {
            events: &[event],
            members: &members,
            manifest_extensions: &manifest_extensions,
        });

        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == "signed_acts_catalog_invalid"),
            "{findings:#?}"
        );
    }

    #[test]
    fn signed_acts_projection_mismatch_is_failure() {
        let event = signature_event();
        let catalog = encode_value(
            &text_map(vec![
                ("projection_schema_version", uint(1)),
                (
                    "derivation_rule_id",
                    Value::Text(SIGNED_ACTS_DERIVATION_RULE.to_string()),
                ),
                ("acts", Value::Array(Vec::new())),
            ])
            .expect("catalog"),
        )
        .expect("encode");
        let extension = extension_for(&catalog);
        let mut members = BTreeMap::new();
        members.insert(SIGNED_ACTS_MEMBER.to_string(), catalog);
        let mut manifest_extensions = BTreeMap::new();
        manifest_extensions.insert(SIGNED_ACTS_EXPORT_EXTENSION.to_string(), extension);

        let findings = WosRecordValidator.validate_export(DomainExport {
            events: &[event],
            members: &members,
            manifest_extensions: &manifest_extensions,
        });

        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == "signed_acts_projection_mismatch"),
            "{findings:#?}"
        );
    }

    #[test]
    fn signed_acts_v1_derivation_rule_is_registry_backed() {
        let event = signature_event();
        let catalog = derive_signed_acts_catalog(std::slice::from_ref(&event)).expect("derive");
        let rule = signed_acts_derivation_rule(SIGNED_ACTS_DERIVATION_RULE)
            .expect("v1 signed acts derivation rule registered");

        assert_eq!(rule.id, SIGNED_ACTS_DERIVATION_RULE);
        assert_eq!(
            (rule.derive)(std::slice::from_ref(&event)).expect("derive"),
            catalog
        );
    }

    #[test]
    fn signed_acts_unknown_derivation_rule_is_failure_without_v1_fallback() {
        let event = signature_event();
        let catalog = derive_signed_acts_catalog(std::slice::from_ref(&event)).expect("derive");
        let extension = extension_for_rule(&catalog, "signed-act-projection-wos-formspec-v2");
        let mut members = BTreeMap::new();
        members.insert(SIGNED_ACTS_MEMBER.to_string(), catalog);
        let mut manifest_extensions = BTreeMap::new();
        manifest_extensions.insert(SIGNED_ACTS_EXPORT_EXTENSION.to_string(), extension);

        let findings = WosRecordValidator.validate_export(DomainExport {
            events: &[event],
            members: &members,
            manifest_extensions: &manifest_extensions,
        });

        assert!(
            findings.iter().any(|finding| {
                finding.kind == "signed_acts_catalog_invalid"
                    && finding
                        .message
                        .contains("unsupported signed acts derivation_rule")
            }),
            "{findings:#?}"
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.kind != "signed_acts_projection_mismatch"),
            "{findings:#?}"
        );
    }

    #[test]
    fn signed_acts_projection_canonicalizes_nested_payload_maps() {
        let event = signature_event_with_consent(Value::Map(vec![
            (
                Value::Text("z".to_string()),
                Value::Text("last".to_string()),
            ),
            (
                Value::Text("a".to_string()),
                Value::Text("first".to_string()),
            ),
        ]));

        let catalog = derive_signed_acts_catalog(&[event]).expect("derive");
        let decoded = decode_value(&catalog).expect("decode derived catalog");
        let root = decoded.as_map().expect("catalog root");
        let acts = map_lookup_value(root, "acts")
            .and_then(Value::as_array)
            .expect("acts");
        let act = acts.first().expect("one act").as_map().expect("act map");
        let consent = map_lookup_value(act, "consent")
            .and_then(Value::as_map)
            .expect("consent map");
        let keys = consent
            .iter()
            .map(|(key, _)| key.as_text().expect("text key"))
            .collect::<Vec<_>>();

        assert_eq!(keys, vec!["a", "z"]);
    }

    #[test]
    fn signed_acts_projection_rejects_duplicate_nested_payload_keys() {
        let event = signature_event_with_raw_consent_payload(Value::Map(vec![
            (
                Value::Text("a".to_string()),
                Value::Text("first".to_string()),
            ),
            (
                Value::Text("a".to_string()),
                Value::Text("second".to_string()),
            ),
        ]));

        let error = derive_signed_acts_catalog(&[event]).expect_err("duplicate key rejects");

        assert!(
            error.contains("duplicate canonical CBOR map key"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn signed_acts_duplicate_nested_payload_keys_fail_validator_domain_path() {
        let event = signature_event_with_raw_consent_payload(Value::Map(vec![
            (
                Value::Text("a".to_string()),
                Value::Text("first".to_string()),
            ),
            (
                Value::Text("a".to_string()),
                Value::Text("second".to_string()),
            ),
        ]));
        let catalog = encode_value(
            &text_map(vec![
                ("projection_schema_version", uint(1)),
                (
                    "derivation_rule_id",
                    Value::Text(SIGNED_ACTS_DERIVATION_RULE.to_string()),
                ),
                ("acts", Value::Array(Vec::new())),
            ])
            .expect("catalog"),
        )
        .expect("encode");
        let extension = extension_for(&catalog);
        let mut members = BTreeMap::new();
        members.insert(SIGNED_ACTS_MEMBER.to_string(), catalog);
        let mut manifest_extensions = BTreeMap::new();
        manifest_extensions.insert(SIGNED_ACTS_EXPORT_EXTENSION.to_string(), extension);

        let findings = WosRecordValidator.validate_export(DomainExport {
            events: &[event],
            members: &members,
            manifest_extensions: &manifest_extensions,
        });

        assert!(
            findings.iter().any(|finding| {
                finding.kind == "signed_acts_catalog_invalid"
                    && finding.message.contains("duplicate canonical CBOR map key")
            }),
            "{findings:#?}"
        );
    }

    #[test]
    fn signed_acts_act_correlation_merges_compatible_source_refs() {
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
            encode_value(&source_refs[0]).unwrap()
        );
        assert_eq!(
            encode_source_ref(0x22),
            encode_value(&source_refs[1]).unwrap()
        );
    }

    #[test]
    fn signed_acts_act_correlation_rejects_incompatible_duplicate_act_id() {
        let error = correlate_projected_acts(vec![
            projected_act("act-1", "signer-1", 0x11),
            projected_act("act-1", "signer-2", 0x22),
        ])
        .expect_err("incompatible act ids must conflict");

        assert!(error.contains("act_correlation_conflict"), "{error}");
    }

    #[test]
    fn signed_acts_act_correlation_rejects_duplicate_source_ref_across_act_ids() {
        let error = correlate_projected_acts(vec![
            projected_act("act-1", "signer-1", 0x11),
            projected_act("act-2", "signer-1", 0x11),
        ])
        .expect_err("duplicate source refs must conflict");

        assert!(
            error.contains("signed acts projection repeats a source_ref"),
            "{error}"
        );
    }

    #[test]
    fn signed_acts_derivation_merges_compatible_duplicate_act_ids() {
        let events = [
            signature_event_with_signer_and_hash("signer-1", 0x22),
            signature_event_with_signer_and_hash("signer-1", 0x11),
        ];

        let catalog = derive_signed_acts_catalog(&events).expect("derive");
        let decoded = decode_value(&catalog).expect("decode derived catalog");
        let root = decoded.as_map().expect("catalog root");
        let acts = map_lookup_value(root, "acts")
            .and_then(Value::as_array)
            .expect("acts");

        assert_eq!(acts.len(), 1);
        let act = acts[0].as_map().expect("act");
        let source_refs = map_lookup_value(act, "source_refs")
            .and_then(Value::as_array)
            .expect("source refs");
        assert_eq!(source_refs.len(), 2);
        assert_eq!(
            encode_source_ref(0x11),
            encode_value(&source_refs[0]).unwrap()
        );
        assert_eq!(
            encode_source_ref(0x22),
            encode_value(&source_refs[1]).unwrap()
        );
    }

    #[test]
    fn signed_acts_act_correlation_conflict_fails_validator_domain_path() {
        let events = [
            signature_event_with_signer_and_hash("signer-1", 0x11),
            signature_event_with_signer_and_hash("signer-2", 0x22),
        ];
        let catalog = encode_value(
            &text_map(vec![
                ("projection_schema_version", uint(1)),
                (
                    "derivation_rule_id",
                    Value::Text(SIGNED_ACTS_DERIVATION_RULE.to_string()),
                ),
                ("acts", Value::Array(Vec::new())),
            ])
            .expect("catalog"),
        )
        .expect("encode");
        let extension = extension_for(&catalog);
        let mut members = BTreeMap::new();
        members.insert(SIGNED_ACTS_MEMBER.to_string(), catalog);
        let mut manifest_extensions = BTreeMap::new();
        manifest_extensions.insert(SIGNED_ACTS_EXPORT_EXTENSION.to_string(), extension);

        let findings = WosRecordValidator.validate_export(DomainExport {
            events: &events,
            members: &members,
            manifest_extensions: &manifest_extensions,
        });

        assert!(
            findings.iter().any(|finding| {
                finding.kind == "signed_acts_catalog_invalid"
                    && finding.message.contains("act_correlation_conflict")
            }),
            "{findings:#?}"
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.kind != "signed_acts_projection_mismatch"),
            "{findings:#?}"
        );
    }

    fn encode_source_ref(source_byte: u8) -> Vec<u8> {
        let event = signature_event_with_signer_and_hash("signer-1", source_byte);
        let source_ref = source_ref(&event, "signature-affirmation").expect("source ref");
        encode_value(&source_ref).expect("source ref bytes")
    }

    fn extension_for(catalog: &[u8]) -> Vec<u8> {
        extension_for_rule(catalog, SIGNED_ACTS_DERIVATION_RULE)
    }

    fn extension_for_rule(catalog: &[u8], derivation_rule: &str) -> Vec<u8> {
        encode_value(
            &text_map(vec![
                (
                    "catalog_digest",
                    Value::Bytes(sha256_bytes(catalog).to_vec()),
                ),
                ("catalog_ref", Value::Text(SIGNED_ACTS_MEMBER.to_string())),
                ("derivation_rule", Value::Text(derivation_rule.to_string())),
            ])
            .expect("extension"),
        )
        .expect("encode")
    }

    fn signature_event() -> DomainEvent {
        signature_event_with_signer_and_hash("signer-1", 0x11)
    }

    fn projected_act(act_id: &str, signer: &str, source_byte: u8) -> ProjectedAct {
        let event = DomainEvent {
            event_type: wos_signature_affirmation_event_type().to_string(),
            payload: None,
            canonical_event_hash: [source_byte; 32],
            authored_at: TrellisTimestamp {
                seconds: 1,
                nanos: 0,
            },
        };
        let source_ref = source_ref(&event, "signature-affirmation").expect("source ref");
        let value = text_map(vec![
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
            first_source_ref: encode_value(&source_ref).expect("source ref key"),
            value,
        }
    }

    fn signature_event_with_consent(consent_reference: Value) -> DomainEvent {
        let payload = signature_payload_with_consent(consent_reference);
        DomainEvent {
            event_type: wos_signature_affirmation_event_type().to_string(),
            payload: Some(encode_value(&payload).expect("payload cbor")),
            canonical_event_hash: [0x11; 32],
            authored_at: TrellisTimestamp {
                seconds: 1,
                nanos: 0,
            },
        }
    }

    fn signature_event_with_signer_and_hash(signer_id: &str, source_byte: u8) -> DomainEvent {
        let consent_reference =
            text_map(vec![("ref", Value::Text("consent-1".to_string()))]).expect("consent");
        let payload = signature_payload_with_consent_and_signer(consent_reference, signer_id);
        DomainEvent {
            event_type: wos_signature_affirmation_event_type().to_string(),
            payload: Some(encode_value(&payload).expect("payload cbor")),
            canonical_event_hash: [source_byte; 32],
            authored_at: TrellisTimestamp {
                seconds: 1,
                nanos: 0,
            },
        }
    }

    fn signature_event_with_raw_consent_payload(consent_reference: Value) -> DomainEvent {
        let payload = signature_payload_with_consent(consent_reference);
        let mut payload_bytes = Vec::new();
        ciborium::into_writer(&payload, &mut payload_bytes).expect("raw payload cbor");
        DomainEvent {
            event_type: wos_signature_affirmation_event_type().to_string(),
            payload: Some(payload_bytes),
            canonical_event_hash: [0x11; 32],
            authored_at: TrellisTimestamp {
                seconds: 1,
                nanos: 0,
            },
        }
    }

    fn signature_payload_with_consent(consent_reference: Value) -> Value {
        signature_payload_with_consent_and_signer(consent_reference, "signer-1")
    }

    fn signature_payload_with_consent_and_signer(
        consent_reference: Value,
        signer_id: &str,
    ) -> Value {
        text_map(vec![
            (
                "event",
                Value::Text(wos_signature_affirmation_event_type().to_string()),
            ),
            (
                "data",
                text_map(vec![
                    ("signerId", Value::Text(signer_id.to_string())),
                    ("roleId", Value::Text("applicant".to_string())),
                    ("role", Value::Text("Applicant".to_string())),
                    ("documentId", Value::Text("doc-1".to_string())),
                    (
                        "documentRef",
                        text_map(vec![
                            ("documentId", Value::Text("doc-1".to_string())),
                            ("locale", Value::Text("en-US".to_string())),
                        ])
                        .expect("document ref"),
                    ),
                    ("signingActId", Value::Text("act-1".to_string())),
                    (
                        "documentHash",
                        Value::Text("sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string()),
                    ),
                    (
                        "presentationHash",
                        Value::Text("sha256:2222222222222222222222222222222222222222222222222222222222222222".to_string()),
                    ),
                    (
                        "documentHashAlgorithm",
                        Value::Text("sha-256".to_string()),
                    ),
                    (
                        "sourceSignatureSystem",
                        Value::Text("formspec".to_string()),
                    ),
                    ("sourceSignatureId", Value::Text("sig-1".to_string())),
                    (
                        "signedPayloadDigest",
                        Value::Text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
                    ),
                    (
                        "signedPayloadDigestAlgorithm",
                        Value::Text("sha-256".to_string()),
                    ),
                    (
                        "signingIntent",
                        Value::Text("urn:formspec:signing-intent:accept@1".to_string()),
                    ),
                    (
                        "signedAt",
                        Value::Text("2026-05-17T00:00:00Z".to_string()),
                    ),
                    (
                        "identityBinding",
                        text_map(vec![("ref", Value::Text("identity-1".to_string()))])
                            .expect("identity"),
                    ),
                    (
                        "consentReference",
                        consent_reference,
                    ),
                    (
                        "signatureProvider",
                        Value::Text("formspec-ring".to_string()),
                    ),
                    ("ceremonyId", Value::Text("ceremony-1".to_string())),
                    (
                        "sourceResponseRef",
                        Value::Text("response-1".to_string()),
                    ),
                    (
                        "primitiveVerification",
                        text_map(vec![("status", Value::Text("verified".to_string()))])
                            .expect("primitive"),
                    ),
                    ("witnessedSignatureRef", Value::Null),
                ])
                .expect("data"),
            ),
        ])
        .expect("payload")
    }
}
