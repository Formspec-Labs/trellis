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
const SIGNED_ACTS_DERIVATION_RULE_V1: &str = "signed-act-projection-wos-formspec-v1";
const SIGNED_ACTS_DERIVATION_RULE_V2: &str = "signed-act-projection-wos-formspec-v2";
const FALLBACK_ACT_ID_DERIVATION_RULE: &str = "signed-act-projection-act-id-v1";
/// 068 signed-acts manifest member (sealed `(hash, event_type)` tuple list).
const SIGNED_ACTS_MANIFEST_MEMBER: &str = "068-signed-acts-manifest.cbor";
/// 068 manifest-extension key binding `068-signed-acts-manifest.cbor`.
const SIGNED_ACTS_MANIFEST_EXPORT_EXTENSION: &str = "trellis.export.signed-acts.manifest.v1";
/// Derivation-rule identifier the 068 extension MUST declare.
const SIGNED_ACTS_MANIFEST_DERIVATION_RULE_V1: &str = "signed-acts-manifest-v1";

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
    uses_fallback_act_id: bool,
    value: Value,
}

struct CorrelatedAct {
    act: ProjectedAct,
    compatibility_key: Vec<u8>,
    source_refs: BTreeMap<Vec<u8>, Value>,
}

/// Verifies the optional `068-signed-acts-manifest.cbor` member against the
/// `trellis.export.signed-acts.manifest.v1` extension binding and the
/// re-derived manifest bytes.
///
/// Emits blocking findings:
/// - `signed_acts_manifest_missing_member` when the extension is declared but
///   the 068 member is absent (substrate damage / declaration violation).
/// - `signed_acts_manifest_extension_digest_mismatch` when SHA-256 of the 068
///   bytes does not match `extension.manifest_digest`.
/// - `signed_acts_manifest_mismatch` when re-derivation from sealed events does
///   not byte-for-byte match the archive member.
/// - `signed_acts_manifest_extension_invalid` when the extension is malformed.
/// - `signed_acts_manifest_member_unbound` when the 068 member is present but
///   the extension is absent.
///
/// All findings are `Severity::Failure` and surface under
/// `domain_admissibility` per `is_projection_finding`.
pub(crate) fn validate_signed_acts_manifest_extension(
    export: &DomainExport<'_>,
) -> Vec<DomainFinding> {
    let extension_bytes = export
        .manifest_extensions
        .get(SIGNED_ACTS_MANIFEST_EXPORT_EXTENSION);
    let member_bytes = export.members.get(SIGNED_ACTS_MANIFEST_MEMBER);
    match (extension_bytes, member_bytes) {
        (None, None) => Vec::new(),
        (None, Some(_)) => vec![finding(
            "signed_acts_manifest_member_unbound",
            None,
            "068-signed-acts-manifest.cbor is present without \
             trellis.export.signed-acts.manifest.v1",
        )],
        (Some(_), None) => vec![finding(
            "signed_acts_manifest_missing_member",
            None,
            "trellis.export.signed-acts.manifest.v1 is declared but \
             068-signed-acts-manifest.cbor is missing from the export",
        )],
        (Some(extension_bytes), Some(member_bytes)) => {
            validate_bound_signed_acts_manifest_extension(export, extension_bytes, member_bytes)
        }
    }
}

fn validate_bound_signed_acts_manifest_extension(
    export: &DomainExport<'_>,
    extension_bytes: &[u8],
    member_bytes: &[u8],
) -> Vec<DomainFinding> {
    let extension = match parse_signed_acts_manifest_extension(extension_bytes) {
        Ok(extension) => extension,
        Err(error) => {
            return vec![finding(
                "signed_acts_manifest_extension_invalid",
                None,
                format!("signed acts manifest extension is invalid: {error}"),
            )];
        }
    };
    let mut findings = Vec::new();
    if extension.catalog_ref != SIGNED_ACTS_MANIFEST_MEMBER {
        findings.push(finding(
            "signed_acts_manifest_extension_invalid",
            None,
            format!(
                "signed acts manifest catalog_ref must be {SIGNED_ACTS_MANIFEST_MEMBER}, got {}",
                extension.catalog_ref
            ),
        ));
    }
    if extension.derivation_rule != SIGNED_ACTS_MANIFEST_DERIVATION_RULE_V1 {
        findings.push(finding(
            "signed_acts_manifest_extension_invalid",
            None,
            format!(
                "signed acts manifest derivation_rule must be \
                 {SIGNED_ACTS_MANIFEST_DERIVATION_RULE_V1}, got {}",
                extension.derivation_rule
            ),
        ));
    }
    if sha256_bytes(member_bytes) != extension.manifest_digest {
        findings.push(finding(
            "signed_acts_manifest_extension_digest_mismatch",
            None,
            "signed acts manifest digest does not match manifest extension",
        ));
        return findings;
    }
    let manifest = match derive_signed_acts_manifest_v1(export.events) {
        Ok(manifest) => manifest,
        Err(error) => {
            findings.push(finding(
                "signed_acts_manifest_extension_invalid",
                None,
                format!("signed acts manifest derivation failed: {error}"),
            ));
            return findings;
        }
    };
    let derived = match encode_signed_acts_manifest_v1(&manifest) {
        Ok(bytes) => bytes,
        Err(error) => {
            findings.push(finding(
                "signed_acts_manifest_extension_invalid",
                None,
                format!("signed acts manifest encoding failed: {error}"),
            ));
            return findings;
        }
    };
    if derived != member_bytes {
        findings.push(finding(
            "signed_acts_manifest_mismatch",
            None,
            "068-signed-acts-manifest.cbor bytes do not match deterministic \
             signed-acts-manifest-v1 derivation",
        ));
    }
    findings
}

#[derive(Clone, Debug)]
struct SignedActsManifestExtension {
    catalog_ref: String,
    manifest_digest: [u8; 32],
    derivation_rule: String,
}

fn parse_signed_acts_manifest_extension(
    bytes: &[u8],
) -> Result<SignedActsManifestExtension, String> {
    let value = decode_value(bytes)?;
    let map = value
        .as_map()
        .ok_or_else(|| "signed acts manifest extension is not a map".to_string())?;
    Ok(SignedActsManifestExtension {
        catalog_ref: map_lookup_text(map, "catalog_ref").map_err(|error| error.to_string())?,
        manifest_digest: map_lookup_fixed_bytes(map, "manifest_digest", 32)
            .map_err(|error| error.to_string())?
            .as_slice()
            .try_into()
            .expect("fixed bytes length checked"),
        derivation_rule: map_lookup_text(map, "derivation_rule")
            .map_err(|error| error.to_string())?,
    })
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
    let catalog_value = match decode_value(member_bytes) {
        Ok(value) => value,
        Err(error) => {
            findings.push(finding(
                "signed_acts_catalog_invalid",
                None,
                format!("066-signed-acts.cbor is invalid CBOR: {error}"),
            ));
            return findings;
        }
    };
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
    if let Err(error) =
        validate_signed_acts_catalog_root(&catalog_value, &extension.derivation_rule)
    {
        findings.push(finding(
            "signed_acts_catalog_invalid",
            None,
            format!("066-signed-acts.cbor is invalid: {error}"),
        ));
        return findings;
    }

    let derived = match (derivation_rule.derive)(export.events) {
        Ok(bytes) => bytes,
        Err(error) => {
            findings.push(finding("signed_acts_catalog_invalid", None, error));
            return findings;
        }
    };
    if derived != member_bytes {
        // Render drift is advisory: the 068 manifest member is the substrate-anchored
        // proof of which events landed; the 066 catalog is a downstream projection
        // whose bytes can legitimately drift across renderers. Substrate-shape
        // failures (catalog missing, digest mismatched, catalog unbound, CBOR
        // invalid) remain `Severity::Failure` above.
        findings.push(advisory_finding(
            "signed_acts_render_drift",
            None,
            "signed acts catalog does not match deterministic WOS/Formspec derivation",
        ));
    }
    findings
}

fn validate_signed_acts_catalog_root(value: &Value, derivation_rule: &str) -> Result<(), String> {
    let map = value
        .as_map()
        .ok_or_else(|| "signed acts catalog root is not a map".to_string())?;
    let expected_version = Value::Integer(1.into());
    if map_lookup_value(map, "projection_schema_version") != Some(&expected_version) {
        return Err("projection_schema_version must be 1".to_string());
    }
    let catalog_rule = map_lookup_value(map, "derivation_rule_id")
        .and_then(Value::as_text)
        .ok_or_else(|| "derivation_rule_id must be text".to_string())?;
    if catalog_rule != derivation_rule {
        return Err(format!(
            "derivation_rule_id must match manifest derivation_rule {derivation_rule}"
        ));
    }
    if !map_lookup_value(map, "acts").is_some_and(|acts| acts.as_array().is_some()) {
        return Err("acts must be an array".to_string());
    }
    Ok(())
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

fn signed_acts_derivation_rules() -> [SignedActsDerivationRule; 2] {
    [
        SignedActsDerivationRule {
            id: SIGNED_ACTS_DERIVATION_RULE_V1,
            derive: derive_signed_acts_catalog_v1,
        },
        SignedActsDerivationRule {
            id: SIGNED_ACTS_DERIVATION_RULE_V2,
            derive: derive_signed_acts_catalog_v2,
        },
    ]
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

/// Builds the v1 signed-acts manifest tuples from `events`.
///
/// Walks `events`, selects each `signature_affirmation` and `signature_admission_failed`
/// event, and emits a `(canonical_event_hash, event_type)` pair per match. The result is
/// sorted byte-deterministically by `(hash bytes ASC, event_type ASC)` so Rust and Python
/// derivations produce identical output (parity gate landed in Task A9).
///
/// Tuple shape matches the future `068-signed-acts-manifest.cbor` export member registered
/// by Task A1's §6.7 extension. The encoder is [`encode_signed_acts_manifest_v1`].
///
/// # Errors
/// Currently infallible (the `Result` keeps the signature consistent with the
/// `SignedActsDeriver` family for future validation rules that may reject malformed input).
pub fn derive_signed_acts_manifest_v1(
    events: &[DomainEvent],
) -> Result<Vec<(Vec<u8>, String)>, String> {
    let mut entries: Vec<(Vec<u8>, String)> = events
        .iter()
        .filter(|event| {
            event.event_type == wos_signature_affirmation_event_type()
                || event.event_type == wos_signature_admission_failed_event_type()
        })
        .map(|event| (event.canonical_event_hash.to_vec(), event.event_type.clone()))
        .collect();
    entries.sort();
    Ok(entries)
}

/// Canonical-CBOR encodes a signed-acts manifest into its `068-signed-acts-manifest.cbor` byte form.
///
/// Layout: a CBOR array with one element per manifest tuple, each element a 2-element
/// CBOR array `[bstr(hash), tstr(event_type)]`. Encoding routes through
/// [`encode_canonical_cbor_value`] so output matches the Trellis §4.2.2 canonical CBOR
/// profile (ADR 0004 — Rust is byte authority).
///
/// # Errors
/// Returns an error string when the underlying canonical CBOR encoder fails (e.g. a tuple
/// element cannot be serialized).
pub fn encode_signed_acts_manifest_v1(
    manifest: &[(Vec<u8>, String)],
) -> Result<Vec<u8>, String> {
    let array = Value::Array(
        manifest
            .iter()
            .map(|(hash, event_type)| {
                Value::Array(vec![
                    Value::Bytes(hash.clone()),
                    Value::Text(event_type.clone()),
                ])
            })
            .collect(),
    );
    encode_value(&array)
}

fn derive_signed_acts_catalog_v1(events: &[DomainEvent]) -> Result<Vec<u8>, String> {
    derive_signed_acts_catalog_with_rule(events, SIGNED_ACTS_DERIVATION_RULE_V1, false)
}

fn derive_signed_acts_catalog_v2(events: &[DomainEvent]) -> Result<Vec<u8>, String> {
    derive_signed_acts_catalog_with_rule(events, SIGNED_ACTS_DERIVATION_RULE_V2, true)
}

fn derive_signed_acts_catalog_with_rule(
    events: &[DomainEvent],
    derivation_rule: &'static str,
    fallback_act_id_allowed: bool,
) -> Result<Vec<u8>, String> {
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
            acts.push(project_admitted_act(
                event,
                &record,
                fallback_act_id_allowed,
            )?);
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
            Value::Text(derivation_rule.to_string()),
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
                existing.act.uses_fallback_act_id |= act.uses_fallback_act_id;
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
                uses_fallback_act_id: correlated.act.uses_fallback_act_id,
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
    fallback_act_id_allowed: bool,
) -> Result<ProjectedAct, String> {
    let source_ref = source_ref(event, "signature-affirmation")?;
    let source_refs = sorted_source_refs(vec![source_ref.clone()])?;
    let (act_id, uses_fallback_act_id) = projected_act_id(
        record.signing_act_id.as_deref(),
        &source_refs,
        fallback_act_id_allowed,
    )?;
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
        ("act_id", Value::Text(act_id.clone())),
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
        act_id,
        signed_at: record.signed_at.clone(),
        first_source_ref: encode_value(&source_ref)?,
        uses_fallback_act_id,
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
        uses_fallback_act_id: false,
        value,
    })
}

fn projected_act_id(
    signing_act_id: Option<&str>,
    source_refs: &Value,
    fallback_act_id_allowed: bool,
) -> Result<(String, bool), String> {
    if let Some(signing_act_id) = signing_act_id {
        return Ok((signing_act_id.to_string(), false));
    }
    if !fallback_act_id_allowed {
        return Err("signature affirmation missing signingActId".to_string());
    }
    let source_ref_bytes = encode_value(source_refs)?;
    let digest = sha256_bytes(&source_ref_bytes);
    Ok((
        format!(
            "{}:{}",
            FALLBACK_ACT_ID_DERIVATION_RULE,
            hex_encode(&digest)
        ),
        true,
    ))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
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

fn advisory_finding(
    kind: impl Into<String>,
    event_hash: Option<[u8; 32]>,
    message: impl Into<String>,
) -> DomainFinding {
    DomainFinding::new(kind, event_hash, Severity::Advisory, message)
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
        let catalog = derive_signed_acts_catalog_v1(std::slice::from_ref(&event)).expect("derive");
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
    fn signed_acts_render_drift_is_advisory() {
        let event = signature_event();
        let catalog = encode_value(
            &text_map(vec![
                ("projection_schema_version", uint(1)),
                (
                    "derivation_rule_id",
                    Value::Text(SIGNED_ACTS_DERIVATION_RULE_V1.to_string()),
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

        let drift = findings
            .iter()
            .find(|finding| finding.kind == "signed_acts_render_drift")
            .unwrap_or_else(|| panic!("expected render-drift finding: {findings:#?}"));
        assert_eq!(
            drift.severity,
            Severity::Advisory,
            "render drift must be advisory, not blocking: {findings:#?}"
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.kind != "signed_acts_projection_mismatch"),
            "old finding kind must no longer be emitted: {findings:#?}"
        );
    }

    #[test]
    fn signed_acts_v1_derivation_rule_is_registry_backed() {
        let event = signature_event();
        let catalog = derive_signed_acts_catalog_v1(std::slice::from_ref(&event)).expect("derive");
        let rule = signed_acts_derivation_rule(SIGNED_ACTS_DERIVATION_RULE_V1)
            .expect("v1 signed acts derivation rule registered");

        assert_eq!(rule.id, SIGNED_ACTS_DERIVATION_RULE_V1);
        assert_eq!(
            (rule.derive)(std::slice::from_ref(&event)).expect("derive"),
            catalog
        );
    }

    #[test]
    fn signed_acts_v2_derivation_rule_derives_fallback_act_id() {
        let event = signature_event_without_signing_act_id();
        let catalog = derive_signed_acts_catalog_v2(std::slice::from_ref(&event)).expect("derive");
        let decoded = decode_value(&catalog).expect("decode catalog");
        let root = decoded.as_map().expect("catalog root");
        let derivation_rule = map_lookup_value(root, "derivation_rule_id")
            .and_then(Value::as_text)
            .expect("derivation rule");
        let acts = map_lookup_value(root, "acts")
            .and_then(Value::as_array)
            .expect("acts");
        let act = acts[0].as_map().expect("act");
        let act_id = map_lookup_value(act, "act_id")
            .and_then(Value::as_text)
            .expect("act id");

        assert_eq!(derivation_rule, SIGNED_ACTS_DERIVATION_RULE_V2);
        assert!(act_id.starts_with("signed-act-projection-act-id-v1:"));
    }

    #[test]
    fn signed_acts_v2_treats_null_signing_act_id_as_absent() {
        let absent = signature_event_without_signing_act_id();
        let explicit_null = signature_event_with_null_signing_act_id();
        let absent_catalog =
            derive_signed_acts_catalog_v2(std::slice::from_ref(&absent)).expect("derive");
        let null_catalog =
            derive_signed_acts_catalog_v2(std::slice::from_ref(&explicit_null)).expect("derive");

        assert_eq!(
            act_id_from_catalog(&absent_catalog),
            act_id_from_catalog(&null_catalog)
        );
        assert!(act_id_from_catalog(&null_catalog).starts_with("signed-act-projection-act-id-v1:"));
    }

    #[test]
    fn signed_acts_v1_derivation_rule_rejects_missing_signing_act_id() {
        let event = signature_event_without_signing_act_id();
        let error = derive_signed_acts_catalog_v1(std::slice::from_ref(&event))
            .expect_err("v1 requires signingActId");

        assert!(error.contains("signature affirmation missing signingActId"));
    }

    #[test]
    fn signed_acts_v2_projection_validates_when_catalog_matches_derivation() {
        let event = signature_event_without_signing_act_id();
        let catalog = derive_signed_acts_catalog_v2(std::slice::from_ref(&event)).expect("derive");
        let extension = extension_for_rule(&catalog, SIGNED_ACTS_DERIVATION_RULE_V2);
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
    fn signed_acts_catalog_rule_mismatch_is_invalid_catalog() {
        let event = signature_event();
        let catalog = derive_signed_acts_catalog_v1(std::slice::from_ref(&event)).expect("derive");
        let extension = extension_for_rule(&catalog, SIGNED_ACTS_DERIVATION_RULE_V2);
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
                    && finding.message.contains("derivation_rule_id must match")
            }),
            "{findings:#?}"
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.kind != "signed_acts_render_drift"
                    && finding.kind != "signed_acts_projection_mismatch"),
            "{findings:#?}"
        );
    }

    #[test]
    fn signed_acts_unknown_derivation_rule_is_failure_without_rule_substitution() {
        let event = signature_event();
        let catalog = derive_signed_acts_catalog_v1(std::slice::from_ref(&event)).expect("derive");
        let extension =
            extension_for_rule(&catalog, "signed-act-projection-wos-formspec-unsupported");
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
                .all(|finding| finding.kind != "signed_acts_render_drift"
                    && finding.kind != "signed_acts_projection_mismatch"),
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

        let catalog = derive_signed_acts_catalog_v1(&[event]).expect("derive");
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

        let error = derive_signed_acts_catalog_v1(&[event]).expect_err("duplicate key rejects");

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
                    Value::Text(SIGNED_ACTS_DERIVATION_RULE_V1.to_string()),
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

        let catalog = derive_signed_acts_catalog_v1(&events).expect("derive");
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
                    Value::Text(SIGNED_ACTS_DERIVATION_RULE_V1.to_string()),
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
                .all(|finding| finding.kind != "signed_acts_render_drift"
                    && finding.kind != "signed_acts_projection_mismatch"),
            "{findings:#?}"
        );
    }

    fn encode_source_ref(source_byte: u8) -> Vec<u8> {
        let event = signature_event_with_signer_and_hash("signer-1", source_byte);
        let source_ref = source_ref(&event, "signature-affirmation").expect("source ref");
        encode_value(&source_ref).expect("source ref bytes")
    }

    fn extension_for(catalog: &[u8]) -> Vec<u8> {
        extension_for_rule(catalog, SIGNED_ACTS_DERIVATION_RULE_V1)
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

    fn signature_event_without_signing_act_id() -> DomainEvent {
        let mut event = signature_event();
        let payload = decode_value(event.payload.as_deref().expect("payload")).expect("payload");
        event.payload =
            Some(encode_value(&remove_data_field(payload, "signingActId")).expect("payload"));
        event
    }

    fn signature_event_with_null_signing_act_id() -> DomainEvent {
        let mut event = signature_event();
        let payload = decode_value(event.payload.as_deref().expect("payload")).expect("payload");
        event.payload = Some(
            encode_value(&replace_data_field(payload, "signingActId", Value::Null))
                .expect("payload"),
        );
        event
    }

    fn act_id_from_catalog(catalog: &[u8]) -> String {
        let decoded = decode_value(catalog).expect("decode catalog");
        let root = decoded.as_map().expect("catalog root");
        let acts = map_lookup_value(root, "acts")
            .and_then(Value::as_array)
            .expect("acts");
        let act = acts[0].as_map().expect("act");
        map_lookup_value(act, "act_id")
            .and_then(Value::as_text)
            .expect("act id")
            .to_string()
    }

    fn remove_data_field(payload: Value, field: &str) -> Value {
        let Value::Map(root) = payload else {
            panic!("payload must be a map");
        };
        Value::Map(
            root.into_iter()
                .map(|(key, value)| {
                    if key.as_text() != Some("data") {
                        return (key, value);
                    }
                    let Value::Map(data) = value else {
                        panic!("data must be a map");
                    };
                    let filtered = data
                        .into_iter()
                        .filter(|(data_key, _)| data_key.as_text() != Some(field))
                        .collect();
                    (key, Value::Map(filtered))
                })
                .collect(),
        )
    }

    fn replace_data_field(payload: Value, field: &str, replacement: Value) -> Value {
        let Value::Map(root) = payload else {
            panic!("payload must be a map");
        };
        Value::Map(
            root.into_iter()
                .map(|(key, value)| {
                    if key.as_text() != Some("data") {
                        return (key, value);
                    }
                    let Value::Map(data) = value else {
                        panic!("data must be a map");
                    };
                    let replaced = data
                        .into_iter()
                        .map(|(data_key, data_value)| {
                            if data_key.as_text() == Some(field) {
                                (data_key, replacement.clone())
                            } else {
                                (data_key, data_value)
                            }
                        })
                        .collect();
                    (key, Value::Map(replaced))
                })
                .collect(),
        )
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
            uses_fallback_act_id: false,
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

    fn signature_admission_failed_event(source_byte: u8) -> DomainEvent {
        // Manifest derivation does not parse the payload — only event_type and
        // canonical_event_hash matter, so the payload can be `None`.
        DomainEvent {
            event_type: wos_signature_admission_failed_event_type().to_string(),
            payload: None,
            canonical_event_hash: [source_byte; 32],
            authored_at: TrellisTimestamp {
                seconds: 1,
                nanos: 0,
            },
        }
    }

    fn unrelated_event(source_byte: u8) -> DomainEvent {
        DomainEvent {
            event_type: "wos.kernel.case_created".to_string(),
            payload: None,
            canonical_event_hash: [source_byte; 32],
            authored_at: TrellisTimestamp {
                seconds: 1,
                nanos: 0,
            },
        }
    }

    #[test]
    fn signed_acts_manifest_empty_events_yields_empty_array() {
        let manifest = derive_signed_acts_manifest_v1(&[]).expect("derive");
        assert!(manifest.is_empty());
        let encoded = encode_signed_acts_manifest_v1(&manifest).expect("encode");
        // CBOR array(0) is a single byte 0x80.
        assert_eq!(encoded, vec![0x80]);
    }

    #[test]
    fn signed_acts_manifest_single_signature_affirmation_is_included() {
        let event = signature_event_with_signer_and_hash("signer-1", 0x22);
        let manifest = derive_signed_acts_manifest_v1(std::slice::from_ref(&event)).expect("derive");

        assert_eq!(manifest.len(), 1);
        assert_eq!(manifest[0].0, vec![0x22u8; 32]);
        assert_eq!(manifest[0].1, wos_signature_affirmation_event_type());
    }

    #[test]
    fn signed_acts_manifest_single_signature_admission_failed_is_included() {
        let event = signature_admission_failed_event(0x33);
        let manifest = derive_signed_acts_manifest_v1(std::slice::from_ref(&event)).expect("derive");

        assert_eq!(manifest.len(), 1);
        assert_eq!(manifest[0].0, vec![0x33u8; 32]);
        assert_eq!(manifest[0].1, wos_signature_admission_failed_event_type());
    }

    #[test]
    fn signed_acts_manifest_mixed_events_sort_by_hash_then_event_type() {
        // Hash 0x11 < 0x22, so the admission-failed event (hash 0x11) sorts first
        // even though its event_type literal sorts after the affirmation literal.
        let affirmation = signature_event_with_signer_and_hash("signer-1", 0x22);
        let admission_failed = signature_admission_failed_event(0x11);

        let manifest =
            derive_signed_acts_manifest_v1(&[affirmation.clone(), admission_failed.clone()])
                .expect("derive");

        assert_eq!(manifest.len(), 2);
        assert_eq!(manifest[0].0, vec![0x11u8; 32]);
        assert_eq!(manifest[0].1, wos_signature_admission_failed_event_type());
        assert_eq!(manifest[1].0, vec![0x22u8; 32]);
        assert_eq!(manifest[1].1, wos_signature_affirmation_event_type());

        // Shuffling input order must not affect output order.
        let reshuffled =
            derive_signed_acts_manifest_v1(&[admission_failed, affirmation]).expect("derive");
        assert_eq!(manifest, reshuffled);
    }

    #[test]
    fn signed_acts_manifest_same_hash_sorts_by_event_type() {
        // Both events share canonical_event_hash 0x44; tie breaks on event_type ASC.
        // "wos.kernel.signature_admission_failed" < "wos.kernel.signature_affirmation"
        // lexicographically (`_` 0x5f < `f` 0x66 at the diverging byte).
        let affirmation = signature_event_with_signer_and_hash("signer-1", 0x44);
        let admission_failed = signature_admission_failed_event(0x44);

        let manifest = derive_signed_acts_manifest_v1(&[affirmation, admission_failed])
            .expect("derive");

        assert_eq!(manifest.len(), 2);
        assert_eq!(manifest[0].1, wos_signature_admission_failed_event_type());
        assert_eq!(manifest[1].1, wos_signature_affirmation_event_type());
    }

    #[test]
    fn signed_acts_manifest_encoding_is_input_order_invariant() {
        let events = [
            signature_event_with_signer_and_hash("signer-1", 0x22),
            signature_admission_failed_event(0x11),
            signature_event_with_signer_and_hash("signer-2", 0x33),
        ];
        let permuted = [events[2].clone(), events[0].clone(), events[1].clone()];

        let canonical = encode_signed_acts_manifest_v1(
            &derive_signed_acts_manifest_v1(&events).expect("derive"),
        )
        .expect("encode");
        let from_permuted = encode_signed_acts_manifest_v1(
            &derive_signed_acts_manifest_v1(&permuted).expect("derive"),
        )
        .expect("encode");

        assert_eq!(canonical, from_permuted);
    }

    #[test]
    fn signed_acts_manifest_encoding_matches_canonical_cbor_layout() {
        // Manually compute the canonical bytes for a one-event manifest:
        //   hash       = [0x00; 32]
        //   event_type = wos.kernel.signature_affirmation (32 ASCII bytes)
        //
        // Encoding:
        //   0x81                              -- array(1)
        //   0x82                              -- array(2)
        //   0x58 0x20 <32 zero bytes>         -- bstr(32) of zeros
        //   0x78 0x20 <"wos.kernel.signature_affirmation">
        //                                     -- tstr(32) one-byte-length form
        let event_type = wos_signature_affirmation_event_type();
        assert_eq!(event_type.len(), 32, "event_type literal length pin");

        let mut expected = Vec::with_capacity(1 + 1 + 2 + 32 + 2 + 32);
        expected.push(0x81);
        expected.push(0x82);
        expected.push(0x58);
        expected.push(0x20);
        expected.extend_from_slice(&[0u8; 32]);
        expected.push(0x78);
        expected.push(0x20);
        expected.extend_from_slice(event_type.as_bytes());

        let manifest = vec![(vec![0u8; 32], event_type.to_string())];
        let encoded = encode_signed_acts_manifest_v1(&manifest).expect("encode");

        assert_eq!(encoded, expected);
    }

    #[test]
    fn signed_acts_manifest_excludes_unrelated_event_types() {
        let manifest =
            derive_signed_acts_manifest_v1(&[unrelated_event(0x55)]).expect("derive");
        assert!(
            manifest.is_empty(),
            "non-signed-acts event_types must be excluded: {manifest:?}"
        );
    }

    // --- 068 signed-acts manifest extension verifier tests ----------------

    fn manifest_extension_for(member_bytes: &[u8]) -> Vec<u8> {
        encode_value(
            &text_map(vec![
                (
                    "catalog_ref",
                    Value::Text(SIGNED_ACTS_MANIFEST_MEMBER.to_string()),
                ),
                (
                    "derivation_rule",
                    Value::Text(SIGNED_ACTS_MANIFEST_DERIVATION_RULE_V1.to_string()),
                ),
                (
                    "manifest_digest",
                    Value::Bytes(sha256_bytes(member_bytes).to_vec()),
                ),
            ])
            .expect("manifest extension"),
        )
        .expect("encode")
    }

    #[test]
    fn signed_acts_manifest_extension_absent_and_member_absent_is_quiet() {
        let event = signature_event();
        let members = BTreeMap::new();
        let manifest_extensions = BTreeMap::new();

        let findings = WosRecordValidator.validate_export(DomainExport {
            events: &[event],
            members: &members,
            manifest_extensions: &manifest_extensions,
        });

        assert!(
            findings.iter().all(|finding| !finding
                .kind
                .starts_with("signed_acts_manifest_")),
            "{findings:#?}"
        );
    }

    #[test]
    fn signed_acts_manifest_extension_round_trips_through_rust_verifier() {
        let event = signature_event();
        let manifest =
            derive_signed_acts_manifest_v1(std::slice::from_ref(&event)).expect("derive");
        let encoded = encode_signed_acts_manifest_v1(&manifest).expect("encode");
        let extension = manifest_extension_for(&encoded);
        let mut members = BTreeMap::new();
        members.insert(SIGNED_ACTS_MANIFEST_MEMBER.to_string(), encoded);
        let mut manifest_extensions = BTreeMap::new();
        manifest_extensions
            .insert(SIGNED_ACTS_MANIFEST_EXPORT_EXTENSION.to_string(), extension);

        let findings = WosRecordValidator.validate_export(DomainExport {
            events: &[event],
            members: &members,
            manifest_extensions: &manifest_extensions,
        });

        assert!(
            findings.iter().all(|finding| !finding
                .kind
                .starts_with("signed_acts_manifest_")),
            "expected no manifest findings: {findings:#?}"
        );
    }

    #[test]
    fn signed_acts_manifest_mismatch_when_member_bytes_disagree_with_derivation() {
        let event = signature_event();
        let manifest =
            derive_signed_acts_manifest_v1(std::slice::from_ref(&event)).expect("derive");
        let mut encoded = encode_signed_acts_manifest_v1(&manifest).expect("encode");
        // Mutate a payload byte (avoid the array head 0x81 0x82 ... and the bstr
        // length tag 0x58 0x20). Flipping a hash byte inside the bstr keeps the
        // SHA-256 of the bytes consistent with the extension digest (we recompute
        // the extension after the mutation), so only the derivation comparison
        // disagrees.
        let mutate_offset = encoded.len() - 1;
        encoded[mutate_offset] ^= 0x01;
        let extension = manifest_extension_for(&encoded);
        let mut members = BTreeMap::new();
        members.insert(SIGNED_ACTS_MANIFEST_MEMBER.to_string(), encoded);
        let mut manifest_extensions = BTreeMap::new();
        manifest_extensions
            .insert(SIGNED_ACTS_MANIFEST_EXPORT_EXTENSION.to_string(), extension);

        let findings = WosRecordValidator.validate_export(DomainExport {
            events: &[event],
            members: &members,
            manifest_extensions: &manifest_extensions,
        });

        let blocking = findings
            .iter()
            .find(|finding| finding.kind == "signed_acts_manifest_mismatch")
            .unwrap_or_else(|| panic!("expected manifest mismatch: {findings:#?}"));
        assert_eq!(blocking.severity, Severity::Failure);
    }

    #[test]
    fn signed_acts_manifest_extension_digest_mismatch_when_extension_digest_wrong() {
        let event = signature_event();
        let manifest =
            derive_signed_acts_manifest_v1(std::slice::from_ref(&event)).expect("derive");
        let encoded = encode_signed_acts_manifest_v1(&manifest).expect("encode");
        // Build an extension that declares a wrong digest.
        let wrong_extension = encode_value(
            &text_map(vec![
                (
                    "catalog_ref",
                    Value::Text(SIGNED_ACTS_MANIFEST_MEMBER.to_string()),
                ),
                (
                    "derivation_rule",
                    Value::Text(SIGNED_ACTS_MANIFEST_DERIVATION_RULE_V1.to_string()),
                ),
                ("manifest_digest", Value::Bytes(vec![0xab; 32])),
            ])
            .expect("extension"),
        )
        .expect("encode");
        let mut members = BTreeMap::new();
        members.insert(SIGNED_ACTS_MANIFEST_MEMBER.to_string(), encoded);
        let mut manifest_extensions = BTreeMap::new();
        manifest_extensions.insert(
            SIGNED_ACTS_MANIFEST_EXPORT_EXTENSION.to_string(),
            wrong_extension,
        );

        let findings = WosRecordValidator.validate_export(DomainExport {
            events: &[event],
            members: &members,
            manifest_extensions: &manifest_extensions,
        });

        let blocking = findings
            .iter()
            .find(|finding| finding.kind == "signed_acts_manifest_extension_digest_mismatch")
            .unwrap_or_else(|| panic!("expected digest mismatch: {findings:#?}"));
        assert_eq!(blocking.severity, Severity::Failure);
        // Once the digest fails, derivation comparison is short-circuited.
        assert!(
            findings
                .iter()
                .all(|finding| finding.kind != "signed_acts_manifest_mismatch"),
            "{findings:#?}"
        );
    }

    #[test]
    fn signed_acts_manifest_missing_member_when_extension_declared_without_member() {
        let event = signature_event();
        let manifest =
            derive_signed_acts_manifest_v1(std::slice::from_ref(&event)).expect("derive");
        let encoded = encode_signed_acts_manifest_v1(&manifest).expect("encode");
        let extension = manifest_extension_for(&encoded);
        let members = BTreeMap::new(); // 068 member absent.
        let mut manifest_extensions = BTreeMap::new();
        manifest_extensions
            .insert(SIGNED_ACTS_MANIFEST_EXPORT_EXTENSION.to_string(), extension);

        let findings = WosRecordValidator.validate_export(DomainExport {
            events: &[event],
            members: &members,
            manifest_extensions: &manifest_extensions,
        });

        let blocking = findings
            .iter()
            .find(|finding| finding.kind == "signed_acts_manifest_missing_member")
            .unwrap_or_else(|| panic!("expected missing-member finding: {findings:#?}"));
        assert_eq!(blocking.severity, Severity::Failure);
    }

    #[test]
    fn signed_acts_manifest_member_unbound_when_member_present_without_extension() {
        let event = signature_event();
        let manifest =
            derive_signed_acts_manifest_v1(std::slice::from_ref(&event)).expect("derive");
        let encoded = encode_signed_acts_manifest_v1(&manifest).expect("encode");
        let mut members = BTreeMap::new();
        members.insert(SIGNED_ACTS_MANIFEST_MEMBER.to_string(), encoded);
        let manifest_extensions = BTreeMap::new();

        let findings = WosRecordValidator.validate_export(DomainExport {
            events: &[event],
            members: &members,
            manifest_extensions: &manifest_extensions,
        });

        let blocking = findings
            .iter()
            .find(|finding| finding.kind == "signed_acts_manifest_member_unbound")
            .unwrap_or_else(|| panic!("expected unbound-member finding: {findings:#?}"));
        assert_eq!(blocking.severity, Severity::Failure);
    }
}
