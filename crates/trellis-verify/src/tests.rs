use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;

use ciborium::Value;
use trellis_cddl::parse_ed25519_cose_key;
use trellis_types::{CONTENT_DOMAIN, domain_separated_sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::certificate_proof::NoopResponseProofResolver;
use crate::export::export_archive_for_tests;
use crate::interop_sidecar::{is_interop_sidecar_path_valid, verify_interop_sidecars};
use crate::kinds::{VerificationFailureKind, VerifyErrorKind};
use crate::parse::{parse_sign1_bytes, parse_signing_key_registry};
use crate::types::TrellisTimestamp;
use crate::util::is_identity_attestation_event_type;
use crate::{verify_event_set, verify_export_zip, verify_single_event, verify_tampered_ledger};

#[test]
fn identity_attestation_event_type_is_core_fixture_only() {
    assert!(!is_identity_attestation_event_type(
        "wos.identity.identityAttestation"
    ));
    assert!(is_identity_attestation_event_type(
        "x-trellis-test/identity-attestation/v1"
    ));
    assert!(!is_identity_attestation_event_type(
        "wos.identity.authenticationMethod"
    ));
}

/// TR-CORE-167 — `interop_sidecar_path_invalid` predicate (ADR 0008
/// §"Phase-1 verifier obligation" step 2.c). Structural cases only;
/// see `verify_interop_sidecars_rejects_manifest_path_outside_interop_tree`
/// for the same check inside `verify_interop_sidecars` (no tamper ZIP —
/// manifest re-signing would duplicate tamper/037..040 / 044 infra).
#[test]
fn interop_sidecar_path_prefix_invariant() {
    // Valid: starts with the literal byte prefix.
    assert!(is_interop_sidecar_path_valid(
        "interop-sidecars/c2pa-manifest/cert-001.c2pa"
    ));
    assert!(is_interop_sidecar_path_valid(
        "interop-sidecars/scitt-receipt/ckpt.cbor"
    ));
    // The trailing-empty case is a definitional edge — the prefix
    // alone is technically valid byte-prefix-wise but no real file
    // would land at a directory path. Predicate accepts; the
    // surrounding manifest walk catches missing-file as a
    // sidecar-missing failure.
    assert!(is_interop_sidecar_path_valid("interop-sidecars/"));

    // Invalid: any non-prefix byte sequence — including paths
    // that *contain* the prefix mid-string, paths into the
    // canonical tree, absolute paths, parent-dir traversals, and
    // the empty string. The predicate is byte-prefix-only; no
    // normalization, no canonicalization, no Unicode folding.
    assert!(!is_interop_sidecar_path_valid(""));
    assert!(!is_interop_sidecar_path_valid("010-events.cbor"));
    assert!(!is_interop_sidecar_path_valid("000-manifest.cbor"));
    assert!(!is_interop_sidecar_path_valid("/interop-sidecars/x"));
    assert!(!is_interop_sidecar_path_valid("./interop-sidecars/x"));
    assert!(!is_interop_sidecar_path_valid("../interop-sidecars/x"));
    assert!(!is_interop_sidecar_path_valid("nested/interop-sidecars/x"));
    assert!(!is_interop_sidecar_path_valid("Interop-sidecars/x")); // case-sensitive
    assert!(!is_interop_sidecar_path_valid("interop-sidecar/x")); // missing trailing 's/'
}

/// TR-CORE-167 — `interop_sidecar_path_invalid` through the real
/// `verify_interop_sidecars` dispatch (ADR 0008 step 2), without a
/// tamper ZIP: a `c2pa-manifest@v1` entry whose `path` points into the
/// canonical tree must fail **path-prefix** before digest lookup.
#[test]
fn verify_interop_sidecars_rejects_manifest_path_outside_interop_tree() {
    let entry = Value::Map(vec![
        (
            Value::Text("kind".into()),
            Value::Text("c2pa-manifest".into()),
        ),
        (
            Value::Text("path".into()),
            Value::Text("010-events.cbor".into()),
        ),
        (
            Value::Text("derivation_version".into()),
            Value::Integer(1u64.into()),
        ),
        (
            Value::Text("content_digest".into()),
            Value::Bytes([0x77_u8; 32].to_vec()),
        ),
        (
            Value::Text("source_ref".into()),
            Value::Text("urn:trellis:test:ref".into()),
        ),
    ]);
    let manifest_map = vec![(
        Value::Text("interop_sidecars".into()),
        Value::Array(vec![entry]),
    )];
    let archive = export_archive_for_tests(BTreeMap::new());
    let report = verify_interop_sidecars(&manifest_map, &archive).expect_err("bad path prefix");
    assert_eq!(report.event_failures.len(), 1);
    assert_eq!(
        report.event_failures[0].kind,
        VerificationFailureKind::InteropSidecarPathInvalid,
        "must not reach missing-file check"
    );
}

/// TR-CORE-168 — manifest-listed dispatched sidecar path must exist.
#[test]
fn verify_interop_sidecars_rejects_missing_manifest_listed_file() {
    const PATH: &str = "interop-sidecars/c2pa-manifest/cert-missing.c2pa";
    let digest = domain_separated_sha256(CONTENT_DOMAIN, b"promised-bytes");

    let entry = Value::Map(vec![
        (
            Value::Text("kind".into()),
            Value::Text("c2pa-manifest".into()),
        ),
        (Value::Text("path".into()), Value::Text(PATH.into())),
        (
            Value::Text("derivation_version".into()),
            Value::Integer(1u64.into()),
        ),
        (
            Value::Text("content_digest".into()),
            Value::Bytes(digest.to_vec()),
        ),
        (
            Value::Text("source_ref".into()),
            Value::Text("urn:trellis:test:ref".into()),
        ),
    ]);
    let manifest_map = vec![(
        Value::Text("interop_sidecars".into()),
        Value::Array(vec![entry]),
    )];
    let archive = export_archive_for_tests(BTreeMap::new());

    let report = verify_interop_sidecars(&manifest_map, &archive).expect_err("missing sidecar");
    assert_eq!(report.event_failures.len(), 1);
    assert_eq!(
        report.event_failures[0].kind,
        VerificationFailureKind::InteropSidecarMissing
    );
}

/// ADR 0008 happy path: `c2pa-manifest@v1` with valid prefix and matching
/// `content_digest` under `trellis-content-v1` (TR-CORE-163).
#[test]
fn verify_interop_sidecars_accepts_c2pa_manifest_with_matching_digest() {
    const PATH: &str = "interop-sidecars/c2pa-manifest/cert-ok.c2pa";
    let sidecar_bytes = b"synthetic-c2pa-payload".to_vec();
    let digest = domain_separated_sha256(CONTENT_DOMAIN, &sidecar_bytes);

    let entry = Value::Map(vec![
        (
            Value::Text("kind".into()),
            Value::Text("c2pa-manifest".into()),
        ),
        (Value::Text("path".into()), Value::Text(PATH.into())),
        (
            Value::Text("derivation_version".into()),
            Value::Integer(1u64.into()),
        ),
        (
            Value::Text("content_digest".into()),
            Value::Bytes(digest.to_vec()),
        ),
        (
            Value::Text("source_ref".into()),
            Value::Text("urn:trellis:test:ref".into()),
        ),
    ]);
    let manifest_map = vec![(
        Value::Text("interop_sidecars".into()),
        Value::Array(vec![entry]),
    )];

    let mut members = BTreeMap::new();
    members.insert(PATH.to_string(), sidecar_bytes);
    let archive = export_archive_for_tests(members);

    let outcomes = verify_interop_sidecars(&manifest_map, &archive).expect("interop ok path");
    assert_eq!(outcomes.len(), 1);
    assert!(outcomes[0].content_digest_ok);
    assert!(outcomes[0].kind_registered);
    assert!(!outcomes[0].phase_1_locked);
    assert!(outcomes[0].failures.is_empty());
    assert_eq!(outcomes[0].path, PATH);
    assert_eq!(outcomes[0].derivation_version, 1);
}

/// ADR 0008 happy path: `did-key-view@v1` uses the same Phase-1
/// digest-binding verifier path as `c2pa-manifest@v1` (TR-CORE-163).
#[test]
fn verify_interop_sidecars_accepts_did_key_view_with_matching_digest() {
    const PATH: &str = "interop-sidecars/did-key-view/signing-keys.json";
    let sidecar_bytes =
        br#"{"version":1,"derivation_version":1,"suite_id":1,"entries":[]}"#.to_vec();
    let digest = domain_separated_sha256(CONTENT_DOMAIN, &sidecar_bytes);

    let entry = Value::Map(vec![
        (
            Value::Text("kind".into()),
            Value::Text("did-key-view".into()),
        ),
        (Value::Text("path".into()), Value::Text(PATH.into())),
        (
            Value::Text("derivation_version".into()),
            Value::Integer(1u64.into()),
        ),
        (
            Value::Text("content_digest".into()),
            Value::Bytes(digest.to_vec()),
        ),
        (
            Value::Text("source_ref".into()),
            Value::Text("urn:trellis:signing-key-registry".into()),
        ),
    ]);
    let manifest_map = vec![(
        Value::Text("interop_sidecars".into()),
        Value::Array(vec![entry]),
    )];

    let mut members = BTreeMap::new();
    members.insert(PATH.to_string(), sidecar_bytes);
    let archive = export_archive_for_tests(members);

    let outcomes = verify_interop_sidecars(&manifest_map, &archive).expect("interop ok path");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].kind, "did-key-view");
    assert_eq!(outcomes[0].path, PATH);
    assert_eq!(outcomes[0].derivation_version, 1);
    assert!(outcomes[0].content_digest_ok);
    assert!(outcomes[0].kind_registered);
    assert!(!outcomes[0].phase_1_locked);
    assert!(outcomes[0].failures.is_empty());
}

fn rebuild_export_zip(template: &[u8], overrides: &[(&str, &[u8])], omit: &[&str]) -> Vec<u8> {
    let prefix = {
        let mut archive = ZipArchive::new(Cursor::new(template)).unwrap();
        let name = archive.by_index(0).unwrap().name().to_string();
        let (root, _) = name.split_once('/').unwrap();
        format!("{root}/")
    };

    let mut members: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    {
        let mut archive = ZipArchive::new(Cursor::new(template)).unwrap();
        for index in 0..archive.len() {
            let mut file = archive.by_index(index).unwrap();
            let name = file.name().to_string();
            let (_, relative) = name.split_once('/').unwrap();
            let mut data = Vec::new();
            std::io::Read::read_to_end(&mut file, &mut data).unwrap();
            members.insert(relative.to_string(), data);
        }
    }
    for key in omit {
        members.remove(*key);
    }
    for (rel, data) in overrides {
        members.insert(rel.to_string(), data.to_vec());
    }

    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        for (relative, data) in members {
            zip.start_file(format!("{prefix}{relative}"), opts).unwrap();
            zip.write_all(&data).unwrap();
        }
        zip.finish().unwrap();
    }
    cursor.into_inner()
}

#[test]
fn verify_single_event_accepts_append_001_fixture() {
    let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vectors/append/001-minimal-inline-payload");
    let key_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vectors/_keys/issuer-001.cose_key");

    let signed_event = fs::read(fixture_root.join("expected-event.cbor")).unwrap();
    let parsed_key = parse_ed25519_cose_key(&fs::read(key_path).unwrap()).unwrap();

    let report = verify_single_event(parsed_key.public_key, &signed_event).unwrap();
    assert!(report.structure_verified);
    assert!(report.integrity_verified);
    assert!(report.readability_verified);
}

#[test]
fn verify_export_zip_accepts_export_001_fixture() {
    let zip_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vectors/verify/001-export-001-two-event-chain/input-export.zip");
    let report = verify_export_zip(&fs::read(zip_path).unwrap());
    assert!(report.structure_verified);
    assert!(report.integrity_verified);
    assert!(report.readability_verified);
}

#[test]
fn verify_export_zip_rejects_invalid_zip_bytes() {
    let report = verify_export_zip(&[1, 2, 3, 4]);
    assert_eq!(
        report.event_failures[0].kind,
        VerificationFailureKind::ExportZipInvalid
    );
}

#[test]
fn verify_export_zip_rejects_zip_without_export_root_directory() {
    let mut buf = Vec::new();
    {
        let mut cursor = Cursor::new(&mut buf);
        let mut zip = ZipWriter::new(&mut cursor);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        zip.start_file("readme.txt", opts).unwrap();
        zip.write_all(b"x").unwrap();
        zip.finish().unwrap();
    }
    let report = verify_export_zip(&buf);
    assert_eq!(
        report.event_failures[0].kind,
        VerificationFailureKind::ExportZipInvalid
    );
    assert!(
        report.warnings[0].contains("export root")
            || report.warnings[0].contains("failed to parse ZIP"),
        "{}",
        report.warnings[0]
    );
}

#[test]
fn verify_export_zip_missing_manifest_is_fatal() {
    let template = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vectors/verify/001-export-001-two-event-chain/input-export.zip"),
    )
    .unwrap();
    let zip = rebuild_export_zip(&template, &[], &["000-manifest.cbor"]);
    let report = verify_export_zip(&zip);
    assert_eq!(
        report.event_failures[0].kind,
        VerificationFailureKind::MissingManifest
    );
}

#[test]
fn verify_export_zip_tampered_events_triggers_archive_integrity_failure() {
    let template = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vectors/verify/001-export-001-two-event-chain/input-export.zip"),
    )
    .unwrap();
    let zip = rebuild_export_zip(&template, &[("010-events.cbor", &[0xff])], &[]);
    let report = verify_export_zip(&zip);
    assert_eq!(
        report.event_failures[0].kind,
        VerificationFailureKind::ArchiveIntegrityFailure,
        "manifest member digests are checked before 010-events.cbor is parsed"
    );
}

#[test]
fn parse_sign1_array_rejects_invalid_cbor() {
    assert!(crate::parse::parse_sign1_array(&[0xff]).is_err());
}

#[test]
fn parse_sign1_array_rejects_array_of_non_sign1_items() {
    let mut bytes = Vec::new();
    ciborium::into_writer(
        &ciborium::Value::Array(vec![ciborium::Value::Integer(0.into())]),
        &mut bytes,
    )
    .unwrap();
    assert!(crate::parse::parse_sign1_array(&bytes).is_err());
}

#[test]
fn verify_tampered_ledger_rejects_signature_flip() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vectors/tamper/001-signature-flip");
    let report = verify_tampered_ledger(
        &fs::read(root.join("input-signing-key-registry.cbor")).unwrap(),
        &fs::read(root.join("input-tampered-ledger.cbor")).unwrap(),
        None,
        None,
    )
    .unwrap();
    assert!(report.structure_verified);
    assert!(!report.integrity_verified);
    assert!(report.readability_verified);
    assert_eq!(
        report.event_failures[0].kind,
        VerificationFailureKind::SignatureInvalid
    );
}

#[test]
fn verify_event_rejects_signature_after_revocation_valid_to() {
    let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vectors/append/009-signing-key-revocation");
    let signed_event = fs::read(fixture_root.join("expected-event.cbor")).unwrap();
    let mut registry_value = ciborium::from_reader::<ciborium::Value, _>(
        &fs::read(fixture_root.join("input-signing-key-registry-after.cbor")).unwrap()[..],
    )
    .unwrap();
    let registry_entries = registry_value.as_array_mut().unwrap();
    let entry_map = registry_entries[0].as_map_mut().unwrap();
    for (key, value) in entry_map.iter_mut() {
        if key.as_text() == Some("valid_to") {
            *value = ciborium::Value::Array(vec![
                ciborium::Value::Integer(1745109999u64.into()),
                ciborium::Value::Integer(0u32.into()),
            ]);
        }
    }
    let mut registry_bytes = Vec::new();
    ciborium::into_writer(&registry_value, &mut registry_bytes).unwrap();

    let parsed = parse_sign1_bytes(&signed_event).unwrap();
    let registry = parse_signing_key_registry(&registry_bytes).unwrap();
    let report = verify_event_set(&[parsed], &registry, None, None, false, None, None);

    assert!(report.structure_verified);
    assert!(!report.integrity_verified);
    assert!(report.readability_verified);
    assert_eq!(
        report.event_failures[0].kind,
        VerificationFailureKind::RevokedAuthority
    );
}

#[test]
fn verify_event_allows_historical_signature_before_revocation_valid_to() {
    let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vectors/append/009-signing-key-revocation");
    let signed_event = fs::read(fixture_root.join("expected-event.cbor")).unwrap();
    let registry_bytes =
        fs::read(fixture_root.join("input-signing-key-registry-after.cbor")).unwrap();

    let parsed = parse_sign1_bytes(&signed_event).unwrap();
    let registry = parse_signing_key_registry(&registry_bytes).unwrap();
    let report = verify_event_set(&[parsed], &registry, None, None, false, None, None);

    assert!(report.structure_verified);
    assert!(report.integrity_verified);
    assert!(report.readability_verified);
}

#[test]
fn rfc6962_inclusion_paths_reconstruct_three_leaf_root() {
    use crate::merkle::{
        merkle_interior_hash, merkle_leaf_hash, merkle_root, root_from_inclusion_proof,
    };

    let c0 = [1u8; 32];
    let c1 = [2u8; 32];
    let c2 = [3u8; 32];
    let l0 = merkle_leaf_hash(c0);
    let l1 = merkle_leaf_hash(c1);
    let l2 = merkle_leaf_hash(c2);
    let root = merkle_root(&[l0, l1, l2]);
    let h01 = merkle_interior_hash(l0, l1);

    assert_eq!(root_from_inclusion_proof(2, 3, l2, &[h01]).unwrap(), root);
    assert_eq!(
        root_from_inclusion_proof(0, 3, l0, &[l1, l2]).unwrap(),
        root
    );
    assert_eq!(
        root_from_inclusion_proof(1, 3, l1, &[l0, l2]).unwrap(),
        root
    );
}

#[test]
fn rfc6962_consistency_proof_one_to_two() {
    use crate::merkle::{merkle_leaf_hash, merkle_root, root_from_consistency_proof};

    let l0 = merkle_leaf_hash([9u8; 32]);
    let l1 = merkle_leaf_hash([8u8; 32]);
    let r1 = merkle_root(&[l0]);
    let r2 = merkle_root(&[l0, l1]);
    assert_eq!(root_from_consistency_proof(1, 2, r1, &[l1]).unwrap(), r2);
    let wrong_head = root_from_consistency_proof(1, 2, r1, &[[0u8; 32]]).unwrap();
    assert_ne!(wrong_head, r2);
}

#[test]
fn inclusion_proof_rejects_short_audit_sibling() {
    use crate::merkle::{merkle_leaf_hash, root_from_inclusion_proof};

    let leaf = merkle_leaf_hash([4u8; 32]);
    let bad = [0u8; 31];
    let v = ciborium::Value::Bytes(bad.to_vec());
    let path = [v];
    assert!(crate::merkle::digest_path_from_values(&path).is_err());
    assert!(root_from_inclusion_proof(0, 1, leaf, &[]).unwrap() == leaf);
    assert!(root_from_inclusion_proof(0, 2, leaf, &[]).is_err());
}

fn test_attachment_hash(suffix: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = suffix;
    b
}

fn attachment_manifest_cbor(rows: &[([u8; 32], Option<[u8; 32]>)]) -> Vec<u8> {
    use ciborium::Value as V;
    let entries = rows
        .iter()
        .map(|(binding, prior)| {
            let mut pairs: Vec<(V, V)> = vec![
                (
                    V::Text("binding_event_hash".into()),
                    V::Bytes(binding.to_vec()),
                ),
                (V::Text("attachment_id".into()), V::Text("id".into())),
                (V::Text("slot_path".into()), V::Text("slot".into())),
                (
                    V::Text("media_type".into()),
                    V::Text("application/octet-stream".into()),
                ),
                (V::Text("byte_length".into()), V::Integer(1u64.into())),
                (
                    V::Text("attachment_sha256".into()),
                    V::Bytes([7u8; 32].to_vec()),
                ),
                (
                    V::Text("payload_content_hash".into()),
                    V::Bytes([8u8; 32].to_vec()),
                ),
            ];
            if let Some(p) = prior {
                pairs.push((V::Text("prior_binding_hash".into()), V::Bytes(p.to_vec())));
            }
            V::Map(pairs)
        })
        .collect::<Vec<_>>();
    let root = V::Array(entries);
    let mut out = Vec::new();
    ciborium::into_writer(&root, &mut out).unwrap();
    out
}

#[test]
fn attachment_topology_duplicate_binding_event_hash() {
    let h = test_attachment_hash(1);
    let bytes = attachment_manifest_cbor(&[(h, None), (h, None)]);
    let entries = crate::parse::parse_attachment_manifest_entries(&bytes).unwrap();
    let mut m = std::collections::BTreeMap::new();
    m.insert(h, 0usize);
    let f = crate::export::attachment_manifest_topology_failures(&entries, &m);
    assert!(
        f.iter()
            .any(|e| e.kind == VerificationFailureKind::AttachmentManifestDuplicateBinding)
    );
}

#[test]
fn attachment_topology_unresolved_prior() {
    let h0 = test_attachment_hash(2);
    let h_unknown = test_attachment_hash(99);
    let bytes = attachment_manifest_cbor(&[(h0, Some(h_unknown))]);
    let entries = crate::parse::parse_attachment_manifest_entries(&bytes).unwrap();
    let mut m = std::collections::BTreeMap::new();
    m.insert(h0, 0usize);
    let f = crate::export::attachment_manifest_topology_failures(&entries, &m);
    assert!(
        f.iter()
            .any(|e| e.kind == VerificationFailureKind::AttachmentPriorBindingUnresolved)
    );
}

#[test]
fn attachment_topology_forward_reference() {
    let h0 = test_attachment_hash(3);
    let h1 = test_attachment_hash(4);
    let bytes = attachment_manifest_cbor(&[(h0, Some(h1))]);
    let entries = crate::parse::parse_attachment_manifest_entries(&bytes).unwrap();
    let mut m = std::collections::BTreeMap::new();
    m.insert(h0, 0usize);
    m.insert(h1, 1);
    let f = crate::export::attachment_manifest_topology_failures(&entries, &m);
    assert!(
        f.iter()
            .any(|e| e.kind == VerificationFailureKind::AttachmentPriorBindingForwardReference)
    );
}

#[test]
fn attachment_topology_lineage_two_cycle() {
    let h0 = test_attachment_hash(10);
    let h1 = test_attachment_hash(11);
    let bytes = attachment_manifest_cbor(&[(h1, Some(h0)), (h0, Some(h1))]);
    let entries = crate::parse::parse_attachment_manifest_entries(&bytes).unwrap();
    let mut m = std::collections::BTreeMap::new();
    m.insert(h0, 0usize);
    m.insert(h1, 1);
    let f = crate::export::attachment_manifest_topology_failures(&entries, &m);
    assert!(
        f.iter()
            .any(|e| e.kind == VerificationFailureKind::AttachmentBindingLineageCycle)
    );
}

#[test]
fn attachment_topology_lineage_three_cycle() {
    let h0 = test_attachment_hash(20);
    let h1 = test_attachment_hash(21);
    let h2 = test_attachment_hash(22);
    let bytes = attachment_manifest_cbor(&[(h0, Some(h2)), (h1, Some(h0)), (h2, Some(h1))]);
    let entries = crate::parse::parse_attachment_manifest_entries(&bytes).unwrap();
    let mut m = std::collections::BTreeMap::new();
    m.insert(h0, 0usize);
    m.insert(h1, 1);
    m.insert(h2, 2);
    let f = crate::export::attachment_manifest_topology_failures(&entries, &m);
    assert!(
        f.iter()
            .any(|e| e.kind == VerificationFailureKind::AttachmentBindingLineageCycle)
    );
}

#[test]
fn attachment_topology_multirevision_ok() {
    let h0 = test_attachment_hash(30);
    let h1 = test_attachment_hash(31);
    let h2 = test_attachment_hash(32);
    let bytes = attachment_manifest_cbor(&[(h0, None), (h1, Some(h0)), (h2, Some(h1))]);
    let entries = crate::parse::parse_attachment_manifest_entries(&bytes).unwrap();
    let mut m = std::collections::BTreeMap::new();
    m.insert(h0, 0usize);
    m.insert(h1, 1);
    m.insert(h2, 2);
    let f = crate::export::attachment_manifest_topology_failures(&entries, &m);
    assert!(f.is_empty());
}

// ------------------------------------------------------------------
// ADR 0005 erasure-evidence unit tests (Stage 2).
//
// These test the internal decode + finalize helpers directly so each
// ADR 0005 §"Verifier obligations" step has byte-level coverage that
// does not require a full COSE_Sign1 envelope. Fixture-level coverage
// is in `trellis-conformance` against `fixtures/vectors/append/023..027`
// and `fixtures/vectors/tamper/017..019`.
// ------------------------------------------------------------------

/// Builder for a minimum-valid erasure-evidence extension map.
/// Tests mutate fields to exercise each ADR 0005 step in isolation.
fn erasure_extension(
    kid_destroyed: &[u8; 16],
    key_class: &str,
    destroyed_at: u64,
    subject_scope: Value,
    attestations: Vec<Value>,
    hsm_receipt: Option<Value>,
    hsm_receipt_kind: Option<Value>,
    cascade_scopes: Vec<&str>,
) -> Vec<(Value, Value)> {
    let cascade_array: Vec<Value> = cascade_scopes
        .into_iter()
        .map(|s| Value::Text(s.to_string()))
        .collect();
    vec![(
        Value::Text("trellis.erasure-evidence.v1".into()),
        Value::Map(vec![
            (
                Value::Text("evidence_id".into()),
                Value::Text("urn:trellis:erasure:test:1".into()),
            ),
            (
                Value::Text("kid_destroyed".into()),
                Value::Bytes(kid_destroyed.to_vec()),
            ),
            (
                Value::Text("key_class".into()),
                Value::Text(key_class.into()),
            ),
            (
                Value::Text("destroyed_at".into()),
                Value::Array(vec![
                    Value::Integer(destroyed_at.into()),
                    Value::Integer(0u32.into()),
                ]),
            ),
            (
                Value::Text("cascade_scopes".into()),
                Value::Array(cascade_array),
            ),
            (
                Value::Text("completion_mode".into()),
                Value::Text("complete".into()),
            ),
            (
                Value::Text("destruction_actor".into()),
                Value::Text("urn:trellis:principal:test-actor".into()),
            ),
            (
                Value::Text("policy_authority".into()),
                Value::Text("urn:trellis:authority:test-policy".into()),
            ),
            (
                Value::Text("reason_code".into()),
                Value::Integer(1u64.into()),
            ),
            (Value::Text("subject_scope".into()), subject_scope),
            (
                Value::Text("hsm_receipt".into()),
                hsm_receipt.unwrap_or(Value::Null),
            ),
            (
                Value::Text("hsm_receipt_kind".into()),
                hsm_receipt_kind.unwrap_or(Value::Null),
            ),
            (
                Value::Text("attestations".into()),
                Value::Array(attestations),
            ),
            (Value::Text("extensions".into()), Value::Null),
        ]),
    )]
}

fn one_attestation(class: &str) -> Value {
    Value::Map(vec![
        (
            Value::Text("authority".into()),
            Value::Text(format!("urn:trellis:authority:test-{class}")),
        ),
        (
            Value::Text("authority_class".into()),
            Value::Text(class.into()),
        ),
        (Value::Text("signature".into()), Value::Bytes(vec![0u8; 64])),
    ])
}

fn per_subject_scope() -> Value {
    Value::Map(vec![
        (
            Value::Text("kind".into()),
            Value::Text("per-subject".into()),
        ),
        (
            Value::Text("subject_refs".into()),
            Value::Array(vec![Value::Text("urn:trellis:subject:test-1".into())]),
        ),
        (Value::Text("ledger_scopes".into()), Value::Null),
        (Value::Text("tenant_refs".into()), Value::Null),
    ])
}

fn deployment_wide_scope() -> Value {
    Value::Map(vec![
        (
            Value::Text("kind".into()),
            Value::Text("deployment-wide".into()),
        ),
        (Value::Text("subject_refs".into()), Value::Null),
        (Value::Text("ledger_scopes".into()), Value::Null),
        (Value::Text("tenant_refs".into()), Value::Null),
    ])
}

#[test]
fn validate_subject_scope_shape_per_subject_accepts_subject_refs_only() {
    let scope = per_subject_scope();
    let map = scope.as_map().unwrap().clone();
    assert!(crate::util::validate_subject_scope_shape(&map, "per-subject").is_ok());
}

#[test]
fn validate_subject_scope_shape_per_subject_rejects_with_ledger_scopes() {
    let scope = Value::Map(vec![
        (
            Value::Text("kind".into()),
            Value::Text("per-subject".into()),
        ),
        (
            Value::Text("subject_refs".into()),
            Value::Array(vec![Value::Text("urn:trellis:subject:test-1".into())]),
        ),
        (
            Value::Text("ledger_scopes".into()),
            Value::Array(vec![Value::Bytes(b"x".to_vec())]),
        ),
        (Value::Text("tenant_refs".into()), Value::Null),
    ]);
    let map = scope.as_map().unwrap().clone();
    let err = crate::util::validate_subject_scope_shape(&map, "per-subject").unwrap_err();
    assert!(err.to_string().contains("subject_scope"));
}

#[test]
fn validate_subject_scope_shape_per_scope_requires_ledger_scopes() {
    let scope = Value::Map(vec![
        (Value::Text("kind".into()), Value::Text("per-scope".into())),
        (Value::Text("subject_refs".into()), Value::Null),
        (
            Value::Text("ledger_scopes".into()),
            Value::Array(vec![Value::Bytes(b"scope-a".to_vec())]),
        ),
        (Value::Text("tenant_refs".into()), Value::Null),
    ]);
    let map = scope.as_map().unwrap().clone();
    assert!(crate::util::validate_subject_scope_shape(&map, "per-scope").is_ok());
}

#[test]
fn validate_subject_scope_shape_per_tenant_requires_tenant_refs() {
    let scope = Value::Map(vec![
        (Value::Text("kind".into()), Value::Text("per-tenant".into())),
        (Value::Text("subject_refs".into()), Value::Null),
        (Value::Text("ledger_scopes".into()), Value::Null),
        (
            Value::Text("tenant_refs".into()),
            Value::Array(vec![Value::Text("urn:trellis:tenant:test".into())]),
        ),
    ]);
    let map = scope.as_map().unwrap().clone();
    assert!(crate::util::validate_subject_scope_shape(&map, "per-tenant").is_ok());
}

#[test]
fn validate_subject_scope_shape_deployment_wide_rejects_any_ref_field() {
    let scope = Value::Map(vec![
        (
            Value::Text("kind".into()),
            Value::Text("deployment-wide".into()),
        ),
        (
            Value::Text("subject_refs".into()),
            Value::Array(vec![Value::Text("urn:trellis:subject:s".into())]),
        ),
        (Value::Text("ledger_scopes".into()), Value::Null),
        (Value::Text("tenant_refs".into()), Value::Null),
    ]);
    let map = scope.as_map().unwrap().clone();
    let err = crate::util::validate_subject_scope_shape(&map, "deployment-wide").unwrap_err();
    assert!(err.to_string().contains("subject_scope"));
}

#[test]
fn validate_subject_scope_shape_unknown_kind_rejected() {
    let scope = Value::Map(vec![
        (Value::Text("kind".into()), Value::Text("not-real".into())),
        (Value::Text("subject_refs".into()), Value::Null),
        (Value::Text("ledger_scopes".into()), Value::Null),
        (Value::Text("tenant_refs".into()), Value::Null),
    ]);
    let map = scope.as_map().unwrap().clone();
    let err = crate::util::validate_subject_scope_shape(&map, "not-real").unwrap_err();
    assert!(err.to_string().contains("not-real"));
}

#[test]
fn decode_erasure_evidence_step1_minimum_valid_payload_decodes() {
    let kid = [0xABu8; 16];
    let extensions = erasure_extension(
        &kid,
        "signing",
        1_745_000_000,
        per_subject_scope(),
        vec![one_attestation("new")],
        None,
        None,
        vec!["CS-03"],
    );
    let details = crate::parse::decode_erasure_evidence_details(
        &extensions,
        TrellisTimestamp {
            seconds: 1_745_000_100,
            nanos: 0,
        },
    )
    .unwrap()
    .expect("erasure extension must decode");
    assert_eq!(details.evidence_id, "urn:trellis:erasure:test:1");
    assert_eq!(details.kid_destroyed, kid.to_vec());
    assert_eq!(details.norm_key_class, "signing");
    assert_eq!(
        details.destroyed_at,
        TrellisTimestamp {
            seconds: 1_745_000_000,
            nanos: 0
        }
    );
    assert_eq!(details.cascade_scopes, vec!["CS-03"]);
    assert_eq!(details.completion_mode, "complete");
    assert!(details.attestation_signatures_well_formed);
}

#[test]
fn decode_erasure_evidence_step1_returns_none_when_extension_absent() {
    let extensions: Vec<(Value, Value)> = vec![(
        Value::Text("trellis.custody-model-transition.v1".into()),
        Value::Map(vec![]),
    )];
    let result = crate::parse::decode_erasure_evidence_details(
        &extensions,
        TrellisTimestamp {
            seconds: 1_745_000_000,
            nanos: 0,
        },
    )
    .unwrap();
    assert!(result.is_none(), "no erasure-evidence ext → None");
}

#[test]
fn decode_erasure_evidence_step2_normalizes_wire_wrap_to_subject() {
    // ADR 0005 step 2 + Core §8.7.6: wire `key_class = "wrap"` MUST
    // normalize to `"subject"` before any registry comparison.
    let kid = [0x01u8; 16];
    let extensions = erasure_extension(
        &kid,
        "wrap",
        1_745_000_000,
        per_subject_scope(),
        vec![one_attestation("new")],
        None,
        None,
        vec!["CS-03"],
    );
    let details = crate::parse::decode_erasure_evidence_details(
        &extensions,
        TrellisTimestamp {
            seconds: 1_745_000_100,
            nanos: 0,
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        details.norm_key_class, "subject",
        "wire 'wrap' must normalize to 'subject' (Wave 17 / ADR 0006)",
    );
}

#[test]
fn decode_erasure_evidence_step3_rejects_per_subject_with_null_subject_refs() {
    let kid = [0x02u8; 16];
    // per-subject kind but subject_refs null violates step 3.
    let bad_scope = Value::Map(vec![
        (
            Value::Text("kind".into()),
            Value::Text("per-subject".into()),
        ),
        (Value::Text("subject_refs".into()), Value::Null),
        (Value::Text("ledger_scopes".into()), Value::Null),
        (Value::Text("tenant_refs".into()), Value::Null),
    ]);
    let extensions = erasure_extension(
        &kid,
        "signing",
        1_745_000_000,
        bad_scope,
        vec![one_attestation("new")],
        None,
        None,
        vec!["CS-03"],
    );
    let err = crate::parse::decode_erasure_evidence_details(
        &extensions,
        TrellisTimestamp {
            seconds: 1_745_000_100,
            nanos: 0,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("subject_scope"));
}

#[test]
fn decode_erasure_evidence_step4_rejects_destroyed_at_after_host_authored_at() {
    // ADR 0005 step 4 / OC-144: destroyed_at MUST be ≤ host event
    // authored_at. Violation surfaces as `erasure_destroyed_at_after_host`.
    let kid = [0x03u8; 16];
    let extensions = erasure_extension(
        &kid,
        "signing",
        1_745_000_500, // destroyed_at > host (1_745_000_100)
        per_subject_scope(),
        vec![one_attestation("new")],
        None,
        None,
        vec!["CS-03"],
    );
    let err = crate::parse::decode_erasure_evidence_details(
        &extensions,
        TrellisTimestamp {
            seconds: 1_745_000_100,
            nanos: 0,
        },
    )
    .unwrap_err();
    assert_eq!(
        err.kind(),
        Some(VerifyErrorKind::ErasureDestroyedAtAfterHost)
    );
}

#[test]
fn decode_erasure_evidence_step6_rejects_hsm_receipt_without_kind() {
    let kid = [0x04u8; 16];
    let extensions = erasure_extension(
        &kid,
        "signing",
        1_745_000_000,
        per_subject_scope(),
        vec![one_attestation("new")],
        Some(Value::Bytes(b"opaque-hsm-bytes".to_vec())),
        None,
        vec!["CS-03"],
    );
    let err = crate::parse::decode_erasure_evidence_details(
        &extensions,
        TrellisTimestamp {
            seconds: 1_745_000_100,
            nanos: 0,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("hsm_receipt"));
}

#[test]
fn decode_erasure_evidence_step6_rejects_hsm_receipt_kind_without_receipt() {
    let kid = [0x05u8; 16];
    let extensions = erasure_extension(
        &kid,
        "signing",
        1_745_000_000,
        per_subject_scope(),
        vec![one_attestation("new")],
        None,
        Some(Value::Text("opaque-vendor-receipt-v1".into())),
        vec!["CS-03"],
    );
    let err = crate::parse::decode_erasure_evidence_details(
        &extensions,
        TrellisTimestamp {
            seconds: 1_745_000_100,
            nanos: 0,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("hsm_receipt"));
}

#[test]
fn decode_erasure_evidence_step6_accepts_both_hsm_fields_present() {
    let kid = [0x06u8; 16];
    let extensions = erasure_extension(
        &kid,
        "signing",
        1_745_000_000,
        per_subject_scope(),
        vec![one_attestation("new")],
        Some(Value::Bytes(b"opaque-hsm-bytes".to_vec())),
        Some(Value::Text("opaque-vendor-receipt-v1".into())),
        vec!["CS-03"],
    );
    let details = crate::parse::decode_erasure_evidence_details(
        &extensions,
        TrellisTimestamp {
            seconds: 1_745_000_100,
            nanos: 0,
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(details.evidence_id, "urn:trellis:erasure:test:1");
}

#[test]
fn decode_erasure_evidence_step7_marks_short_attestation_signature_malformed() {
    // ADR 0005 step 7 (Phase-1 structural): each attestation MUST carry
    // a 64-byte signature. A 32-byte signature flips
    // `attestation_signatures_well_formed = false`.
    let kid = [0x07u8; 16];
    let bad_attestation = Value::Map(vec![
        (
            Value::Text("authority".into()),
            Value::Text("urn:trellis:authority:test-bad".into()),
        ),
        (
            Value::Text("authority_class".into()),
            Value::Text("new".into()),
        ),
        (
            Value::Text("signature".into()),
            Value::Bytes(vec![0u8; 32]), // wrong length
        ),
    ]);
    let extensions = erasure_extension(
        &kid,
        "signing",
        1_745_000_000,
        per_subject_scope(),
        vec![bad_attestation],
        None,
        None,
        vec!["CS-03"],
    );
    let details = crate::parse::decode_erasure_evidence_details(
        &extensions,
        TrellisTimestamp {
            seconds: 1_745_000_100,
            nanos: 0,
        },
    )
    .unwrap()
    .unwrap();
    assert!(!details.attestation_signatures_well_formed);
}

#[test]
fn decode_erasure_evidence_step1_rejects_empty_cascade_scopes() {
    let kid = [0x08u8; 16];
    let extensions = erasure_extension(
        &kid,
        "signing",
        1_745_000_000,
        per_subject_scope(),
        vec![one_attestation("new")],
        None,
        None,
        vec![], // empty
    );
    let err = crate::parse::decode_erasure_evidence_details(
        &extensions,
        TrellisTimestamp {
            seconds: 1_745_000_100,
            nanos: 0,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("cascade_scopes"));
}

#[test]
fn decode_erasure_evidence_step1_rejects_empty_attestations() {
    let kid = [0x09u8; 16];
    let extensions = erasure_extension(
        &kid,
        "signing",
        1_745_000_000,
        per_subject_scope(),
        vec![],
        None,
        None,
        vec!["CS-03"],
    );
    let err = crate::parse::decode_erasure_evidence_details(
        &extensions,
        TrellisTimestamp {
            seconds: 1_745_000_100,
            nanos: 0,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("attestations"));
}

#[test]
fn decode_erasure_evidence_step1_rejects_kid_wrong_size() {
    // Use the manual map builder to bypass the `[u8; 16]` builder helper
    // and force a 15-byte kid.
    let extensions = vec![(
        Value::Text("trellis.erasure-evidence.v1".into()),
        Value::Map(vec![
            (
                Value::Text("evidence_id".into()),
                Value::Text("urn:trellis:erasure:test:bad".into()),
            ),
            (
                Value::Text("kid_destroyed".into()),
                Value::Bytes(vec![0u8; 15]),
            ),
            (
                Value::Text("key_class".into()),
                Value::Text("signing".into()),
            ),
            (
                Value::Text("destroyed_at".into()),
                Value::Integer(1_745_000_000u64.into()),
            ),
            (
                Value::Text("cascade_scopes".into()),
                Value::Array(vec![Value::Text("CS-03".into())]),
            ),
            (
                Value::Text("completion_mode".into()),
                Value::Text("complete".into()),
            ),
            (
                Value::Text("destruction_actor".into()),
                Value::Text("urn:trellis:principal:t".into()),
            ),
            (
                Value::Text("policy_authority".into()),
                Value::Text("urn:trellis:authority:t".into()),
            ),
            (
                Value::Text("reason_code".into()),
                Value::Integer(1u64.into()),
            ),
            (Value::Text("subject_scope".into()), per_subject_scope()),
            (Value::Text("hsm_receipt".into()), Value::Null),
            (Value::Text("hsm_receipt_kind".into()), Value::Null),
            (
                Value::Text("attestations".into()),
                Value::Array(vec![one_attestation("new")]),
            ),
            (Value::Text("extensions".into()), Value::Null),
        ]),
    )];
    let err = crate::parse::decode_erasure_evidence_details(
        &extensions,
        TrellisTimestamp {
            seconds: 1_745_000_100,
            nanos: 0,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("kid_destroyed"));
}

#[test]
fn decode_erasure_evidence_deployment_wide_scope_decodes() {
    let kid = [0x0Au8; 16];
    let extensions = erasure_extension(
        &kid,
        "signing",
        1_745_000_000,
        deployment_wide_scope(),
        vec![one_attestation("prior"), one_attestation("new")],
        None,
        None,
        vec!["CS-01", "CS-02", "CS-03", "CS-04", "CS-05", "CS-06"],
    );
    let details = crate::parse::decode_erasure_evidence_details(
        &extensions,
        TrellisTimestamp {
            seconds: 1_745_000_100,
            nanos: 0,
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(details.subject_scope_kind, "deployment-wide");
    assert_eq!(details.cascade_scopes.len(), 6);
    assert_eq!(details.attestation_classes, vec!["prior", "new"]);
}

// ------------------------------------------------------------------
// finalize_erasure_evidence — steps 2 / 5 / 8 cross-event reasoning.
// These tests construct ErasureEvidenceDetails + ChainEventSummary
// values directly so we can exercise the post-loop logic without
// building a full COSE_Sign1 chain. Fixture-level coverage for the
// happy + tamper paths lives in `trellis-conformance` against
// `fixtures/vectors/append/023..027` and `tamper/017..019`.
// ------------------------------------------------------------------

fn payload_details(
    kid: Vec<u8>,
    norm_key_class: &str,
    destroyed_at: u64,
) -> crate::ErasureEvidenceDetails {
    crate::ErasureEvidenceDetails {
        evidence_id: format!("urn:trellis:erasure:test:{}", kid[0]),
        kid_destroyed: kid,
        norm_key_class: norm_key_class.to_string(),
        destroyed_at: crate::TrellisTimestamp {
            seconds: destroyed_at,
            nanos: 0,
        },
        cascade_scopes: vec!["CS-03".to_string()],
        completion_mode: "complete".to_string(),
        attestation_signatures_well_formed: true,
        attestation_classes: vec!["new".to_string()],
        subject_scope_kind: "per-subject".to_string(),
    }
}

fn chain_summary(
    index: u64,
    authored_at: u64,
    signing_kid: Vec<u8>,
    wrap_recipients: Vec<Vec<u8>>,
    canonical_event_hash: [u8; 32],
) -> crate::ChainEventSummary {
    crate::ChainEventSummary {
        event_index: index,
        authored_at: crate::TrellisTimestamp {
            seconds: authored_at,
            nanos: 0,
        },
        signing_kid,
        wrap_recipients,
        canonical_event_hash,
    }
}

#[test]
fn finalize_erasure_evidence_empty_input_produces_empty_outcome() {
    let registry = BTreeMap::new();
    let mut event_failures = Vec::new();
    let outcomes =
        crate::erasure::finalize_erasure_evidence(&[], &[], &registry, None, &mut event_failures);
    assert!(outcomes.is_empty());
    assert!(event_failures.is_empty());
}

#[test]
fn finalize_step8_flags_post_erasure_use_for_signing_class() {
    // One signing kid destroyed at t=100; a later event at t=200 signs
    // under that kid. Expect post_erasure_uses == 1 and a localized
    // `post_erasure_use` event_failure.
    let kid = vec![0xAAu8; 16];
    let payload = payload_details(kid.clone(), "signing", 100);
    let canonical_hash = [0u8; 32];
    let payloads = vec![(0usize, payload, canonical_hash)];

    let later_hash = [1u8; 32];
    let chain = vec![
        chain_summary(0, 100, kid.clone(), vec![], canonical_hash),
        chain_summary(1, 200, kid.clone(), vec![], later_hash),
    ];

    let registry = BTreeMap::new(); // kid not registered → step 2 skipped
    let mut event_failures = Vec::new();
    let outcomes = crate::erasure::finalize_erasure_evidence(
        &payloads,
        &chain,
        &registry,
        None,
        &mut event_failures,
    );
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].post_erasure_uses, 1);
    assert_eq!(outcomes[0].post_erasure_wraps, 0);
    assert!(
        event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::PostErasureUse
                && f.location == crate::util::hex_string(&later_hash))
    );
}

#[test]
fn finalize_step8_flags_post_erasure_wrap_for_subject_class() {
    // A subject kid destroyed; a later event at t > destroyed_at carries
    // a key_bag.entries[*].recipient equal to the destroyed kid.
    let kid = vec![0xBBu8; 16];
    let payload = payload_details(kid.clone(), "subject", 100);
    let canonical_hash = [0u8; 32];
    let payloads = vec![(0usize, payload, canonical_hash)];

    let signing_kid = vec![0xCCu8; 16]; // a different signing kid
    let later_hash = [2u8; 32];
    let chain = vec![
        chain_summary(0, 100, signing_kid.clone(), vec![], canonical_hash),
        chain_summary(1, 200, signing_kid.clone(), vec![kid.clone()], later_hash),
    ];

    let registry = BTreeMap::new();
    let mut event_failures = Vec::new();
    let outcomes = crate::erasure::finalize_erasure_evidence(
        &payloads,
        &chain,
        &registry,
        None,
        &mut event_failures,
    );
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].post_erasure_uses, 0);
    assert_eq!(outcomes[0].post_erasure_wraps, 1);
    assert!(
        event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::PostErasureWrap
                && f.location == crate::util::hex_string(&later_hash))
    );
}

#[test]
fn finalize_step8_phase1_skips_recovery_class_chain_walk() {
    // ADR 0005 step 8 Phase-1 scope: recovery / scope / tenant-root and
    // extension-`tstr` classes do NOT trigger the chain-walk in Phase 1.
    // Wire-valid: dispatch co-lands with ADR 0006 follow-on.
    let kid = vec![0xDDu8; 16];
    let payload = payload_details(kid.clone(), "recovery", 100);
    let canonical_hash = [0u8; 32];
    let payloads = vec![(0usize, payload, canonical_hash)];

    // Even with a later event that signs under the destroyed kid, the
    // Phase-1 verifier must not flag post_erasure_use for "recovery".
    let later_hash = [3u8; 32];
    let chain = vec![
        chain_summary(0, 100, kid.clone(), vec![], canonical_hash),
        chain_summary(1, 200, kid.clone(), vec![], later_hash),
    ];

    let registry = BTreeMap::new();
    let mut event_failures = Vec::new();
    let outcomes = crate::erasure::finalize_erasure_evidence(
        &payloads,
        &chain,
        &registry,
        None,
        &mut event_failures,
    );
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].post_erasure_uses, 0, "recovery class skipped");
    assert_eq!(outcomes[0].post_erasure_wraps, 0);
    assert!(
        !event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::PostErasureUse),
        "Phase-1 must not flag post_erasure_use for recovery class",
    );
}

#[test]
fn finalize_step5_flags_destroyed_at_conflict_for_same_kid() {
    // ADR 0005 step 5 / OC-145: two payloads with same kid_destroyed
    // but different destroyed_at → `erasure_destroyed_at_conflict`.
    let kid = vec![0xEEu8; 16];
    let payload_a = payload_details(kid.clone(), "signing", 100);
    let payload_b = payload_details(kid.clone(), "signing", 200);
    let hash_a = [0u8; 32];
    let hash_b = [1u8; 32];
    let payloads = vec![(0usize, payload_a, hash_a), (1usize, payload_b, hash_b)];

    let chain = vec![
        chain_summary(0, 100, kid.clone(), vec![], hash_a),
        chain_summary(1, 150, kid.clone(), vec![], hash_b),
    ];

    let registry = BTreeMap::new();
    let mut event_failures = Vec::new();
    let outcomes = crate::erasure::finalize_erasure_evidence(
        &payloads,
        &chain,
        &registry,
        None,
        &mut event_failures,
    );
    assert_eq!(outcomes.len(), 2);
    assert!(
        event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::ErasureDestroyedAtConflict)
    );
    // The second outcome carries the conflict failure tag.
    assert!(
        outcomes[1]
            .failures
            .iter()
            .any(|s| s == "erasure_destroyed_at_conflict")
    );
}

#[test]
fn finalize_step5_flags_key_class_conflict_for_same_kid() {
    // Two payloads, same kid_destroyed, different normalized class →
    // `erasure_key_class_payload_conflict`.
    let kid = vec![0xF0u8; 16];
    let payload_a = payload_details(kid.clone(), "signing", 100);
    let payload_b = payload_details(kid.clone(), "subject", 100);
    let hash_a = [0u8; 32];
    let hash_b = [1u8; 32];
    let payloads = vec![(0usize, payload_a, hash_a), (1usize, payload_b, hash_b)];

    let chain = vec![
        chain_summary(0, 100, kid.clone(), vec![], hash_a),
        chain_summary(1, 150, kid.clone(), vec![], hash_b),
    ];

    let registry = BTreeMap::new();
    let mut event_failures = Vec::new();
    let outcomes = crate::erasure::finalize_erasure_evidence(
        &payloads,
        &chain,
        &registry,
        None,
        &mut event_failures,
    );
    assert_eq!(outcomes.len(), 2);
    assert!(
        event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::ErasureKeyClassPayloadConflict)
    );
}

#[test]
fn finalize_step2_flags_registry_class_mismatch_for_signing_kid() {
    // Registry has the kid as a signing key; payload claims it's a
    // subject key. Step 2 → `erasure_key_class_registry_mismatch`.
    let kid = vec![0xF1u8; 16];
    let payload = payload_details(kid.clone(), "subject", 100);
    let canonical_hash = [0u8; 32];
    let payloads = vec![(0usize, payload, canonical_hash)];

    let chain = vec![chain_summary(0, 100, kid.clone(), vec![], canonical_hash)];

    let mut registry = BTreeMap::new();
    registry.insert(
        kid.clone(),
        crate::SigningKeyEntry {
            public_key: [0u8; 32],
            status: 1,
            valid_from: None,
            valid_to: None,
        },
    );
    let mut event_failures = Vec::new();
    let _outcomes = crate::erasure::finalize_erasure_evidence(
        &payloads,
        &chain,
        &registry,
        None,
        &mut event_failures,
    );
    assert!(
        event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::ErasureKeyClassRegistryMismatch)
    );
}

#[test]
fn finalize_step2_accepts_matching_signing_class() {
    // Registry has the kid as a signing key; payload also claims signing
    // → no step-2 mismatch.
    let kid = vec![0xF2u8; 16];
    let payload = payload_details(kid.clone(), "signing", 100);
    let canonical_hash = [0u8; 32];
    let payloads = vec![(0usize, payload, canonical_hash)];

    let chain = vec![chain_summary(0, 100, kid.clone(), vec![], canonical_hash)];

    let mut registry = BTreeMap::new();
    registry.insert(
        kid.clone(),
        crate::SigningKeyEntry {
            public_key: [0u8; 32],
            status: 1,
            valid_from: None,
            valid_to: None,
        },
    );
    let mut event_failures = Vec::new();
    let outcomes = crate::erasure::finalize_erasure_evidence(
        &payloads,
        &chain,
        &registry,
        None,
        &mut event_failures,
    );
    assert_eq!(outcomes.len(), 1);
    assert!(
        !event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::ErasureKeyClassRegistryMismatch)
    );
}

#[test]
fn finalize_step7_flags_malformed_attestation_signature() {
    // attestation_signatures_well_formed = false → outcome carries
    // signature_verified = false AND a `erasure_attestation_signature_invalid`
    // event_failure surfaces so the report's tamper_kind picks it up.
    let kid = vec![0xF3u8; 16];
    let mut payload = payload_details(kid.clone(), "signing", 100);
    payload.attestation_signatures_well_formed = false;
    let canonical_hash = [0u8; 32];
    let payloads = vec![(0usize, payload, canonical_hash)];

    let chain = vec![chain_summary(0, 100, kid.clone(), vec![], canonical_hash)];

    let registry = BTreeMap::new();
    let mut event_failures = Vec::new();
    let outcomes = crate::erasure::finalize_erasure_evidence(
        &payloads,
        &chain,
        &registry,
        None,
        &mut event_failures,
    );
    assert_eq!(outcomes.len(), 1);
    assert!(!outcomes[0].signature_verified);
    assert!(
        event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::ErasureAttestationSignatureInvalid)
    );
}

#[test]
fn finalize_step8_no_post_erasure_use_when_authored_at_equals_destroyed_at() {
    // ADR 0005 step 8 comparison rule: `authored_at > destroyed_at`
    // (strict). Equal timestamps are not flagged (the erasure event
    // itself may carry that kid).
    let kid = vec![0xF4u8; 16];
    let payload = payload_details(kid.clone(), "signing", 100);
    let canonical_hash = [0u8; 32];
    let payloads = vec![(0usize, payload, canonical_hash)];

    // Event authored at exactly destroyed_at: must NOT trigger.
    let chain = vec![chain_summary(0, 100, kid.clone(), vec![], canonical_hash)];

    let registry = BTreeMap::new();
    let mut event_failures = Vec::new();
    let outcomes = crate::erasure::finalize_erasure_evidence(
        &payloads,
        &chain,
        &registry,
        None,
        &mut event_failures,
    );
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].post_erasure_uses, 0);
    assert_eq!(outcomes[0].post_erasure_wraps, 0);
}

// ------------------------------------------------------------------
// ADR 0007 certificate-of-completion unit tests (Step 2).
//
// These exercise the internal decode + finalize + manifest-extension
// helpers directly, mirroring the ADR 0005 test layout above. Fixture
// coverage for the wire-corpus paths lands in the ADR 0007 execution
// train under fixtures/vectors/append/028..030, tamper/020..026, and
// export/010 in subsequent commits.
// ------------------------------------------------------------------

fn certificate_attestation(class: &str) -> Value {
    Value::Map(vec![
        (
            Value::Text("authority".into()),
            Value::Text(format!("urn:trellis:authority:test-{class}")),
        ),
        (
            Value::Text("authority_class".into()),
            Value::Text(class.into()),
        ),
        (Value::Text("signature".into()), Value::Bytes(vec![0u8; 64])),
    ])
}

fn presentation_artifact_value(
    media_type: &str,
    attachment_id: &str,
    template_hash: Option<Value>,
) -> Value {
    Value::Map(vec![
        (
            Value::Text("content_hash".into()),
            Value::Bytes(vec![0xCAu8; 32]),
        ),
        (
            Value::Text("media_type".into()),
            Value::Text(media_type.into()),
        ),
        (
            Value::Text("byte_length".into()),
            Value::Integer(1024u64.into()),
        ),
        (
            Value::Text("attachment_id".into()),
            Value::Text(attachment_id.into()),
        ),
        (Value::Text("template_id".into()), Value::Null),
        (
            Value::Text("template_hash".into()),
            template_hash.unwrap_or(Value::Null),
        ),
    ])
}

fn signer_display_value(principal_ref: &str, signed_at: u64) -> Value {
    Value::Map(vec![
        (
            Value::Text("principal_ref".into()),
            Value::Text(principal_ref.into()),
        ),
        (
            Value::Text("display_name".into()),
            Value::Text("Test Signer".into()),
        ),
        (Value::Text("display_role".into()), Value::Null),
        (
            Value::Text("signed_at".into()),
            Value::Array(vec![
                Value::Integer(signed_at.into()),
                Value::Integer(0.into()),
            ]),
        ),
    ])
}

fn chain_summary_value(
    signer_count: u64,
    signer_displays: Vec<Value>,
    response_ref: Value,
    workflow_status: &str,
) -> Value {
    Value::Map(vec![
        (
            Value::Text("signer_count".into()),
            Value::Integer(signer_count.into()),
        ),
        (
            Value::Text("signer_display".into()),
            Value::Array(signer_displays),
        ),
        (Value::Text("response_ref".into()), response_ref),
        (
            Value::Text("workflow_status".into()),
            Value::Text(workflow_status.into()),
        ),
        (Value::Text("impact_level".into()), Value::Null),
        (Value::Text("covered_claims".into()), Value::Array(vec![])),
    ])
}

fn certificate_extension(
    signing_event_digests: Vec<[u8; 32]>,
    signer_count: u64,
    signer_displays: Vec<Value>,
    media_type: &str,
    template_hash: Option<Value>,
    response_ref: Value,
) -> Vec<(Value, Value)> {
    let signing_events = signing_event_digests
        .into_iter()
        .map(|d| Value::Bytes(d.to_vec()))
        .collect::<Vec<_>>();
    vec![(
        Value::Text("trellis.certificate-of-completion.v1".into()),
        Value::Map(vec![
            (
                Value::Text("certificate_id".into()),
                Value::Text("urn:trellis:cert:test:1".into()),
            ),
            (Value::Text("case_ref".into()), Value::Null),
            (
                Value::Text("completed_at".into()),
                Value::Array(vec![
                    Value::Integer(1_745_100_000u64.into()),
                    Value::Integer(0.into()),
                ]),
            ),
            (
                Value::Text("presentation_artifact".into()),
                presentation_artifact_value(media_type, "att-1", template_hash),
            ),
            (
                Value::Text("chain_summary".into()),
                chain_summary_value(signer_count, signer_displays, response_ref, "completed"),
            ),
            (
                Value::Text("signing_events".into()),
                Value::Array(signing_events),
            ),
            (Value::Text("workflow_ref".into()), Value::Null),
            (
                Value::Text("attestations".into()),
                Value::Array(vec![certificate_attestation("new")]),
            ),
            (Value::Text("extensions".into()), Value::Null),
        ]),
    )]
}

#[test]
fn decode_certificate_step1_minimum_valid_payload_decodes() {
    let signing_event = [0xAAu8; 32];
    let extensions = certificate_extension(
        vec![signing_event],
        1,
        vec![signer_display_value(
            "urn:trellis:principal:applicant",
            1_745_099_000,
        )],
        "application/pdf",
        None,
        Value::Null,
    );
    let details = crate::parse::decode_certificate_payload(&extensions)
        .unwrap()
        .expect("certificate extension must decode");
    assert_eq!(details.certificate_id, "urn:trellis:cert:test:1");
    assert_eq!(
        details.completed_at,
        TrellisTimestamp {
            seconds: 1_745_100_000,
            nanos: 0
        }
    );
    assert_eq!(details.chain_summary.signer_count, 1);
    assert_eq!(details.signing_events.len(), 1);
    assert_eq!(details.signing_events[0], signing_event);
    assert!(details.attestation_signatures_well_formed);
}

#[test]
fn decode_certificate_step1_returns_none_when_extension_absent() {
    let extensions: Vec<(Value, Value)> = vec![(
        Value::Text("trellis.custody-model-transition.v1".into()),
        Value::Map(vec![]),
    )];
    let result = crate::parse::decode_certificate_payload(&extensions).unwrap();
    assert!(result.is_none(), "no certificate ext → None");
}

#[test]
fn decode_certificate_rejects_signer_count_signing_events_mismatch() {
    // ADR 0007 §"Verifier obligations" step 2 first invariant:
    // signer_count MUST equal len(signing_events). Mismatch surfaces
    // with kind `certificate_chain_summary_mismatch`.
    let signing_event = [0xBBu8; 32];
    let extensions = certificate_extension(
        vec![signing_event], // len = 1
        2,                   // claimed = 2
        vec![signer_display_value(
            "urn:trellis:principal:applicant",
            1_745_099_000,
        )],
        "application/pdf",
        None,
        Value::Null,
    );
    let err = crate::parse::decode_certificate_payload(&extensions).unwrap_err();
    assert_eq!(
        err.kind(),
        Some(VerifyErrorKind::CertificateChainSummaryMismatch)
    );
}

#[test]
fn decode_certificate_rejects_signer_display_signing_events_mismatch() {
    // ADR 0007 §"Verifier obligations" step 2 second invariant:
    // len(signer_display) MUST equal len(signing_events).
    let signing_event = [0xCCu8; 32];
    let extensions = certificate_extension(
        vec![signing_event],
        1,
        vec![
            signer_display_value("urn:trellis:principal:a", 1_745_099_000),
            signer_display_value("urn:trellis:principal:b", 1_745_099_001),
        ],
        "application/pdf",
        None,
        Value::Null,
    );
    let err = crate::parse::decode_certificate_payload(&extensions).unwrap_err();
    assert_eq!(
        err.kind(),
        Some(VerifyErrorKind::CertificateChainSummaryMismatch)
    );
}

#[test]
fn decode_certificate_rejects_html_with_null_template_hash() {
    // ADR 0007 §"Wire shape" PresentationArtifact.template_hash:
    // media_type=text/html requires non-null template_hash. §19.1 has no
    // dedicated tamper_kind; surface as `malformed_cose` (CDDL-shape).
    let signing_event = [0xDDu8; 32];
    let extensions = certificate_extension(
        vec![signing_event],
        1,
        vec![signer_display_value(
            "urn:trellis:principal:applicant",
            1_745_099_000,
        )],
        "text/html",
        None, // template_hash null
        Value::Null,
    );
    let err = crate::parse::decode_certificate_payload(&extensions).unwrap_err();
    assert_eq!(err.kind(), Some(VerifyErrorKind::MalformedCose));
    assert!(err.to_string().contains("template_hash"));
}

#[test]
fn decode_certificate_accepts_html_with_template_hash() {
    let signing_event = [0xEEu8; 32];
    let extensions = certificate_extension(
        vec![signing_event],
        1,
        vec![signer_display_value(
            "urn:trellis:principal:applicant",
            1_745_099_000,
        )],
        "text/html",
        Some(Value::Bytes(vec![0xABu8; 32])),
        Value::Null,
    );
    let details = crate::parse::decode_certificate_payload(&extensions)
        .unwrap()
        .unwrap();
    assert!(details.presentation_artifact.template_hash.is_some());
}

#[test]
fn decode_certificate_rejects_empty_signing_events() {
    // ADR 0007 §"Wire shape" `signing_events: [+ digest]` — non-empty
    // required. The CDDL also marks `signer_display: [+ ...]`; the
    // decoder catches the signer_display arity first because the
    // chain-summary nested map decodes before the top-level
    // signing_events array. Either way, an empty signing-events
    // payload is rejected with a recognizable error.
    let signing_event = [0x99u8; 32];
    // Build an extension with one signer_display row (so we get past
    // the signer_display empty check) and an empty signing_events
    // array — exercises only the signing_events arity guard.
    let mut extensions = certificate_extension(
        vec![signing_event],
        0,
        vec![signer_display_value("urn:trellis:principal:a", 1)],
        "application/pdf",
        None,
        Value::Null,
    );
    let inner_map = extensions[0].1.as_map_mut().unwrap();
    for (key, value) in inner_map.iter_mut() {
        if key.as_text() == Some("signing_events") {
            *value = Value::Array(vec![]);
        }
    }
    let err = crate::parse::decode_certificate_payload(&extensions).unwrap_err();
    assert!(err.to_string().contains("signing_events"), "{err}");
}

#[test]
fn decode_certificate_rejects_empty_attestations() {
    // Reuse the certificate_extension helper but mutate the
    // attestations array to empty after construction.
    let signing_event = [0xF0u8; 32];
    let mut extensions = certificate_extension(
        vec![signing_event],
        1,
        vec![signer_display_value(
            "urn:trellis:principal:applicant",
            1_745_099_000,
        )],
        "application/pdf",
        None,
        Value::Null,
    );
    // Drill into the certificate map's `attestations` array and empty it.
    let inner_map = extensions[0].1.as_map_mut().unwrap();
    for (key, value) in inner_map.iter_mut() {
        if key.as_text() == Some("attestations") {
            *value = Value::Array(vec![]);
        }
    }
    let err = crate::parse::decode_certificate_payload(&extensions).unwrap_err();
    assert!(err.to_string().contains("attestations"), "{err}");
}

#[test]
fn parse_certificate_export_extension_round_trip() {
    // Build a minimum-valid manifest map carrying the optional
    // `trellis.export.certificates-of-completion.v1` extension.
    let catalog_digest = [0x12u8; 32];
    let extension_value = Value::Map(vec![
        (
            Value::Text("catalog_ref".into()),
            Value::Text("065-certificates-of-completion.cbor".into()),
        ),
        (
            Value::Text("catalog_digest".into()),
            Value::Bytes(catalog_digest.to_vec()),
        ),
        (
            Value::Text("entry_count".into()),
            Value::Integer(3u64.into()),
        ),
    ]);
    let manifest_map = vec![(
        Value::Text("extensions".into()),
        Value::Map(vec![(
            Value::Text("trellis.export.certificates-of-completion.v1".into()),
            extension_value,
        )]),
    )];
    let extension = crate::parse::parse_certificate_export_extension(&manifest_map)
        .unwrap()
        .expect("extension must round-trip");
    assert_eq!(extension.catalog_ref, "065-certificates-of-completion.cbor");
    assert_eq!(extension.catalog_digest, catalog_digest);
    assert_eq!(extension.entry_count, 3);
}

#[test]
fn parse_certificate_export_extension_returns_none_when_absent() {
    let manifest_map: Vec<(Value, Value)> = vec![];
    let extension = crate::parse::parse_certificate_export_extension(&manifest_map).unwrap();
    assert!(extension.is_none());
}

fn certificate_details_for_test(
    certificate_id: &str,
    signing_events: Vec<[u8; 32]>,
    signer_count: u64,
) -> crate::CertificateDetails {
    let signer_displays = signing_events
        .iter()
        .enumerate()
        .map(|(i, _)| crate::SignerDisplayDetails {
            principal_ref: format!("urn:trellis:principal:test-{i}"),
            display_name: "Test".to_string(),
            display_role: None,
            signed_at: TrellisTimestamp {
                seconds: 1_745_099_000 + i as u64,
                nanos: 0,
            },
        })
        .collect();
    crate::CertificateDetails {
        certificate_id: certificate_id.to_string(),
        case_ref: None,
        completed_at: TrellisTimestamp {
            seconds: 1_745_100_000,
            nanos: 0,
        },
        presentation_artifact: crate::PresentationArtifactDetails {
            content_hash: [0u8; 32],
            media_type: "application/pdf".to_string(),
            byte_length: 1024,
            attachment_id: format!("att-{certificate_id}"),
            template_id: None,
            template_hash: None,
        },
        chain_summary: crate::ChainSummaryDetails {
            signer_count,
            signer_display: signer_displays,
            response_ref: None,
            workflow_status: "completed".to_string(),
            impact_level: None,
            covered_claims: Vec::new(),
        },
        signing_events,
        workflow_ref: None,
        attestation_signatures_well_formed: true,
    }
}

#[test]
fn finalize_certificates_accumulates_outcome_per_event() {
    // ADR 0007 §"Verifier obligations" step 8: every certificate event
    // contributes one outcome to `report.certificates_of_completion`.
    // Genesis-context (events slice empty) → step 4 stays
    // `attachment_resolved = true`; steps 5/6/7 don't fire because the
    // signing-event digests don't resolve in an empty slice (recorded
    // as `signing_event_unresolved` per step 5).
    let signing_event = [0x55u8; 32];
    let payload = certificate_details_for_test("cert-1", vec![signing_event], 1);
    let canonical_hash = [0u8; 32];
    let payloads = vec![(0usize, payload, canonical_hash)];

    let mut event_failures = Vec::new();
    let outcomes = crate::certificate::finalize_certificates_of_completion(
        &payloads,
        &[],
        &BTreeMap::new(),
        None,
        &NoopResponseProofResolver,
        &mut event_failures,
    );
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].certificate_id, "cert-1");
    assert_eq!(outcomes[0].signer_count, 1);
    assert_eq!(
        outcomes[0].completed_at,
        TrellisTimestamp {
            seconds: 1_745_100_000,
            nanos: 0
        }
    );
    // Empty events slice → unresolvable signing event → step 5 flags.
    assert!(!outcomes[0].all_signing_events_resolved);
    assert!(
        outcomes[0]
            .failures
            .iter()
            .any(|f| f == "signing_event_unresolved")
    );
    assert!(
        event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::SigningEventUnresolved)
    );
}

#[test]
fn finalize_certificates_flags_id_collision_for_disagreeing_payloads() {
    // ADR 0007 §"Verifier obligations" step 2 second sub-clause:
    // duplicate certificate_id with disagreeing canonical payload →
    // `certificate_id_collision`.
    let signing_event_a = [0x60u8; 32];
    let signing_event_b = [0x61u8; 32];
    let payload_a = certificate_details_for_test("cert-collision", vec![signing_event_a], 1);
    // Same id, different signing_events digest → collision.
    let payload_b = certificate_details_for_test("cert-collision", vec![signing_event_b], 1);
    let hash_a = [0u8; 32];
    let hash_b = [1u8; 32];
    let payloads = vec![(0usize, payload_a, hash_a), (1usize, payload_b, hash_b)];

    let mut event_failures = Vec::new();
    let outcomes = crate::certificate::finalize_certificates_of_completion(
        &payloads,
        &[],
        &BTreeMap::new(),
        None,
        &NoopResponseProofResolver,
        &mut event_failures,
    );
    assert_eq!(outcomes.len(), 2);
    assert!(
        event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::CertificateIdCollision),
        "step 2 second sub-clause: duplicate certificate_id with disagreeing payload",
    );
}

#[test]
fn finalize_certificates_no_id_collision_when_payloads_agree() {
    // Two identical payloads under the same id → first-seen wins, no
    // collision flagged.
    let signing_event = [0x70u8; 32];
    let payload_a = certificate_details_for_test("cert-twin", vec![signing_event], 1);
    let payload_b = certificate_details_for_test("cert-twin", vec![signing_event], 1);
    let hash_a = [0u8; 32];
    let hash_b = [1u8; 32];
    let payloads = vec![(0usize, payload_a, hash_a), (1usize, payload_b, hash_b)];

    let mut event_failures = Vec::new();
    let _outcomes = crate::certificate::finalize_certificates_of_completion(
        &payloads,
        &[],
        &BTreeMap::new(),
        None,
        &NoopResponseProofResolver,
        &mut event_failures,
    );
    assert!(
        !event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::CertificateIdCollision)
    );
}

#[test]
fn finalize_certificates_flags_principal_ref_mismatch() {
    // Trellis Core MUST NOT inspect WOS or Formspec field names directly.
    // The principal-ref reading lives in `trellis-verify-wos` behind the
    // `ResponseProofResolver` boundary; this Core test feeds Core a stub
    // resolver that returns a fixed principal-ref so the chain-summary
    // mismatch path can be exercised without consumer-domain decoding.
    use crate::certificate_proof::{
        CertificateResponseProof, ResolverError, ResponseProofResolver,
    };

    struct FixedPrincipalRefResolver(&'static str);
    impl ResponseProofResolver for FixedPrincipalRefResolver {
        fn resolve(
            &self,
            _payload_bytes: &[u8],
        ) -> Result<Option<CertificateResponseProof>, ResolverError> {
            Ok(None)
        }
        fn resolve_principal_ref(&self, _payload_bytes: &[u8]) -> Option<String> {
            Some(self.0.to_string())
        }
    }

    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vectors/append/019-wos-signature-affirmation/expected-event.cbor");
    let signed = fs::read(&fixture).unwrap();
    let parsed = crate::parse::parse_sign1_bytes(&signed).unwrap();
    let details = crate::parse::decode_event_details(&parsed).unwrap();
    let signing_event_hash = details.canonical_event_hash;
    let authored_at = details.authored_at;

    let mut by_hash: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    by_hash.insert(signing_event_hash, 0);
    let pool = vec![details];

    let mut payload =
        certificate_details_for_test("cert-principal-mismatch", vec![signing_event_hash], 1);
    payload.chain_summary.signer_display[0].principal_ref =
        "urn:trellis:principal:not-the-signer".to_string();
    payload.chain_summary.signer_display[0].signed_at = authored_at;

    let mut event_failures = Vec::new();
    let outcomes = crate::certificate::finalize_certificates_of_completion(
        &[(0usize, payload, [0xCEu8; 32])],
        &pool,
        &by_hash,
        None,
        &FixedPrincipalRefResolver("urn:trellis:principal:actual-signer"),
        &mut event_failures,
    );

    assert_eq!(outcomes.len(), 1);
    assert!(!outcomes[0].chain_summary_consistent);
    assert!(
        event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::CertificateChainSummaryMismatch)
    );
}

#[test]
fn finalize_certificates_flags_attestation_when_signature_malformed() {
    // ADR 0007 §"Verifier obligations" step 3 (Phase-1 structural):
    // attestation row with malformed signature flips
    // `chain_summary_consistent = false` and emits
    // `attestation_insufficient`.
    let signing_event = [0x80u8; 32];
    let mut payload = certificate_details_for_test("cert-bad-att", vec![signing_event], 1);
    payload.attestation_signatures_well_formed = false;
    let canonical_hash = [0u8; 32];
    let payloads = vec![(0usize, payload, canonical_hash)];

    let mut event_failures = Vec::new();
    let outcomes = crate::certificate::finalize_certificates_of_completion(
        &payloads,
        &[],
        &BTreeMap::new(),
        None,
        &NoopResponseProofResolver,
        &mut event_failures,
    );
    assert_eq!(outcomes.len(), 1);
    assert!(!outcomes[0].chain_summary_consistent);
    assert!(
        outcomes[0]
            .failures
            .iter()
            .any(|f| f == "attestation_insufficient")
    );
    assert!(
        event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::AttestationInsufficient)
    );
}

#[test]
fn finalize_certificates_genesis_path_marks_attachment_resolved_true() {
    // Phase-1 minimal-genesis posture: the genesis-append code paths
    // (verify_single_event / verify_tampered_ledger) lack chain
    // visibility for attachment lineage. Step 4 defers to the
    // export-bundle path, so the genesis-path outcome must NOT
    // false-positive on `attachment_resolved`.
    let signing_event = [0x90u8; 32];
    let payload = certificate_details_for_test("cert-genesis", vec![signing_event], 1);
    let canonical_hash = [0u8; 32];
    let payloads = vec![(0usize, payload, canonical_hash)];

    let mut event_failures = Vec::new();
    let outcomes = crate::certificate::finalize_certificates_of_completion(
        &payloads,
        &[],
        &BTreeMap::new(),
        None,
        &NoopResponseProofResolver,
        &mut event_failures,
    );
    assert_eq!(outcomes.len(), 1);
    assert!(outcomes[0].attachment_resolved);
    assert!(
        !outcomes[0]
            .failures
            .iter()
            .any(|f| f == "presentation_artifact_attachment_missing"),
        "Phase-1 genesis path must not emit attachment-missing failures",
    );
}

// ---------------------------------------------------------------
// ADR 0010 user-content-attestation focused unit tests.
// Mirrors the certificate-of-completion test pattern: decode is
// covered by passing a CBOR map directly to
// `decode_user_content_attestation_payload`; finalize is covered
// by building `UserContentAttestationDetails` test fixtures and
// running `finalize_user_content_attestations` against synthetic
// chain context. Byte-level vector parity rides the
// `append/036..039` + `tamper/028..034` + `tamper/043` corpus.
// ---------------------------------------------------------------

fn user_content_details_for_test(
    attestation_id: &str,
    attestor: &str,
    signing_intent: &str,
    attested_at: u64,
    signing_kid: Vec<u8>,
    identity_attestation_ref: Option<[u8; 32]>,
) -> crate::UserContentAttestationDetails {
    let attested_at_ts = crate::TrellisTimestamp {
        seconds: attested_at,
        nanos: 0,
    };
    let attested_event_hash = [0xAAu8; 32];
    let attested_event_position = 0;
    let canonical_preimage = crate::parse::compute_user_content_attestation_preimage(
        attestation_id,
        &attested_event_hash,
        attested_event_position,
        attestor,
        identity_attestation_ref.as_ref(),
        signing_intent,
        attested_at_ts,
    );
    crate::UserContentAttestationDetails {
        attestation_id: attestation_id.to_string(),
        attested_event_hash,
        attested_event_position,
        attestor: attestor.to_string(),
        identity_attestation_ref,
        signing_intent: signing_intent.to_string(),
        attested_at: attested_at_ts,
        signature: [0u8; 64],
        signing_kid,
        canonical_preimage,
        step_2_failure: None,
    }
}

#[test]
fn is_syntactically_valid_uri_admits_urn() {
    // Trellis owns the bytes; WOS owns the meaning. URN-style intent
    // URIs (no authority) must pass the syntactic check.
    assert!(crate::util::is_syntactically_valid_uri(
        "urn:trellis:intent:notarial-attestation"
    ));
    assert!(crate::util::is_syntactically_valid_uri(
        "urn:wos:signature-intent:applicant-affirmation"
    ));
    assert!(crate::util::is_syntactically_valid_uri(
        "https://example.invalid/intent/witness"
    ));
}

#[test]
fn is_syntactically_valid_uri_rejects_malformed() {
    // ADR 0010 §"Verifier obligations" step 2 — malformed URI flips
    // `user_content_attestation_intent_malformed`.
    assert!(!crate::util::is_syntactically_valid_uri(""));
    assert!(!crate::util::is_syntactically_valid_uri("no-colon"));
    assert!(!crate::util::is_syntactically_valid_uri(":empty-scheme"));
    assert!(!crate::util::is_syntactically_valid_uri("scheme-only:"));
    assert!(!crate::util::is_syntactically_valid_uri(
        "9digit-start:rest"
    ));
    assert!(!crate::util::is_syntactically_valid_uri("bad space:rest"));
}

#[test]
fn is_operator_uri_detects_companion_6_4_prefixes() {
    // ADR 0010 §"Verifier obligations" step 8 — operator URIs forbidden
    // in `attestor` slot. Phase-1 conservative prefixes are
    // `urn:trellis:operator:` and `urn:wos:operator:`.
    assert!(crate::util::is_operator_uri(
        "urn:trellis:operator:test-deployment"
    ));
    assert!(crate::util::is_operator_uri(
        "urn:wos:operator:agency-of-record"
    ));
    // User principal URIs MUST pass.
    assert!(!crate::util::is_operator_uri(
        "urn:trellis:principal:applicant-001"
    ));
    assert!(!crate::util::is_operator_uri("urn:wos:user:notary-002"));
    assert!(!crate::util::is_operator_uri(""));
}

#[test]
fn parse_admit_unverified_user_attestations_defaults_false() {
    // Empty bytes / non-map / absent field all default to `false`
    // (REQUIRED non-null posture). Critical fail-closed property:
    // a malformed Posture Declaration cannot silently relax the gate.
    assert!(!crate::user_attestation::parse_admit_unverified_user_attestations(&[]));
    assert!(!crate::user_attestation::parse_admit_unverified_user_attestations(&[0x40])); // bstr, not a map
    // Map without the field → false.
    let mut buf = Vec::new();
    ciborium::ser::into_writer(
        &Value::Map(vec![(
            Value::Text("provider_readable".into()),
            Value::Bool(true),
        )]),
        &mut buf,
    )
    .unwrap();
    assert!(!crate::user_attestation::parse_admit_unverified_user_attestations(&buf));
}

#[test]
fn parse_admit_unverified_user_attestations_admits_explicit_true() {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(
        &Value::Map(vec![(
            Value::Text("admit_unverified_user_attestations".into()),
            Value::Bool(true),
        )]),
        &mut buf,
    )
    .unwrap();
    assert!(crate::user_attestation::parse_admit_unverified_user_attestations(&buf));
}

#[test]
fn finalize_uca_flags_operator_in_user_slot() {
    // ADR 0010 §"Verifier obligations" step 8.
    let payload = user_content_details_for_test(
        "uca-test-1",
        "urn:trellis:operator:bad-actor",
        "urn:trellis:intent:applicant",
        1_776_900_000,
        vec![0xC0u8; 16],
        Some([0xBBu8; 32]),
    );
    let canonical_hash = [0xDD; 32];
    let payloads = vec![(0usize, payload, canonical_hash)];
    let registry = BTreeMap::new();
    let mut event_failures = Vec::new();
    let outcomes = crate::user_attestation::finalize_user_content_attestations(
        &payloads,
        &[],
        &BTreeMap::new(),
        &BTreeMap::new(),
        &registry,
        None,
        &(),
        &mut event_failures,
    );
    assert_eq!(outcomes.len(), 1);
    assert!(
        outcomes[0]
            .failures
            .iter()
            .any(|f| f == "user_content_attestation_operator_in_user_slot")
    );
    assert!(
        event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::UserContentAttestationOperatorInUserSlot)
    );
}

#[test]
fn finalize_uca_flags_identity_required_when_posture_default() {
    // ADR 0010 §"Verifier obligations" step 4 null-admission gate.
    // Default posture (no Posture Declaration / `admit_unverified_*`
    // absent) MUST flip `user_content_attestation_identity_required`
    // when `identity_attestation_ref` is null.
    let payload = user_content_details_for_test(
        "uca-required-1",
        "urn:trellis:principal:applicant",
        "urn:trellis:intent:applicant",
        1_776_900_000,
        vec![0xC0u8; 16],
        None, // ← null identity ref triggers step 4 null path
    );
    let canonical_hash = [0xDD; 32];
    let payloads = vec![(0usize, payload, canonical_hash)];
    let registry = BTreeMap::new();
    let mut event_failures = Vec::new();
    let outcomes = crate::user_attestation::finalize_user_content_attestations(
        &payloads,
        &[],
        &BTreeMap::new(),
        &BTreeMap::new(),
        &registry,
        None, // no Posture Declaration → default required
        &(),
        &mut event_failures,
    );
    assert_eq!(outcomes.len(), 1);
    assert!(!outcomes[0].identity_resolved);
    assert!(
        outcomes[0]
            .failures
            .iter()
            .any(|f| f == "user_content_attestation_identity_required")
    );
}

#[test]
fn finalize_uca_admits_null_identity_when_posture_permits() {
    // ADR 0010 §"Verifier obligations" step 4 null-admission gate.
    // Posture Declaration with `admit_unverified_user_attestations: true`
    // permits null `identity_attestation_ref` without flipping integrity.
    let payload = user_content_details_for_test(
        "uca-permitted-1",
        "urn:trellis:principal:applicant",
        "urn:trellis:intent:applicant",
        1_776_900_000,
        vec![0xC0u8; 16],
        None,
    );
    let canonical_hash = [0xDD; 32];
    let payloads = vec![(0usize, payload, canonical_hash)];
    let registry = BTreeMap::new();
    let mut event_failures = Vec::new();

    // Build a minimal Posture Declaration with the admit flag true.
    let mut posture_bytes = Vec::new();
    ciborium::ser::into_writer(
        &Value::Map(vec![(
            Value::Text("admit_unverified_user_attestations".into()),
            Value::Bool(true),
        )]),
        &mut posture_bytes,
    )
    .unwrap();

    let outcomes = crate::user_attestation::finalize_user_content_attestations(
        &payloads,
        &[],
        &BTreeMap::new(),
        &BTreeMap::new(),
        &registry,
        Some(&posture_bytes),
        &(),
        &mut event_failures,
    );
    assert_eq!(outcomes.len(), 1);
    // No identity-required failure under permissive posture.
    assert!(
        !outcomes[0]
            .failures
            .iter()
            .any(|f| f == "user_content_attestation_identity_required")
    );
}

#[test]
fn finalize_uca_accepts_rotating_key_inside_overlap() {
    // Core §8.4 rotation grace: `Rotating` admits new user-content
    // attestations only while `attested_at` is inside the registry-declared
    // overlap interval.
    let attested_at = 1_776_900_000;
    let kid = vec![0xC0u8; 16];
    let payload = user_content_details_for_test(
        "uca-rotating-inside",
        "urn:trellis:principal:applicant",
        "urn:trellis:intent:applicant",
        attested_at,
        kid.clone(),
        Some([0xBBu8; 32]),
    );
    let canonical_hash = [0xDD; 32];
    let payloads = vec![(0usize, payload, canonical_hash)];
    let mut registry = BTreeMap::new();
    registry.insert(
        kid,
        crate::SigningKeyEntry {
            public_key: [0u8; 32],
            status: 1,
            valid_from: Some(TrellisTimestamp {
                seconds: attested_at - 60,
                nanos: 0,
            }),
            valid_to: Some(TrellisTimestamp {
                seconds: attested_at + 60,
                nanos: 0,
            }),
        },
    );
    let mut event_failures = Vec::new();
    let outcomes = crate::user_attestation::finalize_user_content_attestations(
        &payloads,
        &[],
        &BTreeMap::new(),
        &BTreeMap::new(),
        &registry,
        None,
        &(),
        &mut event_failures,
    );
    assert_eq!(outcomes.len(), 1);
    assert!(outcomes[0].key_active);
    assert!(
        !outcomes[0]
            .failures
            .iter()
            .any(|f| f == "user_content_attestation_key_not_active")
    );
}

#[test]
fn finalize_uca_rejects_rotating_key_after_overlap() {
    // A `Rotating` row is not an indefinite new-signature authority. After
    // `valid_to`, UCA step 6 fails with `key_not_active`.
    let attested_at = 1_776_900_000;
    let kid = vec![0xC0u8; 16];
    let payload = user_content_details_for_test(
        "uca-rotating-after",
        "urn:trellis:principal:applicant",
        "urn:trellis:intent:applicant",
        attested_at,
        kid.clone(),
        Some([0xBBu8; 32]),
    );
    let canonical_hash = [0xDD; 32];
    let payloads = vec![(0usize, payload, canonical_hash)];
    let mut registry = BTreeMap::new();
    registry.insert(
        kid,
        crate::SigningKeyEntry {
            public_key: [0u8; 32],
            status: 1,
            valid_from: Some(TrellisTimestamp {
                seconds: attested_at - 120,
                nanos: 0,
            }),
            valid_to: Some(TrellisTimestamp {
                seconds: attested_at - 1,
                nanos: 0,
            }),
        },
    );
    let mut event_failures = Vec::new();
    let outcomes = crate::user_attestation::finalize_user_content_attestations(
        &payloads,
        &[],
        &BTreeMap::new(),
        &BTreeMap::new(),
        &registry,
        None,
        &(),
        &mut event_failures,
    );
    assert_eq!(outcomes.len(), 1);
    assert!(!outcomes[0].key_active);
    assert!(
        outcomes[0]
            .failures
            .iter()
            .any(|f| f == "user_content_attestation_key_not_active")
    );
}

#[test]
fn finalize_uca_flags_key_not_active_for_unregistered_kid() {
    // ADR 0010 §"Verifier obligations" step 6 — kid not in registry =
    // not Active. The Phase-1 verifier flips
    // `user_content_attestation_key_not_active`.
    let payload = user_content_details_for_test(
        "uca-no-key",
        "urn:trellis:principal:applicant",
        "urn:trellis:intent:applicant",
        1_776_900_000,
        vec![0xC0u8; 16],
        Some([0xBBu8; 32]),
    );
    let canonical_hash = [0xDD; 32];
    let payloads = vec![(0usize, payload, canonical_hash)];
    let registry = BTreeMap::new(); // ← empty registry
    let mut event_failures = Vec::new();
    let outcomes = crate::user_attestation::finalize_user_content_attestations(
        &payloads,
        &[],
        &BTreeMap::new(),
        &BTreeMap::new(),
        &registry,
        None,
        &(),
        &mut event_failures,
    );
    assert_eq!(outcomes.len(), 1);
    assert!(!outcomes[0].key_active);
    assert!(
        outcomes[0]
            .failures
            .iter()
            .any(|f| f == "user_content_attestation_key_not_active")
    );
}

#[test]
fn finalize_uca_id_collision_detected_on_disagreeing_payloads() {
    // ADR 0010 §"Verifier obligations" step 7 — two events sharing
    // `attestation_id` with disagreeing canonical payload fail closed.
    let mut a = user_content_details_for_test(
        "uca-dup-1",
        "urn:trellis:principal:applicant",
        "urn:trellis:intent:applicant",
        1_776_900_000,
        vec![0xC0u8; 16],
        Some([0xBBu8; 32]),
    );
    let mut b = a.clone();
    // Mutate an inner field so the canonical payloads disagree.
    b.attested_at = crate::TrellisTimestamp {
        seconds: 1_776_900_999,
        nanos: 0,
    };
    // Canonical preimages must reflect the divergence.
    a.canonical_preimage = crate::parse::compute_user_content_attestation_preimage(
        &a.attestation_id,
        &a.attested_event_hash,
        a.attested_event_position,
        &a.attestor,
        a.identity_attestation_ref.as_ref(),
        &a.signing_intent,
        a.attested_at,
    );
    b.canonical_preimage = crate::parse::compute_user_content_attestation_preimage(
        &b.attestation_id,
        &b.attested_event_hash,
        b.attested_event_position,
        &b.attestor,
        b.identity_attestation_ref.as_ref(),
        &b.signing_intent,
        b.attested_at,
    );

    let payloads = vec![(0usize, a, [0xCC; 32]), (1usize, b, [0xCD; 32])];
    let registry = BTreeMap::new();
    let mut event_failures = Vec::new();
    crate::user_attestation::finalize_user_content_attestations(
        &payloads,
        &[],
        &BTreeMap::new(),
        &BTreeMap::new(),
        &registry,
        None,
        &(),
        &mut event_failures,
    );
    assert!(
        event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::UserContentAttestationIdCollision),
        "step 7 must flag id_collision for disagreeing payloads",
    );
}

#[test]
fn finalize_uca_no_collision_when_byte_identical() {
    // ADR 0010 §"Field semantics" `attestation_id` clause: idempotent
    // re-emission with byte-identical canonical payload MUST NOT flip.
    let a = user_content_details_for_test(
        "uca-same",
        "urn:trellis:principal:applicant",
        "urn:trellis:intent:applicant",
        1_776_900_000,
        vec![0xC0u8; 16],
        Some([0xBBu8; 32]),
    );
    let b = a.clone();
    let payloads = vec![(0usize, a, [0xCC; 32]), (1usize, b, [0xCD; 32])];
    let registry = BTreeMap::new();
    let mut event_failures = Vec::new();
    crate::user_attestation::finalize_user_content_attestations(
        &payloads,
        &[],
        &BTreeMap::new(),
        &BTreeMap::new(),
        &registry,
        None,
        &(),
        &mut event_failures,
    );
    assert!(
        !event_failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::UserContentAttestationIdCollision),
        "byte-identical re-emission must not flip id_collision",
    );
}

#[test]
fn decode_uca_payload_defers_timestamp_skew_to_finalize() {
    // ADR 0010 §"Verifier obligations" step 2 — `attested_at` MUST
    // exactly equal envelope `authored_at`. Step 2 failures are
    // intra-payload-invariant (post-CDDL-decode) and flip
    // `integrity_verified = false` only — they MUST NOT flip
    // `readability_verified`. The decoder records the failure on
    // `step_2_failure` for the finalize pass to raise.
    let kid_bytes: Vec<u8> = vec![0xC0u8; 16];
    let extension_value = Value::Map(vec![
        (
            Value::Text("attestation_id".into()),
            Value::Text("uca-skew-1".into()),
        ),
        (
            Value::Text("attested_event_hash".into()),
            Value::Bytes(vec![0xAA; 32]),
        ),
        (
            Value::Text("attested_event_position".into()),
            Value::Integer(0u64.into()),
        ),
        (
            Value::Text("attestor".into()),
            Value::Text("urn:trellis:principal:applicant".into()),
        ),
        (
            Value::Text("identity_attestation_ref".into()),
            Value::Bytes(vec![0xBB; 32]),
        ),
        (
            Value::Text("signing_intent".into()),
            Value::Text("urn:trellis:intent:applicant".into()),
        ),
        (
            Value::Text("attested_at".into()),
            Value::Array(vec![
                Value::Integer(1_776_900_000u64.into()),
                Value::Integer(0u32.into()),
            ]),
        ),
        (Value::Text("signature".into()), Value::Bytes(vec![0u8; 64])),
        (Value::Text("signing_kid".into()), Value::Bytes(kid_bytes)),
    ]);
    let extensions = vec![(
        Value::Text(crate::USER_CONTENT_ATTESTATION_EVENT_EXTENSION.into()),
        extension_value,
    )];
    // Host envelope authored_at differs from payload attested_at.
    let decoded = crate::parse::decode_user_content_attestation_payload(
        &extensions,
        crate::TrellisTimestamp {
            seconds: 1_776_900_999,
            nanos: 0,
        },
    )
    .expect("step 2 failures decode cleanly; finalize raises them");
    let details = decoded.expect("payload present");
    assert_eq!(
        details.step_2_failure,
        Some(VerificationFailureKind::UserContentAttestationTimestampMismatch)
    );
}

#[test]
fn decode_uca_payload_defers_malformed_intent_uri_to_finalize() {
    // ADR 0010 §"Verifier obligations" step 2. Intra-payload-invariant
    // failure: deferred to finalize via `step_2_failure` marker;
    // `readability_verified` stays `true` per ADR 0010 step 2 prose.
    let kid_bytes: Vec<u8> = vec![0xC0u8; 16];
    let extension_value = Value::Map(vec![
        (
            Value::Text("attestation_id".into()),
            Value::Text("uca-bad-intent".into()),
        ),
        (
            Value::Text("attested_event_hash".into()),
            Value::Bytes(vec![0xAA; 32]),
        ),
        (
            Value::Text("attested_event_position".into()),
            Value::Integer(0u64.into()),
        ),
        (
            Value::Text("attestor".into()),
            Value::Text("urn:trellis:principal:applicant".into()),
        ),
        (
            Value::Text("identity_attestation_ref".into()),
            Value::Bytes(vec![0xBB; 32]),
        ),
        (
            Value::Text("signing_intent".into()),
            Value::Text("not-a-uri".into()),
        ),
        (
            Value::Text("attested_at".into()),
            Value::Array(vec![
                Value::Integer(1_776_900_000u64.into()),
                Value::Integer(0u32.into()),
            ]),
        ),
        (Value::Text("signature".into()), Value::Bytes(vec![0u8; 64])),
        (Value::Text("signing_kid".into()), Value::Bytes(kid_bytes)),
    ]);
    let extensions = vec![(
        Value::Text(crate::USER_CONTENT_ATTESTATION_EVENT_EXTENSION.into()),
        extension_value,
    )];
    let decoded = crate::parse::decode_user_content_attestation_payload(
        &extensions,
        crate::TrellisTimestamp {
            seconds: 1_776_900_000,
            nanos: 0,
        },
    )
    .expect("step 2 failures decode cleanly; finalize raises them");
    let details = decoded.expect("payload present");
    assert_eq!(
        details.step_2_failure,
        Some(VerificationFailureKind::UserContentAttestationIntentMalformed)
    );
}

#[test]
fn decode_uca_payload_returns_none_when_extension_absent() {
    let extensions: Vec<(Value, Value)> = vec![];
    let decoded = crate::parse::decode_user_content_attestation_payload(
        &extensions,
        crate::TrellisTimestamp {
            seconds: 0,
            nanos: 0,
        },
    )
    .expect("absent extension is not an error");
    assert!(decoded.is_none());
}

#[test]
fn decode_uca_payload_succeeds_with_well_formed_input() {
    let kid_bytes: Vec<u8> = vec![0xC0u8; 16];
    let extension_value = Value::Map(vec![
        (
            Value::Text("attestation_id".into()),
            Value::Text("uca-ok-1".into()),
        ),
        (
            Value::Text("attested_event_hash".into()),
            Value::Bytes(vec![0xAA; 32]),
        ),
        (
            Value::Text("attested_event_position".into()),
            Value::Integer(0u64.into()),
        ),
        (
            Value::Text("attestor".into()),
            Value::Text("urn:trellis:principal:applicant".into()),
        ),
        (
            Value::Text("identity_attestation_ref".into()),
            Value::Bytes(vec![0xBB; 32]),
        ),
        (
            Value::Text("signing_intent".into()),
            Value::Text("urn:trellis:intent:applicant".into()),
        ),
        (
            Value::Text("attested_at".into()),
            Value::Array(vec![
                Value::Integer(1_776_900_000u64.into()),
                Value::Integer(0u32.into()),
            ]),
        ),
        (Value::Text("signature".into()), Value::Bytes(vec![0u8; 64])),
        (
            Value::Text("signing_kid".into()),
            Value::Bytes(kid_bytes.clone()),
        ),
    ]);
    let extensions = vec![(
        Value::Text(crate::USER_CONTENT_ATTESTATION_EVENT_EXTENSION.into()),
        extension_value,
    )];
    let decoded = crate::parse::decode_user_content_attestation_payload(
        &extensions,
        crate::TrellisTimestamp {
            seconds: 1_776_900_000,
            nanos: 0,
        },
    )
    .expect("well-formed payload decodes")
    .expect("extension is present");
    assert_eq!(decoded.attestation_id, "uca-ok-1");
    assert_eq!(decoded.attestor, "urn:trellis:principal:applicant");
    assert_eq!(decoded.attested_event_position, 0);
    assert_eq!(decoded.signing_kid, kid_bytes);
    assert_eq!(decoded.signature.len(), 64);
    assert!(!decoded.canonical_preimage.is_empty());
}

#[test]
fn verify_tampered_ledger_detects_timestamp_order_violation() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vectors/tamper/041-timestamp-backwards");
    let report = verify_tampered_ledger(
        &fs::read(root.join("input-signing-key-registry.cbor")).unwrap(),
        &fs::read(root.join("input-tampered-ledger.cbor")).unwrap(),
        None,
        None,
    )
    .unwrap();
    assert!(report.structure_verified);
    assert!(!report.integrity_verified);
    assert!(report.readability_verified);
    assert_eq!(
        report.event_failures[0].kind,
        VerificationFailureKind::TimestampOrderViolation
    );
}

#[test]
fn verify_correction_authorized_surfaces_preservation_report() {
    let correction_root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/vectors/append/011-correction");
    let registry_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vectors/tamper/050-rescission-terminality");

    let event =
        parse_sign1_bytes(&fs::read(correction_root.join("expected-event.cbor")).unwrap()).unwrap();
    let registry_bytes = fs::read(registry_root.join("input-signing-key-registry.cbor")).unwrap();
    let registry = parse_signing_key_registry(&registry_bytes).unwrap();

    let report = verify_event_set(&[event], &registry, None, None, false, None, None);

    assert!(report.structure_verified);
    assert!(report.integrity_verified);
    assert_eq!(report.correction_preservations.len(), 1);
    let correction = &report.correction_preservations[0];
    assert_eq!(correction.event_index, 0);
    assert_eq!(
        correction.target_event_hash.as_deref(),
        Some("9366d6fddc451087771a2514419a9b7a876e8301f849cffc5f45f143d0b29088")
    );
    assert_eq!(
        correction.corrected_field_set,
        vec!["/applicantName", "/mailingAddress/zip"]
    );
}

#[test]
fn verify_equal_timestamps_pass_temporal_check() {
    let genesis_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vectors/append/001-minimal-inline-payload");
    let chain_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vectors/append/005-prior-head-chain");
    let registry_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vectors/tamper/041-timestamp-backwards");

    let genesis_event =
        parse_sign1_bytes(&fs::read(genesis_root.join("expected-event.cbor")).unwrap()).unwrap();
    let chain_event =
        parse_sign1_bytes(&fs::read(chain_root.join("expected-event.cbor")).unwrap()).unwrap();

    let registry_bytes = fs::read(registry_root.join("input-signing-key-registry.cbor")).unwrap();
    let registry = parse_signing_key_registry(&registry_bytes).unwrap();

    let report = verify_event_set(
        &[genesis_event, chain_event],
        &registry,
        None,
        None,
        false,
        None,
        None,
    );

    assert!(report.structure_verified);
    assert!(
        report.integrity_verified,
        "append/001 + append/005 chain should pass all checks including temporal order \
         (authored_at 1745000000 < 1745000001 is non-decreasing)"
    );
    assert!(report.event_failures.is_empty());
}

#[test]
fn verify_rejects_legacy_uint_timestamp_format() {
    let header: Vec<(Value, Value)> = vec![
        (
            Value::Text("event_type".into()),
            Value::Bytes(b"x-trellis-test/append-minimal".to_vec()),
        ),
        (
            Value::Text("authored_at".into()),
            Value::Integer(1745000000.into()),
        ),
        (
            Value::Text("retention_tier".into()),
            Value::Integer(0.into()),
        ),
        (
            Value::Text("classification".into()),
            Value::Bytes(b"x-trellis-test/unclassified".to_vec()),
        ),
    ];
    let result = crate::parse::map_lookup_timestamp(&header, "authored_at");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), Some(VerifyErrorKind::LegacyTimestampFormat));
}

#[test]
fn verify_rejects_timestamp_nanos_out_of_range() {
    let result = crate::parse::decode_timestamp_array(&[
        Value::Integer(1745000000.into()),
        Value::Integer(1_000_000_000.into()),
    ]);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), Some(VerifyErrorKind::TimestampNanosOutOfRange));
}
