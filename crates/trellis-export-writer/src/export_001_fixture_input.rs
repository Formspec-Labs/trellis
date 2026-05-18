// Rust guideline compliant 2026-05-15
//! Pinned [`ExportWriterInput`](crate::ExportWriterInput) for the committed
//! vector `fixtures/vectors/export/001-two-event-chain`.

use std::path::Path;

use integrity_cbor::{Value, decode_cbor_value};
use trellis_types::StoredEvent;

use crate::{
    ExportWriterInput, PostureDeclaration, RegistrySnapshot, SigningKeyMaterial, TrellisTimestamp,
};

fn read_fixture(root: impl AsRef<Path>, relative: &str) -> Vec<u8> {
    let root = root.as_ref();
    std::fs::read(root.join(relative)).unwrap_or_else(|err| {
        panic!(
            "failed read fixture `{}` under {}: {err}",
            relative,
            root.display()
        );
    })
}

fn parse_fixture_ed25519_cose_key(bytes: &[u8]) -> ([u8; 32], [u8; 32]) {
    let value = decode_cbor_value(bytes).expect("fixture COSE key must decode");
    let map = value.as_map().expect("fixture COSE key must be a map");
    (
        integer_label_fixed_32(map, -4),
        integer_label_fixed_32(map, -2),
    )
}

fn integer_label_fixed_32(map: &[(Value, Value)], label: i128) -> [u8; 32] {
    let vec = map
        .iter()
        .find(|(key, _)| {
            key.as_integer()
                .is_some_and(|integer| i128::from(integer) == label)
        })
        .and_then(|(_, value)| value.as_bytes().cloned())
        .unwrap_or_else(|| panic!("missing integer label {label} in fixture COSE key"));
    vec.try_into().unwrap_or_else(|vec: Vec<u8>| {
        panic!("fixture label {label} must be 32 bytes, got {}", vec.len())
    })
}

/// Builds deterministic export writer input matching `export/001-two-event-chain`.
///
/// `vectors_root` is the `fixtures/vectors` directory.
#[must_use]
pub fn export_001_writer_input(vectors_root: &Path) -> ExportWriterInput {
    let event_001_bytes = read_fixture(
        vectors_root,
        "append/001-minimal-inline-payload/expected-event.cbor",
    );
    let event_005_bytes = read_fixture(
        vectors_root,
        "append/005-prior-head-chain/expected-event.cbor",
    );
    let payload_001 = read_fixture(
        vectors_root,
        "append/001-minimal-inline-payload/expected-event-payload.cbor",
    );
    let payload_005 = read_fixture(
        vectors_root,
        "append/005-prior-head-chain/expected-event-payload.cbor",
    );
    let registry = read_fixture(
        vectors_root,
        "append/009-signing-key-revocation/input-domain-registry.cbor",
    );
    let (private_seed, public_key) =
        parse_fixture_ed25519_cose_key(&read_fixture(vectors_root, "_keys/issuer-001.cose_key"));

    ExportWriterInput {
        scope: b"test-response-ledger".to_vec(),
        events: vec![
            StoredEvent::new(
                b"test-response-ledger".to_vec(),
                0,
                payload_001,
                event_001_bytes,
            ),
            StoredEvent::new(
                b"test-response-ledger".to_vec(),
                1,
                payload_005,
                event_005_bytes,
            ),
        ],
        registries: vec![RegistrySnapshot {
            bytes: registry,
            registry_format: 1,
            registry_version: "x-trellis-test/registry-009-v1".to_string(),
            bound_at_sequence: 0,
        }],
        signing_key: SigningKeyMaterial {
            private_seed,
            public_key,
            valid_from: TrellisTimestamp::new(1_745_000_000, 0).expect("valid timestamp"),
            valid_to: None,
        },
        generator: "x-trellis-test/export-generator-001".to_string(),
        generated_at: TrellisTimestamp::new(1_745_000_060, 0).expect("valid timestamp"),
        checkpoint_timestamps: vec![
            TrellisTimestamp::new(1_745_000_050, 0).expect("valid timestamp"),
            TrellisTimestamp::new(1_745_000_060, 0).expect("valid timestamp"),
        ],
        posture_declaration: PostureDeclaration {
            provider_readable: true,
            reader_held: false,
            delegated_compute: false,
            external_anchor_required: false,
            external_anchor_name: None,
            recovery_without_user: true,
            metadata_leakage_summary: "Fixture export: envelope reveals event_type, authored_at (1s granularity), retention_tier, classification, ledger_scope, and COSE kid.".to_string(),
        },
        omitted_payload_checks: Vec::new(),
        readme_title: "Trellis Export (Fixture) \u{2014} export/001-two-event-chain".to_string(),
        root_dir_override: None,
        external_anchors: Vec::new(),
        extensions: None,
        seal_fence: None,
        witness_key_registry: None,
        signed_acts_catalog: None,
        signed_acts_manifest: None,
        policy_closure: None,
    }
}
