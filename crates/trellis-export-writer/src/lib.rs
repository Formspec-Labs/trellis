// Rust guideline compliant 2026-05-15
//! Trellis Phase-1 export writer.
//!
//! This crate owns the Core section 18 export-emission orchestration: deterministic bundle
//! assembly, manifest digest binding, Merkle proof material, checkpoint chain
//! construction, signing-key registry emission, and posture declaration
//! materialization. Storage adapters hand it a durable ledger snapshot; the
//! writer does not depend on WOS event types.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use integrity_bundle::{Bundle, BundleEntry};
use integrity_cbor::{
    Value, decode_cbor_value, domain_separated_sha256, encode_bstr, encode_tstr, encode_uint,
    map_lookup_bytes, map_lookup_u64, sha256_bytes,
};
use integrity_cose::{
    derive_kid, protected_header_bytes, sig_structure_bytes, sign_ed25519, sign1_bytes,
};
pub use integrity_hpke::{HPKE_SUITE1_AAD, HPKE_SUITE1_INFO};
use stack_common_error::StackError;
use trellis_types::StoredEvent;

const EVENT_DOMAIN: &str = "trellis-event-v1";
const CHECKPOINT_DOMAIN: &str = "trellis-checkpoint-v1";
const MERKLE_LEAF_DOMAIN: &str = "trellis-merkle-leaf-v1";
const MERKLE_INTERIOR_DOMAIN: &str = "trellis-merkle-interior-v1";
const EXPORT_MANIFEST_DOMAIN: &str = "trellis-export-manifest-v1";
const SUITE_ID_PHASE_1: u64 = 1;

pub const MANIFEST_MEMBER: &str = "000-manifest.cbor";
pub const EVENTS_MEMBER: &str = "010-events.cbor";
pub const INCLUSION_PROOFS_MEMBER: &str = "020-inclusion-proofs.cbor";
pub const CONSISTENCY_PROOFS_MEMBER: &str = "025-consistency-proofs.cbor";
pub const SIGNING_KEY_REGISTRY_MEMBER: &str = "030-signing-key-registry.cbor";
pub const CHECKPOINTS_MEMBER: &str = "040-checkpoints.cbor";
pub const REGISTRY_DIR: &str = "050-registries";
pub const VERIFY_MEMBER: &str = "090-verify.sh";
pub const README_MEMBER: &str = "098-README.md";

/// Core timestamp wire shape: `[seconds UTC, nanos]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrellisTimestamp {
    pub unix_secs: u64,
    pub subsec_nanos: u32,
}

impl TrellisTimestamp {
    pub const MAX_SUBSEC_NANOS: u32 = 999_999_999;

    /// Builds a Core timestamp.
    ///
    /// # Errors
    /// Returns an error if `subsec_nanos` exceeds the Core timestamp bound.
    pub fn new(unix_secs: u64, subsec_nanos: u32) -> Result<Self, StackError> {
        if subsec_nanos > Self::MAX_SUBSEC_NANOS {
            return Err(StackError::bad_request(format!(
                "timestamp nanoseconds {subsec_nanos} exceed {}",
                Self::MAX_SUBSEC_NANOS
            )));
        }
        Ok(Self {
            unix_secs,
            subsec_nanos,
        })
    }

    fn to_value(self) -> Value {
        Value::Array(vec![
            uint(self.unix_secs),
            uint(u64::from(self.subsec_nanos)),
        ])
    }
}

/// Ed25519 signing material used for the manifest, checkpoints, and embedded
/// signing-key registry snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningKeyMaterial {
    pub private_seed: [u8; 32],
    pub public_key: [u8; 32],
    pub valid_from: TrellisTimestamp,
    pub valid_to: Option<TrellisTimestamp>,
}

impl SigningKeyMaterial {
    #[must_use]
    pub fn kid(&self) -> [u8; 16] {
        derive_kid(SUITE_ID_PHASE_1, self.public_key)
    }
}

/// Immutable domain-registry bytes to embed under `050-registries/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrySnapshot {
    pub bytes: Vec<u8>,
    pub registry_format: u64,
    pub registry_version: String,
    pub bound_at_sequence: u64,
}

/// Export posture declaration carried in the manifest and rendered into the
/// README inspection view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostureDeclaration {
    pub provider_readable: bool,
    pub reader_held: bool,
    pub delegated_compute: bool,
    pub external_anchor_required: bool,
    pub external_anchor_name: Option<String>,
    pub recovery_without_user: bool,
    pub metadata_leakage_summary: String,
}

impl PostureDeclaration {
    fn to_value(&self) -> Result<Value, StackError> {
        text_map(vec![
            ("provider_readable", Value::Bool(self.provider_readable)),
            ("reader_held", Value::Bool(self.reader_held)),
            ("delegated_compute", Value::Bool(self.delegated_compute)),
            (
                "external_anchor_required",
                Value::Bool(self.external_anchor_required),
            ),
            (
                "external_anchor_name",
                option_text(self.external_anchor_name.as_deref()),
            ),
            (
                "recovery_without_user",
                Value::Bool(self.recovery_without_user),
            ),
            (
                "metadata_leakage_summary",
                Value::Text(self.metadata_leakage_summary.clone()),
            ),
        ])
    }

    fn to_sorted_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "delegated_compute".to_string(),
            serde_json::Value::Bool(self.delegated_compute),
        );
        map.insert(
            "external_anchor_name".to_string(),
            self.external_anchor_name
                .as_ref()
                .map_or(serde_json::Value::Null, |value| {
                    serde_json::Value::String(value.clone())
                }),
        );
        map.insert(
            "external_anchor_required".to_string(),
            serde_json::Value::Bool(self.external_anchor_required),
        );
        map.insert(
            "metadata_leakage_summary".to_string(),
            serde_json::Value::String(self.metadata_leakage_summary.clone()),
        );
        map.insert(
            "provider_readable".to_string(),
            serde_json::Value::Bool(self.provider_readable),
        );
        map.insert(
            "reader_held".to_string(),
            serde_json::Value::Bool(self.reader_held),
        );
        map.insert(
            "recovery_without_user".to_string(),
            serde_json::Value::Bool(self.recovery_without_user),
        );
        serde_json::Value::Object(map)
    }
}

/// Input snapshot for one export emission.
#[derive(Clone, Debug, PartialEq)]
pub struct ExportWriterInput {
    pub scope: Vec<u8>,
    pub events: Vec<StoredEvent>,
    pub registries: Vec<RegistrySnapshot>,
    pub signing_key: SigningKeyMaterial,
    pub generator: String,
    pub generated_at: TrellisTimestamp,
    pub checkpoint_timestamps: Vec<TrellisTimestamp>,
    pub posture_declaration: PostureDeclaration,
    pub omitted_payload_checks: Vec<Value>,
    pub readme_title: String,
    pub root_dir_override: Option<String>,
    pub external_anchors: Vec<Value>,
    pub extensions: Option<Value>,
}

/// Complete export writer output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportPackage {
    pub root_dir: String,
    pub entries: Vec<BundleEntry>,
    pub zip_bytes: Vec<u8>,
    pub manifest_payload: Vec<u8>,
    pub manifest_digest: [u8; 32],
    pub head_checkpoint_digest: [u8; 32],
    pub tree_head_hash: [u8; 32],
}

impl ExportPackage {
    #[must_use]
    pub fn member_bytes(&self, member: &str) -> Option<&[u8]> {
        let path = format!("{}/{member}", self.root_dir);
        self.entries
            .iter()
            .find(|entry| entry.path() == path)
            .map(BundleEntry::bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedEvent {
    sequence: u64,
    canonical_event: Vec<u8>,
    signed_event: Vec<u8>,
    canonical_event_hash: [u8; 32],
    leaf_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq)]
struct RegistryBindingMaterial {
    member: String,
    bytes: Vec<u8>,
    value: Value,
}

/// Writes a Trellis Phase-1 export package.
///
/// # Errors
/// Returns an error when the ledger snapshot is empty or inconsistent, CBOR
/// encoding fails, signatures cannot be assembled, or bundle serialization
/// rejects a member path.
pub fn write_export(input: ExportWriterInput) -> Result<ExportPackage, StackError> {
    validate_top_level_input(&input)?;
    let events = prepare_events(&input)?;
    let tree_head_hash = merkle_root(
        &events
            .iter()
            .map(|event| event.leaf_hash)
            .collect::<Vec<_>>(),
    )?;

    let events_cbor =
        array_of_raw_cbor_values(events.iter().map(|event| event.signed_event.as_slice()))?;
    let registry_material = registry_binding_material(&input.registries)?;
    let signing_key_registry_cbor = signing_key_registry_cbor(&input.signing_key)?;
    let checkpoints = checkpoint_chain(&input, &events)?;
    let checkpoints_cbor = array_of_raw_cbor_values(
        checkpoints
            .iter()
            .map(|checkpoint| checkpoint.sign1.as_slice()),
    )?;
    let inclusion_proofs_cbor = inclusion_proofs_cbor(&events)?;
    let consistency_proofs_cbor = consistency_proofs_cbor(&events)?;
    let head_checkpoint_digest = checkpoints
        .last()
        .map(|checkpoint| checkpoint.digest)
        .ok_or_else(|| StackError::internal("checkpoint chain unexpectedly empty"))?;
    let root_dir = input
        .root_dir_override
        .clone()
        .unwrap_or_else(|| root_dir(&input.scope, events.len(), tree_head_hash));

    let verify_sh = default_verify_script();
    let readme = readme_bytes(
        &input,
        events.len(),
        tree_head_hash,
        head_checkpoint_digest,
        &registry_material,
    )?;

    let manifest_payload = manifest_payload_cbor(ManifestPayloadInput {
        input: &input,
        tree_size: events.len(),
        head_checkpoint_digest,
        registry_bindings: registry_material
            .iter()
            .map(|binding| binding.value.clone())
            .collect(),
        signing_key_registry_cbor: &signing_key_registry_cbor,
        events_cbor: &events_cbor,
        checkpoints_cbor: &checkpoints_cbor,
        inclusion_proofs_cbor: &inclusion_proofs_cbor,
        consistency_proofs_cbor: &consistency_proofs_cbor,
    })?;
    let signed_manifest = sign_cose(&input.signing_key, &manifest_payload);
    let manifest_digest = export_manifest_digest(&input.scope, &manifest_payload);

    let mut bundle = Bundle::new();
    bundle.add_entry(BundleEntry::new(
        format!("{root_dir}/{MANIFEST_MEMBER}"),
        signed_manifest,
    ));
    bundle.add_entry(BundleEntry::new(
        format!("{root_dir}/{EVENTS_MEMBER}"),
        events_cbor,
    ));
    bundle.add_entry(BundleEntry::new(
        format!("{root_dir}/{INCLUSION_PROOFS_MEMBER}"),
        inclusion_proofs_cbor,
    ));
    bundle.add_entry(BundleEntry::new(
        format!("{root_dir}/{CONSISTENCY_PROOFS_MEMBER}"),
        consistency_proofs_cbor,
    ));
    bundle.add_entry(BundleEntry::new(
        format!("{root_dir}/{SIGNING_KEY_REGISTRY_MEMBER}"),
        signing_key_registry_cbor,
    ));
    bundle.add_entry(BundleEntry::new(
        format!("{root_dir}/{CHECKPOINTS_MEMBER}"),
        checkpoints_cbor,
    ));
    for binding in registry_material {
        bundle.add_entry(BundleEntry::new(
            format!("{root_dir}/{}", binding.member),
            binding.bytes,
        ));
    }
    bundle.add_entry(BundleEntry::new(
        format!("{root_dir}/{VERIFY_MEMBER}"),
        verify_sh,
    ));
    bundle.add_entry(BundleEntry::new(
        format!("{root_dir}/{README_MEMBER}"),
        readme,
    ));

    let zip_bytes = bundle.to_zip_bytes().map_err(|error| {
        StackError::internal(format!("failed to serialize export ZIP: {error}"))
    })?;
    Ok(ExportPackage {
        root_dir,
        entries: bundle.entries().to_vec(),
        zip_bytes,
        manifest_payload,
        manifest_digest,
        head_checkpoint_digest,
        tree_head_hash,
    })
}

fn validate_top_level_input(input: &ExportWriterInput) -> Result<(), StackError> {
    if input.scope.is_empty() {
        return Err(StackError::bad_request("export scope must not be empty"));
    }
    if !input.scope.is_ascii() {
        return Err(StackError::bad_request(
            "export scope must be ASCII for deterministic ZIP paths",
        ));
    }
    if input.events.is_empty() {
        return Err(StackError::bad_request(
            "export requires at least one stored event",
        ));
    }
    if input.events.len() != input.checkpoint_timestamps.len() {
        return Err(StackError::bad_request(format!(
            "checkpoint timestamp count {} does not match event count {}",
            input.checkpoint_timestamps.len(),
            input.events.len()
        )));
    }
    if input.registries.is_empty() {
        return Err(StackError::bad_request(
            "export requires at least one registry snapshot",
        ));
    }
    if input.generator.is_empty() {
        return Err(StackError::bad_request(
            "export generator must not be empty",
        ));
    }
    if input.readme_title.is_empty() {
        return Err(StackError::bad_request("README title must not be empty"));
    }
    if let Some(root_dir) = &input.root_dir_override {
        validate_ascii_path_segment(root_dir, "root_dir_override")?;
    }
    Ok(())
}

fn prepare_events(input: &ExportWriterInput) -> Result<Vec<PreparedEvent>, StackError> {
    let mut events = input.events.clone();
    events.sort_by_key(StoredEvent::sequence);
    let mut prepared = Vec::with_capacity(events.len());
    for (expected_sequence, event) in events.iter().enumerate() {
        let expected_sequence = u64::try_from(expected_sequence)
            .map_err(|_| StackError::internal("event count exceeds u64"))?;
        if event.sequence() != expected_sequence {
            return Err(StackError::bad_request(format!(
                "stored events must be contiguous from sequence 0; expected {expected_sequence}, got {}",
                event.sequence()
            )));
        }
        if event.scope() != input.scope.as_slice() {
            return Err(StackError::bad_request(format!(
                "stored event sequence {} scope does not match export scope",
                event.sequence()
            )));
        }
        let payload = decode_cbor_value(event.canonical_event()).map_err(|error| {
            StackError::bad_request(format!(
                "stored event sequence {} canonical payload is invalid CBOR: {error}",
                event.sequence()
            ))
        })?;
        let payload_map = payload.as_map().ok_or_else(|| {
            StackError::bad_request(format!(
                "stored event sequence {} canonical payload is not a map",
                event.sequence()
            ))
        })?;
        let payload_scope = map_lookup_bytes(payload_map, "ledger_scope").map_err(|error| {
            StackError::bad_request(format!(
                "stored event sequence {} ledger_scope is invalid: {error}",
                event.sequence()
            ))
        })?;
        if payload_scope != input.scope {
            return Err(StackError::bad_request(format!(
                "stored event sequence {} payload scope does not match export scope",
                event.sequence()
            )));
        }
        let payload_sequence = map_lookup_u64(payload_map, "sequence").map_err(|error| {
            StackError::bad_request(format!(
                "stored event sequence {} payload sequence is invalid: {error}",
                event.sequence()
            ))
        })?;
        if payload_sequence != event.sequence() {
            return Err(StackError::bad_request(format!(
                "stored event sequence {} payload sequence is {payload_sequence}",
                event.sequence()
            )));
        }
        let signed = integrity_cose::decode_cose_sign1(event.signed_event()).map_err(|error| {
            StackError::bad_request(format!(
                "stored event sequence {} signed event is invalid COSE_Sign1: {error}",
                event.sequence()
            ))
        })?;
        let signed_payload = signed.payload().ok_or_else(|| {
            StackError::bad_request(format!(
                "stored event sequence {} uses a detached payload; export/001 Phase-1 requires embedded event payloads",
                event.sequence()
            ))
        })?;
        if signed_payload != event.canonical_event() {
            return Err(StackError::bad_request(format!(
                "stored event sequence {} signed payload does not match canonical payload bytes",
                event.sequence()
            )));
        }
        decode_cbor_value(event.signed_event()).map_err(|error| {
            StackError::bad_request(format!(
                "stored event sequence {} signed event is invalid CBOR: {error}",
                event.sequence()
            ))
        })?;
        let canonical_event_hash = canonical_event_hash(&input.scope, event.canonical_event());
        if let Some(stored_hash) = event.canonical_event_hash()
            && stored_hash != &canonical_event_hash
        {
            return Err(StackError::bad_request(format!(
                "stored event sequence {} canonical_event_hash does not match payload bytes",
                event.sequence()
            )));
        }
        let leaf_hash = merkle_leaf_hash(canonical_event_hash);
        prepared.push(PreparedEvent {
            sequence: event.sequence(),
            canonical_event: event.canonical_event().to_vec(),
            signed_event: event.signed_event().to_vec(),
            canonical_event_hash,
            leaf_hash,
        });
    }
    Ok(prepared)
}

fn registry_binding_material(
    registries: &[RegistrySnapshot],
) -> Result<Vec<RegistryBindingMaterial>, StackError> {
    let mut sorted = registries.to_vec();
    sorted.sort_by(|left, right| {
        left.bound_at_sequence
            .cmp(&right.bound_at_sequence)
            .then_with(|| left.registry_version.cmp(&right.registry_version))
    });
    let mut seen_members = BTreeMap::new();
    let mut material = Vec::with_capacity(sorted.len());
    for registry in sorted {
        if registry.bytes.is_empty() {
            return Err(StackError::bad_request(
                "registry snapshot bytes must not be empty",
            ));
        }
        if registry.registry_version.is_empty() {
            return Err(StackError::bad_request(
                "registry snapshot version must not be empty",
            ));
        }
        let digest = sha256_bytes(&registry.bytes);
        let digest_hex = hex_lower(&digest);
        let member = format!("{REGISTRY_DIR}/{digest_hex}.cbor");
        if seen_members.insert(member.clone(), ()).is_some() {
            return Err(StackError::bad_request(format!(
                "duplicate registry snapshot digest {digest_hex}"
            )));
        }
        let value = text_map(vec![
            ("registry_digest", Value::Bytes(digest.to_vec())),
            ("registry_format", uint(registry.registry_format)),
            (
                "registry_version",
                Value::Text(registry.registry_version.clone()),
            ),
            ("bound_at_sequence", uint(registry.bound_at_sequence)),
        ])?;
        material.push(RegistryBindingMaterial {
            member,
            bytes: registry.bytes,
            value,
        });
    }
    Ok(material)
}

fn signing_key_registry_cbor(signing_key: &SigningKeyMaterial) -> Result<Vec<u8>, StackError> {
    let entry = text_map(vec![
        ("kid", Value::Bytes(signing_key.kid().to_vec())),
        ("pubkey", Value::Bytes(signing_key.public_key.to_vec())),
        ("suite_id", uint(SUITE_ID_PHASE_1)),
        ("status", uint(0)),
        ("valid_from", signing_key.valid_from.to_value()),
        (
            "valid_to",
            signing_key
                .valid_to
                .map_or(Value::Null, TrellisTimestamp::to_value),
        ),
        ("supersedes", Value::Null),
        ("attestation", Value::Null),
    ])?;
    encode_value(&Value::Array(vec![entry]))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SignedCheckpoint {
    digest: [u8; 32],
    sign1: Vec<u8>,
}

fn checkpoint_chain(
    input: &ExportWriterInput,
    events: &[PreparedEvent],
) -> Result<Vec<SignedCheckpoint>, StackError> {
    let leaves = events
        .iter()
        .map(|event| event.leaf_hash)
        .collect::<Vec<_>>();
    let mut prior_digest = None;
    let mut checkpoints = Vec::with_capacity(events.len());
    for tree_size in 1..=events.len() {
        let tree_head_hash = merkle_root(&leaves[..tree_size])?;
        let payload = checkpoint_payload(
            &input.scope,
            u64::try_from(tree_size).map_err(|_| StackError::internal("tree size exceeds u64"))?,
            tree_head_hash,
            input.checkpoint_timestamps[tree_size - 1],
            prior_digest,
        )?;
        let payload_bytes = encode_value(&payload)?;
        let digest = checkpoint_digest(&input.scope, &payload_bytes);
        let sign1 = sign_cose(&input.signing_key, &payload_bytes);
        prior_digest = Some(digest);
        checkpoints.push(SignedCheckpoint { digest, sign1 });
    }
    Ok(checkpoints)
}

fn checkpoint_payload(
    scope: &[u8],
    tree_size: u64,
    tree_head_hash: [u8; 32],
    timestamp: TrellisTimestamp,
    prev_checkpoint_hash: Option<[u8; 32]>,
) -> Result<Value, StackError> {
    text_map(vec![
        ("version", uint(1)),
        ("scope", Value::Bytes(scope.to_vec())),
        ("tree_size", uint(tree_size)),
        ("tree_head_hash", Value::Bytes(tree_head_hash.to_vec())),
        ("timestamp", timestamp.to_value()),
        ("anchor_ref", Value::Null),
        (
            "prev_checkpoint_hash",
            prev_checkpoint_hash.map_or(Value::Null, |digest| Value::Bytes(digest.to_vec())),
        ),
        ("extensions", Value::Null),
    ])
}

fn inclusion_proofs_cbor(events: &[PreparedEvent]) -> Result<Vec<u8>, StackError> {
    let leaves = events
        .iter()
        .map(|event| event.leaf_hash)
        .collect::<Vec<_>>();
    let mut proofs = Vec::with_capacity(events.len());
    for event in events {
        let audit_path = inclusion_proof(&leaves, event.sequence as usize)?;
        let proof = text_map(vec![
            ("leaf_index", uint(event.sequence)),
            (
                "tree_size",
                uint(
                    u64::try_from(events.len())
                        .map_err(|_| StackError::internal("event count exceeds u64"))?,
                ),
            ),
            ("leaf_hash", Value::Bytes(event.leaf_hash.to_vec())),
            (
                "audit_path",
                Value::Array(
                    audit_path
                        .into_iter()
                        .map(|digest| Value::Bytes(digest.to_vec()))
                        .collect(),
                ),
            ),
        ])?;
        proofs.push((uint(event.sequence), proof));
    }
    let value = canonical_map(proofs)?;
    encode_value(&value)
}

fn consistency_proofs_cbor(events: &[PreparedEvent]) -> Result<Vec<u8>, StackError> {
    let leaves = events
        .iter()
        .map(|event| event.leaf_hash)
        .collect::<Vec<_>>();
    let mut records = Vec::new();
    for from_tree_size in 1..events.len() {
        let proof_path = consistency_proof(&leaves, from_tree_size, events.len())?;
        let record = text_map(vec![
            (
                "from_tree_size",
                uint(
                    u64::try_from(from_tree_size)
                        .map_err(|_| StackError::internal("tree size exceeds u64"))?,
                ),
            ),
            (
                "to_tree_size",
                uint(
                    u64::try_from(events.len())
                        .map_err(|_| StackError::internal("tree size exceeds u64"))?,
                ),
            ),
            (
                "proof_path",
                Value::Array(
                    proof_path
                        .into_iter()
                        .map(|digest| Value::Bytes(digest.to_vec()))
                        .collect(),
                ),
            ),
        ])?;
        records.push(record);
    }
    encode_value(&Value::Array(records))
}

struct ManifestPayloadInput<'a> {
    input: &'a ExportWriterInput,
    tree_size: usize,
    head_checkpoint_digest: [u8; 32],
    registry_bindings: Vec<Value>,
    signing_key_registry_cbor: &'a [u8],
    events_cbor: &'a [u8],
    checkpoints_cbor: &'a [u8],
    inclusion_proofs_cbor: &'a [u8],
    consistency_proofs_cbor: &'a [u8],
}

fn manifest_payload_cbor(args: ManifestPayloadInput<'_>) -> Result<Vec<u8>, StackError> {
    let tree_size =
        u64::try_from(args.tree_size).map_err(|_| StackError::internal("tree size exceeds u64"))?;
    let manifest_payload = text_map(vec![
        ("format", Value::Text("trellis-export/1".to_string())),
        ("version", uint(1)),
        ("generator", Value::Text(args.input.generator.clone())),
        ("generated_at", args.input.generated_at.to_value()),
        ("scope", Value::Bytes(args.input.scope.clone())),
        ("tree_size", uint(tree_size)),
        (
            "head_checkpoint_digest",
            Value::Bytes(args.head_checkpoint_digest.to_vec()),
        ),
        ("registry_bindings", Value::Array(args.registry_bindings)),
        (
            "signing_key_registry_digest",
            Value::Bytes(sha256_bytes(args.signing_key_registry_cbor).to_vec()),
        ),
        (
            "events_digest",
            Value::Bytes(sha256_bytes(args.events_cbor).to_vec()),
        ),
        (
            "checkpoints_digest",
            Value::Bytes(sha256_bytes(args.checkpoints_cbor).to_vec()),
        ),
        (
            "inclusion_proofs_digest",
            Value::Bytes(sha256_bytes(args.inclusion_proofs_cbor).to_vec()),
        ),
        (
            "consistency_proofs_digest",
            Value::Bytes(sha256_bytes(args.consistency_proofs_cbor).to_vec()),
        ),
        ("payloads_inlined", Value::Bool(false)),
        (
            "external_anchors",
            Value::Array(args.input.external_anchors.clone()),
        ),
        (
            "posture_declaration",
            args.input.posture_declaration.to_value()?,
        ),
        ("head_format_version", uint(1)),
        (
            "omitted_payload_checks",
            Value::Array(args.input.omitted_payload_checks.clone()),
        ),
        (
            "extensions",
            args.input.extensions.clone().unwrap_or(Value::Null),
        ),
    ])?;
    encode_value(&manifest_payload)
}

fn readme_bytes(
    input: &ExportWriterInput,
    tree_size: usize,
    tree_head_hash: [u8; 32],
    head_checkpoint_digest: [u8; 32],
    registries: &[RegistryBindingMaterial],
) -> Result<Vec<u8>, StackError> {
    let scope = std::str::from_utf8(&input.scope).map_err(|error| {
        StackError::bad_request(format!("export scope is not valid UTF-8: {error}"))
    })?;
    let first_registry_digest = registries
        .first()
        .and_then(|registry| {
            registry
                .member
                .strip_prefix(REGISTRY_DIR)
                .and_then(|rest| rest.strip_prefix('/'))
                .and_then(|rest| rest.strip_suffix(".cbor"))
        })
        .ok_or_else(|| StackError::internal("registry material unexpectedly empty"))?;
    let posture_json = serde_json::to_string_pretty(&input.posture_declaration.to_sorted_json())
        .map_err(|error| StackError::internal(format!("failed to encode posture JSON: {error}")))?;
    let omitted_json = serde_json::to_string(&input.omitted_payload_checks).map_err(|error| {
        StackError::internal(format!("failed to encode omitted checks JSON: {error}"))
    })?;
    let readme = format!(
        "# {}\n\
         \n\
         - scope (manifest.scope): `{scope}`\n\
         - tree_size (manifest.tree_size): `{tree_size}`\n\
         - tree_head_hash (checkpoint[{}].tree_head_hash): `{}`\n\
         - head_checkpoint_digest: `{}`\n\
         - registry_digest: `{first_registry_digest}`\n\
         \n\
         ## Posture Declaration (manifest.posture_declaration)\n\
         ```json\n\
         {posture_json}\n\
         ```\n\
         \n\
         ## Omitted payload checks\n\
         ```json\n\
         {omitted_json}\n\
         ```\n\
         \n\
         ## Verify\n\
         Run `./090-verify.sh` from this directory (or run your verifier directly).\n",
        input.readme_title,
        tree_size - 1,
        hex_lower(&tree_head_hash),
        hex_lower(&head_checkpoint_digest),
    );
    Ok(readme.into_bytes())
}

fn default_verify_script() -> Vec<u8> {
    ("#!/bin/sh\n\
         set -eu\n\
         \n\
         # Trellis export verifier invocation (\u{00a7}18.8).\n\
         #\n\
         # Pass the export ZIP path as the only argument; the operator CLI\n\
         # verifies it through trellis-verify-wos.\n\
         \n\
         if [ \"$#\" -ne 1 ]; then\n\
         \x20 echo \"usage: $0 <export.zip>\" >&2\n\
         \x20 exit 2\n\
         fi\n\
         \n\
         if command -v trellis-cli >/dev/null 2>&1; then\n\
         \x20 exec trellis-cli verify-export \"$1\"\n\
         fi\n\
         \n\
         echo \"trellis-cli not found in PATH.\" >&2\n\
         echo \"Run `trellis-cli verify-export $1`.\" >&2\n\
         exit 2\n")
        .as_bytes()
        .to_vec()
}

fn root_dir(scope: &[u8], tree_size: usize, tree_head_hash: [u8; 32]) -> String {
    let scope = std::str::from_utf8(scope).expect("validated ASCII scope is valid UTF-8");
    let head_hex = hex_lower(&tree_head_hash);
    format!("trellis-export-{scope}-{tree_size}-{}", &head_hex[..8])
}

fn sign_cose(signing_key: &SigningKeyMaterial, payload: &[u8]) -> Vec<u8> {
    let protected_header = protected_header_bytes(signing_key.kid());
    let sig_structure = sig_structure_bytes(&protected_header, payload);
    let signature = sign_ed25519(signing_key.private_seed, &sig_structure);
    sign1_bytes(&protected_header, payload, signature)
}

fn canonical_event_hash(scope: &[u8], canonical_event_bytes: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.push(0xa3);
    preimage.extend_from_slice(&encode_tstr("version"));
    preimage.extend_from_slice(&encode_uint(1));
    preimage.extend_from_slice(&encode_tstr("ledger_scope"));
    preimage.extend_from_slice(&encode_bstr(scope));
    preimage.extend_from_slice(&encode_tstr("event_payload"));
    preimage.extend_from_slice(canonical_event_bytes);
    domain_separated_sha256(EVENT_DOMAIN, &preimage)
}

fn checkpoint_digest(scope: &[u8], checkpoint_payload_bytes: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.push(0xa3);
    preimage.extend_from_slice(&encode_tstr("scope"));
    preimage.extend_from_slice(&encode_bstr(scope));
    preimage.extend_from_slice(&encode_tstr("version"));
    preimage.extend_from_slice(&encode_uint(1));
    preimage.extend_from_slice(&encode_tstr("checkpoint_payload"));
    preimage.extend_from_slice(checkpoint_payload_bytes);
    domain_separated_sha256(CHECKPOINT_DOMAIN, &preimage)
}

fn export_manifest_digest(scope: &[u8], manifest_payload_bytes: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.push(0xa3);
    preimage.extend_from_slice(&encode_tstr("scope"));
    preimage.extend_from_slice(&encode_bstr(scope));
    preimage.extend_from_slice(&encode_tstr("version"));
    preimage.extend_from_slice(&encode_uint(1));
    preimage.extend_from_slice(&encode_tstr("manifest_payload"));
    preimage.extend_from_slice(manifest_payload_bytes);
    domain_separated_sha256(EXPORT_MANIFEST_DOMAIN, &preimage)
}

fn merkle_leaf_hash(canonical_hash: [u8; 32]) -> [u8; 32] {
    domain_separated_sha256(MERKLE_LEAF_DOMAIN, &canonical_hash)
}

fn merkle_interior_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut joined = Vec::with_capacity(64);
    joined.extend_from_slice(&left);
    joined.extend_from_slice(&right);
    domain_separated_sha256(MERKLE_INTERIOR_DOMAIN, &joined)
}

fn merkle_root(leaves: &[[u8; 32]]) -> Result<[u8; 32], StackError> {
    match leaves.len() {
        0 => Err(StackError::bad_request(
            "Merkle tree requires at least one leaf",
        )),
        1 => Ok(leaves[0]),
        len => {
            let split = largest_power_of_two_less_than(len);
            Ok(merkle_interior_hash(
                merkle_root(&leaves[..split])?,
                merkle_root(&leaves[split..])?,
            ))
        }
    }
}

fn inclusion_proof(leaves: &[[u8; 32]], index: usize) -> Result<Vec<[u8; 32]>, StackError> {
    if leaves.is_empty() || index >= leaves.len() {
        return Err(StackError::bad_request(
            "inclusion proof index is out of range",
        ));
    }
    if leaves.len() == 1 {
        return Ok(Vec::new());
    }
    let split = largest_power_of_two_less_than(leaves.len());
    if index < split {
        let mut proof = inclusion_proof(&leaves[..split], index)?;
        proof.push(merkle_root(&leaves[split..])?);
        Ok(proof)
    } else {
        let mut proof = inclusion_proof(&leaves[split..], index - split)?;
        proof.push(merkle_root(&leaves[..split])?);
        Ok(proof)
    }
}

fn consistency_proof(
    leaves: &[[u8; 32]],
    from_tree_size: usize,
    to_tree_size: usize,
) -> Result<Vec<[u8; 32]>, StackError> {
    if from_tree_size == 0 || from_tree_size > to_tree_size || to_tree_size > leaves.len() {
        return Err(StackError::bad_request(
            "consistency proof tree sizes are invalid",
        ));
    }
    consistency_subproof(&leaves[..to_tree_size], from_tree_size, true)
}

fn consistency_subproof(
    leaves: &[[u8; 32]],
    from_tree_size: usize,
    complete_subtree: bool,
) -> Result<Vec<[u8; 32]>, StackError> {
    if from_tree_size == leaves.len() {
        return if complete_subtree {
            Ok(Vec::new())
        } else {
            Ok(vec![merkle_root(leaves)?])
        };
    }
    let split = largest_power_of_two_less_than(leaves.len());
    if from_tree_size <= split {
        let mut proof = consistency_subproof(&leaves[..split], from_tree_size, complete_subtree)?;
        proof.push(merkle_root(&leaves[split..])?);
        Ok(proof)
    } else {
        let mut proof = consistency_subproof(&leaves[split..], from_tree_size - split, false)?;
        proof.push(merkle_root(&leaves[..split])?);
        Ok(proof)
    }
}

fn largest_power_of_two_less_than(value: usize) -> usize {
    debug_assert!(value > 1);
    1usize << (usize::BITS - (value - 1).leading_zeros() - 1)
}

fn array_of_raw_cbor_values<'a>(
    values: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Vec<u8>, StackError> {
    let values = values.into_iter().collect::<Vec<_>>();
    let mut out = encode_major_len(4, values.len() as u64);
    for value in values {
        decode_cbor_value(value)
            .map_err(|error| StackError::bad_request(format!("invalid raw CBOR value: {error}")))?;
        out.extend_from_slice(value);
    }
    Ok(out)
}

fn text_map(fields: Vec<(&str, Value)>) -> Result<Value, StackError> {
    canonical_map(
        fields
            .into_iter()
            .map(|(key, value)| (Value::Text(key.to_string()), value))
            .collect(),
    )
}

fn canonical_map(fields: Vec<(Value, Value)>) -> Result<Value, StackError> {
    let mut fields = fields
        .into_iter()
        .map(|(key, value)| {
            let encoded = encode_value(&key)?;
            Ok((encoded, key, value))
        })
        .collect::<Result<Vec<_>, StackError>>()?;
    fields.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(Value::Map(
        fields
            .into_iter()
            .map(|(_, key, value)| (key, value))
            .collect(),
    ))
}

fn encode_value(value: &Value) -> Result<Vec<u8>, StackError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map_err(|error| StackError::internal(format!("failed to encode CBOR: {error}")))?;
    Ok(bytes)
}

fn encode_major_len(major: u8, value: u64) -> Vec<u8> {
    let prefix = major << 5;
    match value {
        0..=23 => vec![prefix | value as u8],
        24..=0xff => vec![prefix | 24, value as u8],
        0x100..=0xffff => {
            let mut out = vec![prefix | 25];
            out.extend_from_slice(&(value as u16).to_be_bytes());
            out
        }
        0x1_0000..=0xffff_ffff => {
            let mut out = vec![prefix | 26];
            out.extend_from_slice(&(value as u32).to_be_bytes());
            out
        }
        _ => {
            let mut out = vec![prefix | 27];
            out.extend_from_slice(&value.to_be_bytes());
            out
        }
    }
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn option_text(value: Option<&str>) -> Value {
    value.map_or(Value::Null, |value| Value::Text(value.to_string()))
}

fn validate_ascii_path_segment(value: &str, label: &str) -> Result<(), StackError> {
    if !value.is_ascii() {
        return Err(StackError::bad_request(format!(
            "{label} must be ASCII for deterministic ZIP paths"
        )));
    }
    if value.contains('/') || value.is_empty() {
        return Err(StackError::bad_request(format!(
            "{label} must be a non-empty single path segment"
        )));
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    #[test]
    fn export_001_fixture_matches_generator_zip_byte_for_byte() {
        let root = fixtures_root();
        let event_001_bytes = read(
            &root,
            "append/001-minimal-inline-payload/expected-event.cbor",
        );
        let event_005_bytes = read(&root, "append/005-prior-head-chain/expected-event.cbor");
        let payload_001 = read(
            &root,
            "append/001-minimal-inline-payload/expected-event-payload.cbor",
        );
        let payload_005 = read(
            &root,
            "append/005-prior-head-chain/expected-event-payload.cbor",
        );
        let registry = read(
            &root,
            "append/009-signing-key-revocation/input-domain-registry.cbor",
        );
        let (private_seed, public_key) =
            parse_fixture_key(&read(&root, "_keys/issuer-001.cose_key"));
        let input = ExportWriterInput {
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
        };

        let package = write_export(input).expect("write export");
        assert_eq!(
            package.root_dir,
            "trellis-export-test-response-ledger-2-280d3354"
        );
        for member in [
            MANIFEST_MEMBER,
            EVENTS_MEMBER,
            INCLUSION_PROOFS_MEMBER,
            CONSISTENCY_PROOFS_MEMBER,
            SIGNING_KEY_REGISTRY_MEMBER,
            CHECKPOINTS_MEMBER,
            "050-registries/651b13673bfa5c30f422512a2e8282479df6c903ff2d6b1cd56f0dca74d4a78a.cbor",
            VERIFY_MEMBER,
            README_MEMBER,
        ] {
            let actual = package.member_bytes(member).expect("generated member");
            let expected = read(&root, &format!("export/001-two-event-chain/{member}"));
            assert_eq!(
                hex_lower(&sha256_bytes(actual)),
                hex_lower(&sha256_bytes(&expected)),
                "{member} digest differs"
            );
            assert_eq!(actual, expected.as_slice(), "{member} bytes differ");
        }
        let expected = read(&root, "export/001-two-event-chain/expected-export.zip");
        let actual_entries =
            integrity_bundle::read_stored_zip(&package.zip_bytes).expect("actual zip parses");
        let expected_entries =
            integrity_bundle::read_stored_zip(&expected).expect("expected zip parses");
        assert_eq!(actual_entries, expected_entries);
        if package.zip_bytes != expected {
            let first_diff = package
                .zip_bytes
                .iter()
                .zip(expected.iter())
                .position(|(left, right)| left != right)
                .unwrap_or_else(|| package.zip_bytes.len().min(expected.len()));
            panic!(
                "zip bytes differ at offset {first_diff}: actual={:02x?} expected={:02x?}",
                package.zip_bytes.get(first_diff..first_diff + 16),
                expected.get(first_diff..first_diff + 16)
            );
        }
        let verification = trellis_verify_wos::verify_export_zip(&package.zip_bytes);
        assert!(verification.trellis.structure_verified, "{verification:#?}");
        assert!(verification.trellis.integrity_verified, "{verification:#?}");
        assert_eq!(
            hex_lower(&sha256_bytes(&package.zip_bytes)),
            "8c79630db6accc5fd01be3a37f01a4c01c367e0bdfaa5af79cc24ac7d6c87279"
        );
    }

    #[test]
    fn rejects_empty_event_set() {
        let input = ExportWriterInput {
            scope: b"scope".to_vec(),
            events: Vec::new(),
            registries: vec![RegistrySnapshot {
                bytes: vec![0xa0],
                registry_format: 1,
                registry_version: "test".to_string(),
                bound_at_sequence: 0,
            }],
            signing_key: SigningKeyMaterial {
                private_seed: [0; 32],
                public_key: [1; 32],
                valid_from: TrellisTimestamp::new(1, 0).expect("valid timestamp"),
                valid_to: None,
            },
            generator: "test".to_string(),
            generated_at: TrellisTimestamp::new(1, 0).expect("valid timestamp"),
            checkpoint_timestamps: Vec::new(),
            posture_declaration: PostureDeclaration {
                provider_readable: true,
                reader_held: false,
                delegated_compute: false,
                external_anchor_required: false,
                external_anchor_name: None,
                recovery_without_user: true,
                metadata_leakage_summary: "test".to_string(),
            },
            omitted_payload_checks: Vec::new(),
            readme_title: "Trellis Export".to_string(),
            root_dir_override: None,
            external_anchors: Vec::new(),
            extensions: None,
        };
        let error = write_export(input).expect_err("empty export must reject");
        assert!(error.to_string().contains("requires at least one"));
    }

    #[test]
    fn merkle_proofs_cover_non_power_of_two_tree() {
        let leaves = (0u8..5)
            .map(|value| merkle_leaf_hash([value; 32]))
            .collect::<Vec<_>>();
        let root = merkle_root(&leaves).expect("root");
        for index in 0..leaves.len() {
            let proof = inclusion_proof(&leaves, index).expect("inclusion proof");
            let computed = root_from_inclusion_proof(leaves[index], index, leaves.len(), &proof);
            assert_eq!(computed, root);
        }

        for from_size in 1..leaves.len() {
            let proof = consistency_proof(&leaves, from_size, leaves.len()).expect("consistency");
            let old_root = merkle_root(&leaves[..from_size]).expect("old root");
            let new_root = root_from_consistency_proof(from_size, leaves.len(), old_root, &proof)
                .expect("consistency proof verifies");
            assert_eq!(new_root, root);
        }
    }

    fn fixtures_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/vectors")
    }

    fn read(root: &Path, relative: &str) -> Vec<u8> {
        std::fs::read(root.join(relative)).unwrap_or_else(|error| {
            panic!("failed to read fixture {relative}: {error}");
        })
    }

    fn parse_fixture_key(bytes: &[u8]) -> ([u8; 32], [u8; 32]) {
        let value = decode_cbor_value(bytes).expect("valid COSE key fixture");
        let map = value.as_map().expect("COSE key is a map");
        let private_seed = integer_label_bytes(map, -4);
        let public_key = integer_label_bytes(map, -2);
        (
            private_seed.try_into().expect("seed is 32 bytes"),
            public_key.try_into().expect("pubkey is 32 bytes"),
        )
    }

    fn integer_label_bytes(map: &[(Value, Value)], label: i128) -> Vec<u8> {
        map.iter()
            .find(|(key, _)| {
                key.as_integer()
                    .is_some_and(|integer| i128::from(integer) == label)
            })
            .and_then(|(_, value)| value.as_bytes().cloned())
            .unwrap_or_else(|| panic!("missing integer label {label}"))
    }

    fn root_from_inclusion_proof(
        leaf_hash: [u8; 32],
        index: usize,
        size: usize,
        proof: &[[u8; 32]],
    ) -> [u8; 32] {
        if size == 1 {
            return leaf_hash;
        }
        let split = largest_power_of_two_less_than(size);
        if index < split {
            let left =
                root_from_inclusion_proof(leaf_hash, index, split, &proof[..proof.len() - 1]);
            merkle_interior_hash(left, *proof.last().expect("right sibling"))
        } else {
            let right = root_from_inclusion_proof(
                leaf_hash,
                index - split,
                size - split,
                &proof[..proof.len() - 1],
            );
            merkle_interior_hash(*proof.last().expect("left sibling"), right)
        }
    }

    fn root_from_consistency_proof(
        size1: usize,
        size2: usize,
        root1: [u8; 32],
        proof: &[[u8; 32]],
    ) -> Result<[u8; 32], StackError> {
        if size2 < size1 {
            return Err(StackError::bad_request("invalid consistency sizes"));
        }
        if size1 == size2 {
            if !proof.is_empty() {
                return Err(StackError::bad_request("same-size proof must be empty"));
            }
            return Ok(root1);
        }
        if size1 == 0 || proof.is_empty() {
            return Err(StackError::bad_request("invalid consistency proof"));
        }
        let (mut inner, border) = decomp_inclusion_proof((size1 - 1) as u64, size2 as u64);
        let shift = (size1 as u64).trailing_zeros() as usize;
        if inner < shift {
            return Err(StackError::bad_request("invalid consistency proof shape"));
        }
        inner -= shift;
        let mut seed = proof[0];
        let mut start = 1usize;
        if size1 == 1usize << shift {
            seed = root1;
            start = 0;
        }
        if proof.len() != start + inner + border {
            return Err(StackError::bad_request("invalid consistency proof length"));
        }
        let suffix = &proof[start..];
        let mask = ((size1 - 1) as u64) >> shift;
        let hash1 = chain_inner_right_merkle(seed, &suffix[..inner], mask);
        let hash1 = chain_border_right_merkle(hash1, &suffix[inner..]);
        if hash1 != root1 {
            return Err(StackError::bad_request(
                "consistency proof does not recover old root",
            ));
        }
        let hash2 = chain_inner_merkle(seed, &suffix[..inner], mask);
        Ok(chain_border_right_merkle(hash2, &suffix[inner..]))
    }

    fn decomp_inclusion_proof(index: u64, size: u64) -> (usize, usize) {
        let inner = inner_proof_size(index, size);
        let border = (index >> inner).count_ones() as usize;
        (inner, border)
    }

    fn inner_proof_size(index: u64, size: u64) -> usize {
        let xor = index ^ (size - 1);
        if xor == 0 {
            0
        } else {
            (u64::BITS - xor.leading_zeros()) as usize
        }
    }

    fn chain_inner_merkle(mut seed: [u8; 32], proof: &[[u8; 32]], index: u64) -> [u8; 32] {
        for (i, sibling) in proof.iter().enumerate() {
            if (index >> i) & 1 == 0 {
                seed = merkle_interior_hash(seed, *sibling);
            } else {
                seed = merkle_interior_hash(*sibling, seed);
            }
        }
        seed
    }

    fn chain_inner_right_merkle(mut seed: [u8; 32], proof: &[[u8; 32]], index: u64) -> [u8; 32] {
        for (i, sibling) in proof.iter().enumerate() {
            if (index >> i) & 1 == 1 {
                seed = merkle_interior_hash(*sibling, seed);
            }
        }
        seed
    }

    fn chain_border_right_merkle(mut seed: [u8; 32], proof: &[[u8; 32]]) -> [u8; 32] {
        for sibling in proof {
            seed = merkle_interior_hash(*sibling, seed);
        }
        seed
    }
}
