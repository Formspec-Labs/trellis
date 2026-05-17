// Rust guideline compliant 2026-02-21
//! Trellis append scaffold for the current G-4 vectors.

#![forbid(unsafe_code)]

use std::backtrace::Backtrace;
use std::fmt::{Display, Formatter};

use integrity_cose::{
    SUITE_ID_PHASE_1, derive_kid, sig_structure_bytes, sign_ed25519, sign1_bytes,
    substrate_protected_header,
};
use trellis_cddl::{
    append_head_bytes, canonical_event_from_authored, canonical_event_hash_preimage,
    parse_authored_event, parse_ed25519_cose_key,
};
use trellis_types::{
    AUTHOR_EVENT_DOMAIN, AppendArtifacts, AppendHead, ArtifactType, EVENT_DOMAIN, StoredEvent,
    domain_separated_sha256,
};

/// COSE EdDSA algorithm identifier used by Trellis Phase 1.
const ALG_EDDSA: i32 = -8;

/// Store seam for the append scaffold.
pub trait LedgerStore {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Persists the signed and canonical bytes for one appended event.
    fn append_event(&mut self, event: StoredEvent) -> Result<(), Self::Error>;
}

/// Authored-event input bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthoredEvent {
    bytes: Vec<u8>,
}

impl AuthoredEvent {
    /// Creates authored-event input from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the authored bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// COSE signing-key input bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningKeyMaterial {
    bytes: Vec<u8>,
}

impl SigningKeyMaterial {
    /// Creates signing-key input from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the raw COSE_Key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Error returned when append artifacts cannot be constructed.
#[derive(Debug)]
pub struct AppendError {
    message: String,
    backtrace: Backtrace,
}

impl AppendError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            backtrace: Backtrace::capture(),
        }
    }
}

impl Display for AppendError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AppendError {}

impl AppendError {
    /// Returns the captured backtrace for this append failure.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

/// Runs the current append pipeline against authored bytes and a signing key.
///
/// This slice is intentionally narrow but real: it computes the author hash,
/// canonical payload, COSE signature, canonical-event hash, and `AppendHead`
/// from the authored bytes already pinned in the fixture corpus, then persists
/// the bytes in the provided store.
///
/// # Errors
/// Returns an error when fixture inputs cannot be decoded or the store rejects
/// the appended event.
pub fn append_event<S: LedgerStore>(
    store: &mut S,
    signing_key: &SigningKeyMaterial,
    authored_event: &AuthoredEvent,
) -> Result<AppendArtifacts, AppendError> {
    let parsed_event = parse_authored_event(authored_event.as_bytes())
        .map_err(|error| AppendError::new(error.to_string()))?;
    let parsed_key = parse_ed25519_cose_key(signing_key.as_bytes())
        .map_err(|error| AppendError::new(error.to_string()))?;

    let author_event_hash = domain_separated_sha256(AUTHOR_EVENT_DOMAIN, authored_event.as_bytes());
    let canonical_event =
        canonical_event_from_authored(authored_event.as_bytes(), author_event_hash)
            .map_err(|error| AppendError::new(error.to_string()))?;

    let kid = derive_kid(1, parsed_key.public_key);
    let protected_header = substrate_protected_header(
        ALG_EDDSA,
        &kid,
        SUITE_ID_PHASE_1,
        ArtifactType::Event.cose_value(),
    );
    let sig_structure = sig_structure_bytes(&protected_header, &canonical_event);
    let signature = sign_ed25519(parsed_key.private_seed, &sig_structure);
    let signed_event = sign1_bytes(&protected_header, &canonical_event, signature);

    let canonical_preimage =
        canonical_event_hash_preimage(&parsed_event.ledger_scope, &canonical_event);
    let canonical_event_hash = domain_separated_sha256(EVENT_DOMAIN, &canonical_preimage);
    let append_head = append_head_bytes(
        &parsed_event.ledger_scope,
        parsed_event.sequence,
        canonical_event_hash,
    );

    // Thread the parsed `idempotency_key` (Core §6.1 / §17.2 — already
    // length-validated by `parse_authored_event`) into `StoredEvent` so the
    // backing `LedgerStore` can enforce the §17.3 unique-`(scope, key)`
    // invariant. Phase-1 callers always supply a key (the field is required
    // by §6.1 / §28); the `with_idempotency_key` constructor encodes that.
    store
        .append_event(StoredEvent::with_idempotency_key(
            parsed_event.ledger_scope.clone(),
            parsed_event.sequence,
            canonical_event.clone(),
            signed_event.clone(),
            parsed_event.idempotency_key.clone(),
        ))
        .map_err(|error| AppendError::new(format!("store append failed: {error}")))?;

    let _head = AppendHead::new(
        parsed_event.ledger_scope,
        parsed_event.sequence,
        canonical_event_hash,
    );

    Ok(AppendArtifacts {
        author_event_hash,
        canonical_event_hash,
        protected_header,
        sig_structure,
        canonical_event,
        signed_event,
        append_head,
    })
}
