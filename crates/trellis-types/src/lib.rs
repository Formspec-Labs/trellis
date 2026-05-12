// Rust guideline compliant 2026-02-21
//! Shared Trellis types and byte helpers.
//!
//! This crate keeps the Phase-1 append scaffold on `std` types and fixed
//! byte constructions. It owns Trellis profile types and constants, and
//! re-exports shared integrity helpers to keep existing callers stable during
//! substrate extraction.

#![forbid(unsafe_code)]

pub use integrity_cbor::{
    CborHelperError, Value, decode_cbor_value, domain_separated_sha256, encode_bstr,
    encode_cbor_negative_int, encode_tstr, encode_uint, map_lookup_array, map_lookup_bool,
    map_lookup_bytes, map_lookup_fixed_bytes, map_lookup_integer_label_bytes,
    map_lookup_integer_label_value, map_lookup_map, map_lookup_optional_bytes,
    map_lookup_optional_fixed_bytes, map_lookup_optional_map, map_lookup_optional_text,
    map_lookup_optional_value, map_lookup_text, map_lookup_u64, map_lookup_value, sha256_bytes,
};

/// Domain tag for `author_event_hash`.
pub const AUTHOR_EVENT_DOMAIN: &str = "trellis-author-event-v1";

/// Domain tag for `content_hash`.
pub const CONTENT_DOMAIN: &str = "trellis-content-v1";

/// Domain tag for `canonical_event_hash`.
pub const EVENT_DOMAIN: &str = "trellis-event-v1";

/// Phase-1 Trellis signature suite identifier (Core §7 suite registry).
pub const SUITE_ID_PHASE_1: u64 = 1;

/// COSE protected-header map label for Trellis `suite_id` (Core §7.4, RFC 9052 §3.1).
///
/// This value must stay aligned with Python `COSE_LABEL_SUITE_ID` in
/// `fixtures/vectors/_generator/_lib/byte_utils.py` and with every runtime
/// that builds or parses Phase-1 protected headers.
pub const COSE_LABEL_SUITE_ID: i128 = -65_537;

/// Unsigned magnitude `n` such that the CBOR negative integer `-1 - n` equals
/// [`COSE_LABEL_SUITE_ID`] (here `n = 65536` gives `-65537`).
pub const COSE_SUITE_ID_LABEL_MAGNITUDE: u64 = 65_536;

/// COSE protected-header map label for Trellis `profile_id` (Core §7.4).
///
/// The label follows the sequentially-descending Trellis private-use header
/// allocation after `suite_id = -65537` and `artifact_type = -65538`.
pub const COSE_LABEL_PROFILE_ID: i128 = -65_539;

/// Unsigned magnitude `n` such that the CBOR negative integer `-1 - n` equals
/// [`COSE_LABEL_PROFILE_ID`] (here `n = 65538` gives `-65539`).
pub const COSE_PROFILE_ID_LABEL_MAGNITUDE: u64 = 65_538;

/// Signed and canonical event bytes stored after a successful append.
///
/// `idempotency_key` is the optional Core §6.1 / §17 wire-contract
/// identity. Phase-1 callers that have already extracted the key from the
/// authored event (the §17.3 retry-conflict resolution path) pass it
/// through [`StoredEvent::with_idempotency_key`]; legacy callers that
/// have not yet been threaded use [`StoredEvent::new`] which defaults to
/// `None`. The stores read the key via [`StoredEvent::idempotency_key`]
/// to enforce the §17.3 unique-`(scope, key)` invariant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEvent {
    scope: Vec<u8>,
    sequence: u64,
    canonical_event: Vec<u8>,
    signed_event: Vec<u8>,
    idempotency_key: Option<Vec<u8>>,
    canonical_event_hash: Option<[u8; 32]>,
}

impl StoredEvent {
    /// Creates a stored event snapshot without an `idempotency_key`.
    ///
    /// Phase-1 callers prefer [`StoredEvent::with_idempotency_key`] when the
    /// authored event has been parsed; this constructor stays available for
    /// legacy / structural-only callers.
    ///
    /// # Examples
    /// ```rust
    /// use trellis_types::StoredEvent;
    ///
    /// let event = StoredEvent::new(b"scope".to_vec(), 0, vec![0x01], vec![0x02]);
    /// assert_eq!(event.sequence(), 0);
    /// assert!(event.idempotency_key().is_none());
    /// ```
    pub fn new(
        scope: Vec<u8>,
        sequence: u64,
        canonical_event: Vec<u8>,
        signed_event: Vec<u8>,
    ) -> Self {
        Self {
            scope,
            sequence,
            canonical_event,
            signed_event,
            idempotency_key: None,
            canonical_event_hash: None,
        }
    }

    /// Creates a stored event snapshot carrying its Core §6.1 `idempotency_key`.
    ///
    /// The caller MUST have already validated that `idempotency_key.len()` is
    /// in the closed interval `[IDEMPOTENCY_KEY_MIN_LEN, IDEMPOTENCY_KEY_MAX_LEN]`
    /// (see [`IDEMPOTENCY_KEY_MIN_LEN`] / [`IDEMPOTENCY_KEY_MAX_LEN`]). This
    /// constructor does not re-validate; the store-side `append_event_in_tx`
    /// path is the load-bearing length check.
    pub fn with_idempotency_key(
        scope: Vec<u8>,
        sequence: u64,
        canonical_event: Vec<u8>,
        signed_event: Vec<u8>,
        idempotency_key: Vec<u8>,
    ) -> Self {
        Self {
            scope,
            sequence,
            canonical_event,
            signed_event,
            idempotency_key: Some(idempotency_key),
            canonical_event_hash: None,
        }
    }

    /// Returns the ledger scope bytes.
    pub fn scope(&self) -> &[u8] {
        &self.scope
    }

    /// Returns the sequence number within the ledger scope.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the canonical event bytes.
    pub fn canonical_event(&self) -> &[u8] {
        &self.canonical_event
    }

    /// Returns the signed COSE event bytes.
    pub fn signed_event(&self) -> &[u8] {
        &self.signed_event
    }

    /// Returns the Core §6.1 `idempotency_key` if it was threaded through the
    /// authored-event parse, otherwise `None`. Used by `LedgerStore` impls
    /// to enforce the §17.3 unique-`(ledger_scope, idempotency_key)` invariant.
    pub fn idempotency_key(&self) -> Option<&[u8]> {
        self.idempotency_key.as_deref()
    }

    pub fn canonical_event_hash(&self) -> Option<&[u8; 32]> {
        self.canonical_event_hash.as_ref()
    }

    pub fn with_canonical_event_hash(mut self, hash: Option<[u8; 32]>) -> Self {
        self.canonical_event_hash = hash;
        self
    }
}

/// Minimum byte length of `idempotency_key` per Core §6.1 / §17.2 (`bstr .size (1..64)`).
pub const IDEMPOTENCY_KEY_MIN_LEN: usize = 1;

/// Maximum byte length of `idempotency_key` per Core §6.1 / §17.2 (`bstr .size (1..64)`).
pub const IDEMPOTENCY_KEY_MAX_LEN: usize = 64;

/// Returns `true` iff `key` satisfies the Core §6.1 `bstr .size (1..64)` bound.
#[must_use]
pub fn idempotency_key_length_in_bound(key: &[u8]) -> bool {
    (IDEMPOTENCY_KEY_MIN_LEN..=IDEMPOTENCY_KEY_MAX_LEN).contains(&key.len())
}

/// The append head returned after a successful append.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendHead {
    scope: Vec<u8>,
    sequence: u64,
    canonical_event_hash: [u8; 32],
}

impl AppendHead {
    /// Creates a new append head value.
    pub fn new(scope: Vec<u8>, sequence: u64, canonical_event_hash: [u8; 32]) -> Self {
        Self {
            scope,
            sequence,
            canonical_event_hash,
        }
    }

    /// Returns the ledger scope bytes.
    pub fn scope(&self) -> &[u8] {
        &self.scope
    }

    /// Returns the sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the canonical event hash.
    pub fn canonical_event_hash(&self) -> [u8; 32] {
        self.canonical_event_hash
    }
}

/// Byte artifacts produced by the current append scaffold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendArtifacts {
    pub author_event_hash: [u8; 32],
    pub canonical_event_hash: [u8; 32],
    pub protected_header: Vec<u8>,
    pub sig_structure: Vec<u8>,
    pub canonical_event: Vec<u8>,
    pub signed_event: Vec<u8>,
    pub append_head: Vec<u8>,
}

/// Encodes the CBOR map key bytes for [`COSE_LABEL_SUITE_ID`].
///
/// Equivalent to canonical CBOR for integer `-65537` (`-1 - 65536`).
#[must_use]
pub fn encode_cose_suite_id_label() -> Vec<u8> {
    encode_cbor_negative_int(COSE_SUITE_ID_LABEL_MAGNITUDE)
}

/// Encodes the CBOR map key bytes for [`COSE_LABEL_PROFILE_ID`].
///
/// Equivalent to canonical CBOR for integer `-65539` (`-1 - 65538`).
#[must_use]
pub fn encode_cose_profile_id_label() -> Vec<u8> {
    encode_cbor_negative_int(COSE_PROFILE_ID_LABEL_MAGNITUDE)
}

/// Domain tag for `checkpoint_digest`.
pub const CHECKPOINT_DOMAIN: &str = "trellis-checkpoint-v1";

/// Computes a standard Trellis checkpoint digest per Core §18.2.
pub fn checkpoint_digest(scope: &[u8], payload_bytes: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.push(0xa3);
    preimage.extend_from_slice(&encode_tstr("scope"));
    preimage.extend_from_slice(&encode_bstr(scope));
    preimage.extend_from_slice(&encode_tstr("version"));
    preimage.extend_from_slice(&encode_uint(1));
    preimage.extend_from_slice(&encode_tstr("checkpoint_payload"));
    preimage.extend_from_slice(payload_bytes);
    domain_separated_sha256(CHECKPOINT_DOMAIN, &preimage)
}

#[cfg(test)]
mod tests {
    use super::{encode_cose_profile_id_label, encode_cose_suite_id_label, encode_uint};

    #[test]
    fn encode_uint_matches_single_byte_for_small_suite_ids() {
        assert_eq!(encode_uint(1), vec![0x01]);
    }

    #[test]
    fn encode_cose_suite_id_label_matches_historical_bytes() {
        assert_eq!(
            encode_cose_suite_id_label(),
            vec![0x3a, 0x00, 0x01, 0x00, 0x00]
        );
    }

    #[test]
    fn encode_cose_profile_id_label_matches_allocated_bytes() {
        assert_eq!(
            encode_cose_profile_id_label(),
            vec![0x3a, 0x00, 0x01, 0x00, 0x02]
        );
    }
}
