// Rust guideline compliant 2026-02-21
//! WOS/Formspec implementation of the Trellis Core
//! [`ResponseProofResolver`] trait.
//!
//! Reads consumer-domain field names (`data.signedPayloadDigest`,
//! `data.signedPayloadDigestAlgorithm`, legacy `data.formspecResponseRef`,
//! `data.signerId`) out of opaque payload bytes and returns a neutral
//! [`CertificateResponseProof`] (or principal-ref string) to Trellis Core,
//! or `Ok(None)` if the payload is not a signing-event payload this
//! resolver knows how to interpret.
//!
//! Phase M relocated these readers from `trellis-verify` into
//! `trellis-verify-wos`. Phase N flips the malformed-digest branch from
//! silent-skip (`Ok(None)`) to fail-closed
//! [`ResolverError::MalformedResponseDigest`]: when the consumer-domain
//! payload declares `signedPayloadDigestAlgorithm = "sha-256"` and carries a
//! `signedPayloadDigest` that does not parse as 32 bytes of hex, the
//! resolver returns `Err` so the Core verifier can emit a distinct
//! `malformed_response_digest` failure rather than silently skipping the
//! response-ref equivalence check.

#![forbid(unsafe_code)]

use trellis_types::{decode_cbor_value, map_lookup_map, map_lookup_text};
use trellis_verify::certificate_proof::{
    CertificateResponseProof, ResolverError, ResponseProofResolver,
};

/// WOS/Formspec consumer-domain implementation of
/// [`ResponseProofResolver`]. Stateless; instantiate per-call.
pub struct WosFormspecResolver;

impl WosFormspecResolver {
    /// Returns a fresh [`WosFormspecResolver`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for WosFormspecResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponseProofResolver for WosFormspecResolver {
    fn resolve(
        &self,
        payload_bytes: &[u8],
    ) -> Result<Option<CertificateResponseProof>, ResolverError> {
        let Ok(value) = decode_cbor_value(payload_bytes) else {
            return Ok(None);
        };
        let Some(map) = value.as_map() else {
            return Ok(None);
        };
        let Ok(data) = map_lookup_map(map, "data") else {
            return Ok(None);
        };
        if let Ok(algorithm) = map_lookup_text(data, "signedPayloadDigestAlgorithm")
            && algorithm == "sha-256"
            && let Ok(digest) = map_lookup_text(data, "signedPayloadDigest")
        {
            return match parse_sha256_hex(&digest) {
                Some(response_hash) => Ok(Some(CertificateResponseProof { response_hash })),
                None => Err(ResolverError::MalformedResponseDigest(format!(
                    "signedPayloadDigest {digest:?} does not match sha-256 hex format \
                     (expected 64 hex chars)"
                ))),
            };
        }
        let Ok(response_ref) = map_lookup_text(data, "formspecResponseRef") else {
            return Ok(None);
        };
        Ok(parse_sha256_text(&response_ref)
            .map(|response_hash| CertificateResponseProof { response_hash }))
    }

    fn resolve_principal_ref(&self, payload_bytes: &[u8]) -> Option<String> {
        let value = decode_cbor_value(payload_bytes).ok()?;
        let map = value.as_map()?;
        let data = map_lookup_map(map, "data").ok()?;
        map_lookup_text(data, "signerId").ok()
    }
}

fn parse_sha256_text(value: &str) -> Option<[u8; 32]> {
    let hex = value.strip_prefix("sha256:")?;
    parse_sha256_hex(hex)
}

fn parse_sha256_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = value.as_bytes();
    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        out[i] = (high << 4) | low;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
