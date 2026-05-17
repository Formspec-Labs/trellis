"""Generate byte-exact reference vector `append/001-minimal-inline-payload`.

Authoring aid only. Every construction block carries an inline Core-§ citation
naming the normative paragraph that determines the bytes. This script is NOT
normative; `derivation.md` is the spec-prose reproduction evidence. If this
script and Core disagree, Core wins.

Determinism: two runs of this script produce byte-identical output. No randomness,
no wall-clock reads, no environment lookups beyond pinned inputs.

Scope decision: this first vector is **structural-only** for the payload layer.
Per Core §9.4, production wraps MUST use a fresh X25519 ephemeral keypair per
recipient; this vector exercises the `append` surface (authored/canonical/signed
event surfaces per §6.8, author_event_hash per §9.5, canonical_event_hash per
§9.2, AppendHead per §10.6) without exercising HPKE wrap. The `PayloadInline`
ciphertext field carries the pinned 64-byte payload bytes directly as opaque
bytes; `KeyBag.entries` is the empty list (CDDL `[*]` admits zero entries).
A later vector in the append/ series will exercise real HPKE wrap with pinned
ephemeral keys. `derivation.md` declares this scope explicitly.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cbor2  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from _lib.byte_utils import ts  # noqa: E402

# ---------------------------------------------------------------------------
# Pinned inputs (see `fixtures/vectors/_keys/`, `_inputs/`, and task brief).
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent           # fixtures/vectors/
KEY_FILE = ROOT / "_keys" / "issuer-001.cose_key"
PAYLOAD_FILE = ROOT / "_inputs" / "sample-payload-001.bin"
OUT_DIR = ROOT / "append" / "001-minimal-inline-payload"

# Event-level pinned values.
LEDGER_SCOPE = b"test-response-ledger"                  # bstr, §10.6 AppendHead CDDL
SEQUENCE = 0                                            # genesis event, §10.2
TIMESTAMP = ts(1745000000)                                # Unix seconds UTC, §12.1 authored_at
EVENT_TYPE = b"x-trellis-test/append-minimal"           # §14.6 reserved test prefix
CLASSIFICATION = b"x-trellis-test/unclassified"         # §14.6 reserved test prefix
RETENTION_TIER = 0                                      # §12.1; plaintext
IDEMPOTENCY_KEY = b"idemp-append-001" + b"\x00" * 0     # 16 bytes, §6.1 .size (1..64)
assert len(IDEMPOTENCY_KEY) == 16

# PayloadInline-specific pinned values.
# 12-byte nonce per §6.4 (bstr .size 12). Pinned all-zero for reproducibility;
# structural-only vector does not decrypt so nonce value is not
# cryptographically load-bearing.
PAYLOAD_NONCE = b"\x00" * 12

# Phase 1 signature suite: Ed25519 / COSE_Sign1, §7.1.
SUITE_ID = 1
ALG_EDDSA = -8                                          # COSE alg, §7.1
COSE_LABEL_ALG = 1                                      # §7.4, per RFC 9052 §3.1
COSE_LABEL_KID = 4                                      # §7.4, per RFC 9052 §3.1
COSE_LABEL_SUITE_ID = -65537                            # §7.4, Trellis-reserved
COSE_LABEL_ARTIFACT_TYPE = -65538                       # §7.4 / ADR 0109, Trellis substrate role
ARTIFACT_TYPE_EVENT = "event"                           # ADR 0109 closed substrate role

# Domain-separation tags, §9.8 registry.
TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"               # §9.2
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1" # §9.5
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"           # §9.3


# ---------------------------------------------------------------------------
# dCBOR (RFC 8949 §4.2.2, Core §5.1).
# cbor2.dumps(..., canonical=True) selects the Core Deterministic Encoding
# profile: smallest integer representation, byte-wise lexicographic map-key
# ordering of canonical CBOR key encodings, definite-length items, no duplicate
# keys. This matches §5.1's requirements for every byte emitted below.
# ---------------------------------------------------------------------------

def dcbor(value: object) -> bytes:
    return cbor2.dumps(value, canonical=True)


# ---------------------------------------------------------------------------
# §9.1 domain separation discipline.
# digest = SHA-256(
#     len(tag)       as 4-byte big-endian unsigned ||
#     tag            as UTF-8 bytes ||
#     len(component) as 4-byte big-endian unsigned ||
#     component      as raw bytes
# )
# Multi-component inputs repeat len||component for each component in fixed
# order. For a single-component preimage, a single len||component pair suffices.
# ---------------------------------------------------------------------------

def domain_separated_preimage(tag: str, component: bytes) -> bytes:
    tag_bytes = tag.encode("utf-8")
    return (
        len(tag_bytes).to_bytes(4, "big")
        + tag_bytes
        + len(component).to_bytes(4, "big")
        + component
    )


def domain_separated_sha256(tag: str, component: bytes) -> bytes:
    return hashlib.sha256(domain_separated_preimage(tag, component)).digest()


# ---------------------------------------------------------------------------
# Load pinned signing key (COSE_Key, Ed25519). §8.2 SigningKeyEntry.pubkey is
# raw key bytes per suite_id; §7.1 pins Phase 1 to Ed25519 with 32-byte raw
# public key per RFC 8032.
# ---------------------------------------------------------------------------

def load_issuer_key() -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    seed = cose_key[-4]         # COSE_Key label -4 = 'd' (private key / seed)
    pubkey = cose_key[-2]       # COSE_Key label -2 = 'x' (public key)
    assert len(seed) == 32 and len(pubkey) == 32
    return seed, pubkey


# ---------------------------------------------------------------------------
# §8.3 Derived kid construction (pinned).
# kid = SHA-256(dCBOR_encode_uint(suite_id) || pubkey_raw)[0..16]
# For suite_id = 1, dCBOR encodes the unsigned integer 1 as the single byte
# 0x01 (smallest representation, §5.1). pubkey_raw is the 32-byte Ed25519 x
# coordinate. Byte order is fixed: suite_id bytes first, then pubkey bytes.
# ---------------------------------------------------------------------------

def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    suite_id_dcbor = dcbor(suite_id)                    # §5.1: uint 1 → 0x01
    return hashlib.sha256(suite_id_dcbor + pubkey_raw).digest()[:16]


# ---------------------------------------------------------------------------
# CDDL struct builders. Order of Python-dict insertion does not affect output
# bytes because dcbor() applies dCBOR canonical ordering to every map.
# ---------------------------------------------------------------------------

def build_event_header() -> dict:
    # §12.1 EventHeader.
    return {
        "event_type":             EVENT_TYPE,
        "authored_at":            TIMESTAMP,
        "retention_tier":         RETENTION_TIER,
        "classification":         CLASSIFICATION,
        # §12.2: Phase 1 outcome_commitment / subject_ref_commitment /
        # tag_commitment are digest / null. Null for this vector (no commitments).
        "outcome_commitment":     None,
        "subject_ref_commitment": None,
        "tag_commitment":         None,
        # §12.1 witness_ref: reserved Phase 4; null in Phase 1.
        "witness_ref":            None,
        # §12.3 extensions: null or empty map; §6.7 Phase 1 emission rule. null
        # is the shorter encoding and is explicitly admitted by the CDDL.
        "extensions":             None,
    }


def build_payload_ref(ciphertext: bytes) -> dict:
    # §6.4 PayloadInline.
    return {
        "ref_type":   "inline",
        "ciphertext": ciphertext,
        "nonce":      PAYLOAD_NONCE,                    # §6.4 bstr .size 12
    }


def build_key_bag() -> dict:
    # §9.4 KeyBag. Structural-only vector: empty entries list. CDDL `[*]`
    # admits zero entries. See file docstring for rationale.
    return {"entries": []}


def build_author_event_hash_preimage(
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
) -> dict:
    # §9.5 / Appendix A AuthorEventHashPreimage.
    # Excludes author_event_hash and all signature material by construction.
    return {
        "version":         1,                           # §6.1 wire-format version
        "ledger_scope":    LEDGER_SCOPE,
        "sequence":        SEQUENCE,
        "prev_hash":       None,                        # §10.2: null iff sequence == 0
        "causal_deps":     None,                        # §10.3: null in Phase 1
        "content_hash":    content_hash,
        "header":          header,
        "commitments":     None,                        # §13.3: null or [] in Phase 1
        "payload_ref":     payload_ref,
        "key_bag":         key_bag,
        "idempotency_key": IDEMPOTENCY_KEY,             # §6.1 bstr .size (1..64)
        "extensions":      None,                        # §6.5 Phase 1 emission rule
    }


def build_event_payload(
    author_event_hash: bytes,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
) -> dict:
    # §6.1 EventPayload. Same fields as AuthorEventHashPreimage plus
    # author_event_hash. No signature bytes (signing is external, §6.6).
    return {
        "version":           1,
        "ledger_scope":      LEDGER_SCOPE,
        "sequence":          SEQUENCE,
        "prev_hash":         None,
        "causal_deps":       None,
        "author_event_hash": author_event_hash,
        "content_hash":      content_hash,
        "header":            header,
        "commitments":       None,
        "payload_ref":       payload_ref,
        "key_bag":           key_bag,
        "idempotency_key":   IDEMPOTENCY_KEY,
        "extensions":        None,
    }


def build_canonical_event_hash_preimage(event_payload: dict) -> dict:
    # §9.2 / Appendix A CanonicalEventHashPreimage.
    return {
        "version":       1,
        "ledger_scope":  LEDGER_SCOPE,
        "event_payload": event_payload,
    }


# ---------------------------------------------------------------------------
# §7.4 Protected-header map and RFC 9052 §4.4 Sig_structure.
# ---------------------------------------------------------------------------

def build_protected_header(kid: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> dict:
    # Four mandatory substrate headers per §7.4 / ADR 0109. dCBOR
    # serialization (map-key canonical order) is applied at encode time.
    return {
        COSE_LABEL_ALG:      ALG_EDDSA,
        COSE_LABEL_KID:      kid,
        COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
    }


def build_sig_structure(protected_bstr: bytes, payload_bstr: bytes) -> bytes:
    # RFC 9052 §4.4 Sig_structure for COSE_Sign1:
    #   ["Signature1", protected, external_aad, payload]
    # Per §6.6 external_aad is the zero-length byte string for Phase 1.
    return dcbor(["Signature1", protected_bstr, b"", payload_bstr])


# ---------------------------------------------------------------------------
# §10.6 AppendHead.
# ---------------------------------------------------------------------------

def build_append_head(scope: bytes, sequence: int, canonical_event_hash: bytes) -> dict:
    return {
        "scope":                scope,
        "sequence":             sequence,
        "canonical_event_hash": canonical_event_hash,
    }


# ---------------------------------------------------------------------------
# Write + report helper.
# ---------------------------------------------------------------------------

def write_bytes(name: str, data: bytes) -> None:
    path = OUT_DIR / name
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"  {name:45s}  {len(data):>5d} bytes  sha256={digest}")


# ---------------------------------------------------------------------------
# Main pipeline.
# ---------------------------------------------------------------------------

def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"generating vector at {OUT_DIR.relative_to(ROOT.parent.parent)}/")

    # 1. Load signing key.
    seed, pubkey_raw = load_issuer_key()

    # 2. Derive kid per §8.3.
    kid = derive_kid(SUITE_ID, pubkey_raw)

    # 3. Load pinned payload plaintext. For the structural-only vector, these
    #    bytes are used directly as the PayloadInline.ciphertext bstr; the
    #    vector does not exercise HPKE wrap (see file docstring + derivation.md).
    payload_bytes = PAYLOAD_FILE.read_bytes()
    assert len(payload_bytes) == 64

    # 4. content_hash over the (opaque) ciphertext bytes per §9.3 + §9.1.
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_bytes)

    # 5. Build authored-form map (§6.8 / §9.5 AuthorEventHashPreimage), serialize,
    #    commit as `input-author-event-hash-preimage.cbor`.
    header = build_event_header()
    payload_ref = build_payload_ref(payload_bytes)
    key_bag = build_key_bag()
    authored_map = build_author_event_hash_preimage(
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
    )
    authored_bytes = dcbor(authored_map)
    write_bytes("input-author-event-hash-preimage.cbor", authored_bytes)

    # 6. author_event_hash preimage bytes (§9.5 + §9.1). Commit.
    author_event_preimage = domain_separated_preimage(
        TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes,
    )
    write_bytes("author-event-preimage.bin", author_event_preimage)

    # 7. SHA-256 → author_event_hash. Commit.
    author_event_hash = hashlib.sha256(author_event_preimage).digest()
    assert len(author_event_hash) == 32
    write_bytes("author-event-hash.bin", author_event_hash)

    # 8. Build canonical-form map (§6.8 / §6.1 EventPayload), serialize,
    #    commit as `expected-event-payload.cbor`. This is the bstr that will
    #    become the COSE_Sign1 payload.
    event_payload = build_event_payload(
        author_event_hash=author_event_hash,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
    )
    event_payload_bytes = dcbor(event_payload)
    write_bytes("expected-event-payload.cbor", event_payload_bytes)

    # 9. Build COSE protected header and serialize as dCBOR; wrap in bstr per
    #    RFC 9052 §3 (the "protected bstr"). §7.4 mandates dCBOR ordering of
    #    the map bytes.
    protected_map = build_protected_header(kid)
    protected_map_bytes = dcbor(protected_map)

    # 10. Sig_structure per RFC 9052 §4.4 (invoked by Core §7.4 step 5).
    sig_structure = build_sig_structure(protected_map_bytes, event_payload_bytes)
    write_bytes("sig-structure.bin", sig_structure)

    # 11. Ed25519 sign the Sig_structure bytes. §7.1 alg = -8 EdDSA; RFC 8032
    #     Ed25519 signs the input bytes directly (no pre-hash, "pure" Ed25519).
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    signature = sk.sign(sig_structure)
    assert len(signature) == 64                         # Ed25519 signature size

    # 12. Assemble COSE_Sign1 tag-18 wire envelope (§6.1, §6.8 signed form,
    #     §7.4). RFC 9052 §4.2: COSE_Sign1 = [protected_bstr, unprotected_map,
    #     payload_or_nil, signature_bstr], CBOR-tagged with tag 18.
    #     Payload is embedded (§6.1 "whose payload is the dCBOR encoding of
    #     EventPayload"), not detached.
    unprotected = {}                                    # no unprotected headers
    cose_sign1 = cbor2.CBORTag(
        18,
        [protected_map_bytes, unprotected, event_payload_bytes, signature],
    )
    cose_sign1_bytes = dcbor(cose_sign1)
    write_bytes("expected-event.cbor", cose_sign1_bytes)

    # 13. canonical_event_hash per §9.2 + §9.1 over dCBOR(CanonicalEventHashPreimage).
    canonical_preimage_struct = build_canonical_event_hash_preimage(event_payload)
    canonical_preimage_bytes = dcbor(canonical_preimage_struct)
    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1, canonical_preimage_bytes,
    )

    # 14. Build AppendHead per §10.6, serialize, commit.
    append_head = build_append_head(LEDGER_SCOPE, SEQUENCE, canonical_event_hash)
    append_head_bytes = dcbor(append_head)
    write_bytes("expected-append-head.cbor", append_head_bytes)

    # Informational: print derived intermediates (not committed on disk — the
    # committed files are sufficient for byte-exact review).
    print()
    print(f"  kid                          = {kid.hex()}")
    print(f"  content_hash                 = {content_hash.hex()}")
    print(f"  author_event_hash            = {author_event_hash.hex()}")
    print(f"  canonical_event_hash         = {canonical_event_hash.hex()}")
    print(f"  protected_header_map_bytes   = {protected_map_bytes.hex()}")
    print(f"  signature (Ed25519, 64 B)    = {signature.hex()}")


if __name__ == "__main__":
    main()
