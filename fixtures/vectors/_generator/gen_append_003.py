"""Generate byte-exact reference vector `append/003-external-payload-ref`.

Authoring aid only. Every construction block carries an inline Core-§ citation
naming the normative paragraph that determines the bytes. This script is NOT
normative; `derivation.md` is the spec-prose reproduction evidence. If this
script and Core disagree, Core wins.

Determinism: two runs of this script produce byte-identical output. No
randomness, no wall-clock reads, no environment lookups beyond pinned inputs.

Scope decision: this is the **first `PayloadExternal` vector** (Core §6.4).
Where 001 pinned `PayloadInline` (embedded opaque ciphertext bstr), 003 pins
`PayloadExternal` — a distinct wire shape carrying `{ref_type, content_hash,
availability, retrieval_hint}` instead of embedded ciphertext. The external
ciphertext bytes live in `_inputs/sample-external-payload-003.bin` so the
vector bundle is self-contained (§19 step 4g exercises the InExport branch —
the verifier can locate the bytes named by `payload_ref`).

Three load-bearing properties pinned by this vector:

  * #4 (§6.4, §9.3) — `content_hash` is computed over the **ciphertext bytes
    named by `payload_ref`**, regardless of whether those bytes live inline
    or externally. 003 proves byte-by-byte that the hashing construction does
    not depend on payload location.

  * #8 partial (§6.4) — `PayloadExternal.content_hash` MUST equal
    `EventPayload.content_hash` (Core §6.4: "For PayloadExternal,
    EventPayload.content_hash MUST equal PayloadExternal.content_hash").
    The commitment/reference slot in the envelope header is populated, not
    left empty — the "reserved slots stay reserved when payload is off-graph"
    claim of invariant #8.

  * #13 (§17.2, §17.3) — idempotency key distinct from 001/005 under the
    same ledger scope so the `(ledger_scope, idempotency_key)` identity
    resolves to a different canonical event.

Genesis choice: 003 is **genesis** (`sequence = 0`, `prev_hash = null`). This
keeps the vector focused on the `PayloadExternal` wire shape. Non-genesis
chain-linkage is already exercised by 005; co-exercising it here would dilute
the single-variation discipline.

`availability = InExport (0)`: chosen so the ciphertext bytes are present in
the fixture bundle. This is the cleanest test of the integrity-verified path
(§19 step 4g's "if bytes exist, hash and compare" branch). Later vectors may
exercise `External`, `Withheld`, or `Unavailable` to cover the
`omitted_payload_checks` branch of §19 step 4g.

`retrieval_hint = null`: no retrieval hint is needed for `InExport`
(retrieval hint is a `tstr / null` per §6.4 CDDL; null is shorter and
sufficient when the bytes are in-bundle).

Extraction decision: same as gen_append_005 — this script duplicates the
dCBOR / domain-separation / COSE-assembly helpers from gen_append_001.py
inline rather than importing from a shared `_generator/_lib/`. Rationale: 003
is still early in the vector series, and keeping it a self-contained reading
of Core (rather than a consumer of an internal library) preserves the G-5
stranger-test discipline named in the fixture-system design. When a fourth
append vector lands, a narrow extraction becomes worth the cost; at three
generators it is not.
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
# Pinned inputs. Paths mirror gen_append_001 / gen_append_005 so the three
# generators can be diffed side by side.
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent           # fixtures/vectors/
KEY_FILE = ROOT / "_keys" / "issuer-001.cose_key"
# Distinct 64-byte external payload so content_hash differs meaningfully from
# 001/005's inline content_hash. Bytes live in `_inputs/` so they're resolvable
# within the fixture bundle (InExport availability branch of §19 step 4g).
PAYLOAD_FILE = ROOT / "_inputs" / "sample-external-payload-003.bin"
OUT_DIR = ROOT / "append" / "003-external-payload-ref"

# Event-level pinned values.
# Same `ledger_scope` as 001/005 so all three vectors cohabit the same logical
# scope identity space; idempotency keys distinguish them per §17.3.
LEDGER_SCOPE = b"test-response-ledger"                  # bstr, §10.6 AppendHead CDDL
SEQUENCE = 0                                            # genesis event, §10.2
TIMESTAMP = ts(1745000003)                                # +3s vs 001 for narrative clarity
EVENT_TYPE = b"x-trellis-test/append-external"          # §14.6 reserved test prefix
CLASSIFICATION = b"x-trellis-test/unclassified"         # §14.6; inherited from 001
RETENTION_TIER = 0                                      # §12.1; plaintext

# §17.2 idempotency_key MUST be distinct from 001/005 under the same scope or
# §17.3's `(ledger_scope, idempotency_key)` identity rule would force 003 to
# resolve to one of the prior canonical events rather than to its own.
# 001 pinned `b"idemp-append-001"`; 005 pinned `b"idemp-append-005"`;
# 003 pins `b"idemp-append-003"` (same 16-byte length, same .size (1..64)).
IDEMPOTENCY_KEY = b"idemp-append-003"
assert len(IDEMPOTENCY_KEY) == 16

# PayloadExternal-specific pinned values.
# §6.4 CDDL:
#   PayloadExternal = {
#     ref_type:       "external",
#     content_hash:   digest,
#     availability:   AvailabilityHint,
#     retrieval_hint: tstr / null,
#   }
# §6.4 AvailabilityHint: InExport=0, External=1, Withheld=2, Unavailable=3.
# InExport is the cleanest test of the structure+integrity path: the
# ciphertext bytes are in `_inputs/`, so §19 step 4g's "bytes exist → hash
# and compare" branch runs.
PAYLOAD_AVAILABILITY = 0                                # InExport, §6.4
PAYLOAD_RETRIEVAL_HINT = None                           # tstr / null, §6.4; null for InExport

# Phase 1 signature suite: Ed25519 / COSE_Sign1, §7.1.
SUITE_ID = 1
ALG_EDDSA = -8                                          # COSE alg, §7.1
COSE_LABEL_ALG = 1                                      # §7.4, per RFC 9052 §3.1
COSE_LABEL_KID = 4                                      # §7.4, per RFC 9052 §3.1
COSE_LABEL_SUITE_ID = -65537                            # §7.4, Trellis-reserved
COSE_LABEL_ARTIFACT_TYPE = -65538
ARTIFACT_TYPE_EVENT = "event"
ARTIFACT_TYPE_CHECKPOINT = "checkpoint"
ARTIFACT_TYPE_MANIFEST = "manifest"

# Domain-separation tags, §9.8 registry.
TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"               # §9.2
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1" # §9.5
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"           # §9.3


# ---------------------------------------------------------------------------
# dCBOR (RFC 8949 §4.2.2, Core §5.1). Identical discipline to 001 / 005.
# ---------------------------------------------------------------------------

def dcbor(value: object) -> bytes:
    return cbor2.dumps(value, canonical=True)


# ---------------------------------------------------------------------------
# §9.1 domain separation discipline. Identical to 001 / 005.
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
# Load pinned signing key. §8.2 SigningKeyEntry.pubkey is raw key bytes.
# Same issuer as 001 / 005; no key rotation (that is 002's scope).
# ---------------------------------------------------------------------------

def load_issuer_key() -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    seed = cose_key[-4]         # COSE_Key label -4 = 'd' (private key / seed)
    pubkey = cose_key[-2]       # COSE_Key label -2 = 'x' (public key)
    assert len(seed) == 32 and len(pubkey) == 32
    return seed, pubkey


# ---------------------------------------------------------------------------
# §8.3 Derived kid construction. Identical to 001 / 005 — same key, same
# suite, same output 16 bytes.
# ---------------------------------------------------------------------------

def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    suite_id_dcbor = dcbor(suite_id)                    # §5.1: uint 1 → 0x01
    return hashlib.sha256(suite_id_dcbor + pubkey_raw).digest()[:16]


# ---------------------------------------------------------------------------
# CDDL struct builders. §12.1 EventHeader / §9.4 KeyBag identical in shape
# to 001. §6.4 PayloadExternal replaces PayloadInline — that is the
# load-bearing delta of this vector.
# ---------------------------------------------------------------------------

def build_event_header() -> dict:
    # §12.1 EventHeader.
    return {
        "event_type":             EVENT_TYPE,
        "authored_at":            TIMESTAMP,
        "retention_tier":         RETENTION_TIER,
        "classification":         CLASSIFICATION,
        "outcome_commitment":     None,
        "subject_ref_commitment": None,
        "tag_commitment":         None,
        "witness_ref":            None,
        "extensions":             None,
    }


def build_payload_ref_external(content_hash: bytes) -> dict:
    # §6.4 PayloadExternal. The ref_type tag "external" discriminates the
    # variant from PayloadInline ("inline"). `content_hash` is the 32-byte
    # digest from the `trellis-content-v1` construction over the external
    # ciphertext bytes (§9.3); it MUST equal the sibling EventPayload-level
    # content_hash field per §6.4 ("For PayloadExternal,
    # EventPayload.content_hash MUST equal PayloadExternal.content_hash").
    # `availability = InExport (0)` per §6.4 AvailabilityHint enum.
    # `retrieval_hint = null` — not needed for InExport.
    return {
        "ref_type":       "external",
        "content_hash":   content_hash,
        "availability":   PAYLOAD_AVAILABILITY,
        "retrieval_hint": PAYLOAD_RETRIEVAL_HINT,
    }


def build_key_bag() -> dict:
    # §9.4 KeyBag. Structural-only vector: empty entries list. CDDL `[*]`
    # admits zero entries. HPKE wrap is exercised by 004, not here.
    return {"entries": []}


def build_author_event_hash_preimage(
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
) -> dict:
    # §9.5 / Appendix A AuthorEventHashPreimage. Shape identical to 001;
    # `payload_ref` now carries a PayloadExternal tagged struct instead of
    # PayloadInline.
    return {
        "version":         1,                           # §6.1 wire-format version
        "ledger_scope":    LEDGER_SCOPE,
        "sequence":        SEQUENCE,
        "prev_hash":       None,                        # §10.2: null iff sequence == 0
        "causal_deps":     None,                        # §10.3: null in Phase 1
        "content_hash":    content_hash,
        "header":          header,
        "commitments":     None,                        # §13.3
        "payload_ref":     payload_ref,
        "key_bag":         key_bag,
        "idempotency_key": IDEMPOTENCY_KEY,
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
# §7.4 Protected-header map and RFC 9052 §4.4 Sig_structure. Identical to
# 001 / 005.
# ---------------------------------------------------------------------------

def build_protected_header(kid: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> dict:
    return {
        COSE_LABEL_ALG:      ALG_EDDSA,
        COSE_LABEL_KID:      kid,
        COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
    }


def build_sig_structure(protected_bstr: bytes, payload_bstr: bytes) -> bytes:
    # RFC 9052 §4.4: ["Signature1", protected, external_aad, payload];
    # Core §6.6 pins external_aad = h'' (zero-length) for Phase 1.
    return dcbor(["Signature1", protected_bstr, b"", payload_bstr])


# ---------------------------------------------------------------------------
# §10.6 AppendHead builder.
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

    # 1. Load signing key (same issuer as 001/005; no rotation here).
    seed, pubkey_raw = load_issuer_key()

    # 2. Derive kid per §8.3. Same inputs as 001/005 → same 16 bytes.
    kid = derive_kid(SUITE_ID, pubkey_raw)

    # 3. Load pinned external payload plaintext. These bytes ARE the
    #    ciphertext named by `payload_ref.content_hash` for the purpose of
    #    §9.3's "exact ciphertext bytes named by payload_ref" — this vector
    #    is structural-only for the cryptographic layer (same convention as
    #    001). A production implementation would AEAD-encrypt plaintext and
    #    the resulting bytes would be stored externally at the location
    #    `retrieval_hint` identifies; in 003 the bytes live at
    #    `../../_inputs/sample-external-payload-003.bin` and the
    #    availability hint is `InExport`.
    payload_bytes = PAYLOAD_FILE.read_bytes()
    assert len(payload_bytes) == 64

    # 4. content_hash over the (external, opaque) ciphertext bytes per §9.3 + §9.1.
    #    Same construction as 001 / 005 — the hash discipline is invariant
    #    under payload location (that is the load-bearing claim of #4 when
    #    externalised).
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_bytes)

    # 5. Build authored-form map (§6.8 / §9.5 AuthorEventHashPreimage) with
    #    PayloadExternal payload_ref, serialize, commit.
    header = build_event_header()
    payload_ref = build_payload_ref_external(content_hash)
    # §6.4: PayloadExternal.content_hash MUST equal EventPayload.content_hash.
    # The generator asserts this equality explicitly at build time so a
    # reviewer diffing the script sees the invariant stated.
    assert payload_ref["content_hash"] == content_hash, (
        "§6.4: PayloadExternal.content_hash MUST equal EventPayload.content_hash"
    )
    key_bag = build_key_bag()
    authored_map = build_author_event_hash_preimage(
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
    )
    authored_bytes = dcbor(authored_map)
    write_bytes("input-author-event-hash-preimage.cbor", authored_bytes)

    # 6. author_event_hash preimage bytes (§9.5 + §9.1) + digest.
    author_event_preimage = domain_separated_preimage(
        TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes,
    )
    write_bytes("author-event-preimage.bin", author_event_preimage)
    author_event_hash = hashlib.sha256(author_event_preimage).digest()
    assert len(author_event_hash) == 32
    write_bytes("author-event-hash.bin", author_event_hash)

    # 7. Build canonical-form map (§6.8 / §6.1 EventPayload), serialize, commit.
    event_payload = build_event_payload(
        author_event_hash=author_event_hash,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
    )
    event_payload_bytes = dcbor(event_payload)
    write_bytes("expected-event-payload.cbor", event_payload_bytes)

    # 8. Build COSE protected header; serialize as dCBOR.
    protected_map = build_protected_header(kid)
    protected_map_bytes = dcbor(protected_map)

    # 9. Sig_structure per RFC 9052 §4.4 (invoked by §7.4 step 5).
    sig_structure = build_sig_structure(protected_map_bytes, event_payload_bytes)
    write_bytes("sig-structure.bin", sig_structure)

    # 10. Ed25519 sign the Sig_structure bytes. §7.1.
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    signature = sk.sign(sig_structure)
    assert len(signature) == 64

    # 11. Assemble COSE_Sign1 tag-18 wire envelope (§6.1, §6.8 signed form,
    #     §7.4). Payload embedded per §6.1.
    unprotected: dict = {}
    cose_sign1 = cbor2.CBORTag(
        18,
        [protected_map_bytes, unprotected, event_payload_bytes, signature],
    )
    cose_sign1_bytes = dcbor(cose_sign1)
    write_bytes("expected-event.cbor", cose_sign1_bytes)

    # 12. canonical_event_hash per §9.2 + §9.1 over dCBOR(CanonicalEventHashPreimage).
    canonical_preimage_struct = build_canonical_event_hash_preimage(event_payload)
    canonical_preimage_bytes = dcbor(canonical_preimage_struct)
    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1, canonical_preimage_bytes,
    )

    # 13. AppendHead per §10.6 for the post-append state.
    append_head = build_append_head(LEDGER_SCOPE, SEQUENCE, canonical_event_hash)
    append_head_bytes = dcbor(append_head)
    write_bytes("expected-append-head.cbor", append_head_bytes)

    print()
    print(f"  kid                          = {kid.hex()}")
    print(f"  content_hash                 = {content_hash.hex()}")
    print(f"  author_event_hash            = {author_event_hash.hex()}")
    print(f"  canonical_event_hash         = {canonical_event_hash.hex()}")
    print(f"  protected_header_map_bytes   = {protected_map_bytes.hex()}")
    print(f"  signature (Ed25519, 64 B)    = {signature.hex()}")


if __name__ == "__main__":
    main()
