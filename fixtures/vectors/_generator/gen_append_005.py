"""Generate byte-exact reference vector `append/005-prior-head-chain`.

Authoring aid only. Every construction block carries an inline Core-§ citation
naming the normative paragraph that determines the bytes. This script is NOT
normative; `derivation.md` is the spec-prose reproduction evidence. If this
script and Core disagree, Core wins.

Determinism: two runs of this script produce byte-identical output. No
randomness, no wall-clock reads, no environment lookups beyond pinned inputs.

Scope decision: this is the **first non-genesis** vector (`sequence = 1`), the
cheapest derivation that exercises Core §10.2 `prev_hash` linkage with
non-trivial content. It pins three invariants that the genesis vector (001)
cannot reach:

  * #5  — exactly one canonical order per ledger scope (§10.1 + §10.2)
  * #10 — Phase-1 envelope = Phase-3 case-ledger event (§10 strict superset);
          #10 has non-trivial content only once `sequence > 0`
  * #13 — append idempotency (§17.2/§17.3), via a distinct `idempotency_key`
          relative to vector 001 under the same `(ledger_scope, key)` space

All other constructions (authored / canonical / signed surfaces per §6.8,
author_event_hash per §9.5, canonical_event_hash per §9.2, COSE_Sign1 per §7.4,
AppendHead per §10.6) are identical in shape to 001; only the fields §10.2
requires to change at `sequence > 0` and the idempotency key differ. Payload
shape is intentionally copied from 001 (64-byte inline, empty KeyBag) so that
the derivation.md focuses on the chain-linkage semantics rather than
re-deriving payload plumbing already covered by 001.

Extraction decision: this script duplicates the dCBOR / domain-separation /
COSE-assembly helpers from `gen_append_001.py` inline rather than importing
from a shared `_generator/_lib/`. Rationale: 005 is the first non-genesis
vector, and keeping it a self-contained reading of Core (rather than a
consumer of an internal library) preserves the G-5 stranger-test discipline
named in the fixture-system design ("Spec-interpretive code ... is
hand-written in the generator with inline Core § citations"). When a third
and fourth append vector land, an `_generator/_lib/` extraction of the
narrow byte-level utilities (dcbor / domain_separated_preimage) becomes
worth the cost; at two generators it is not.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

# Sibling `_lib` package import. See `_lib/byte_utils.py` for the narrow
# set of shared helpers (dcbor, domain_separated_sha256, COSE constants)
# that were duplicated verbatim across this generator, gen_export_001, and
# gen_verify_negative_export_001 before the extraction landed.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import cbor2  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from _lib.byte_utils import (  # noqa: E402
    ALG_EDDSA,
    COSE_LABEL_ALG,
    COSE_LABEL_KID,
    COSE_LABEL_SUITE_ID,
    ARTIFACT_TYPE_CHECKPOINT,
    ARTIFACT_TYPE_EVENT,
    ARTIFACT_TYPE_MANIFEST,
    COSE_LABEL_ARTIFACT_TYPE,
    SUITE_ID_PHASE_1,
    dcbor,
    domain_separated_sha256,
    ts,
)

# ---------------------------------------------------------------------------
# Pinned inputs. Paths mirror `gen_append_001.py` so the two generators can be
# diffed side by side to see exactly what changed at `sequence > 0`.
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent           # fixtures/vectors/
KEY_FILE = ROOT / "_keys" / "issuer-001.cose_key"
PAYLOAD_FILE = ROOT / "_inputs" / "sample-payload-001.bin"
PRIOR_VECTOR_DIR = ROOT / "append" / "001-minimal-inline-payload"
OUT_DIR = ROOT / "append" / "005-prior-head-chain"

# Event-level pinned values. Same ledger_scope as 001 — that is load-bearing:
# §10.2 `prev_hash` linkage is per-scope, so 005 and 001 MUST share `ledger_scope`
# for the chain-linkage claim to have content. All other "event identity"
# fields that §10.2 does not pin (event_type, classification, timestamp) are
# inherited from 001 so the derivation.md can focus on the §10.2 delta.
LEDGER_SCOPE = b"test-response-ledger"                  # bstr, §10.6; equal to 001's
SEQUENCE = 1                                            # §10.2: `sequence > 0`
TIMESTAMP = ts(1745000001)                              # +1s vs 001 for narrative clarity
EVENT_TYPE = b"x-trellis-test/append-minimal"           # §14.6; inherited from 001
CLASSIFICATION = b"x-trellis-test/unclassified"         # §14.6; inherited from 001
RETENTION_TIER = 0                                      # §12.1

# §17.2 idempotency_key MUST be distinct from 001's under the same scope or
# §17.3's `(ledger_scope, idempotency_key)` identity rule would force 005 to
# resolve to 001's canonical event rather than to a new sequence position.
# 001 pinned `b"idemp-append-001"`; 005 pins `b"idemp-append-005"` (same
# 16-byte length, same .size (1..64) envelope — §6.1).
IDEMPOTENCY_KEY = b"idemp-append-005"
assert len(IDEMPOTENCY_KEY) == 16

# PayloadInline-specific pinned values. Inherited from 001 without change.
PAYLOAD_NONCE = b"\x00" * 12                            # §6.4 bstr .size 12

# Phase 1 signature suite: Ed25519 / COSE_Sign1, §7.1. Issuer key NOT rotated;
# 005 is chain-linkage, not key-rotation (that is vector 002). ALG_EDDSA,
# COSE_LABEL_*, and SUITE_ID_PHASE_1 are imported from _lib.byte_utils.
SUITE_ID = SUITE_ID_PHASE_1

# Domain-separation tags, §9.8 registry.
TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"               # §9.2
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1" # §9.5
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"           # §9.3


# ---------------------------------------------------------------------------
# dCBOR and §9.1 domain_separated_sha256 are imported from _lib.byte_utils.
# `domain_separated_preimage` stays local because gen_append_005 is the only
# generator that needs the preimage bytes in isolation (for
# `author_event_preimage` construction); the other byte-level callers wrap
# it inside a hash.
# ---------------------------------------------------------------------------

def domain_separated_preimage(tag: str, component: bytes) -> bytes:
    tag_bytes = tag.encode("utf-8")
    return (
        len(tag_bytes).to_bytes(4, "big")
        + tag_bytes
        + len(component).to_bytes(4, "big")
        + component
    )


# ---------------------------------------------------------------------------
# Load pinned signing key. §8.2 SigningKeyEntry.pubkey is raw key bytes.
# ---------------------------------------------------------------------------

def load_issuer_key() -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    seed = cose_key[-4]         # COSE_Key label -4 = 'd' (private key / seed)
    pubkey = cose_key[-2]       # COSE_Key label -2 = 'x' (public key)
    assert len(seed) == 32 and len(pubkey) == 32
    return seed, pubkey


# ---------------------------------------------------------------------------
# §8.3 Derived kid construction (pinned). Identical to 001 — same key, same
# suite, same output 16 bytes.
# ---------------------------------------------------------------------------

def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    suite_id_dcbor = dcbor(suite_id)                    # §5.1: uint 1 → 0x01
    return hashlib.sha256(suite_id_dcbor + pubkey_raw).digest()[:16]


# ---------------------------------------------------------------------------
# Load the prior head per §10.6. 005's `prev_hash` is defined by §10.2 to
# equal the `canonical_event_hash` of the `sequence = N-1` event; §10.6 names
# the `AppendHead` artifact as the structural companion that carries that
# hash between calls. The author reads it from the prior AppendHead and
# writes it into 005's authored/canonical preimages.
# ---------------------------------------------------------------------------

def load_prior_canonical_event_hash() -> bytes:
    prior_head_path = PRIOR_VECTOR_DIR / "expected-append-head.cbor"
    prior_head = cbor2.loads(prior_head_path.read_bytes())
    # §10.6 AppendHead CDDL: {scope, sequence, canonical_event_hash}.
    # §10.2 requires prev_hash of event N = canonical_event_hash of event N-1
    # in the same scope; assert that shape here so a reviewer diffing the
    # generator sees the three preconditions stated explicitly.
    assert prior_head["scope"] == LEDGER_SCOPE, "prior head scope must equal 005's ledger_scope"
    assert prior_head["sequence"] == SEQUENCE - 1, "prior head sequence must equal 005.sequence - 1"
    assert len(prior_head["canonical_event_hash"]) == 32, "digest is 32 bytes (§9.2)"
    return prior_head["canonical_event_hash"]


# ---------------------------------------------------------------------------
# CDDL struct builders. §12.1 EventHeader / §6.4 PayloadInline / §9.4 KeyBag
# identical in shape to 001; only `authored_at` differs (narrative-only).
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


def build_payload_ref(ciphertext: bytes) -> dict:
    # §6.4 PayloadInline.
    return {
        "ref_type":   "inline",
        "ciphertext": ciphertext,
        "nonce":      PAYLOAD_NONCE,
    }


def build_key_bag() -> dict:
    # §9.4 KeyBag.
    return {"entries": []}


def build_author_event_hash_preimage(
    prev_hash: bytes,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
) -> dict:
    # §9.5 / Appendix A AuthorEventHashPreimage. The ONLY structural delta
    # vs 001 is `prev_hash`: `null` for genesis (§10.2 `sequence == 0`)
    # becomes the 32-byte digest bstr of the prior event's canonical_event_hash
    # (§10.2 `sequence == N > 0`).
    return {
        "version":         1,
        "ledger_scope":    LEDGER_SCOPE,
        "sequence":        SEQUENCE,
        "prev_hash":       prev_hash,                   # §10.2 `sequence > 0`
        "causal_deps":     None,                        # §10.3: null in Phase 1
        "content_hash":    content_hash,
        "header":          header,
        "commitments":     None,                        # §13.3
        "payload_ref":     payload_ref,
        "key_bag":         key_bag,
        "idempotency_key": IDEMPOTENCY_KEY,
        "extensions":      None,
    }


def build_event_payload(
    prev_hash: bytes,
    author_event_hash: bytes,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
) -> dict:
    # §6.1 EventPayload. Same fields as AuthorEventHashPreimage plus
    # author_event_hash.
    return {
        "version":           1,
        "ledger_scope":      LEDGER_SCOPE,
        "sequence":          SEQUENCE,
        "prev_hash":         prev_hash,
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
# §7.4 Protected-header map and RFC 9052 §4.4 Sig_structure. Identical to 001.
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
# §10.6 AppendHead builder. Identical shape to 001; `sequence` is now 1.
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

    # 1. Load signing key (same issuer as 001; no rotation here).
    seed, pubkey_raw = load_issuer_key()

    # 2. Derive kid per §8.3. Same inputs as 001 → same 16 bytes.
    kid = derive_kid(SUITE_ID, pubkey_raw)

    # 3. Load prior AppendHead per §10.6 and extract `prev_hash` per §10.2.
    #    Also copy the prior head file into 005's directory as an input
    #    artifact so the vector is self-contained for stranger-test review
    #    (the stranger does not have to walk sibling vectors to confirm the
    #    `prev_hash` linkage; the bytes they need are all present here).
    prev_hash = load_prior_canonical_event_hash()
    prior_head_bytes = (PRIOR_VECTOR_DIR / "expected-append-head.cbor").read_bytes()
    write_bytes("input-prior-append-head.cbor", prior_head_bytes)

    # 4. Load pinned payload plaintext; reuse 001's 64-byte payload opaquely.
    payload_bytes = PAYLOAD_FILE.read_bytes()
    assert len(payload_bytes) == 64

    # 5. content_hash over ciphertext bytes per §9.3 + §9.1. Identical to 001
    #    because the payload bytes and the tag are identical.
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_bytes)

    # 6. Build authored-form map (§6.8 / §9.5), serialize, commit.
    header = build_event_header()
    payload_ref = build_payload_ref(payload_bytes)
    key_bag = build_key_bag()
    authored_map = build_author_event_hash_preimage(
        prev_hash=prev_hash,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
    )
    authored_bytes = dcbor(authored_map)
    write_bytes("input-author-event-hash-preimage.cbor", authored_bytes)

    # 7. author_event_hash preimage bytes (§9.5 + §9.1) + digest.
    author_event_preimage = domain_separated_preimage(
        TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes,
    )
    write_bytes("author-event-preimage.bin", author_event_preimage)
    author_event_hash = hashlib.sha256(author_event_preimage).digest()
    assert len(author_event_hash) == 32
    write_bytes("author-event-hash.bin", author_event_hash)

    # 8. Build canonical-form map (§6.8 / §6.1), serialize, commit.
    event_payload = build_event_payload(
        prev_hash=prev_hash,
        author_event_hash=author_event_hash,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
    )
    event_payload_bytes = dcbor(event_payload)
    write_bytes("expected-event-payload.cbor", event_payload_bytes)

    # 9. Build COSE protected header; serialize as dCBOR.
    protected_map = build_protected_header(kid)
    protected_map_bytes = dcbor(protected_map)

    # 10. Sig_structure per RFC 9052 §4.4 (invoked by §7.4 step 5).
    sig_structure = build_sig_structure(protected_map_bytes, event_payload_bytes)
    write_bytes("sig-structure.bin", sig_structure)

    # 11. Ed25519 sign the Sig_structure bytes. §7.1.
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    signature = sk.sign(sig_structure)
    assert len(signature) == 64

    # 12. Assemble COSE_Sign1 tag-18 wire envelope (§6.1, §6.8 signed form,
    #     §7.4). Payload embedded per §6.1.
    unprotected: dict = {}
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

    # 14. AppendHead per §10.6 for the post-append state. `sequence = 1` is the
    #     load-bearing difference vs 001's AppendHead.
    append_head = build_append_head(LEDGER_SCOPE, SEQUENCE, canonical_event_hash)
    append_head_bytes = dcbor(append_head)
    write_bytes("expected-append-head.cbor", append_head_bytes)

    print()
    print(f"  prev_hash (from 001)         = {prev_hash.hex()}")
    print(f"  kid                          = {kid.hex()}")
    print(f"  content_hash                 = {content_hash.hex()}")
    print(f"  author_event_hash            = {author_event_hash.hex()}")
    print(f"  canonical_event_hash         = {canonical_event_hash.hex()}")
    print(f"  protected_header_map_bytes   = {protected_map_bytes.hex()}")
    print(f"  signature (Ed25519, 64 B)    = {signature.hex()}")


if __name__ == "__main__":
    main()
