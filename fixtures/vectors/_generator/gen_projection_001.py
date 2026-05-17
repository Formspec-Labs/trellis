"""Generate byte-exact reference vector `projection/001-watermark-attestation`.

Authoring aid only. Every construction carries an inline Core / Companion §
citation naming the normative paragraph that determines the bytes. This script
is NOT normative; `derivation.md` is the spec-prose reproduction evidence. If
this script and the specs disagree, the specs win.

Determinism: two runs produce byte-identical output. No randomness, no
wall-clock reads, no environment lookups beyond pinned inputs.

Scope. First-batch O-3 fixture exercising Test 1 (watermark attestation) per
`thoughts/specs/2026-04-18-trellis-o3-projection-conformance.md`. The fixture
carries:

  - a minimal 2-event canonical chain (`input-chain.cbor` = CBOR array of two
    COSE_Sign1 envelopes),
  - a signed Checkpoint at `tree_size = 2` (`input-checkpoint.cbor`) whose
    digest (§11.2, §9.6) is the Watermark's `checkpoint_ref`,
  - a minimal view artifact embedding the Watermark (`input-view.cbor`),
  - `expected-watermark.cbor` = `dCBOR(Watermark)` byte-compare target.

The chain events are structural-only (PayloadInline with opaque ciphertext,
empty KeyBag, empty causal_deps / commitments / extensions) — identical in
shape to `append/001-minimal-inline-payload` so the construction is reviewable
against an already-pinned reference.
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
# Pinned inputs.
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent           # fixtures/vectors/
KEY_FILE = ROOT / "_keys" / "issuer-001.cose_key"
OUT_DIR = ROOT / "projection" / "001-watermark-attestation"

# Ledger-scope pin. Distinct from append/001's scope to avoid confusion under a
# future multi-fixture runner that composes several vectors into one ledger.
LEDGER_SCOPE = b"test-projection-ledger"                 # §10.4, §11.2

# Two events at sequence 0 and 1. Both use x-trellis-test/ reserved prefixes
# (§14.6). Event 0's idempotency key differs from event 1's so that the two
# canonical_event_hash values are distinct (otherwise the Merkle leaves collide
# and tree_head_hash is a degenerate double-hash).
EVENT_DEFS = [
    {
        "sequence":        0,
        "prev_hash":       None,
        "authored_at":     ts(1745000000),
        "event_type":      b"x-trellis-test/projection-seed",
        "classification":  b"x-trellis-test/unclassified",
        "retention_tier":  0,
        "idempotency_key": b"idemp-proj-000" + b"\x00" * 2,  # 16 bytes
        "payload_bytes":   b"projection-payload-0".ljust(32, b"\x00"),
    },
    {
        "sequence":        1,
        # prev_hash populated at build time after event 0 is hashed.
        "prev_hash":       None,
        "authored_at":     ts(1745000060),
        "event_type":      b"x-trellis-test/projection-follow",
        "classification":  b"x-trellis-test/unclassified",
        "retention_tier":  0,
        "idempotency_key": b"idemp-proj-001" + b"\x00" * 2,  # 16 bytes
        "payload_bytes":   b"projection-payload-1".ljust(32, b"\x00"),
    },
]
for ev in EVENT_DEFS:
    assert len(ev["idempotency_key"]) == 16

# Checkpoint-level pins.
CHECKPOINT_TIMESTAMP = ts(1745000120)                        # §11.2 timestamp

# Watermark / view pins (Core §15.2 and Companion §14.1).
WATERMARK_BUILT_AT = ts(1745000180)                          # §15.2 built_at
WATERMARK_REBUILD_PATH = "trellis.projection.v1/minimal"  # §15.3 identifier
WATERMARK_PROJECTION_SCHEMA_ID = "urn:trellis:projection:minimal:v1"  # §15.2

# Signature-suite pins (§7.1).
SUITE_ID = 1
ALG_EDDSA = -8
COSE_LABEL_ALG = 1
COSE_LABEL_KID = 4
COSE_LABEL_SUITE_ID = -65537
COSE_LABEL_ARTIFACT_TYPE = -65538
ARTIFACT_TYPE_EVENT = "event"
ARTIFACT_TYPE_CHECKPOINT = "checkpoint"
ARTIFACT_TYPE_MANIFEST = "manifest"
PAYLOAD_NONCE = b"\x00" * 12                             # §6.4 bstr .size 12

# Domain-separation tags (§9.8).
TAG_EVENT = "trellis-event-v1"                           # §9.2
TAG_AUTHOR = "trellis-author-event-v1"                   # §9.5
TAG_CONTENT = "trellis-content-v1"                       # §9.3
TAG_CHECKPOINT = "trellis-checkpoint-v1"                 # §9.6
TAG_MERKLE_LEAF = "trellis-merkle-leaf-v1"               # §11.3
TAG_MERKLE_INTERIOR = "trellis-merkle-interior-v1"       # §11.3


# ---------------------------------------------------------------------------
# dCBOR (§5.1) + §9.1 domain separation.
# ---------------------------------------------------------------------------

def dcbor(value: object) -> bytes:
    return cbor2.dumps(value, canonical=True)


def domain_separated_preimage(tag: str, component: bytes) -> bytes:
    tag_bytes = tag.encode("utf-8")
    return (
        len(tag_bytes).to_bytes(4, "big")
        + tag_bytes
        + len(component).to_bytes(4, "big")
        + component
    )


def ds_sha256(tag: str, component: bytes) -> bytes:
    return hashlib.sha256(domain_separated_preimage(tag, component)).digest()


# ---------------------------------------------------------------------------
# Key load + §8.3 kid derivation.
# ---------------------------------------------------------------------------

def load_issuer_key() -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    assert len(seed) == 32 and len(pubkey) == 32
    return seed, pubkey


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


# ---------------------------------------------------------------------------
# CDDL builders.
# ---------------------------------------------------------------------------

def build_event_header(ev: dict) -> dict:
    # §12.1.
    return {
        "event_type":             ev["event_type"],
        "authored_at":            ev["authored_at"],
        "retention_tier":         ev["retention_tier"],
        "classification":         ev["classification"],
        "outcome_commitment":     None,
        "subject_ref_commitment": None,
        "tag_commitment":         None,
        "witness_ref":            None,
        "extensions":             None,
    }


def build_payload_inline(ciphertext: bytes) -> dict:
    # §6.4 PayloadInline. Ciphertext carried as opaque bytes (structural-only).
    return {
        "ref_type":   "inline",
        "ciphertext": ciphertext,
        "nonce":      PAYLOAD_NONCE,
    }


def build_key_bag() -> dict:
    # §9.4, empty entries (CDDL `[*]` admits zero).
    return {"entries": []}


def build_authored_preimage(ev: dict, content_hash: bytes) -> dict:
    # §9.5 AuthorEventHashPreimage.
    return {
        "version":         1,
        "ledger_scope":    LEDGER_SCOPE,
        "sequence":        ev["sequence"],
        "prev_hash":       ev["prev_hash"],
        "causal_deps":     None,
        "content_hash":    content_hash,
        "header":          build_event_header(ev),
        "commitments":     None,
        "payload_ref":     build_payload_inline(ev["payload_bytes"]),
        "key_bag":         build_key_bag(),
        "idempotency_key": ev["idempotency_key"],
        "extensions":      None,
    }


def build_event_payload(ev: dict, author_event_hash: bytes, content_hash: bytes) -> dict:
    # §6.1 EventPayload.
    return {
        "version":           1,
        "ledger_scope":      LEDGER_SCOPE,
        "sequence":          ev["sequence"],
        "prev_hash":         ev["prev_hash"],
        "causal_deps":       None,
        "author_event_hash": author_event_hash,
        "content_hash":      content_hash,
        "header":            build_event_header(ev),
        "commitments":       None,
        "payload_ref":       build_payload_inline(ev["payload_bytes"]),
        "key_bag":           build_key_bag(),
        "idempotency_key":   ev["idempotency_key"],
        "extensions":        None,
    }


def build_canonical_preimage(event_payload: dict) -> dict:
    # §9.2 CanonicalEventHashPreimage.
    return {
        "version":       1,
        "ledger_scope":  LEDGER_SCOPE,
        "event_payload": event_payload,
    }


def build_protected_header(kid: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> dict:
    # §7.4 protected header (alg, kid, suite_id, artifact_type).
    return {
        COSE_LABEL_ALG:      ALG_EDDSA,
        COSE_LABEL_KID:      kid,
        COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
    }


def build_sig_structure(protected_bstr: bytes, payload_bstr: bytes) -> bytes:
    # RFC 9052 §4.4; external_aad = zero-length per §6.6.
    return dcbor(["Signature1", protected_bstr, b"", payload_bstr])


def sign_cose_sign1(seed: bytes, protected_map_bytes: bytes, payload_bytes: bytes) -> bytes:
    # §6.1, §7.4, RFC 9052 §4.2 — tag-18 envelope with embedded payload.
    sig_struct = build_sig_structure(protected_map_bytes, payload_bytes)
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    signature = sk.sign(sig_struct)
    assert len(signature) == 64
    envelope = cbor2.CBORTag(
        18,
        [protected_map_bytes, {}, payload_bytes, signature],
    )
    return dcbor(envelope)


def build_one_event(seed: bytes, kid: bytes, ev: dict) -> tuple[bytes, bytes]:
    """Return (cose_sign1_envelope_bytes, canonical_event_hash)."""
    content_hash = ds_sha256(TAG_CONTENT, ev["payload_bytes"])
    authored = build_authored_preimage(ev, content_hash)
    authored_bytes = dcbor(authored)
    author_event_hash = ds_sha256(TAG_AUTHOR, authored_bytes)
    event_payload = build_event_payload(ev, author_event_hash, content_hash)
    event_payload_bytes = dcbor(event_payload)
    protected_map_bytes = dcbor(build_protected_header(kid))
    envelope_bytes = sign_cose_sign1(seed, protected_map_bytes, event_payload_bytes)
    canonical_preimage = dcbor(build_canonical_preimage(event_payload))
    canonical_event_hash = ds_sha256(TAG_EVENT, canonical_preimage)
    return envelope_bytes, canonical_event_hash


# ---------------------------------------------------------------------------
# §11.3 Merkle tree (RFC 6962-compatible, domain-separated).
# For tree_size = 2 the tree is a single interior node above two leaves.
# ---------------------------------------------------------------------------

def merkle_leaf_hash(canonical_event_hash: bytes) -> bytes:
    return ds_sha256(TAG_MERKLE_LEAF, canonical_event_hash)


def merkle_interior_hash(left: bytes, right: bytes) -> bytes:
    return ds_sha256(TAG_MERKLE_INTERIOR, left + right)


def merkle_root_for_two(canonical_event_hashes: list[bytes]) -> bytes:
    assert len(canonical_event_hashes) == 2
    l0 = merkle_leaf_hash(canonical_event_hashes[0])
    l1 = merkle_leaf_hash(canonical_event_hashes[1])
    return merkle_interior_hash(l0, l1)


# ---------------------------------------------------------------------------
# §11.2 CheckpointPayload + §9.6 checkpoint digest.
# ---------------------------------------------------------------------------

def build_checkpoint_payload(tree_size: int, tree_head_hash: bytes) -> dict:
    return {
        "version":              1,
        "scope":                LEDGER_SCOPE,
        "tree_size":            tree_size,
        "tree_head_hash":       tree_head_hash,
        "timestamp":            CHECKPOINT_TIMESTAMP,
        "anchor_ref":           None,
        "prev_checkpoint_hash": None,
        "extensions":           None,
    }


def build_checkpoint_hash_preimage(checkpoint_payload: dict) -> dict:
    # §9.6 CheckpointHashPreimage.
    return {
        "version":            1,
        "scope":              LEDGER_SCOPE,
        "checkpoint_payload": checkpoint_payload,
    }


# ---------------------------------------------------------------------------
# Core §15.2 Watermark.
# ---------------------------------------------------------------------------

def build_watermark(tree_size: int, tree_head_hash: bytes, checkpoint_ref: bytes) -> dict:
    return {
        "scope":                LEDGER_SCOPE,
        "tree_size":            tree_size,
        "tree_head_hash":       tree_head_hash,
        "checkpoint_ref":       checkpoint_ref,
        "built_at":             WATERMARK_BUILT_AT,
        "rebuild_path":         WATERMARK_REBUILD_PATH,
        "projection_schema_id": WATERMARK_PROJECTION_SCHEMA_ID,
    }


# A minimal derived view artifact. The fixture pins both the Watermark bytes
# AND a wrapping view structure so the runner sees that the Watermark is an
# embedded field, not the whole file. `view.body` is a small opaque map.
def build_view(watermark: dict) -> dict:
    return {
        "watermark": watermark,
        "body": {
            "item_count": 2,
            "schema_id":  WATERMARK_PROJECTION_SCHEMA_ID,
        },
    }


# ---------------------------------------------------------------------------
# Output helper.
# ---------------------------------------------------------------------------

def write_bytes(name: str, data: bytes) -> None:
    path = OUT_DIR / name
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"  {name:35s}  {len(data):>5d} bytes  sha256={digest}")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"generating vector at {OUT_DIR.relative_to(ROOT.parent.parent)}/")

    seed, pubkey_raw = load_issuer_key()
    kid = derive_kid(SUITE_ID, pubkey_raw)

    # 1. Build event 0 → envelope bytes + canonical_event_hash[0].
    ev0_bytes, ceh0 = build_one_event(seed, kid, EVENT_DEFS[0])

    # 2. Patch event 1 prev_hash = canonical_event_hash[0] per §10.2, then build.
    EVENT_DEFS[1]["prev_hash"] = ceh0
    ev1_bytes, ceh1 = build_one_event(seed, kid, EVENT_DEFS[1])

    # 3. Write the canonical chain (CBOR array of COSE_Sign1 envelopes).
    # The chain file is a definite-length CBOR array of two already-encoded
    # envelope bstrings. To stay within dCBOR we round-trip through cbor2.
    chain_structure = [cbor2.loads(ev0_bytes), cbor2.loads(ev1_bytes)]
    chain_bytes = dcbor(chain_structure)
    write_bytes("input-chain.cbor", chain_bytes)

    # 4. Merkle root at tree_size = 2 (§11.3).
    tree_head_hash = merkle_root_for_two([ceh0, ceh1])

    # 5. Build CheckpointPayload, sign as COSE_Sign1 (Checkpoint = COSESign1Bytes
    #    per §11.2), write.
    checkpoint_payload = build_checkpoint_payload(2, tree_head_hash)
    checkpoint_payload_bytes = dcbor(checkpoint_payload)
    protected_map_bytes = dcbor(build_protected_header(kid))
    signed_checkpoint_bytes = sign_cose_sign1(
        seed, protected_map_bytes, checkpoint_payload_bytes,
    )
    write_bytes("input-checkpoint.cbor", signed_checkpoint_bytes)

    # 6. Compute checkpoint_digest = SHA-256 domain-sep over
    #    dCBOR(CheckpointHashPreimage) per §9.6. This is the value of
    #    Watermark.checkpoint_ref (§15.2).
    ckpt_preimage = build_checkpoint_hash_preimage(checkpoint_payload)
    ckpt_preimage_bytes = dcbor(ckpt_preimage)
    checkpoint_ref = ds_sha256(TAG_CHECKPOINT, ckpt_preimage_bytes)

    # 7. Build Watermark (§15.2, Companion §14.1); write dCBOR(Watermark) as
    #    the byte-compare target.
    watermark = build_watermark(2, tree_head_hash, checkpoint_ref)
    watermark_bytes = dcbor(watermark)
    write_bytes("expected-watermark.cbor", watermark_bytes)

    # 8. Build the minimal view artifact that embeds the Watermark; write.
    view = build_view(watermark)
    view_bytes = dcbor(view)
    write_bytes("input-view.cbor", view_bytes)

    # Informational — not committed on disk.
    print()
    print(f"  kid                          = {kid.hex()}")
    print(f"  canonical_event_hash[0]      = {ceh0.hex()}")
    print(f"  canonical_event_hash[1]      = {ceh1.hex()}")
    print(f"  tree_head_hash               = {tree_head_hash.hex()}")
    print(f"  checkpoint_ref               = {checkpoint_ref.hex()}")


if __name__ == "__main__":
    main()
