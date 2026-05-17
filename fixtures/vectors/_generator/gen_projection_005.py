"""Generate byte-exact reference vector `projection/005-watermark-staff-view-decision-binding`.

Authoring aid only. Every construction carries an inline Core / Companion §
citation. This script is NOT normative; `derivation.md` is the spec-prose
reproduction evidence. If this script and the specs disagree, the specs win.

Determinism: two runs produce byte-identical output. No randomness, no
wall-clock reads, no environment lookups beyond pinned inputs.

Scope — the final O-3 breadth fixture. Stream B fixture (c) per
`TODO.md` §Stream B: `projection/005-watermark-staff-view-decision-binding`,
closing TR-OP-006 and Companion §17.4 Staff-View. Spec anchor landed in Core
§6.7 Posture-transition extension registry with `trellis.staff-view-
decision-binding.v1` Phase-1 extension, §28 Appendix A `StaffViewDecisionBinding`
CDDL, and §19 verifier-step 4.k semantics (decode-and-validate on presence
of the extension key).

This vector is shaped like `projection/001-watermark-attestation` — a 2-event
canonical chain, a Checkpoint at `tree_size = 2`, a derived view embedding a
§15.2 `Watermark`. It adds:

  * a staff-view `projection_schema_id` = `"trellis.staff-view.v1"` and a
    staff-view `rebuild_path` = `"trellis.staff-view.v1/default"` on the
    Watermark itself; and
  * a committed `expected-staff-view-decision-binding.cbor` carrying the
    §28 Appendix A `StaffViewDecisionBinding` whose `watermark` is byte-identical to
    the view's embedded Watermark, with `staff_view_ref` pinned to the
    derived-artifact URI, `stale_acknowledged = false` (watermark is not
    older than the Companion §17.3 threshold), and `extensions = null`.

The byte-testable claims per TR-OP-006 (watermark presence + stale-status):
  (a) Every §15.2 required Watermark field is present in `expected-
      watermark.cbor` and equals the pinned bytes;
  (b) The Watermark inside the committed `StaffViewDecisionBinding`
      byte-equals the standalone `expected-watermark.cbor`;
  (c) `stale_acknowledged` is a boolean; its value is pinned (`false`) so a
      conformance runner can byte-compare the whole binding artifact.

Ledger-scope choice — `test-staff-view-ledger`, deliberately distinct from
every other fixture scope (no collision at `sequence = 0` with
`test-projection-ledger` 001..004 or the append-fixture scopes).
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
OUT_DIR = ROOT / "projection" / "005-watermark-staff-view-decision-binding"

# Ledger-scope pin, §10.4. Distinct from every other fixture scope.
LEDGER_SCOPE = b"test-staff-view-ledger"

# Two-event chain. Structural-only, identical in shape to projection/001 /
# append/001 so the construction is reviewable against an already-pinned
# reference. The `event_type` prefix is §14.6-reserved.
EVENT_DEFS = [
    {
        "sequence":        0,
        "prev_hash":       None,
        "authored_at":     ts(1745020000),
        "event_type":      b"x-trellis-test/staff-view-seed",
        "classification":  b"x-trellis-test/unclassified",
        "retention_tier":  0,
        "idempotency_key": b"idemp-staff-005a" + b"\x00" * 0,  # 16 bytes
        "payload_bytes":   b"staff-view-payload-0".ljust(32, b"\x00"),
    },
    {
        "sequence":        1,
        # prev_hash populated at build time after event 0 is hashed.
        "prev_hash":       None,
        "authored_at":     ts(1745020060),
        "event_type":      b"x-trellis-test/staff-view-follow",
        "classification":  b"x-trellis-test/unclassified",
        "retention_tier":  0,
        "idempotency_key": b"idemp-staff-005b" + b"\x00" * 0,  # 16 bytes
        "payload_bytes":   b"staff-view-payload-1".ljust(32, b"\x00"),
    },
]
for ev in EVENT_DEFS:
    assert len(ev["idempotency_key"]) == 16

# Checkpoint-level pins.
CHECKPOINT_TIMESTAMP = ts(1745020120)                        # §11.2 timestamp

# Staff-view Watermark / binding pins (Core §15.2, §28 Appendix A; Companion §17.4).
WATERMARK_BUILT_AT = ts(1745020180)                          # §15.2 built_at
WATERMARK_REBUILD_PATH = "trellis.staff-view.v1/default"  # §17.4 / §15.3 identifier
WATERMARK_PROJECTION_SCHEMA_ID = "trellis.staff-view.v1"  # §17.4 staff-view schema URI

# StaffViewDecisionBinding pins (§28 Appendix A).
BINDING_STAFF_VIEW_REF = "urn:trellis:staff-view:test-005/default"  # §28 Appendix A optional RFC 3986
BINDING_STALE_ACKNOWLEDGED = False                       # §28 Appendix A; §17.3 stale-view ack
BINDING_EXTENSIONS = None                                 # §28 Appendix A `{ * tstr => any } / null`

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
    # §6.4 PayloadInline.
    return {
        "ref_type":   "inline",
        "ciphertext": ciphertext,
        "nonce":      PAYLOAD_NONCE,
    }


def build_key_bag() -> dict:
    # §9.4, empty entries.
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
    # §7.4 protected header.
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
# §11.3 Merkle tree for tree_size = 2.
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
# Core §15.2 Watermark + §28 Appendix A StaffViewDecisionBinding.
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


def build_staff_view_decision_binding(watermark: dict) -> dict:
    # §28 Appendix A StaffViewDecisionBinding CDDL.
    return {
        "watermark":          watermark,
        "staff_view_ref":     BINDING_STAFF_VIEW_REF,
        "stale_acknowledged": BINDING_STALE_ACKNOWLEDGED,
        "extensions":         BINDING_EXTENSIONS,
    }


# A minimal derived view artifact embedding the staff-view Watermark. Parallels
# projection/001's `build_view` but with a staff-view body (row count + schema).
def build_view(watermark: dict) -> dict:
    return {
        "watermark": watermark,
        "body": {
            "row_count": 2,
            "schema_id": WATERMARK_PROJECTION_SCHEMA_ID,
        },
    }


# ---------------------------------------------------------------------------
# Output helper.
# ---------------------------------------------------------------------------

def write_bytes(name: str, data: bytes) -> None:
    path = OUT_DIR / name
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"  {name:45s}  {len(data):>5d} bytes  sha256={digest}")


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
    chain_structure = [cbor2.loads(ev0_bytes), cbor2.loads(ev1_bytes)]
    chain_bytes = dcbor(chain_structure)
    write_bytes("input-chain.cbor", chain_bytes)

    # 4. Merkle root at tree_size = 2 (§11.3).
    tree_head_hash = merkle_root_for_two([ceh0, ceh1])

    # 5. Build CheckpointPayload, sign as COSE_Sign1.
    checkpoint_payload = build_checkpoint_payload(2, tree_head_hash)
    checkpoint_payload_bytes = dcbor(checkpoint_payload)
    protected_map_bytes = dcbor(build_protected_header(kid))
    signed_checkpoint_bytes = sign_cose_sign1(
        seed, protected_map_bytes, checkpoint_payload_bytes,
    )
    write_bytes("input-checkpoint.cbor", signed_checkpoint_bytes)

    # 6. Compute checkpoint_digest = §9.6 domain-sep.
    ckpt_preimage_bytes = dcbor(build_checkpoint_hash_preimage(checkpoint_payload))
    checkpoint_ref = ds_sha256(TAG_CHECKPOINT, ckpt_preimage_bytes)

    # 7. Build staff-view Watermark (§15.2 with §17.4 staff-view schema id);
    #    write dCBOR(Watermark) as the byte-compare target.
    watermark = build_watermark(2, tree_head_hash, checkpoint_ref)
    watermark_bytes = dcbor(watermark)
    write_bytes("expected-watermark.cbor", watermark_bytes)

    # 8. Build the minimal staff-view artifact embedding the Watermark.
    view = build_view(watermark)
    view_bytes = dcbor(view)
    write_bytes("input-view.cbor", view_bytes)

    # 9. Build the §28 Appendix A StaffViewDecisionBinding. The binding's `watermark`
    #    field is byte-identical to `expected-watermark.cbor` — same dict,
    #    same dCBOR key-ordering. Commit as the primary byte-compare target
    #    for TR-OP-006's staff-view coverage.
    binding = build_staff_view_decision_binding(watermark)
    binding_bytes = dcbor(binding)
    write_bytes("expected-staff-view-decision-binding.cbor", binding_bytes)

    # 10. Invariant reproduction assertion (in-script). The Watermark bytes
    #     inside the binding equal the standalone Watermark bytes.
    binding_decoded = cbor2.loads(binding_bytes)
    embedded_watermark_bytes = dcbor(binding_decoded["watermark"])
    assert embedded_watermark_bytes == watermark_bytes, (
        "staff-view binding watermark bytes != standalone watermark bytes"
    )
    assert binding_decoded["stale_acknowledged"] is False
    assert binding_decoded["staff_view_ref"] == BINDING_STAFF_VIEW_REF

    # Informational — not committed on disk.
    print()
    print(f"  kid                          = {kid.hex()}")
    print(f"  canonical_event_hash[0]      = {ceh0.hex()}")
    print(f"  canonical_event_hash[1]      = {ceh1.hex()}")
    print(f"  tree_head_hash               = {tree_head_hash.hex()}")
    print(f"  checkpoint_ref               = {checkpoint_ref.hex()}")


if __name__ == "__main__":
    main()
