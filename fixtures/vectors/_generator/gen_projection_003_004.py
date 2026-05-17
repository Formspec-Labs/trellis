"""Generate O-3 cadence fixtures projection/003, 004, 006, and 007.

Authoring aid only. The normative source is Core + Companion prose and each
fixture's derivation.md. This script pins deterministic bytes for:

  - projection/003-cadence-positive-height: checkpoints at heights 2, 4, 6.
  - projection/004-cadence-gap: checkpoints at heights 2 and 6, missing 4.
  - projection/006-cadence-positive-time: time-driven cadence, satisfied.
  - projection/007-cadence-event-gap: event-driven cadence, missing one point.

Both fixtures exercise TR-OP-008, the declared snapshot-cadence obligation.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cbor2  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from _lib.byte_utils import ts  # noqa: E402


ROOT = Path(__file__).resolve().parent.parent
KEY_FILE = ROOT / "_keys" / "issuer-001.cose_key"
OUT_POSITIVE = ROOT / "projection" / "003-cadence-positive-height"
OUT_GAP = ROOT / "projection" / "004-cadence-gap"
OUT_TIME_POSITIVE = ROOT / "projection" / "006-cadence-positive-time"
OUT_EVENT_GAP = ROOT / "projection" / "007-cadence-event-gap"

LEDGER_SCOPE = b"test-cadence-ledger"
EVENT_COUNT = 6
CADENCE_INTERVAL = 2
REQUIRED_HEIGHTS = [2, 4, 6]

SUITE_ID = 1
ALG_EDDSA = -8
COSE_LABEL_ALG = 1
COSE_LABEL_KID = 4
COSE_LABEL_SUITE_ID = -65537
COSE_LABEL_ARTIFACT_TYPE = -65538
ARTIFACT_TYPE_EVENT = "event"
ARTIFACT_TYPE_CHECKPOINT = "checkpoint"
ARTIFACT_TYPE_MANIFEST = "manifest"
PAYLOAD_NONCE = b"\x00" * 12

TAG_EVENT = "trellis-event-v1"
TAG_AUTHOR = "trellis-author-event-v1"
TAG_CONTENT = "trellis-content-v1"
TAG_CHECKPOINT = "trellis-checkpoint-v1"
TAG_MERKLE_LEAF = "trellis-merkle-leaf-v1"
TAG_MERKLE_INTERIOR = "trellis-merkle-interior-v1"


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


def load_issuer_key() -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    assert len(seed) == 32 and len(pubkey) == 32
    return seed, pubkey


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def build_event_header(ev: dict) -> dict:
    return {
        "event_type":             ev["event_type"],
        "authored_at":            ev["authored_at"],
        "retention_tier":         0,
        "classification":         b"x-trellis-test/unclassified",
        "outcome_commitment":     None,
        "subject_ref_commitment": None,
        "tag_commitment":         None,
        "witness_ref":            None,
        "extensions":             None,
    }


def build_payload_inline(ciphertext: bytes) -> dict:
    return {
        "ref_type":   "inline",
        "ciphertext": ciphertext,
        "nonce":      PAYLOAD_NONCE,
    }


def build_key_bag() -> dict:
    return {"entries": []}


def build_authored_preimage(ev: dict, content_hash: bytes) -> dict:
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
    return {
        "version":       1,
        "ledger_scope":  LEDGER_SCOPE,
        "event_payload": event_payload,
    }


def build_protected_header(kid: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> dict:
    return {
        COSE_LABEL_ALG:      ALG_EDDSA,
        COSE_LABEL_KID:      kid,
        COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
    }


def build_sig_structure(protected_bstr: bytes, payload_bstr: bytes) -> bytes:
    return dcbor(["Signature1", protected_bstr, b"", payload_bstr])


def sign_cose_sign1(seed: bytes, protected_map_bytes: bytes, payload_bytes: bytes) -> bytes:
    sig_struct = build_sig_structure(protected_map_bytes, payload_bytes)
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    signature = sk.sign(sig_struct)
    assert len(signature) == 64
    return dcbor(cbor2.CBORTag(18, [protected_map_bytes, {}, payload_bytes, signature]))


def event_def(sequence: int, prev_hash: bytes | None) -> dict:
    idempotency = f"idemp-cad-{sequence:03d}".encode("ascii") + b"\x00" * 3
    assert len(idempotency) == 16
    return {
        "sequence":        sequence,
        "prev_hash":       prev_hash,
        "authored_at":     ts(1745200000 + (sequence * 60)),
        "event_type":      b"x-trellis-test/cadence-event",
        "idempotency_key": idempotency,
        "payload_bytes":   f"cadence-payload-{sequence}".encode("ascii").ljust(32, b"\x00"),
    }


def build_one_event(
    seed: bytes, kid: bytes, sequence: int, prev_hash: bytes | None
) -> tuple[bytes, bytes]:
    ev = event_def(sequence, prev_hash)
    content_hash = ds_sha256(TAG_CONTENT, ev["payload_bytes"])
    authored_bytes = dcbor(build_authored_preimage(ev, content_hash))
    author_event_hash = ds_sha256(TAG_AUTHOR, authored_bytes)
    event_payload = build_event_payload(ev, author_event_hash, content_hash)
    event_payload_bytes = dcbor(event_payload)
    protected_map_bytes = dcbor(build_protected_header(kid))
    envelope_bytes = sign_cose_sign1(seed, protected_map_bytes, event_payload_bytes)
    canonical_preimage = dcbor(build_canonical_preimage(event_payload))
    canonical_event_hash = ds_sha256(TAG_EVENT, canonical_preimage)
    return envelope_bytes, canonical_event_hash


def merkle_leaf_hash(canonical_event_hash: bytes) -> bytes:
    return ds_sha256(TAG_MERKLE_LEAF, canonical_event_hash)


def merkle_interior_hash(left: bytes, right: bytes) -> bytes:
    return ds_sha256(TAG_MERKLE_INTERIOR, left + right)


def largest_power_of_two_less_than(n: int) -> int:
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def merkle_root(canonical_event_hashes: list[bytes]) -> bytes:
    assert canonical_event_hashes
    if len(canonical_event_hashes) == 1:
        return merkle_leaf_hash(canonical_event_hashes[0])
    split = largest_power_of_two_less_than(len(canonical_event_hashes))
    return merkle_interior_hash(
        merkle_root(canonical_event_hashes[:split]),
        merkle_root(canonical_event_hashes[split:]),
    )


def build_checkpoint_payload(
    tree_size: int, tree_head_hash: bytes, prev_checkpoint_hash: bytes | None
) -> dict:
    return {
        "version":              1,
        "scope":                LEDGER_SCOPE,
        "tree_size":            tree_size,
        "tree_head_hash":       tree_head_hash,
        "timestamp":            ts(1745201000 + (tree_size * 60)),
        "anchor_ref":           None,
        "prev_checkpoint_hash": prev_checkpoint_hash,
        "extensions":           None,
    }


def build_checkpoint_hash_preimage(checkpoint_payload: dict) -> dict:
    return {
        "version":            1,
        "scope":              LEDGER_SCOPE,
        "checkpoint_payload": checkpoint_payload,
    }


def build_checkpoint(
    seed: bytes,
    kid: bytes,
    tree_size: int,
    canonical_event_hashes: list[bytes],
    prev_checkpoint_hash: bytes | None,
) -> tuple[bytes, bytes, dict]:
    tree_head_hash = merkle_root(canonical_event_hashes[:tree_size])
    payload = build_checkpoint_payload(tree_size, tree_head_hash, prev_checkpoint_hash)
    payload_bytes = dcbor(payload)
    protected_map_bytes = dcbor(build_protected_header(kid))
    checkpoint_bytes = sign_cose_sign1(seed, protected_map_bytes, payload_bytes)
    checkpoint_hash = ds_sha256(TAG_CHECKPOINT, dcbor(build_checkpoint_hash_preimage(payload)))
    return checkpoint_bytes, checkpoint_hash, payload


def build_report(
    observed_heights: list[int],
    *,
    cadence_kind: str,
    interval: int,
    required_heights: list[int],
) -> dict:
    missing = [height for height in required_heights if height not in observed_heights]
    return {
        "cadence_kind":        cadence_kind,
        "interval":            interval,
        "expected_tree_sizes": required_heights,
        "observed_tree_sizes": observed_heights,
        "missing_tree_sizes":  missing,
        "cadence_satisfied":   not missing,
        "failure_code":        None if not missing else "missing-required-checkpoint",
    }


def write_bytes(out_dir: Path, name: str, data: bytes) -> None:
    path = out_dir / name
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    rel = path.relative_to(ROOT).as_posix()
    print(f"  {rel:64s} {len(data):>5d} bytes sha256={digest}")


def write_fixture(
    out_dir: Path,
    chain_bytes: bytes,
    checkpoints: dict[int, bytes],
    observed_heights: list[int],
    *,
    cadence_kind: str = "height-based",
    interval: int = CADENCE_INTERVAL,
    required_heights: list[int] = REQUIRED_HEIGHTS,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for pattern in (
        "input-chain.cbor",
        "input-checkpoint-*.cbor",
        "expected-cadence-report.cbor",
    ):
        for stale in out_dir.glob(pattern):
            stale.unlink()
    write_bytes(out_dir, "input-chain.cbor", chain_bytes)
    for height in observed_heights:
        write_bytes(out_dir, f"input-checkpoint-{height:03d}.cbor", checkpoints[height])
    report = build_report(
        observed_heights,
        cadence_kind=cadence_kind,
        interval=interval,
        required_heights=required_heights,
    )
    write_bytes(out_dir, "expected-cadence-report.cbor", dcbor(report))


def main() -> None:
    seed, pubkey_raw = load_issuer_key()
    kid = derive_kid(SUITE_ID, pubkey_raw)

    envelopes = []
    canonical_event_hashes = []
    prev_hash = None
    for sequence in range(EVENT_COUNT):
        envelope, canonical_event_hash = build_one_event(seed, kid, sequence, prev_hash)
        envelopes.append(cbor2.loads(envelope))
        canonical_event_hashes.append(canonical_event_hash)
        prev_hash = canonical_event_hash

    chain_bytes = dcbor(envelopes)

    checkpoints: dict[int, bytes] = {}
    checkpoint_hashes: dict[int, bytes] = {}
    prev_checkpoint_hash = None
    for height in REQUIRED_HEIGHTS:
        checkpoint_bytes, checkpoint_hash, _payload = build_checkpoint(
            seed,
            kid,
            height,
            canonical_event_hashes,
            prev_checkpoint_hash,
        )
        checkpoints[height] = checkpoint_bytes
        checkpoint_hashes[height] = checkpoint_hash
        prev_checkpoint_hash = checkpoint_hash

    write_fixture(OUT_POSITIVE, chain_bytes, checkpoints, [2, 4, 6])
    write_fixture(
        OUT_TIME_POSITIVE,
        chain_bytes,
        checkpoints,
        [2, 4, 6],
        cadence_kind="time-driven",
        interval=120,
    )

    # The negative fixture intentionally omits the required height-4 checkpoint.
    # Its height-6 checkpoint links back to height 2, matching the observed
    # checkpoint chain rather than pretending the missing checkpoint exists.
    gap_checkpoints: dict[int, bytes] = {}
    checkpoint_2, checkpoint_hash_2, _payload_2 = build_checkpoint(
        seed, kid, 2, canonical_event_hashes, None
    )
    checkpoint_6, _checkpoint_hash_6, _payload_6 = build_checkpoint(
        seed, kid, 6, canonical_event_hashes, checkpoint_hash_2
    )
    gap_checkpoints[2] = checkpoint_2
    gap_checkpoints[6] = checkpoint_6
    write_fixture(OUT_GAP, chain_bytes, gap_checkpoints, [2, 6])
    write_fixture(
        OUT_EVENT_GAP,
        chain_bytes,
        gap_checkpoints,
        [2, 6],
        cadence_kind="event-driven",
        interval=2,
    )

    print()
    print(f"  kid                          = {kid.hex()}")
    for index, digest in enumerate(canonical_event_hashes):
        print(f"  canonical_event_hash[{index}]      = {digest.hex()}")
    for height in REQUIRED_HEIGHTS:
        print(f"  tree_head_hash[{height}]           = {merkle_root(canonical_event_hashes[:height]).hex()}")
        print(f"  checkpoint_ref[{height}]           = {checkpoint_hashes[height].hex()}")


if __name__ == "__main__":
    main()
