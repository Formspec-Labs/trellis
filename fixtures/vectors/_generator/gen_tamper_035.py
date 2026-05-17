"""Generate byte-exact reference vector `tamper/035-idempotency-key-payload-mismatch`.

Authoring aid only. Core prose and committed vector bytes are normative.
This vector exercises Core §17.3 clause 3 + §17.5 IdempotencyKeyPayloadMismatch:
two events in the same `ledger_scope` share `idempotency_key` but have
different `content_hash` (hence different `author_event_hash` and
`canonical_event_hash`). The verifier MUST surface
`tamper_kind = "idempotency_key_payload_mismatch"`.

Construction: two-event ledger built from scratch.
  * Event 0 (genesis): sequence=0, prev_hash=null, idempotency_key=K,
    payload=plaintext_a → content_hash=CH_A.
  * Event 1 (follower): sequence=1, prev_hash=hash(event 0), idempotency_key=K
    (collision!), payload=plaintext_b ≠ plaintext_a → content_hash=CH_B ≠ CH_A.

Both events sign legitimately under issuer-001; both decode and pass §19
step 4.a–4.h checks individually. The §17.3 dedup-detection check at the
ledger-walk layer surfaces the duplicate (scope, key) identity with
divergent canonical material.

Distinct from `tamper/006-event-reorder` (chain integrity, prev_hash break)
and from any signature/structural tamper — both events here are valid.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

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
# Pinned inputs.
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
KEY_FILE = ROOT / "_keys" / "issuer-001.cose_key"
OUT_DIR = ROOT / "tamper" / "035-idempotency-key-payload-mismatch"

LEDGER_SCOPE = b"test-response-ledger"
SUITE_ID = SUITE_ID_PHASE_1
EVENT_TYPE = b"x-trellis-test/append-minimal"
CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0

# §17.3 — same idempotency_key for both events. Length 24 bytes,
# satisfies §6.1 `bstr .size (1..64)`.
COLLIDING_IDEMPOTENCY_KEY = b"idemp-tamper-035-collide"
assert 1 <= len(COLLIDING_IDEMPOTENCY_KEY) <= 64

# Two distinct payloads of equal length so map shape stays stable.
PLAINTEXT_A = (b"Trellis tamper/035 payload A: original" + b"\x00" * 26)[:64]
PLAINTEXT_B = (b"Trellis tamper/035 payload B: conflict" + b"\x00" * 26)[:64]
assert len(PLAINTEXT_A) == 64 and len(PLAINTEXT_B) == 64
assert PLAINTEXT_A != PLAINTEXT_B

# Distinct authored_at to mirror tamper/006's narrative (sequence 0 < sequence 1).
TIMESTAMP_GENESIS = ts(1745000350)
TIMESTAMP_FOLLOWER = ts(1745000351)

PAYLOAD_NONCE = b"\x00" * 12  # structural-only, mirrors append/001 / append/005

# Domain-separation tags (§9.8).
TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def load_signing_seed_and_pubkey() -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    return cose_key[-4], cose_key[-2]


def build_event_header(authored_at: int) -> dict:
    return {
        "event_type": EVENT_TYPE,
        "authored_at": authored_at,
        "retention_tier": RETENTION_TIER,
        "classification": CLASSIFICATION,
        "outcome_commitment": None,
        "subject_ref_commitment": None,
        "tag_commitment": None,
        "witness_ref": None,
        "extensions": None,
    }


def build_payload_ref(plaintext: bytes) -> dict:
    # Structural-only PayloadInline: ciphertext bstr carries plaintext opaquely
    # (matches append/001 / append/005's structural-only discipline).
    return {
        "ref_type": "inline",
        "ciphertext": plaintext,
        "nonce": PAYLOAD_NONCE,
    }


def build_authored_map(
    sequence: int,
    prev_hash: bytes | None,
    idempotency_key: bytes,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
) -> dict:
    return {
        "version": 1,
        "ledger_scope": LEDGER_SCOPE,
        "sequence": sequence,
        "prev_hash": prev_hash,
        "causal_deps": None,
        "content_hash": content_hash,
        "header": header,
        "commitments": None,
        "payload_ref": payload_ref,
        "key_bag": {"entries": []},
        "idempotency_key": idempotency_key,
        "extensions": None,
    }


def build_event_payload_map(authored_map: dict, author_event_hash: bytes) -> dict:
    payload = dict(authored_map)
    payload["author_event_hash"] = author_event_hash
    return payload


def build_protected_header(kid: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> dict:
    return {
        COSE_LABEL_ALG: ALG_EDDSA,
        COSE_LABEL_KID: kid,
        COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
    }


def build_sig_structure(protected_bstr: bytes, payload_bstr: bytes) -> bytes:
    return dcbor(["Signature1", protected_bstr, b"", payload_bstr])


def build_canonical_event_hash_preimage(event_payload: dict) -> dict:
    return {
        "version": 1,
        "ledger_scope": LEDGER_SCOPE,
        "event_payload": event_payload,
    }


def build_signing_key_entry(kid: bytes, pubkey_raw: bytes) -> dict:
    return {
        "kid": kid,
        "pubkey": pubkey_raw,
        "suite_id": SUITE_ID,
        "status": 0,  # Active
        "valid_from": ts(1745000000),
        "valid_to": None,
        "supersedes": None,
        "attestation": None,
    }


def build_one_event(
    *,
    sequence: int,
    prev_hash: bytes | None,
    idempotency_key: bytes,
    plaintext: bytes,
    authored_at: int,
    seed: bytes,
    kid: bytes,
) -> tuple[bytes, bytes, bytes]:
    """Produce (signed_envelope_bytes, canonical_event_hash, content_hash)."""
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, plaintext)
    header = build_event_header(authored_at)
    payload_ref = build_payload_ref(plaintext)
    authored_map = build_authored_map(
        sequence=sequence,
        prev_hash=prev_hash,
        idempotency_key=idempotency_key,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
    )
    authored_bytes = dcbor(authored_map)
    author_event_hash = domain_separated_sha256(
        TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes
    )
    event_payload = build_event_payload_map(authored_map, author_event_hash)
    event_payload_bytes = dcbor(event_payload)

    protected_bstr = dcbor(build_protected_header(kid))
    sig_structure = build_sig_structure(protected_bstr, event_payload_bytes)
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    cose_sign1 = cbor2.CBORTag(18, [protected_bstr, {}, event_payload_bytes, signature])
    signed_bytes = dcbor(cose_sign1)

    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1,
        dcbor(build_canonical_event_hash_preimage(event_payload)),
    )
    return signed_bytes, canonical_event_hash, content_hash


def write_bytes(name: str, data: bytes) -> None:
    path = OUT_DIR / name
    path.write_bytes(data)
    print(f"  {name:50s}  {len(data):>5d} bytes  sha256={hashlib.sha256(data).hexdigest()}")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"generating vector at {OUT_DIR.relative_to(ROOT.parent.parent)}/")

    seed, pubkey = load_signing_seed_and_pubkey()
    kid = derive_kid(SUITE_ID, pubkey)

    # Event 0: genesis with idempotency_key K and plaintext A.
    event_a_bytes, hash_a, content_a = build_one_event(
        sequence=0,
        prev_hash=None,
        idempotency_key=COLLIDING_IDEMPOTENCY_KEY,
        plaintext=PLAINTEXT_A,
        authored_at=TIMESTAMP_GENESIS,
        seed=seed,
        kid=kid,
    )

    # Event 1: follower with idempotency_key K (same!) and plaintext B (different!).
    # prev_hash points correctly at event 0; sequence = 1; the chain is intact
    # at §10.2 / §19 step 4.h. Only §17.3 detects the conflict.
    event_b_bytes, hash_b, content_b = build_one_event(
        sequence=1,
        prev_hash=hash_a,
        idempotency_key=COLLIDING_IDEMPOTENCY_KEY,
        plaintext=PLAINTEXT_B,
        authored_at=TIMESTAMP_FOLLOWER,
        seed=seed,
        kid=kid,
    )

    assert content_a != content_b, "content_hash MUST diverge — payloads differ"
    assert hash_a != hash_b, "canonical_event_hash MUST diverge — preimages differ"

    write_bytes("input-tampered-event-at-index-0.cbor", event_a_bytes)
    write_bytes("input-tampered-event-at-index-1.cbor", event_b_bytes)

    ledger_bytes = dcbor([cbor2.loads(event_a_bytes), cbor2.loads(event_b_bytes)])
    write_bytes("input-tampered-ledger.cbor", ledger_bytes)

    registry = [build_signing_key_entry(kid, pubkey)]
    registry_bytes = dcbor(registry)
    write_bytes("input-signing-key-registry.cbor", registry_bytes)

    print()
    print(f"  ledger_scope                 = {LEDGER_SCOPE.decode()}")
    print(f"  colliding idempotency_key    = {COLLIDING_IDEMPOTENCY_KEY!r} ({len(COLLIDING_IDEMPOTENCY_KEY)}B)")
    print(f"  event 0 canonical_event_hash = {hash_a.hex()}")
    print(f"  event 1 canonical_event_hash = {hash_b.hex()}  (the failing event)")
    print(f"  event 0 content_hash         = {content_a.hex()}")
    print(f"  event 1 content_hash         = {content_b.hex()}")
    print(f"  kid                          = {kid.hex()}")
    print("  tamper_kind                  = idempotency_key_payload_mismatch")


if __name__ == "__main__":
    main()
