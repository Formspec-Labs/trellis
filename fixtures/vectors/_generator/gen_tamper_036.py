"""Generate byte-exact reference vector `tamper/036-idempotency-key-too-long`.

Authoring aid only. Core prose and committed vector bytes are normative.
This vector exercises Core §6.1 / §17.2 structural bound `bstr .size (1..64)`:
the authored event's `idempotency_key` is 65 bytes (one over the upper bound).
Verifier MUST reject at the structural-parse layer with
`tamper_kind = "idempotency_key_length_invalid"` (§17.5), independent of any
§17.3 retry-conflict resolution.

The signature over the (over-length) authored bytes IS valid (the issuer
signed exactly what is stored); the rejection is on structural CDDL
conformance to §28 (`bstr .size (1..64)`), not on signature or chain
integrity. This isolates the structural-reject path so an implementation
that passes signature + hash recomputation but fails to enforce the size
bound is detected.

Sign-but-verify-mismatch surface — the only Core §19 step that fires before
any per-event check is the §17.2 / §6.1 size-bound check on the parsed
authored event. Pinning the bound to a verifier-side rejection makes
TR-CORE-158 testable.
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

ROOT = Path(__file__).resolve().parent.parent
KEY_FILE = ROOT / "_keys" / "issuer-001.cose_key"
OUT_DIR = ROOT / "tamper" / "036-idempotency-key-too-long"

LEDGER_SCOPE = b"test-response-ledger"
SUITE_ID = SUITE_ID_PHASE_1
EVENT_TYPE = b"x-trellis-test/append-minimal"
CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0
TIMESTAMP = ts(1745000360)
PAYLOAD_NONCE = b"\x00" * 12

# §6.1 / §17.2 structural-bound violator: 65 bytes — exactly one over the
# upper bound `bstr .size (1..64)`.
TOO_LONG_IDEMPOTENCY_KEY = b"x" * 65
assert len(TOO_LONG_IDEMPOTENCY_KEY) == 65

PLAINTEXT = (b"Trellis tamper/036 payload" + b"\x00" * 38)[:64]
assert len(PLAINTEXT) == 64

TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def load_signing_seed_and_pubkey() -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    return cose_key[-4], cose_key[-2]


def build_signing_key_entry(kid: bytes, pubkey_raw: bytes) -> dict:
    return {
        "kid": kid,
        "pubkey": pubkey_raw,
        "suite_id": SUITE_ID,
        "status": 0,
        "valid_from": ts(1745000000),
        "valid_to": None,
        "supersedes": None,
        "attestation": None,
    }


def write_bytes(name: str, data: bytes) -> None:
    path = OUT_DIR / name
    path.write_bytes(data)
    print(f"  {name:50s}  {len(data):>5d} bytes  sha256={hashlib.sha256(data).hexdigest()}")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"generating vector at {OUT_DIR.relative_to(ROOT.parent.parent)}/")

    seed, pubkey = load_signing_seed_and_pubkey()
    kid = derive_kid(SUITE_ID, pubkey)

    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, PLAINTEXT)
    header = {
        "event_type": EVENT_TYPE,
        "authored_at": TIMESTAMP,
        "retention_tier": RETENTION_TIER,
        "classification": CLASSIFICATION,
        "outcome_commitment": None,
        "subject_ref_commitment": None,
        "tag_commitment": None,
        "witness_ref": None,
        "extensions": None,
    }
    payload_ref = {"ref_type": "inline", "ciphertext": PLAINTEXT, "nonce": PAYLOAD_NONCE}
    authored_map = {
        "version": 1,
        "ledger_scope": LEDGER_SCOPE,
        "sequence": 0,
        "prev_hash": None,
        "causal_deps": None,
        "content_hash": content_hash,
        "header": header,
        "commitments": None,
        "payload_ref": payload_ref,
        "key_bag": {"entries": []},
        "idempotency_key": TOO_LONG_IDEMPOTENCY_KEY,  # 65 bytes — VIOLATION
        "extensions": None,
    }
    authored_bytes = dcbor(authored_map)
    author_event_hash = domain_separated_sha256(TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes)
    event_payload = dict(authored_map)
    event_payload["author_event_hash"] = author_event_hash
    event_payload_bytes = dcbor(event_payload)

    protected_bstr = dcbor({
        COSE_LABEL_ALG: ALG_EDDSA,
        COSE_LABEL_KID: kid,
        COSE_LABEL_SUITE_ID: SUITE_ID,
        COSE_LABEL_ARTIFACT_TYPE: ARTIFACT_TYPE_EVENT,
    })
    sig_structure = dcbor(["Signature1", protected_bstr, b"", event_payload_bytes])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    cose_sign1 = cbor2.CBORTag(18, [protected_bstr, {}, event_payload_bytes, signature])
    signed_bytes = dcbor(cose_sign1)

    canonical_preimage = {"version": 1, "ledger_scope": LEDGER_SCOPE, "event_payload": event_payload}
    canonical_event_hash = domain_separated_sha256(TAG_TRELLIS_EVENT_V1, dcbor(canonical_preimage))

    write_bytes("input-tampered-event.cbor", signed_bytes)
    ledger_bytes = dcbor([cose_sign1])
    write_bytes("input-tampered-ledger.cbor", ledger_bytes)

    registry = [build_signing_key_entry(kid, pubkey)]
    write_bytes("input-signing-key-registry.cbor", dcbor(registry))

    print()
    print(f"  ledger_scope                 = {LEDGER_SCOPE.decode()}")
    print(f"  idempotency_key length       = {len(TOO_LONG_IDEMPOTENCY_KEY)} bytes (bound: 1..64)")
    print(f"  signature                    = valid (Ed25519 over over-length payload)")
    print(f"  canonical_event_hash         = {canonical_event_hash.hex()}")
    print(f"  kid                          = {kid.hex()}")
    print("  tamper_kind                  = idempotency_key_length_invalid")


if __name__ == "__main__":
    main()
