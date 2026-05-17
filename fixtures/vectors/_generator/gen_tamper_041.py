"""Generate byte-exact reference vector `tamper/041-timestamp-backwards`.

Authoring aid only. This script is NOT normative; `derivation.md` is the
spec-prose reproduction evidence. If this script and Core disagree, Core wins.

Determinism: two runs produce byte-identical output. No randomness, no
wall-clock reads, no environment lookups beyond pinned inputs.

Scope — ADR 0069 D-3: timestamps must be non-decreasing along chain order.
This vector exercises the temporal-order check at Core §19 step 4.h-temporal.
The hash chain is valid, signatures are valid, but event[1].authored_at <
event[0].authored_at.

Construction:
  1. Load append/001 (genesis, authored_at=1745000000) and append/005
     (sequence=1, authored_at=1745000001) byte-exact events.
  2. Mutate append/005's payload header.authored_at from 1745000001 to
     1744999999 (1 second BEFORE the genesis event).
  3. Re-encode the tampered payload as dCBOR; re-sign under issuer-001.
  4. Build a two-element ledger: [untampered genesis, tampered chain event].

The verifier walk:
  * Step 4.a — kid resolves in registry. PASS for both events.
  * Step 4.b — signatures verify (genesis unchanged, chain event re-signed).
    PASS.
  * Step 4.c — payloads decode. PASS.
  * Step 4.d — author_event_hash recomputation. The chain event's preimage
    changed (authored_at mutated), so the recomputed hash differs from the
    stored one. This vector must also update author_event_hash in the payload
    to match the recomputed value so step 4.d passes — isolating the tamper
    to the temporal-order check.
  * Step 4.e — canonical_event_hash recomputes from payload bytes; matches
    because we re-encoded the payload. PASS.
  * Step 4.h — prev_hash links correctly (genesis canonical hash unchanged).
    PASS.
  * Step 4.h-temporal (ADR 0069 D-3) — event[1].authored_at (1744999999) <
    event[0].authored_at (1745000000). **FAIL** — timestamp_order_violation.
  * Step 9 — integrity_verified drops to false.
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
GENESIS_DIR = ROOT / "append" / "001-minimal-inline-payload"
CHAIN_DIR = ROOT / "append" / "005-prior-head-chain"
OUT_DIR = ROOT / "tamper" / "041-timestamp-backwards"

EXPECTED_GENESIS_EVENT_SHA256 = (
    "deca82133a10729c570e277ee38a975b7f6b9e79374052f80069b3863bdd733d"
)
EXPECTED_CHAIN_EVENT_SHA256 = (
    "a22ff7aa140f5aacc429cab158688c34823af7e0ec5b88bcac7e63a0fcf27091"
)
EXPECTED_GENESIS_CANONICAL_HASH_HEX = (
    "bb2cdb1e0aa3bcae1d50cb72d68b26af45b92e088f820e901c3d6d1558694396"
)

LEDGER_SCOPE = b"test-response-ledger"

SUITE_ID = 1
ALG_EDDSA = -8
COSE_LABEL_ALG = 1
COSE_LABEL_KID = 4
COSE_LABEL_SUITE_ID = -65537
COSE_LABEL_ARTIFACT_TYPE = -65538
ARTIFACT_TYPE_EVENT = "event"
ARTIFACT_TYPE_CHECKPOINT = "checkpoint"
ARTIFACT_TYPE_MANIFEST = "manifest"

ISSUER_VALID_FROM = ts(1745000000)
SIGNING_KEY_ACTIVE_STATUS = 0

GENESIS_AUTHORED_AT = ts(1745000000)
TAMPERED_CHAIN_AUTHORED_AT = ts(1744999999)

TAG_AUTHOR_EVENT = "trellis-author-event-v1"
TAG_CANONICAL_EVENT = "trellis-event-v1"


def dcbor(value: object) -> bytes:
    return cbor2.dumps(value, canonical=True)


def domain_separated_sha256(tag: str, component: bytes) -> bytes:
    tag_bytes = tag.encode("utf-8")
    buf = bytearray()
    buf += len(tag_bytes).to_bytes(4, "big")
    buf += tag_bytes
    buf += len(component).to_bytes(4, "big")
    buf += component
    return hashlib.sha256(bytes(buf)).digest()


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def load_issuer_key() -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    assert len(seed) == 32 and len(pubkey) == 32
    return seed, pubkey


def build_protected_header(kid: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> dict:
    return {
        COSE_LABEL_ALG: ALG_EDDSA,
        COSE_LABEL_KID: kid,
        COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
    }


def build_sig_structure(protected_bstr: bytes, payload_bstr: bytes) -> bytes:
    return dcbor(["Signature1", protected_bstr, b"", payload_bstr])


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def build_signing_key_entry(kid: bytes, pubkey_raw: bytes) -> dict:
    return {
        "kid": kid,
        "pubkey": pubkey_raw,
        "suite_id": SUITE_ID,
        "status": SIGNING_KEY_ACTIVE_STATUS,
        "valid_from": ISSUER_VALID_FROM,
        "valid_to": None,
        "supersedes": None,
        "attestation": None,
    }


def recompute_author_event_hash(preimage: dict) -> bytes:
    return domain_separated_sha256(TAG_AUTHOR_EVENT, dcbor(preimage))


def recompute_canonical_event_hash(scope: bytes, payload_bytes: bytes) -> bytes:
    preimage = bytearray()
    preimage.append(0xA3)
    preimage.extend(dcbor("version"))
    preimage.extend(dcbor(1))
    preimage.extend(dcbor("ledger_scope"))
    preimage.extend(dcbor(scope))
    preimage.extend(dcbor("event_payload"))
    preimage.extend(payload_bytes)
    return domain_separated_sha256(TAG_CANONICAL_EVENT, bytes(preimage))


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

    genesis_event_bytes = GENESIS_DIR.joinpath("expected-event.cbor").read_bytes()
    assert (
        hashlib.sha256(genesis_event_bytes).hexdigest()
        == EXPECTED_GENESIS_EVENT_SHA256
    ), "append/001 genesis event drifted"

    genesis_envelope = cbor2.loads(genesis_event_bytes)
    genesis_payload = cbor2.loads(genesis_envelope.value[2])
    assert genesis_payload["header"]["authored_at"] == GENESIS_AUTHORED_AT
    assert genesis_payload["sequence"] == 0
    assert genesis_payload["ledger_scope"] == LEDGER_SCOPE

    genesis_canonical_hash = recompute_canonical_event_hash(
        LEDGER_SCOPE, genesis_envelope.value[2]
    )
    genesis_hash_via_head = cbor2.loads(
        GENESIS_DIR.joinpath("expected-append-head.cbor").read_bytes()
    )["canonical_event_hash"]
    assert genesis_canonical_hash == bytes(genesis_hash_via_head), (
        f"genesis canonical hash mismatch: recompute={genesis_canonical_hash.hex()} "
        f"vs append_head={bytes(genesis_hash_via_head).hex()}"
    )

    chain_preimage_bytes = CHAIN_DIR.joinpath(
        "input-author-event-hash-preimage.cbor"
    ).read_bytes()
    chain_preimage = cbor2.loads(chain_preimage_bytes)

    assert chain_preimage["header"]["authored_at"] == ts(1745000001)
    assert chain_preimage["sequence"] == 1
    assert chain_preimage["prev_hash"] == genesis_hash_via_head

    tampered_preimage = dict(chain_preimage)
    tampered_header = dict(chain_preimage["header"])  # independent copy — header is replaced wholesale
    tampered_header["authored_at"] = TAMPERED_CHAIN_AUTHORED_AT
    tampered_preimage["header"] = tampered_header

    tampered_author_event_hash = recompute_author_event_hash(tampered_preimage)

    upstream_payload = cbor2.loads(
        CHAIN_DIR.joinpath("expected-event-payload.cbor").read_bytes()
    )
    tampered_payload = dict(upstream_payload)
    tampered_payload["header"] = tampered_header
    tampered_payload["author_event_hash"] = tampered_author_event_hash

    tampered_payload_bytes = dcbor(tampered_payload)

    tampered_canonical_hash = recompute_canonical_event_hash(
        LEDGER_SCOPE, tampered_payload_bytes
    )

    protected_map_bytes = dcbor(build_protected_header(kid))
    sig_structure = build_sig_structure(protected_map_bytes, tampered_payload_bytes)
    signature = ed25519_sign(seed, sig_structure)

    tampered_envelope = cbor2.CBORTag(
        18,
        [protected_map_bytes, {}, tampered_payload_bytes, signature],
    )

    ledger_bytes = dcbor([genesis_envelope, tampered_envelope])

    write_bytes("input-tampered-event.cbor", dcbor(tampered_envelope))
    write_bytes("input-tampered-ledger.cbor", ledger_bytes)

    registry = [build_signing_key_entry(kid, pubkey_raw)]
    write_bytes("input-signing-key-registry.cbor", dcbor(registry))

    print()
    print(f"  genesis authored_at              = {GENESIS_AUTHORED_AT}")
    print(f"  tampered chain authored_at       = {TAMPERED_CHAIN_AUTHORED_AT}")
    print(f"  tampered canonical_event_hash    = {tampered_canonical_hash.hex()}")
    print(f"  kid                              = {kid.hex()}")
    print(f"  tamper_kind                      = timestamp_order_violation")


if __name__ == "__main__":
    main()
