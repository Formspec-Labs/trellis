"""Generate byte-exact reference vector `tamper/042-timestamp-legacy-uint-rejected`.

Authoring aid only. This script is NOT normative; `derivation.md` is the
spec-prose reproduction evidence. If this script and Core disagree, Core wins.

Determinism: two runs produce byte-identical output. No randomness, no
wall-clock reads, no environment lookups beyond pinned inputs.

Scope — ADR 0069 D-2.1: timestamps on the wire MUST be `[uint, uint]`
arrays (protobuf pattern). Legacy bare `uint` encoding is rejected at decode
time with `legacy_timestamp_format` error kind.

Construction:
  1. Load append/001 (genesis) byte-exact event.
  2. Mutate the payload header.authored_at from `[1745000000, 0]` to bare
     `1745000000` (legacy uint encoding).
  3. Re-encode the tampered payload as dCBOR; re-sign under issuer-001.
  4. Build a single-element ledger: [tampered genesis event].

The verifier walk:
  * Step 4.a — kid resolves in registry. PASS.
  * Step 4.b — signatures verify (re-signed with real key). PASS.
  * Step 4.c — payload decodes from COSE. PASS.
  * Step 4.c-header — `map_lookup_timestamp(header, "authored_at")` sees
    `Value::Integer` instead of `Value::Array`. **FAIL** —
    `legacy_timestamp_format`.
  * Step 9 — `integrity_verified` = false; `readability_verified` = false
    (structural rejection at decode time).

This is a structural failure: the verifier cannot extract timestamps from the
event header, so the entire verification walk aborts at the first event.
`structure_verified` remains true (COSE envelope is valid), but
`readability_verified` is false because the payload fails to parse.
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
OUT_DIR = ROOT / "tamper" / "042-timestamp-legacy-uint-rejected"

EXPECTED_GENESIS_EVENT_SHA256 = (
    "deca82133a10729c570e277ee38a975b7f6b9e79374052f80069b3863bdd733d"
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
    upstream_payload = cbor2.loads(genesis_envelope.value[2])

    tampered_header = dict(upstream_payload["header"])
    tampered_header["authored_at"] = 1745000000

    tampered_payload = dict(upstream_payload)
    tampered_payload["header"] = tampered_header

    tampered_payload_bytes = dcbor(tampered_payload)

    protected_map_bytes = dcbor(build_protected_header(kid))
    sig_structure = build_sig_structure(protected_map_bytes, tampered_payload_bytes)
    signature = ed25519_sign(seed, sig_structure)

    tampered_envelope = cbor2.CBORTag(
        18,
        [protected_map_bytes, {}, tampered_payload_bytes, signature],
    )

    ledger_bytes = dcbor([tampered_envelope])

    write_bytes("input-tampered-event.cbor", dcbor(tampered_envelope))
    write_bytes("input-tampered-ledger.cbor", ledger_bytes)

    registry = [build_signing_key_entry(kid, pubkey_raw)]
    write_bytes("input-signing-key-registry.cbor", dcbor(registry))

    print()
    print(f"  authored_at encoding: bare uint 1745000000 (legacy)")
    print(f"  tamper_kind: legacy_timestamp_format")


if __name__ == "__main__":
    main()
