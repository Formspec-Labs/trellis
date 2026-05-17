"""Generate ADR 0066 D-3 tamper vector `tamper/050-rescission-terminality`.

The vector builds a valid four-event chain:

1. `append/011-correction`
2. `append/012-amendment`
3. `append/013-rescission`
4. a freshly signed `wos.governance.determination_amended` event

The final event is hash-linked, content-hash-valid, and signature-valid, but
it appears after `wos.governance.determination_rescinded` without an
intervening `wos.governance.reinstated` event. Core §19 step 4.h therefore
must report `rescission_terminality_violation`.
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
SOURCE_DIRS = [
    ROOT / "append" / "011-correction",
    ROOT / "append" / "012-amendment",
    ROOT / "append" / "013-rescission",
]
OUT_DIR = ROOT / "tamper" / "050-rescission-terminality"

CHAIN_SCOPE = b"wos-case:adr0066-fixture-primary"
CLASSIFICATION = b"x-trellis-test/unclassified"
PAYLOAD_NONCE = b"\x00" * 12
SUITE_ID = SUITE_ID_PHASE_1

TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"
TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"


def load_issuer_key() -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    assert isinstance(seed, bytes) and len(seed) == 32
    assert isinstance(pubkey, bytes) and len(pubkey) == 32
    return seed, pubkey


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def marker_hash(label: str) -> str:
    return hashlib.sha256(f"adr0066:{label}".encode("utf-8")).hexdigest()


def build_event_header(event_type: bytes, authored_at: list[int]) -> dict:
    return {
        "event_type": event_type,
        "authored_at": authored_at,
        "retention_tier": 0,
        "classification": CLASSIFICATION,
        "outcome_commitment": None,
        "subject_ref_commitment": None,
        "tag_commitment": None,
        "witness_ref": None,
        "extensions": None,
    }


def build_protected_header(kid: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> dict:
    return {
        COSE_LABEL_ALG: ALG_EDDSA,
        COSE_LABEL_KID: kid,
        COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
    }


def build_canonical_event_hash(ledger_scope: bytes, event_payload: dict) -> bytes:
    return domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1,
        dcbor({
            "version": 1,
            "ledger_scope": ledger_scope,
            "event_payload": event_payload,
        }),
    )


def build_sign1(seed: bytes, kid: bytes, payload_bytes: bytes) -> bytes:
    protected_map_bytes = dcbor(build_protected_header(kid))
    sig_structure = dcbor(["Signature1", protected_map_bytes, b"", payload_bytes])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    return dcbor(cbor2.CBORTag(18, [protected_map_bytes, {}, payload_bytes, signature]))


def build_terminality_event(
    *,
    seed: bytes,
    kid: bytes,
    prev_hash: bytes,
) -> tuple[bytes, bytes, bytes]:
    record = {
        "id": "adr0066-tamper-050",
        "event": "wos.governance.determination_amended",
        "timestamp": "2026-05-07T10:00:50Z",
        "auditLayer": "facts",
        "definitionVersion": "1.0.0",
        "data": {
            "priorDeterminationHash": marker_hash("prior-determination"),
            "newDeterminationValue": {
                "eligible": True,
                "monthlyAmount": 1995,
            },
            "amendmentAuthorizationEventHash": marker_hash(
                "post-rescission-amendment-authorized"
            ),
        },
    }
    record_bytes = dcbor(record)
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, record_bytes)
    header = build_event_header(
        b"wos.governance.determination_amended",
        ts(1_777_000_050),
    )
    payload_ref = {
        "ref_type": "inline",
        "ciphertext": record_bytes,
        "nonce": PAYLOAD_NONCE,
    }
    authored_map = {
        "version": 1,
        "ledger_scope": CHAIN_SCOPE,
        "sequence": 3,
        "prev_hash": prev_hash,
        "causal_deps": None,
        "content_hash": content_hash,
        "header": header,
        "commitments": None,
        "payload_ref": payload_ref,
        "key_bag": {"entries": []},
        "idempotency_key": b"idemp-adr0066-tamper-050",
        "extensions": None,
    }
    author_event_hash = domain_separated_sha256(
        TAG_TRELLIS_AUTHOR_EVENT_V1,
        dcbor(authored_map),
    )
    event_payload = dict(authored_map)
    event_payload["author_event_hash"] = author_event_hash
    event_payload_bytes = dcbor(event_payload)
    canonical_event_hash = build_canonical_event_hash(CHAIN_SCOPE, event_payload)
    return build_sign1(seed, kid, event_payload_bytes), record_bytes, canonical_event_hash


def write_bytes(name: str, data: bytes) -> None:
    path = OUT_DIR / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print(f"  {name:40s} {len(data):>5d} bytes  sha256={hashlib.sha256(data).hexdigest()}")


def write_text(name: str, text: str) -> None:
    path = OUT_DIR / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def manifest_for(failing_event_id: str) -> str:
    return f'''id = "tamper/050-rescission-terminality"
op = "tamper"
status = "active"
description = "Validly signs and hash-links a determination amendment after `wos.governance.determination_rescinded` without an intervening reinstatement. ADR 0066 D-3 requires `rescission_terminality_violation`."

[coverage]
tr_core = [
    "TR-CORE-171",
]

[inputs]
ledger = "input-tampered-ledger.cbor"
tampered_event = "input-tampered-event.cbor"
mode_record = "input-post-rescission-amendment-record.cbor"
signing_key_registry = "input-signing-key-registry.cbor"

[expected.report]
structure_verified = true
integrity_verified = false
readability_verified = true
tamper_kind = "rescission_terminality_violation"
failing_event_id = "{failing_event_id}"

[derivation]
document = "derivation.md"
'''


def derivation_for(failing_event_id: str, rescission_hash: str) -> str:
    return f"""# Derivation - `tamper/050-rescission-terminality`

This vector exercises ADR 0066 D-3 rescission terminality. The first three
events are copied byte-for-byte from `append/011-correction`,
`append/012-amendment`, and `append/013-rescission`. The fourth event is a new
`wos.governance.determination_amended` event with:

- `sequence` = `3`
- `prev_hash` = `{rescission_hash}`
- `event_type` = `wos.governance.determination_amended`

The fourth event recomputes `content_hash`, `author_event_hash`, and
`canonical_event_hash`, then signs the resulting payload under
`issuer-001`. Hash linkage, content hash, and signature verification all pass.

The failure is semantic and chain-local: the chain already observed
`wos.governance.determination_rescinded`, and no
`wos.governance.reinstated` event appears before the later determination
amendment. Core section 19 step 4.h / TR-CORE-171 requires the verifier to
record `rescission_terminality_violation`.

Pinned failing event id: `{failing_event_id}`.

Generator: `fixtures/vectors/_generator/gen_tamper_050.py`.
"""


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"generating vector at {OUT_DIR.relative_to(ROOT.parent.parent)}/")

    seed, pubkey = load_issuer_key()
    kid = derive_kid(SUITE_ID, pubkey)

    source_events = [
        cbor2.loads(path.joinpath("expected-event.cbor").read_bytes())
        for path in SOURCE_DIRS
    ]
    rescission_head = cbor2.loads(
        SOURCE_DIRS[-1].joinpath("expected-append-head.cbor").read_bytes()
    )
    rescission_hash = bytes(rescission_head["canonical_event_hash"])

    tampered_event, record_bytes, canonical_hash = build_terminality_event(
        seed=seed,
        kid=kid,
        prev_hash=rescission_hash,
    )
    tampered_event_value = cbor2.loads(tampered_event)
    ledger_bytes = dcbor([*source_events, tampered_event_value])
    signing_key_registry = [{
        "kid": kid,
        "pubkey": pubkey,
        "suite_id": SUITE_ID,
        "status": 0,
        "valid_from": ts(1_777_000_011),
        "valid_to": None,
        "supersedes": None,
        "attestation": None,
    }]

    write_bytes("input-post-rescission-amendment-record.cbor", record_bytes)
    write_bytes("input-tampered-event.cbor", tampered_event)
    write_bytes("input-tampered-ledger.cbor", ledger_bytes)
    write_bytes("input-signing-key-registry.cbor", dcbor(signing_key_registry))
    write_text("manifest.toml", manifest_for(canonical_hash.hex()))
    write_text("derivation.md", derivation_for(canonical_hash.hex(), rescission_hash.hex()))

    print()
    print(f"  rescission canonical_event_hash = {rescission_hash.hex()}")
    print(f"  failing_event_id                = {canonical_hash.hex()}")
    print("  tamper_kind                     = rescission_terminality_violation")


if __name__ == "__main__":
    main()
