"""Generate `tamper/043` — UCA rotating-key overlap boundary."""
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
KEY_ISSUER = ROOT / "_keys" / "issuer-001.cose_key"

CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0
PAYLOAD_NONCE = b"\x00" * 12
SUITE_ID = SUITE_ID_PHASE_1

EVENT_TYPE_HOST = b"trellis.test.host-event.v1"
EVENT_TYPE_IDENTITY = b"x-trellis-test/identity-attestation/v1"
EVENT_TYPE_UCA = b"trellis.user-content-attestation.v1"

TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"
TAG_USER_CONTENT_ATTESTATION_V1 = "trellis-user-content-attestation-v1"

HOST_AUTHORED_AT_SECONDS = 1_776_900_000
HOST_AUTHORED_AT = ts(HOST_AUTHORED_AT_SECONDS)
ROTATING_VALID_FROM = 1_776_899_000
ROTATING_VALID_TO = 1_776_899_999


def domain_separated_preimage(tag: str, component: bytes) -> bytes:
    tag_bytes = tag.encode("utf-8")
    return (
        len(tag_bytes).to_bytes(4, "big")
        + tag_bytes
        + len(component).to_bytes(4, "big")
        + component
    )


def load_cose_key(path: Path) -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(path.read_bytes())
    return cose_key[-4], cose_key[-2]


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def write_bytes(out_dir: Path, name: str, data: bytes) -> str:
    path = out_dir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"  {name:55s}  {len(data):>5d} bytes  sha256={digest}")
    return digest


def write_text(out_dir: Path, name: str, text: str) -> None:
    path = out_dir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def cose_sign1(seed: bytes, kid: bytes, payload_bytes: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> bytes:
    protected = dcbor(
        {
            COSE_LABEL_ALG: ALG_EDDSA,
            COSE_LABEL_KID: kid,
            COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
        }
    )
    sig_structure = dcbor(["Signature1", protected, b"", payload_bytes])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    return dcbor(cbor2.CBORTag(18, [protected, {}, payload_bytes, signature]))


def build_rotating_key_registry_after_overlap(kid: bytes, pubkey: bytes) -> bytes:
    return dcbor(
        [
            {
                "kid": kid,
                "pubkey": pubkey,
                "status": 1,
                "valid_from": ts(ROTATING_VALID_FROM),
                "valid_to": ts(ROTATING_VALID_TO),
            }
        ]
    )


def build_event_header(event_type: bytes) -> dict:
    return {
        "event_type": event_type,
        "authored_at": HOST_AUTHORED_AT,
        "retention_tier": RETENTION_TIER,
        "classification": CLASSIFICATION,
        "outcome_commitment": None,
        "subject_ref_commitment": None,
        "tag_commitment": None,
        "witness_ref": None,
        "extensions": None,
    }


def build_event(
    *,
    ledger_scope: bytes,
    sequence: int,
    prev_hash: bytes | None,
    event_type: bytes,
    extensions: dict | None,
    payload_marker: bytes,
    idempotency_key: bytes,
) -> tuple[bytes, bytes]:
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_marker)
    header = build_event_header(event_type)
    payload_ref = {
        "ref_type": "inline",
        "ciphertext": payload_marker,
        "nonce": PAYLOAD_NONCE,
    }
    key_bag = {"entries": []}
    authored_map = {
        "version": 1,
        "ledger_scope": ledger_scope,
        "sequence": sequence,
        "prev_hash": prev_hash,
        "causal_deps": None,
        "content_hash": content_hash,
        "header": header,
        "commitments": None,
        "payload_ref": payload_ref,
        "key_bag": key_bag,
        "idempotency_key": idempotency_key,
        "extensions": extensions,
    }
    authored_bytes = dcbor(authored_map)
    author_event_hash = hashlib.sha256(
        domain_separated_preimage(TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes)
    ).digest()
    event_payload = {
        "version": 1,
        "ledger_scope": ledger_scope,
        "sequence": sequence,
        "prev_hash": prev_hash,
        "causal_deps": None,
        "author_event_hash": author_event_hash,
        "content_hash": content_hash,
        "header": header,
        "commitments": None,
        "payload_ref": payload_ref,
        "key_bag": key_bag,
        "idempotency_key": idempotency_key,
        "extensions": extensions,
    }
    event_payload_bytes = dcbor(event_payload)
    canonical_preimage = dcbor(
        {
            "version": 1,
            "ledger_scope": ledger_scope,
            "event_payload": event_payload,
        }
    )
    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1, canonical_preimage
    )
    return event_payload_bytes, canonical_event_hash


def build_identity_event(
    *,
    seed: bytes,
    kid: bytes,
    ledger_scope: bytes,
    sequence: int,
    prev_hash: bytes | None,
    subject: str,
    payload_marker: bytes,
    idempotency_key: bytes,
) -> tuple[bytes, bytes]:
    extensions = {EVENT_TYPE_IDENTITY.decode("utf-8"): {"subject": subject}}
    payload_bytes, canonical_hash = build_event(
        ledger_scope=ledger_scope,
        sequence=sequence,
        prev_hash=prev_hash,
        event_type=EVENT_TYPE_IDENTITY,
        extensions=extensions,
        payload_marker=payload_marker,
        idempotency_key=idempotency_key,
    )
    return cose_sign1(seed, kid, payload_bytes), canonical_hash


def build_host_event(
    *,
    seed: bytes,
    kid: bytes,
    ledger_scope: bytes,
    sequence: int,
    prev_hash: bytes | None,
    payload_marker: bytes,
    idempotency_key: bytes,
) -> tuple[bytes, bytes]:
    payload_bytes, canonical_hash = build_event(
        ledger_scope=ledger_scope,
        sequence=sequence,
        prev_hash=prev_hash,
        event_type=EVENT_TYPE_HOST,
        extensions=None,
        payload_marker=payload_marker,
        idempotency_key=idempotency_key,
    )
    return cose_sign1(seed, kid, payload_bytes), canonical_hash


def sign_uca(
    *,
    seed: bytes,
    attestation_id: str,
    attested_event_hash: bytes,
    attested_event_position: int,
    attestor: str,
    identity_attestation_ref: bytes,
    signing_intent: str,
) -> bytes:
    preimage = dcbor(
        [
            attestation_id,
            attested_event_hash,
            attested_event_position,
            attestor,
            identity_attestation_ref,
            signing_intent,
            HOST_AUTHORED_AT,
        ]
    )
    digest = domain_separated_sha256(TAG_USER_CONTENT_ATTESTATION_V1, preimage)
    return Ed25519PrivateKey.from_private_bytes(seed).sign(digest)


def build_uca_event(
    *,
    seed: bytes,
    kid: bytes,
    ledger_scope: bytes,
    sequence: int,
    prev_hash: bytes,
    attestation_id: str,
    host_hash: bytes,
    identity_hash: bytes,
    attestor: str,
    signing_intent: str,
) -> tuple[bytes, bytes]:
    signature = sign_uca(
        seed=seed,
        attestation_id=attestation_id,
        attested_event_hash=host_hash,
        attested_event_position=1,
        attestor=attestor,
        identity_attestation_ref=identity_hash,
        signing_intent=signing_intent,
    )
    uca_payload = {
        "attestation_id": attestation_id,
        "attested_event_hash": host_hash,
        "attested_event_position": 1,
        "attestor": attestor,
        "identity_attestation_ref": identity_hash,
        "signing_intent": signing_intent,
        "attested_at": HOST_AUTHORED_AT,
        "signature": signature,
        "signing_kid": kid,
        "extensions": None,
    }
    payload_bytes, canonical_hash = build_event(
        ledger_scope=ledger_scope,
        sequence=sequence,
        prev_hash=prev_hash,
        event_type=EVENT_TYPE_UCA,
        extensions={EVENT_TYPE_UCA.decode("utf-8"): uca_payload},
        payload_marker=b"uca-event-043",
        idempotency_key=b"idemp-043-uca",
    )
    return cose_sign1(seed, kid, payload_bytes), canonical_hash


def write_manifest(out_dir: Path, failing_event_id: str) -> None:
    write_text(
        out_dir,
        "manifest.toml",
        f'''id          = "tamper/043-uca-rotating-after-valid-to"
op          = "tamper"
status      = "active"
description = """Core §8.4 rotation-grace boundary violation: `signing_kid` resolves to a signing key with `status = 1` (Rotating), `valid_from` before `attested_at`, and `valid_to` before `attested_at`. `Rotating` is admitted only inside the declared overlap window; after `valid_to`, UCA step 6 flips `key_active = false` and emits `user_content_attestation_key_not_active`."""

[coverage]
tr_core = [
    "TR-CORE-018",
    "TR-CORE-030",
    "TR-CORE-035",
    "TR-CORE-156",
]
tr_op = [
    "TR-OP-133",
]

[inputs]
ledger               = "input-tampered-ledger.cbor"
tampered_event       = "input-tampered-event.cbor"
signing_key_registry = "input-signing-key-registry.cbor"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
tamper_kind          = "user_content_attestation_key_not_active"
failing_event_id     = "{failing_event_id}"

[derivation]
document = "derivation.md"
''',
    )


def gen_tamper_043(*, seed: bytes, pub: bytes, kid: bytes) -> bytes:
    out_dir = ROOT / "tamper" / "043-uca-rotating-after-valid-to"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {out_dir.relative_to(ROOT.parent.parent)}/")

    scope = b"trellis-uca-tamper:043-rotating-after-valid-to"
    attestor = "urn:trellis:principal:applicant-043"
    attestation_id = "urn:trellis:user-content-attestation:tamper:043"
    signing_intent = "urn:wos:signature-intent:applicant-affirmation"

    identity_signed, identity_hash = build_identity_event(
        seed=seed,
        kid=kid,
        ledger_scope=scope,
        sequence=0,
        prev_hash=None,
        subject=attestor,
        payload_marker=b"identity-event-043",
        idempotency_key=b"idemp-043-identity",
    )
    host_signed, host_hash = build_host_event(
        seed=seed,
        kid=kid,
        ledger_scope=scope,
        sequence=1,
        prev_hash=identity_hash,
        payload_marker=b"host-event-043",
        idempotency_key=b"idemp-043-host",
    )
    uca_signed, uca_hash = build_uca_event(
        seed=seed,
        kid=kid,
        ledger_scope=scope,
        sequence=2,
        prev_hash=host_hash,
        attestation_id=attestation_id,
        host_hash=host_hash,
        identity_hash=identity_hash,
        attestor=attestor,
        signing_intent=signing_intent,
    )

    ledger = dcbor(
        [
            cbor2.loads(identity_signed),
            cbor2.loads(host_signed),
            cbor2.loads(uca_signed),
        ]
    )
    write_bytes(out_dir, "input-tampered-ledger.cbor", ledger)
    write_bytes(
        out_dir,
        "input-signing-key-registry.cbor",
        build_rotating_key_registry_after_overlap(kid, pub),
    )
    write_bytes(out_dir, "input-tampered-event.cbor", uca_signed)
    write_manifest(out_dir, uca_hash.hex())
    write_text(
        out_dir,
        "derivation.md",
        f"""# Derivation — `tamper/043-uca-rotating-after-valid-to`

3-event chain on `ledger_scope = {scope!r}`:

* seq 0: identity-attestation event.
* seq 1: host event.
* seq 2: user-content-attestation event signed under kid
  `{kid.hex()}`.

The registry marks that kid as `Rotating` (`SigningKeyStatus = 1`) with:

* `valid_from = [{ROTATING_VALID_FROM}, 0]`
* `valid_to = [{ROTATING_VALID_TO}, 0]`
* UCA `attested_at = [{HOST_AUTHORED_AT_SECONDS}, 0]`

Core §8.4 admits `Rotating` only during the declared rotation-grace overlap.
Because this attestation's `attested_at` is after `valid_to`, verifier step 6
flips `key_active = false` and emits
`user_content_attestation_key_not_active` with `failing_event_id` =
`{uca_hash.hex()}`.

Generator: `_generator/gen_tamper_043.py`.
""",
    )
    return uca_hash


def main() -> None:
    seed, pub = load_cose_key(KEY_ISSUER)
    kid = derive_kid(SUITE_ID, pub)
    gen_tamper_043(seed=seed, pub=pub, kid=kid)


if __name__ == "__main__":
    main()
