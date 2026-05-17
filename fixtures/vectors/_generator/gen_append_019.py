"""Generate byte-exact reference vector `append/019-wos-signature-affirmation`.

Authoring aid only. This vector exercises Trellis Core §23 composition with
WOS `custodyHook` for the WOS Signature Profile provenance family:
`SignatureAffirmation` stays a WOS-authored record, while Trellis owns the
envelope, canonical append, hash chain, and signature.
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
OUT_DIR = ROOT / "append" / "019-wos-signature-affirmation"

CASE_ID = "sba-poc_case_01jqrpd32jf8xtx9qxkkv3rqsc"
RECORD_ID = "sba-poc_prov_01jqt0f0wm8f4b7n1j6m2r3k4p"
LEDGER_SCOPE = f"wos-case:{CASE_ID}".encode("utf-8")
SEQUENCE = 0
TIMESTAMP = ts(1776877800)
EVENT_TYPE = b"wos.kernel.signature_affirmation"
CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0
PAYLOAD_NONCE = b"\x00" * 12
SUITE_ID = SUITE_ID_PHASE_1

TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"
TAG_TRELLIS_WOS_IDEMPOTENCY_V1 = "trellis-wos-idempotency-v1"

WOS_RECORD = {
    "id": RECORD_ID,
    "event": "wos.kernel.signature_affirmation",
    "timestamp": "2026-04-22T14:30:00Z",
    "actorId": "applicant",
    "auditLayer": "facts",
    "data": {
        "signerId": "applicant",
        "roleId": "applicantSigner",
        "role": "signer",
        "documentId": "benefitsApplication",
        "documentHash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "documentHashAlgorithm": "sha-256",
        "signedAt": "2026-04-22T12:00:00Z",
        "identityBinding": {
            "method": "email-otp",
            "assuranceLevel": "standard",
            "providerRef": "urn:agency.gov:identity:providers:email-otp",
        },
        "consentReference": {
            "consentTextRef": "urn:agency.gov:consent:esign-benefits:v1",
            "consentVersion": "1.0.0",
            "acceptedAtPath": "authoredSignatures[0].signedAt",
            "affirmationPath": "authoredSignatures[0].consentAccepted",
        },
        "signatureProvider": "urn:agency.gov:signature:providers:formspec",
        "ceremonyId": "ceremony-2026-0001",
        "profileRef": "urn:agency.gov:wos:signature-profile:benefits:v1",
        "formspecResponseRef": "https://example.org/forms/signature-attestation#responses/resp-2026-0001",
        "custodyHookEligible": True,
    },
}

WOS_IDEMPOTENCY_TUPLE = {
    "caseId": CASE_ID,
    "recordId": RECORD_ID,
}


def domain_separated_preimage(tag: str, component: bytes) -> bytes:
    tag_bytes = tag.encode("utf-8")
    return (
        len(tag_bytes).to_bytes(4, "big")
        + tag_bytes
        + len(component).to_bytes(4, "big")
        + component
    )


def load_issuer_key() -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    assert len(seed) == 32 and len(pubkey) == 32
    return seed, pubkey


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def build_event_header() -> dict:
    return {
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


def build_payload_ref(ciphertext: bytes) -> dict:
    return {
        "ref_type": "inline",
        "ciphertext": ciphertext,
        "nonce": PAYLOAD_NONCE,
    }


def build_key_bag() -> dict:
    return {"entries": []}


def build_author_event_hash_preimage(
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
    idempotency_key: bytes,
) -> dict:
    return {
        "version": 1,
        "ledger_scope": LEDGER_SCOPE,
        "sequence": SEQUENCE,
        "prev_hash": None,
        "causal_deps": None,
        "content_hash": content_hash,
        "header": header,
        "commitments": None,
        "payload_ref": payload_ref,
        "key_bag": key_bag,
        "idempotency_key": idempotency_key,
        "extensions": None,
    }


def build_event_payload(
    author_event_hash: bytes,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
    idempotency_key: bytes,
) -> dict:
    return {
        "version": 1,
        "ledger_scope": LEDGER_SCOPE,
        "sequence": SEQUENCE,
        "prev_hash": None,
        "causal_deps": None,
        "author_event_hash": author_event_hash,
        "content_hash": content_hash,
        "header": header,
        "commitments": None,
        "payload_ref": payload_ref,
        "key_bag": key_bag,
        "idempotency_key": idempotency_key,
        "extensions": None,
    }


def build_canonical_event_hash_preimage(event_payload: dict) -> dict:
    return {
        "version": 1,
        "ledger_scope": LEDGER_SCOPE,
        "event_payload": event_payload,
    }


def build_protected_header(kid: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> dict:
    return {
        COSE_LABEL_ALG: ALG_EDDSA,
        COSE_LABEL_KID: kid,
        COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
    }


def build_sig_structure(protected_bstr: bytes, payload_bstr: bytes) -> bytes:
    return dcbor(["Signature1", protected_bstr, b"", payload_bstr])


def build_append_head(scope: bytes, sequence: int, canonical_event_hash: bytes) -> dict:
    return {
        "scope": scope,
        "sequence": sequence,
        "canonical_event_hash": canonical_event_hash,
    }


def write_bytes(name: str, data: bytes) -> None:
    path = OUT_DIR / name
    path.write_bytes(data)
    print(f"  {name:45s}  {len(data):>5d} bytes  sha256={hashlib.sha256(data).hexdigest()}")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"generating vector at {OUT_DIR.relative_to(ROOT.parent.parent)}/")

    seed, pubkey_raw = load_issuer_key()
    kid = derive_kid(SUITE_ID, pubkey_raw)

    wos_payload = dcbor(WOS_RECORD)
    write_bytes("input-wos-record.dcbor", wos_payload)

    tuple_bytes = dcbor(WOS_IDEMPOTENCY_TUPLE)
    write_bytes("input-wos-idempotency-tuple.cbor", tuple_bytes)
    idempotency_key = domain_separated_sha256(TAG_TRELLIS_WOS_IDEMPOTENCY_V1, tuple_bytes)
    assert len(idempotency_key) == 32

    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, wos_payload)

    header = build_event_header()
    payload_ref = build_payload_ref(wos_payload)
    key_bag = build_key_bag()
    authored_map = build_author_event_hash_preimage(
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
        idempotency_key=idempotency_key,
    )
    authored_bytes = dcbor(authored_map)
    write_bytes("input-author-event-hash-preimage.cbor", authored_bytes)

    author_event_preimage = domain_separated_preimage(
        TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes
    )
    write_bytes("author-event-preimage.bin", author_event_preimage)
    author_event_hash = hashlib.sha256(author_event_preimage).digest()
    write_bytes("author-event-hash.bin", author_event_hash)

    event_payload = build_event_payload(
        author_event_hash=author_event_hash,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
        idempotency_key=idempotency_key,
    )
    event_payload_bytes = dcbor(event_payload)
    write_bytes("expected-event-payload.cbor", event_payload_bytes)

    protected_map_bytes = dcbor(build_protected_header(kid))
    sig_structure = build_sig_structure(protected_map_bytes, event_payload_bytes)
    write_bytes("sig-structure.bin", sig_structure)

    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    cose_sign1 = cbor2.CBORTag(18, [protected_map_bytes, {}, event_payload_bytes, signature])
    write_bytes("expected-event.cbor", dcbor(cose_sign1))

    canonical_preimage_bytes = dcbor(build_canonical_event_hash_preimage(event_payload))
    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1, canonical_preimage_bytes
    )
    append_head = build_append_head(LEDGER_SCOPE, SEQUENCE, canonical_event_hash)
    write_bytes("expected-append-head.cbor", dcbor(append_head))

    print()
    print(f"  wos_payload_sha256           = {hashlib.sha256(wos_payload).hexdigest()}")
    print(f"  idempotency_key              = {idempotency_key.hex()}")
    print(f"  content_hash                 = {content_hash.hex()}")
    print(f"  author_event_hash            = {author_event_hash.hex()}")
    print(f"  canonical_event_hash         = {canonical_event_hash.hex()}")


if __name__ == "__main__":
    main()
