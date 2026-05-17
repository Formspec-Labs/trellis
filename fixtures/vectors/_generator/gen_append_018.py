"""Generate byte-exact vector `append/018-attachment-bound`.

Authoring aid only. The normative split is ADR 0072 + Formspec Respondent
Ledger §6.9 + Trellis Core §6:

* Formspec owns the `EvidenceAttachmentBinding` metadata shape.
* Trellis carries that metadata in
  `EventPayload.extensions["trellis.evidence-attachment-binding.v1"]`.
* Trellis `PayloadExternal` names the attachment ciphertext bytes; its
  `content_hash` equals the Formspec `payload_content_hash` value.
"""
from __future__ import annotations

import hashlib
import json
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
FORMSPEC_FIXTURE_CANDIDATES = [
    ROOT.parents[2] / "fixtures" / "respondent-ledger" / "attachment-added-binding.json",
    ROOT.parents[2] / "formspec" / "fixtures" / "respondent-ledger" / "attachment-added-binding.json",
    ROOT.parents[3] / "formspec" / "fixtures" / "respondent-ledger" / "attachment-added-binding.json",
]
FORMSPEC_FIXTURE = next(
    (candidate for candidate in FORMSPEC_FIXTURE_CANDIDATES if candidate.is_file()),
    FORMSPEC_FIXTURE_CANDIDATES[0],
)
OUT_DIR = ROOT / "append" / "018-attachment-bound"

ATTACHMENT_CIPHERTEXT = (
    b"formspec attachment ciphertext fixture 018\n" + bytes(range(32))
)

LEDGER_SCOPE = b"respondent-ledger:resp-8d0b1e85"
SEQUENCE = 0
TIMESTAMP = ts(1776866400)
EVENT_TYPE = b"formspec.attachment.added"
CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0
SUITE_ID = SUITE_ID_PHASE_1

EXTENSION_KEY = "trellis.evidence-attachment-binding.v1"
TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"
TAG_TRELLIS_FORMSPEC_IDEMPOTENCY_V1 = "trellis-formspec-idempotency-v1"


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


def load_formspec_fixture() -> dict:
    if not FORMSPEC_FIXTURE.is_file():
        raise FileNotFoundError(
            f"Missing Formspec fixture {FORMSPEC_FIXTURE}. "
            "Checked formspec-stack root, nested formspec/, and sibling formspec/ layouts."
        )
    return json.loads(FORMSPEC_FIXTURE.read_text())


def parse_hash(value: str) -> bytes:
    prefix, hex_value = value.split(":", 1)
    assert prefix == "sha256"
    digest = bytes.fromhex(hex_value)
    assert len(digest) == 32
    return digest


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


def build_payload_ref(content_hash: bytes) -> dict:
    return {
        "ref_type": "external",
        "content_hash": content_hash,
        "availability": 0,
        "retrieval_hint": None,
    }


def build_key_bag() -> dict:
    return {"entries": []}


def build_idempotency_key(formspec_event: dict) -> tuple[dict, bytes, bytes]:
    preimage = {
        "responseId": formspec_event["responseId"],
        "eventId": formspec_event["eventId"],
    }
    preimage_bytes = dcbor(preimage)
    key = domain_separated_sha256(TAG_TRELLIS_FORMSPEC_IDEMPOTENCY_V1, preimage_bytes)
    return preimage, preimage_bytes, key


def build_author_event_hash_preimage(
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
    idempotency_key: bytes,
    extensions: dict,
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
        "extensions": extensions,
    }


def build_event_payload(
    author_event_hash: bytes,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
    idempotency_key: bytes,
    extensions: dict,
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
        "extensions": extensions,
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
    print(f"  {name:48s} {len(data):>5d} bytes  sha256={hashlib.sha256(data).hexdigest()}")


def write_text(name: str, data: str) -> None:
    path = OUT_DIR / name
    path.write_text(data)
    print(f"  {name:48s} {len(data.encode('utf-8')):>5d} bytes  sha256={hashlib.sha256(data.encode('utf-8')).hexdigest()}")


def manifest_text() -> str:
    return '''id          = "append/018-attachment-bound"
op          = "append"
status      = "active"
description = """Genesis append of a Formspec Respondent Ledger `attachment.added` \
event under ADR 0072. The Formspec `EvidenceAttachmentBinding` metadata rides \
in `EventPayload.extensions["trellis.evidence-attachment-binding.v1"]`; \
`PayloadExternal` names the attachment ciphertext bytes."""

[coverage]
tr_core = [
    "TR-CORE-001",  # canonical append contract
    "TR-CORE-018",  # authored / canonical / signed event surfaces
    "TR-CORE-021",  # ledger_scope declared; genesis sequence = 0
    "TR-CORE-030",  # dCBOR encoding + canonical event hash construction
    "TR-CORE-031",  # content_hash computed over ciphertext bytes
    "TR-CORE-050",  # idempotency_key stable in wire contract
    "TR-CORE-080",  # Phase-1 envelope admits later case-ledger evidence events
]

[inputs]
signing_key              = "../../_keys/issuer-001.cose_key"
formspec_event           = "input-formspec-respondent-ledger-event.json"
attachment_ciphertext    = "input-attachment-ciphertext.bin"
attachment_binding       = "input-evidence-attachment-binding.cbor"
idempotency_preimage     = "input-formspec-idempotency-preimage.cbor"
authored_event           = "input-author-event-hash-preimage.cbor"

[expected]
author_event_hash = "author-event-hash.bin"
canonical_event   = "expected-event-payload.cbor"
signed_event      = "expected-event.cbor"
append_head       = "expected-append-head.cbor"

[derivation]
document = "derivation.md"
'''


def derivation_text(
    content_hash: bytes,
    idempotency_key: bytes,
    author_event_hash: bytes,
    canonical_event_hash: bytes,
) -> str:
    return f"""# append/018 attachment-bound

This vector pins the Trellis half of ADR 0072 for a Formspec-originated
attachment binding.

## Inputs

- Formspec authored fixture: `input-formspec-respondent-ledger-event.json`,
  copied from the Formspec workspace file `fixtures/respondent-ledger/attachment-added-binding.json` (repository root; not under `trellis/fixtures/vectors/`).
- Attachment ciphertext bytes: `input-attachment-ciphertext.bin`.
- Binding metadata: `input-evidence-attachment-binding.cbor`, the dCBOR
  encoding of `attachmentBinding` from the Formspec fixture.

## Contract

The Trellis event is a genesis append with:

- `EventHeader.event_type = "formspec.attachment.added"`
- `EventPayload.payload_ref = PayloadExternal`
- `EventPayload.extensions["trellis.evidence-attachment-binding.v1"] =
  EvidenceAttachmentBinding`
- `EventPayload.content_hash = PayloadExternal.content_hash =
  EvidenceAttachmentBinding.payload_content_hash`

The payload hash is over the attachment ciphertext bytes named by
`PayloadExternal`, not over the binding metadata.

## Pinned hashes

- `content_hash`: `{content_hash.hex()}`
- `idempotency_key`: `{idempotency_key.hex()}`
- `author_event_hash`: `{author_event_hash.hex()}`
- `canonical_event_hash`: `{canonical_event_hash.hex()}`
"""


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"generating vector at {OUT_DIR.relative_to(ROOT.parent.parent)}/")

    formspec_event = load_formspec_fixture()
    binding = formspec_event["attachmentBinding"]
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, ATTACHMENT_CIPHERTEXT)
    assert content_hash == parse_hash(binding["payload_content_hash"])

    seed, pubkey_raw = load_issuer_key()
    kid = derive_kid(SUITE_ID, pubkey_raw)

    write_text(
        "input-formspec-respondent-ledger-event.json",
        json.dumps(formspec_event, indent=2, sort_keys=True) + "\n",
    )
    write_bytes("input-attachment-ciphertext.bin", ATTACHMENT_CIPHERTEXT)
    write_bytes("input-evidence-attachment-binding.cbor", dcbor(binding))

    _, idempotency_preimage_bytes, idempotency_key = build_idempotency_key(formspec_event)
    write_bytes("input-formspec-idempotency-preimage.cbor", idempotency_preimage_bytes)

    extensions = {EXTENSION_KEY: binding}
    header = build_event_header()
    payload_ref = build_payload_ref(content_hash)
    key_bag = build_key_bag()
    authored_map = build_author_event_hash_preimage(
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
        idempotency_key=idempotency_key,
        extensions=extensions,
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
        extensions=extensions,
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

    write_text("manifest.toml", manifest_text())
    write_text(
        "derivation.md",
        derivation_text(
            content_hash=content_hash,
            idempotency_key=idempotency_key,
            author_event_hash=author_event_hash,
            canonical_event_hash=canonical_event_hash,
        ),
    )


if __name__ == "__main__":
    main()
