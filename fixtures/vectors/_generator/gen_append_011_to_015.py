"""Generate byte-exact ADR 0066 append vectors `append/011..015`.

Authoring aid only. The vectors pin Trellis envelope bytes for the five
accepted ADR 0066 modes:

* 011 correction: same-chain authorizing act.
* 012 amendment: same-chain determination-changing act.
* 013 rescission: same-chain determination-withdrawal act.
* 014 reinstatement: same-chain reactivation after rescission.
* 015 supersession: new-chain genesis with `trellis.supersedes-chain-id.v1`.

WOS owns the governance record semantics. Trellis owns the envelope bytes,
canonical hashes, chain linkage, and the registered supersession extension.
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

CHAIN_SCOPE = b"wos-case:adr0066-fixture-primary"
SUPERSEDING_SCOPE = b"wos-case:adr0066-fixture-superseding"
CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0
PAYLOAD_NONCE = b"\x00" * 12
SUITE_ID = SUITE_ID_PHASE_1

EXT_SUPERSEDES_CHAIN_ID = "trellis.supersedes-chain-id.v1"

TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"


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


def marker_hash(label: str) -> str:
    return hashlib.sha256(f"adr0066:{label}".encode("utf-8")).hexdigest()


def event_hash_marker(label: str) -> bytes:
    return hashlib.sha256(f"adr0066:event:{label}".encode("utf-8")).digest()


def checkpoint_hash_marker(label: str) -> bytes:
    return hashlib.sha256(f"adr0066:checkpoint:{label}".encode("utf-8")).digest()


def build_event_header(event_type: bytes, authored_at: int) -> dict:
    return {
        "event_type": event_type,
        "authored_at": authored_at,
        "retention_tier": RETENTION_TIER,
        "classification": CLASSIFICATION,
        "outcome_commitment": None,
        "subject_ref_commitment": None,
        "tag_commitment": None,
        "witness_ref": None,
        "extensions": None,
    }


def build_payload_ref(payload_bytes: bytes) -> dict:
    return {
        "ref_type": "inline",
        "ciphertext": payload_bytes,
        "nonce": PAYLOAD_NONCE,
    }


def build_key_bag() -> dict:
    return {"entries": []}


def build_author_event_hash_preimage(
    *,
    ledger_scope: bytes,
    sequence: int,
    prev_hash: bytes | None,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    idempotency_key: bytes,
    extensions: dict | None,
) -> dict:
    return {
        "version": 1,
        "ledger_scope": ledger_scope,
        "sequence": sequence,
        "prev_hash": prev_hash,
        "causal_deps": None,
        "content_hash": content_hash,
        "header": header,
        "commitments": None,
        "payload_ref": payload_ref,
        "key_bag": build_key_bag(),
        "idempotency_key": idempotency_key,
        "extensions": extensions,
    }


def build_event_payload(
    *,
    authored_map: dict,
    author_event_hash: bytes,
) -> dict:
    event_payload = dict(authored_map)
    event_payload["author_event_hash"] = author_event_hash
    return event_payload


def build_canonical_event_hash_preimage(
    ledger_scope: bytes, event_payload: dict
) -> dict:
    return {
        "version": 1,
        "ledger_scope": ledger_scope,
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


def write_bytes(out_dir: Path, name: str, data: bytes) -> str:
    path = out_dir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"  {name:50s} {len(data):>5d} bytes  sha256={digest}")
    return digest


def write_text(out_dir: Path, name: str, text: str) -> None:
    path = out_dir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def authority_basis(value: str) -> dict:
    return {"kind": "actorPolicyRef", "value": value}


def mode_specs() -> list[dict]:
    determination_hash = marker_hash("prior-determination")
    correction_target = marker_hash("response-submitted")
    amendment_auth = marker_hash("amendment-authorized")
    rescission_auth = marker_hash("rescission-authorized")
    reinstatement_auth = marker_hash("reinstatement-authorized")
    prior_rescission = marker_hash("determination-rescinded")
    superseded_checkpoint = checkpoint_hash_marker("primary-head")

    return [
        {
            "dir": "append/011-correction",
            "vector_id": "011",
            "mode": "correction",
            "ledger_scope": CHAIN_SCOPE,
            "sequence": 0,
            "event_type": b"wos.governance.correction_authorized",
            "timestamp": ts(1_777_000_011),
            "idempotency_key": b"idemp-adr0066-011",
            "record": {
                "id": "adr0066-prov-011",
                "event": "wos.governance.correction_authorized",
                "timestamp": "2026-05-07T10:00:11Z",
                "auditLayer": "facts",
                "definitionVersion": "1.0.0",
                "actorId": "supervisor-001",
                "data": {
                    "correctionTargetEventHash": correction_target,
                    "correctedFieldSet": ["/applicantName", "/mailingAddress/zip"],
                    "reason": "transcription error corrected against signed source document",
                    "authorizingActorId": "supervisor-001",
                    "authorityBasis": authority_basis("intake-supervisor-correction-policy"),
                },
            },
            "description": "ADR 0066 mode 1 correction-authorizing act on the existing chain.",
        },
        {
            "dir": "append/012-amendment",
            "vector_id": "012",
            "mode": "amendment",
            "ledger_scope": CHAIN_SCOPE,
            "sequence": 1,
            "event_type": b"wos.governance.determination_amended",
            "timestamp": ts(1_777_000_012),
            "idempotency_key": b"idemp-adr0066-012",
            "record": {
                "id": "adr0066-prov-012",
                "event": "wos.governance.determination_amended",
                "timestamp": "2026-05-07T10:00:12Z",
                "auditLayer": "facts",
                "definitionVersion": "1.0.0",
                "data": {
                    "priorDeterminationHash": determination_hash,
                    "newDeterminationValue": {
                        "eligible": True,
                        "monthlyAmount": 1850,
                    },
                    "amendmentAuthorizationEventHash": amendment_auth,
                },
            },
            "description": "ADR 0066 mode 2 determination-changing amendment event on the same chain.",
        },
        {
            "dir": "append/013-rescission",
            "vector_id": "013",
            "mode": "rescission",
            "ledger_scope": CHAIN_SCOPE,
            "sequence": 2,
            "event_type": b"wos.governance.determination_rescinded",
            "timestamp": ts(1_777_000_013),
            "idempotency_key": b"idemp-adr0066-013",
            "record": {
                "id": "adr0066-prov-013",
                "event": "wos.governance.determination_rescinded",
                "timestamp": "2026-05-07T10:00:13Z",
                "auditLayer": "facts",
                "definitionVersion": "1.0.0",
                "data": {
                    "priorDeterminationHash": determination_hash,
                    "rescissionAuthorizationEventHash": rescission_auth,
                },
            },
            "description": "ADR 0066 mode 4 determination-rescinded event on the same chain.",
        },
        {
            "dir": "append/014-reinstatement",
            "vector_id": "014",
            "mode": "reinstatement",
            "ledger_scope": CHAIN_SCOPE,
            "sequence": 3,
            "event_type": b"wos.governance.reinstated",
            "timestamp": ts(1_777_000_014),
            "idempotency_key": b"idemp-adr0066-014",
            "record": {
                "id": "adr0066-prov-014",
                "event": "wos.governance.reinstated",
                "timestamp": "2026-05-07T10:00:14Z",
                "auditLayer": "facts",
                "definitionVersion": "1.0.0",
                "data": {
                    "priorRescissionEventHash": prior_rescission,
                    "reactivationAuthorizationEventHash": reinstatement_auth,
                    "reason": "rescission overturned on appeal; original determination restored",
                },
            },
            "description": "ADR 0066 mode 5 reinstatement event on the same chain.",
        },
        {
            "dir": "append/015-supersession",
            "vector_id": "015",
            "mode": "supersession",
            "ledger_scope": SUPERSEDING_SCOPE,
            "sequence": 0,
            "event_type": b"wos.kernel.supersession_started",
            "timestamp": ts(1_777_000_015),
            "idempotency_key": b"idemp-adr0066-015",
            "extensions": {
                EXT_SUPERSEDES_CHAIN_ID: {
                    "chain_id": CHAIN_SCOPE,
                    "checkpoint_hash": superseded_checkpoint,
                },
            },
            "record": {
                "id": "adr0066-prov-015",
                "event": "wos.kernel.supersession_started",
                "timestamp": "2026-05-07T10:00:15Z",
                "auditLayer": "facts",
                "definitionVersion": "1.0.0",
                "data": {
                    "relationship": {
                        "type": "supersedes",
                        "supersededChainId": CHAIN_SCOPE.decode("utf-8"),
                        "supersededCheckpointHash": superseded_checkpoint.hex(),
                    },
                    "reason": "appeal opened a replacement case file while preserving the prior chain",
                },
            },
            "description": "ADR 0066 mode 3 new-chain supersession event with registered Trellis linkage extension.",
        },
    ]


def manifest_for(spec: dict) -> str:
    tr_core = [
        "TR-CORE-001",
        "TR-CORE-018",
        "TR-CORE-021",
        "TR-CORE-030",
        "TR-CORE-031",
        "TR-CORE-050",
        "TR-CORE-080",
    ]
    if spec["vector_id"] == "015":
        tr_core.append("TR-CORE-169")
    tr_core_lines = ",\n    ".join(f'"{item}"' for item in tr_core)

    input_extra = ""
    if spec["vector_id"] == "015":
        input_extra = (
            'supersedes_chain_id_payload = "input-supersedes-chain-id.cbor"\n'
            'superseded_checkpoint_hash = "input-superseded-checkpoint-hash.bin"\n'
        )

    return f'''id          = "{spec["dir"]}"
op          = "append"
status      = "active"
description = """{spec["description"]}"""

[coverage]
tr_core = [
    {tr_core_lines},
]

[inputs]
signing_key      = "../../_keys/issuer-001.cose_key"
mode_record      = "input-adr0066-record.cbor"
authored_event   = "input-author-event-hash-preimage.cbor"
{input_extra}
[expected]
author_event_hash = "author-event-hash.bin"
canonical_event   = "expected-event-payload.cbor"
signed_event      = "expected-event.cbor"
append_head       = "expected-append-head.cbor"

[derivation]
document = "derivation.md"
'''


def derivation_for(
    spec: dict,
    *,
    content_hash: bytes,
    author_event_hash: bytes,
    canonical_event_hash: bytes,
    prev_hash: bytes | None,
) -> str:
    prev_text = "null" if prev_hash is None else prev_hash.hex()
    extension_text = ""
    if spec["vector_id"] == "015":
        ext_payload = spec["extensions"][EXT_SUPERSEDES_CHAIN_ID]
        extension_text = f"""
## Supersession extension

`EventPayload.extensions["{EXT_SUPERSEDES_CHAIN_ID}"]` carries
`SupersedesChainIdPayload`:

- `chain_id` = `{ext_payload['chain_id'].decode('utf-8')}`
- `checkpoint_hash` = `{ext_payload['checkpoint_hash'].hex()}`

This pins Core section 6.7 / section 28 and TR-CORE-169 at the fixture layer.
"""

    return f"""# Derivation - `{spec["dir"]}`

{spec["description"]}

## Inputs

- Issuer key: `_keys/issuer-001.cose_key` (Ed25519 / suite-id 1).
- `ledger_scope` = `{spec['ledger_scope'].decode('utf-8')}`
- `sequence` = `{spec['sequence']}`
- `prev_hash` = `{prev_text}`
- `event_type` = `{spec['event_type'].decode('utf-8')}`
- WOS/Formspec-owned payload bytes: `input-adr0066-record.cbor`.

The payload record is dCBOR-encoded as the inline ciphertext marker. Trellis
does not interpret the WOS governance fields in this positive append vector;
the envelope binds them through `content_hash`, `author_event_hash`, the COSE
signature, and `canonical_event_hash`.
{extension_text}
## Pinned hashes

- `content_hash` = `{content_hash.hex()}`
- `author_event_hash` = `{author_event_hash.hex()}`
- `canonical_event_hash` = `{canonical_event_hash.hex()}`

Generator: `fixtures/vectors/_generator/gen_append_011_to_015.py`.
"""


def generate_vector(
    spec: dict,
    *,
    issuer_seed: bytes,
    kid: bytes,
    prev_hash: bytes | None,
) -> bytes:
    out_dir = ROOT / spec["dir"]
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating vector at {out_dir.relative_to(ROOT.parent.parent)}/")

    record_bytes = dcbor(spec["record"])
    write_bytes(out_dir, "input-adr0066-record.cbor", record_bytes)

    extensions = spec.get("extensions")
    if spec["vector_id"] == "015":
        ext_payload = extensions[EXT_SUPERSEDES_CHAIN_ID]
        write_bytes(out_dir, "input-supersedes-chain-id.cbor", dcbor(ext_payload))
        write_bytes(
            out_dir,
            "input-superseded-checkpoint-hash.bin",
            ext_payload["checkpoint_hash"],
        )

    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, record_bytes)
    header = build_event_header(spec["event_type"], spec["timestamp"])
    payload_ref = build_payload_ref(record_bytes)
    authored_map = build_author_event_hash_preimage(
        ledger_scope=spec["ledger_scope"],
        sequence=spec["sequence"],
        prev_hash=prev_hash,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        idempotency_key=spec["idempotency_key"],
        extensions=extensions,
    )
    authored_bytes = dcbor(authored_map)
    write_bytes(out_dir, "input-author-event-hash-preimage.cbor", authored_bytes)

    author_event_preimage = domain_separated_preimage(
        TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes
    )
    write_bytes(out_dir, "author-event-preimage.bin", author_event_preimage)
    author_event_hash = hashlib.sha256(author_event_preimage).digest()
    write_bytes(out_dir, "author-event-hash.bin", author_event_hash)

    event_payload = build_event_payload(
        authored_map=authored_map,
        author_event_hash=author_event_hash,
    )
    event_payload_bytes = dcbor(event_payload)
    write_bytes(out_dir, "expected-event-payload.cbor", event_payload_bytes)

    protected_map_bytes = dcbor(build_protected_header(kid))
    sig_structure = build_sig_structure(protected_map_bytes, event_payload_bytes)
    write_bytes(out_dir, "sig-structure.bin", sig_structure)

    signature = Ed25519PrivateKey.from_private_bytes(issuer_seed).sign(sig_structure)
    cose_sign1 = cbor2.CBORTag(
        18, [protected_map_bytes, {}, event_payload_bytes, signature]
    )
    write_bytes(out_dir, "expected-event.cbor", dcbor(cose_sign1))

    canonical_preimage = dcbor(
        build_canonical_event_hash_preimage(spec["ledger_scope"], event_payload)
    )
    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1, canonical_preimage
    )
    append_head = build_append_head(
        spec["ledger_scope"], spec["sequence"], canonical_event_hash
    )
    write_bytes(out_dir, "expected-append-head.cbor", dcbor(append_head))

    write_text(out_dir, "manifest.toml", manifest_for(spec))
    write_text(
        out_dir,
        "derivation.md",
        derivation_for(
            spec,
            content_hash=content_hash,
            author_event_hash=author_event_hash,
            canonical_event_hash=canonical_event_hash,
            prev_hash=prev_hash,
        ),
    )

    print()
    print(f"  mode                 = {spec['mode']}")
    print(f"  ledger_scope         = {spec['ledger_scope']!r}")
    print(f"  sequence             = {spec['sequence']}")
    print(f"  content_hash         = {content_hash.hex()}")
    print(f"  author_event_hash    = {author_event_hash.hex()}")
    print(f"  canonical_event_hash = {canonical_event_hash.hex()}")
    return canonical_event_hash


def main() -> None:
    issuer_seed, issuer_pub = load_issuer_key()
    kid = derive_kid(SUITE_ID, issuer_pub)
    chain_prev_hash: bytes | None = None
    for spec in mode_specs():
        prev_hash = None if spec["vector_id"] == "015" else chain_prev_hash
        canonical_event_hash = generate_vector(
            spec,
            issuer_seed=issuer_seed,
            kid=kid,
            prev_hash=prev_hash,
        )
        if spec["vector_id"] != "015":
            chain_prev_hash = canonical_event_hash


if __name__ == "__main__":
    main()
