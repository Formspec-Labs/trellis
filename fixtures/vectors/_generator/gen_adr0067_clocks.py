"""Generate ADR 0067 statutory-clock append and verify vectors.

Outputs:
- append/043-clock-started
- append/044-clock-satisfied
- append/045-clock-elapsed
- append/046-clock-paused-resumed
- verify/018-export-043-open-clocks
- tamper/051-clock-calendar-mismatch

WOS owns the clock record semantics. Trellis pins envelope bytes, export
member binding, advisory replay, and the ADR 0067 D-4 pause/resume calendar
integrity invariant.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cbor2  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from _lib.byte_utils import (  # noqa: E402
    ALG_EDDSA,
    CBOR_TAG_COSE_SIGN1,
    COSE_LABEL_ALG,
    COSE_LABEL_KID,
    COSE_LABEL_SUITE_ID,
    ARTIFACT_TYPE_CHECKPOINT,
    ARTIFACT_TYPE_EVENT,
    ARTIFACT_TYPE_MANIFEST,
    COSE_LABEL_ARTIFACT_TYPE,
    SUITE_ID_PHASE_1,
    dcbor,
    deterministic_zipinfo,
    domain_separated_sha256,
    ts,
)


ROOT = Path(__file__).resolve().parent.parent
KEY_FILE = ROOT / "_keys" / "issuer-001.cose_key"

CHAIN_SCOPE = b"wos-case:adr0067-fixture"
CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0
PAYLOAD_NONCE = b"\x00" * 12
SUITE_ID = SUITE_ID_PHASE_1

OPEN_CLOCKS_EXPORT_EXTENSION = "trellis.export.open-clocks.v1"
OPEN_CLOCKS_MEMBER = "open-clocks.json"

TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CHECKPOINT_V1 = "trellis-checkpoint-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"
TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_EXPORT_MANIFEST_V1 = "trellis-export-manifest-v1"
TAG_TRELLIS_MERKLE_INTERIOR_V1 = "trellis-merkle-interior-v1"
TAG_TRELLIS_MERKLE_LEAF_V1 = "trellis-merkle-leaf-v1"

GENERATED_AT = ts(1_777_001_200)
CHECKPOINT_TIMESTAMP = ts(1_777_001_210)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def load_issuer_key() -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    assert isinstance(seed, bytes) and len(seed) == 32
    assert isinstance(pubkey, bytes) and len(pubkey) == 32
    return seed, pubkey


def derive_kid(pubkey_raw: bytes) -> bytes:
    return sha256(dcbor(SUITE_ID) + pubkey_raw)[:16]


def marker_hash(label: str) -> str:
    return marker_bytes(label).hex()


def marker_bytes(label: str) -> bytes:
    return sha256(f"adr0067:{label}".encode("utf-8"))


def build_event_header(event_type: bytes, authored_at: list[int]) -> dict:
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


def build_author_event_hash_preimage(
    *,
    ledger_scope: bytes,
    sequence: int,
    prev_hash: bytes | None,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    idempotency_key: bytes,
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
        "key_bag": {"entries": []},
        "idempotency_key": idempotency_key,
        "extensions": None,
    }


def build_event_payload(authored_map: dict, author_event_hash: bytes) -> dict:
    event_payload = dict(authored_map)
    event_payload["author_event_hash"] = author_event_hash
    return event_payload


def canonical_event_hash(ledger_scope: bytes, event_payload: dict) -> bytes:
    preimage = {
        "version": 1,
        "ledger_scope": ledger_scope,
        "event_payload": event_payload,
    }
    return domain_separated_sha256(TAG_TRELLIS_EVENT_V1, dcbor(preimage))


def checkpoint_digest(ledger_scope: bytes, checkpoint_payload: dict) -> bytes:
    preimage = {
        "version": 1,
        "scope": ledger_scope,
        "checkpoint_payload": checkpoint_payload,
    }
    return domain_separated_sha256(TAG_TRELLIS_CHECKPOINT_V1, dcbor(preimage))


def merkle_leaf_hash(canonical_hash: bytes) -> bytes:
    return domain_separated_sha256(TAG_TRELLIS_MERKLE_LEAF_V1, canonical_hash)


def merkle_interior(left: bytes, right: bytes) -> bytes:
    return domain_separated_sha256(TAG_TRELLIS_MERKLE_INTERIOR_V1, left + right)


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return bytes(32)
    level = list(leaves)
    while len(level) > 1:
        next_level: list[bytes] = []
        index = 0
        while index < len(level):
            if index + 1 == len(level):
                next_level.append(level[index])
            else:
                next_level.append(merkle_interior(level[index], level[index + 1]))
            index += 2
        level = next_level
    return level[0]


def inclusion_proofs(leaf_hashes: list[bytes]) -> dict[int, dict]:
    if len(leaf_hashes) == 1:
        return {
            0: {
                "leaf_index": 0,
                "tree_size": 1,
                "leaf_hash": leaf_hashes[0],
                "audit_path": [],
            }
        }
    if len(leaf_hashes) == 3:
        interior_01 = merkle_interior(leaf_hashes[0], leaf_hashes[1])
        return {
            0: {
                "leaf_index": 0,
                "tree_size": 3,
                "leaf_hash": leaf_hashes[0],
                "audit_path": [leaf_hashes[1], leaf_hashes[2]],
            },
            1: {
                "leaf_index": 1,
                "tree_size": 3,
                "leaf_hash": leaf_hashes[1],
                "audit_path": [leaf_hashes[0], leaf_hashes[2]],
            },
            2: {
                "leaf_index": 2,
                "tree_size": 3,
                "leaf_hash": leaf_hashes[2],
                "audit_path": [interior_01],
            },
        }
    raise AssertionError("this generator only emits one- or three-event exports")


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
    return dcbor(
        cbor2.CBORTag(CBOR_TAG_COSE_SIGN1, [protected, {}, payload_bytes, signature])
    )


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def clock_started_record(
    *,
    record_id: str,
    timestamp: str,
    clock_id: str,
    clock_kind: str,
    origin_event_hash: str,
    duration: str,
    calendar_ref: str | None,
    statute_reference: str,
    computed_deadline: str,
) -> dict:
    return {
        "id": record_id,
        "event": "wos.governance.clock_started",
        "timestamp": timestamp,
        "auditLayer": "facts",
        "definitionVersion": "1.0.0",
        "actorId": "clerk-001",
        "data": {
            "clockId": clock_id,
            "clockKind": clock_kind,
            "originEventHash": origin_event_hash,
            "duration": duration,
            "calendarRef": calendar_ref,
            "statuteReference": statute_reference,
            "computedDeadline": computed_deadline,
        },
    }


def clock_resolved_record(
    *,
    record_id: str,
    timestamp: str,
    clock_id: str,
    origin_clock_hash: str,
    resolution: str,
    resolving_event_hash: str,
    resolved_at: str,
) -> dict:
    return {
        "id": record_id,
        "event": "wos.governance.clock_resolved",
        "timestamp": timestamp,
        "auditLayer": "facts",
        "definitionVersion": "1.0.0",
        "actorId": "clerk-001",
        "data": {
            "clockId": clock_id,
            "originClockHash": origin_clock_hash,
            "resolution": resolution,
            "resolvingEventHash": resolving_event_hash,
            "resolvedAt": resolved_at,
        },
    }


def append_specs() -> list[dict]:
    return [
        {
            "dir": "append/043-clock-started",
            "vector_id": "043",
            "description": "ADR 0067 clockStarted record opening a statutory response clock.",
            "event_type": b"wos.governance.clock_started",
            "sequence": 0,
            "timestamp": ts(1_777_001_043),
            "idempotency_key": b"idemp-adr0067-043",
            "record": clock_started_record(
                record_id="adr0067-clock-043",
                timestamp="2026-05-07T10:17:23Z",
                clock_id="appeal-response-clock",
                clock_kind="appeal-response",
                origin_event_hash=marker_hash("appeal-notice-served"),
                duration="P30D",
                calendar_ref="urn:wos:calendar:business-days-us-federal-v1",
                statute_reference="42-U.S.C-0067-demo-30-day-response",
                computed_deadline="2026-06-18T00:00:00Z",
            ),
        },
        {
            "dir": "append/044-clock-satisfied",
            "vector_id": "044",
            "description": "ADR 0067 clockResolved record satisfying the opened response clock.",
            "event_type": b"wos.governance.clock_resolved",
            "sequence": 1,
            "timestamp": ts(1_777_001_044),
            "idempotency_key": b"idemp-adr0067-044",
            "record_factory": lambda prior_hashes: clock_resolved_record(
                record_id="adr0067-clock-044",
                timestamp="2026-05-07T10:17:24Z",
                clock_id="appeal-response-clock",
                origin_clock_hash=prior_hashes["043"].hex(),
                resolution="satisfied",
                resolving_event_hash=marker_hash("appeal-response-filed"),
                resolved_at="2026-05-21T15:30:00Z",
            ),
        },
        {
            "dir": "append/045-clock-elapsed",
            "vector_id": "045",
            "description": "ADR 0067 clockResolved record marking an independent notice clock elapsed.",
            "event_type": b"wos.governance.clock_resolved",
            "sequence": 2,
            "timestamp": ts(1_777_001_045),
            "idempotency_key": b"idemp-adr0067-045",
            "record": clock_resolved_record(
                record_id="adr0067-clock-045",
                timestamp="2026-05-07T10:17:25Z",
                clock_id="notice-review-clock",
                origin_clock_hash=marker_hash("notice-review-origin"),
                resolution="elapsed",
                resolving_event_hash=marker_hash("notice-review-timeout"),
                resolved_at="2026-05-30T00:00:00Z",
            ),
        },
        {
            "dir": "append/046-clock-paused-resumed",
            "vector_id": "046",
            "description": "ADR 0067 residual clockStarted segment after a pause/resume boundary.",
            "event_type": b"wos.governance.clock_started",
            "sequence": 3,
            "timestamp": ts(1_777_001_046),
            "idempotency_key": b"idemp-adr0067-046",
            "record": clock_started_record(
                record_id="adr0067-clock-046",
                timestamp="2026-05-07T10:17:26Z",
                clock_id="hearing-window-clock",
                clock_kind="hearing-window",
                origin_event_hash=marker_hash("hearing-window-resumed"),
                duration="P20D",
                calendar_ref="urn:wos:calendar:business-days-us-federal-v1",
                statute_reference="42-U.S.C-0067-demo-hearing-window",
                computed_deadline="2026-06-08T00:00:00Z",
            ),
        },
    ]


def render_append_manifest(spec: dict) -> str:
    return f'''id          = "{spec["dir"]}"
op          = "append"
status      = "active"
description = """{spec["description"]}"""

[coverage]
tr_core = [
    "TR-CORE-001",
    "TR-CORE-018",
    "TR-CORE-021",
    "TR-CORE-030",
    "TR-CORE-031",
    "TR-CORE-050",
    "TR-CORE-080",
]

[inputs]
signing_key      = "../../_keys/issuer-001.cose_key"
mode_record      = "input-clock-record.cbor"
authored_event   = "input-author-event-hash-preimage.cbor"

[expected]
author_event_hash = "author-event-hash.bin"
canonical_event   = "expected-event-payload.cbor"
signed_event      = "expected-event.cbor"
append_head       = "expected-append-head.cbor"

[derivation]
document = "derivation.md"
'''


def render_append_derivation(
    spec: dict,
    *,
    content_hash: bytes,
    author_event_hash: bytes,
    canonical_hash: bytes,
    prev_hash: bytes | None,
) -> str:
    prev = "null" if prev_hash is None else prev_hash.hex()
    return f"""# Derivation - `{spec["dir"]}`

{spec["description"]}

The WOS-owned provenance record is dCBOR-encoded as `input-clock-record.cbor`.
Trellis treats that record as inline payload bytes and binds it through
`content_hash`, `author_event_hash`, the COSE signature, and
`canonical_event_hash`.

## Inputs

- `ledger_scope` = `{CHAIN_SCOPE.decode("utf-8")}`
- `sequence` = `{spec["sequence"]}`
- `prev_hash` = `{prev}`
- `event_type` = `{spec["event_type"].decode("utf-8")}`
- `event` = `{spec["record"]["event"]}`

## Pinned hashes

- `content_hash` = `{content_hash.hex()}`
- `author_event_hash` = `{author_event_hash.hex()}`
- `canonical_event_hash` = `{canonical_hash.hex()}`

Generator: `fixtures/vectors/_generator/gen_adr0067_clocks.py`.
"""


def build_signed_event(
    *,
    seed: bytes,
    kid: bytes,
    spec: dict,
    record: dict,
    prev_hash: bytes | None,
) -> dict:
    record_bytes = dcbor(record)
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, record_bytes)
    header = build_event_header(spec["event_type"], spec["timestamp"])
    payload_ref = build_payload_ref(record_bytes)
    authored_map = build_author_event_hash_preimage(
        ledger_scope=CHAIN_SCOPE,
        sequence=spec["sequence"],
        prev_hash=prev_hash,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        idempotency_key=spec["idempotency_key"],
    )
    authored_bytes = dcbor(authored_map)
    author_event_hash = domain_separated_sha256(
        TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes
    )
    event_payload = build_event_payload(authored_map, author_event_hash)
    event_payload_bytes = dcbor(event_payload)
    protected = dcbor(
        {
            COSE_LABEL_ALG: ALG_EDDSA,
            COSE_LABEL_KID: kid,
            COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: ARTIFACT_TYPE_EVENT,
        }
    )
    sig_structure = dcbor(["Signature1", protected, b"", event_payload_bytes])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    signed_event = dcbor(
        cbor2.CBORTag(
            CBOR_TAG_COSE_SIGN1, [protected, {}, event_payload_bytes, signature]
        )
    )
    canonical_hash = canonical_event_hash(CHAIN_SCOPE, event_payload)
    append_head = {
        "scope": CHAIN_SCOPE,
        "sequence": spec["sequence"],
        "canonical_event_hash": canonical_hash,
    }
    return {
        "record_bytes": record_bytes,
        "authored_bytes": authored_bytes,
        "author_event_hash": author_event_hash,
        "event_payload": event_payload,
        "event_payload_bytes": event_payload_bytes,
        "sig_structure": sig_structure,
        "signed_event": signed_event,
        "canonical_hash": canonical_hash,
        "append_head": append_head,
        "content_hash": content_hash,
    }


def generate_append_vectors(seed: bytes, kid: bytes) -> list[dict]:
    generated: list[dict] = []
    canonical_by_vector: dict[str, bytes] = {}
    prev_hash: bytes | None = None
    for spec in append_specs():
        if "record_factory" in spec:
            spec["record"] = spec["record_factory"](canonical_by_vector)
        built = build_signed_event(
            seed=seed,
            kid=kid,
            spec=spec,
            record=spec["record"],
            prev_hash=prev_hash,
        )
        out_dir = ROOT / spec["dir"]
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True)
        write_bytes(out_dir / "input-clock-record.cbor", built["record_bytes"])
        write_bytes(
            out_dir / "input-author-event-hash-preimage.cbor", built["authored_bytes"]
        )
        write_bytes(out_dir / "author-event-hash.bin", built["author_event_hash"])
        write_bytes(out_dir / "expected-event-payload.cbor", built["event_payload_bytes"])
        write_bytes(out_dir / "sig-structure.bin", built["sig_structure"])
        write_bytes(out_dir / "expected-event.cbor", built["signed_event"])
        write_bytes(out_dir / "expected-append-head.cbor", dcbor(built["append_head"]))
        write_text(out_dir / "manifest.toml", render_append_manifest(spec))
        write_text(
            out_dir / "derivation.md",
            render_append_derivation(
                spec,
                content_hash=built["content_hash"],
                author_event_hash=built["author_event_hash"],
                canonical_hash=built["canonical_hash"],
                prev_hash=prev_hash,
            ),
        )
        canonical_by_vector[spec["vector_id"]] = built["canonical_hash"]
        prev_hash = built["canonical_hash"]
        generated.append({**spec, **built})
    return generated


def canonical_open_clocks_json(rows: list[dict], sealed_at: list[int]) -> bytes:
    rendered_rows: list[str] = []
    for row in sorted(rows, key=lambda item: (item["origin_event_hash"], item["clock_id"])):
        rendered_rows.append(
            '{"clock_id":'
            + json.dumps(row["clock_id"], separators=(",", ":"))
            + ',"clock_kind":'
            + json.dumps(row["clock_kind"], separators=(",", ":"))
            + ',"computed_deadline":['
            + str(row["computed_deadline"][0])
            + ","
            + str(row["computed_deadline"][1])
            + '],"origin_event_hash":"'
            + row["origin_event_hash"]
            + '"}'
        )
    return (
        '{"open_clocks":['
        + ",".join(rendered_rows)
        + '],"sealed_at":['
        + str(sealed_at[0])
        + ","
        + str(sealed_at[1])
        + "]}\n"
    ).encode("utf-8")


def export_manifest_payload(
    *,
    member_bytes: dict[str, bytes],
    registry_digest: bytes,
    head_checkpoint_digest: bytes,
    tree_size: int,
    open_clocks_bytes: bytes | None,
) -> dict:
    extensions = None
    if open_clocks_bytes is not None:
        extensions = {
            OPEN_CLOCKS_EXPORT_EXTENSION: {
                "open_clocks_digest": sha256(open_clocks_bytes),
                "open_clock_count": 1,
            }
        }
    return {
        "format": "trellis-export/1",
        "version": 1,
        "generator": "x-trellis-test/adr0067-clock-generator",
        "generated_at": GENERATED_AT,
        "scope": CHAIN_SCOPE,
        "tree_size": tree_size,
        "head_checkpoint_digest": head_checkpoint_digest,
        "registry_bindings": [
            {
                "registry_digest": registry_digest,
                "registry_format": 1,
                "registry_version": "x-trellis-test/adr0067-registry-v1",
                "bound_at_sequence": 0,
            }
        ],
        "signing_key_registry_digest": sha256(member_bytes["030-signing-key-registry.cbor"]),
        "events_digest": sha256(member_bytes["010-events.cbor"]),
        "checkpoints_digest": sha256(member_bytes["040-checkpoints.cbor"]),
        "inclusion_proofs_digest": sha256(member_bytes["020-inclusion-proofs.cbor"]),
        "consistency_proofs_digest": sha256(member_bytes["025-consistency-proofs.cbor"]),
        "extensions": extensions,
    }


def write_export_zip(out_dir: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(out_dir / "input-export.zip", "w") as zf:
        for member_name in sorted(members):
            info = deterministic_zipinfo(f"adr0067-clock-export/{member_name}")
            zf.writestr(info, members[member_name])
        for info in zf.filelist:
            info.external_attr = 0


def build_export(
    *,
    out_dir: Path,
    seed: bytes,
    kid: bytes,
    pubkey: bytes,
    events: list[dict],
    include_open_clocks: bool,
) -> bytes:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    event_values = [cbor2.loads(event["signed_event"]) for event in events]
    events_cbor = dcbor(event_values)
    canonical_hashes = [event["canonical_hash"] for event in events]
    leaf_hashes = [merkle_leaf_hash(value) for value in canonical_hashes]
    tree_root = merkle_root(leaf_hashes)

    checkpoint_payload = {
        "version": 1,
        "scope": CHAIN_SCOPE,
        "tree_size": len(events),
        "tree_head_hash": tree_root,
        "timestamp": CHECKPOINT_TIMESTAMP,
        "anchor_ref": None,
        "prev_checkpoint_hash": None,
        "extensions": None,
    }
    checkpoint_bytes = cose_sign1(seed, kid, dcbor(checkpoint_payload), ARTIFACT_TYPE_CHECKPOINT)
    checkpoints_cbor = dcbor([cbor2.loads(checkpoint_bytes)])
    head_digest = checkpoint_digest(CHAIN_SCOPE, checkpoint_payload)

    signing_registry = dcbor(
        [
            {
                "kid": kid,
                "pubkey": pubkey,
                "suite_id": SUITE_ID,
                "status": 0,
                "valid_from": ts(GENERATED_AT[0] - 1_000),
                "valid_to": None,
                "supersedes": None,
                "attestation": None,
            }
        ]
    )
    domain_registry = {
        "governance": {
            "ruleset_id": "x-trellis-test/adr0067-ruleset-v1",
            "ruleset_digest": marker_bytes("clock-ruleset"),
        },
        "event_types": {
            "wos.governance.clock_resolved": {
                "privacy_class": "public",
                "commitment_schema": "x-trellis-test/clock-resolved-v1",
            },
            "wos.governance.clock_started": {
                "privacy_class": "public",
                "commitment_schema": "x-trellis-test/clock-started-v1",
            },
        },
        "classifications": ["x-trellis-test/unclassified"],
        "role_vocabulary": ["x-trellis-test/role-author"],
    }
    registry_cbor = dcbor(domain_registry)
    registry_digest = sha256(registry_cbor)

    members: dict[str, bytes] = {
        "010-events.cbor": events_cbor,
        "020-inclusion-proofs.cbor": dcbor(inclusion_proofs(leaf_hashes)),
        "025-consistency-proofs.cbor": dcbor([]),
        "030-signing-key-registry.cbor": signing_registry,
        "040-checkpoints.cbor": checkpoints_cbor,
        f"050-registries/{registry_digest.hex()}.cbor": registry_cbor,
        "090-verify.sh": b"#!/bin/sh\nset -eu\n",
        "098-README.md": b"# ADR 0067 clock export fixture\n",
    }
    open_clocks_bytes = None
    if include_open_clocks:
        open_clocks_bytes = canonical_open_clocks_json(
            [
                {
                    "clock_id": "appeal-response-clock",
                    "clock_kind": "appeal-response",
                    "computed_deadline": [1_777_001_100, 0],
                    "origin_event_hash": events[0]["canonical_hash"].hex(),
                }
            ],
            GENERATED_AT,
        )
        members[OPEN_CLOCKS_MEMBER] = open_clocks_bytes

    manifest_payload = export_manifest_payload(
        member_bytes=members,
        registry_digest=registry_digest,
        head_checkpoint_digest=head_digest,
        tree_size=len(events),
        open_clocks_bytes=open_clocks_bytes,
    )
    manifest_bytes = cose_sign1(seed, kid, dcbor(manifest_payload), ARTIFACT_TYPE_MANIFEST)
    members["000-manifest.cbor"] = manifest_bytes

    for name, data in members.items():
        write_bytes(out_dir / name, data)
    write_export_zip(out_dir, members)
    return canonical_hashes[-1]


def render_verify_manifest() -> str:
    return '''id          = "verify/018-export-043-open-clocks"
op          = "verify"
status      = "active"
description = """Positive ADR 0067 export with manifest-bound open-clocks.json."""

[coverage]
tr_core = [
    "TR-CORE-001",
    "TR-CORE-018",
    "TR-CORE-030",
    "TR-CORE-050",
    "TR-CORE-068",
    "TR-CORE-172",
]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified  = true
integrity_verified  = true
readability_verified = true

[derivation]
document = "derivation.md"
'''


def render_tamper_manifest(failing_hash: bytes) -> str:
    return f'''id = "tamper/051-clock-calendar-mismatch"
op = "tamper"
status = "active"
description = "Validly signed ADR 0067 pause/resume export whose resumed clockStarted changes calendarRef, which must fail with clock_calendar_mismatch."

[coverage]
tr_core = [
    "TR-CORE-173",
]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified = true
integrity_verified = false
readability_verified = true
tamper_kind = "clock_calendar_mismatch"
failing_event_id = "{failing_hash.hex()}"

[derivation]
document = "derivation.md"
'''


def render_export_derivation(title: str, *, failing_hash: bytes | None = None) -> str:
    failure = ""
    if failing_hash is not None:
        failure = (
            "\nThe third event is the resumed `clockStarted` segment. It keeps "
            "`clockId` and `clockKind` from the paused segment but changes "
            f"`calendarRef`; verifiers localize `clock_calendar_mismatch` at `{failing_hash.hex()}`.\n"
        )
    return f"""# Derivation - {title}

Generator: `fixtures/vectors/_generator/gen_adr0067_clocks.py`.

The export ZIP is deterministic per Core section 18.1. The manifest signs and
digest-binds `010-events.cbor`, `020-inclusion-proofs.cbor`,
`025-consistency-proofs.cbor`, `030-signing-key-registry.cbor`,
`040-checkpoints.cbor`, and the registry snapshot. The positive vector also
digest-binds `open-clocks.json` through
`trellis.export.open-clocks.v1.open_clocks_digest`.
{failure}
"""


def generate_verify_and_tamper(seed: bytes, kid: bytes, pubkey: bytes, appends: list[dict]) -> None:
    verify_dir = ROOT / "verify" / "018-export-043-open-clocks"
    build_export(
        out_dir=verify_dir,
        seed=seed,
        kid=kid,
        pubkey=pubkey,
        events=[appends[0]],
        include_open_clocks=True,
    )
    write_text(verify_dir / "manifest.toml", render_verify_manifest())
    write_text(
        verify_dir / "derivation.md",
        render_export_derivation("`verify/018-export-043-open-clocks`"),
    )

    tamper_specs = [
        {
            "event_type": b"wos.governance.clock_started",
            "sequence": 0,
            "timestamp": ts(1_777_001_151),
            "idempotency_key": b"idemp-adr0067-tamper-start",
            "record": clock_started_record(
                record_id="adr0067-tamper-start",
                timestamp="2026-05-07T10:19:11Z",
                clock_id="pause-resume-clock",
                clock_kind="appeal-response",
                origin_event_hash=marker_hash("pause-resume-origin"),
                duration="P30D",
                calendar_ref="urn:wos:calendar:business-days-us-federal-v1",
                statute_reference="42-U.S.C-0067-demo-pause-resume",
                computed_deadline="2026-06-18T00:00:00Z",
            ),
        },
        {
            "event_type": b"wos.governance.clock_resolved",
            "sequence": 1,
            "timestamp": ts(1_777_001_152),
            "idempotency_key": b"idemp-adr0067-tamper-pause",
            "record": None,
        },
        {
            "event_type": b"wos.governance.clock_started",
            "sequence": 2,
            "timestamp": ts(1_777_001_153),
            "idempotency_key": b"idemp-adr0067-tamper-resume",
            "record": clock_started_record(
                record_id="adr0067-tamper-resume",
                timestamp="2026-05-07T10:19:13Z",
                clock_id="pause-resume-clock",
                clock_kind="appeal-response",
                origin_event_hash=marker_hash("pause-resume-residual"),
                duration="P20D",
                calendar_ref="urn:wos:calendar:calendar-days-v1",
                statute_reference="42-U.S.C-0067-demo-pause-resume",
                computed_deadline="2026-06-08T00:00:00Z",
            ),
        },
    ]
    tamper_events: list[dict] = []
    prev_hash: bytes | None = None
    for index, spec in enumerate(tamper_specs):
        if index == 1:
            spec["record"] = clock_resolved_record(
                record_id="adr0067-tamper-pause",
                timestamp="2026-05-07T10:19:12Z",
                clock_id="pause-resume-clock",
                origin_clock_hash=tamper_events[0]["canonical_hash"].hex(),
                resolution="paused",
                resolving_event_hash=marker_hash("pause-cause"),
                resolved_at="2026-05-25T12:00:00Z",
            )
        built = build_signed_event(
            seed=seed,
            kid=kid,
            spec=spec,
            record=spec["record"],
            prev_hash=prev_hash,
        )
        prev_hash = built["canonical_hash"]
        tamper_events.append({**spec, **built})

    tamper_dir = ROOT / "tamper" / "051-clock-calendar-mismatch"
    failing_hash = build_export(
        out_dir=tamper_dir,
        seed=seed,
        kid=kid,
        pubkey=pubkey,
        events=tamper_events,
        include_open_clocks=False,
    )
    write_text(tamper_dir / "manifest.toml", render_tamper_manifest(failing_hash))
    write_text(
        tamper_dir / "derivation.md",
        render_export_derivation(
            "`tamper/051-clock-calendar-mismatch`", failing_hash=failing_hash
        ),
    )


def main() -> None:
    seed, pubkey = load_issuer_key()
    kid = derive_kid(pubkey)
    appends = generate_append_vectors(seed, kid)
    generate_verify_and_tamper(seed, kid, pubkey, appends)


if __name__ == "__main__":
    main()
