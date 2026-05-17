"""Generate intake-handoff append/export/verify/tamper vectors.

Authoring aid only. The committed bytes and derivation notes are the evidence
surface; this script exists so the CBOR and ZIP bytes are reproducible.
"""

from __future__ import annotations

import copy
import hashlib
import json
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
    trellis_cli_verify_script,
    ts,
)


ROOT = Path(__file__).resolve().parent.parent
KEY_ISSUER_001 = ROOT / "_keys" / "issuer-001.cose_key"

APPEND_020 = ROOT / "append" / "020-wos-intake-accepted-workflow-attach"
APPEND_021 = ROOT / "append" / "021-wos-intake-accepted-public-create"
APPEND_022 = ROOT / "append" / "022-wos-case-created-public-intake"
OUT_EXPORT_007 = ROOT / "export" / "007-intake-handoffs-public-create"
OUT_EXPORT_008 = ROOT / "export" / "008-intake-handoffs-workflow-attach"
OUT_VERIFY_015 = ROOT / "verify" / "015-export-007-intake-response-hash-mismatch"
OUT_EXPORT_013 = ROOT / "export" / "013-intake-handoffs-public-create-empty-outputs"
OUT_VERIFY_016 = ROOT / "verify" / "016-export-013-intake-empty-outputs"
OUT_TAMPER_015 = ROOT / "tamper" / "015-intake-handoff-catalog-digest-mismatch"

TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"
TAG_TRELLIS_WOS_IDEMPOTENCY_V1 = "trellis-wos-idempotency-v1"
TAG_TRELLIS_CHECKPOINT_V1 = "trellis-checkpoint-v1"
TAG_TRELLIS_MERKLE_LEAF_V1 = "trellis-merkle-leaf-v1"
TAG_TRELLIS_MERKLE_INTERIOR_V1 = "trellis-merkle-interior-v1"
EXTENSION_KEY = "trellis.export.intake-handoffs.v1"

CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0
PAYLOAD_NONCE = b"\x00" * 12

WORKFLOW_CASE_ID = "sba-poc_case_01jy0workflowattach00000001"
PUBLIC_CASE_ID = "sba-poc_case_01jy0publiccreate000000001"

WORKFLOW_DEFINITION_URL = "https://example.gov/forms/benefits-intake"
WORKFLOW_DEFINITION_VERSION = "1.0.0"

WORKFLOW_INTAKE_RECORD_ID = "sba-poc_prov_01jy0workflowattachintake001"
PUBLIC_INTAKE_RECORD_ID = "sba-poc_prov_01jy0publiccreateintake0001"
PUBLIC_CASE_CREATED_RECORD_ID = "sba-poc_prov_01jy0publiccreatecase00001"

WORKFLOW_AUTHORED_AT = ts(1776954600)
PUBLIC_INTAKE_AUTHORED_AT = ts(1776958200)
PUBLIC_CASE_CREATED_AUTHORED_AT = ts(1776958260)

CHECKPOINT_TIMESTAMP_WORKFLOW = ts(1776954660)
CHECKPOINT_TIMESTAMP_PUBLIC = ts(1776958320)
GENERATED_AT_WORKFLOW = ts(1776954670)
GENERATED_AT_PUBLIC = ts(1776958330)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def canonical_json_bytes(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def load_seed_and_pubkey(path: Path) -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(path.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    assert isinstance(seed, bytes) and len(seed) == 32
    assert isinstance(pubkey, bytes) and len(pubkey) == 32
    return seed, pubkey


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def protected_header(kid: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> bytes:
    return dcbor(
        {
            COSE_LABEL_ALG: ALG_EDDSA,
            COSE_LABEL_KID: kid,
            COSE_LABEL_SUITE_ID: SUITE_ID_PHASE_1, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
        }
    )


def cose_sign1(seed: bytes, kid: bytes, payload_bytes: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> bytes:
    protected = protected_header(kid, artifact_type)
    sig_structure = dcbor(["Signature1", protected, b"", payload_bytes])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    return dcbor(cbor2.CBORTag(CBOR_TAG_COSE_SIGN1, [protected, {}, payload_bytes, signature]))


def domain_separated_preimage(tag: str, component: bytes) -> bytes:
    tag_bytes = tag.encode("utf-8")
    return (
        len(tag_bytes).to_bytes(4, "big")
        + tag_bytes
        + len(component).to_bytes(4, "big")
        + component
    )


def canonical_event_hash(scope: bytes, event_payload: dict) -> bytes:
    preimage = {"version": 1, "ledger_scope": scope, "event_payload": event_payload}
    return domain_separated_sha256(TAG_TRELLIS_EVENT_V1, dcbor(preimage))


def checkpoint_digest(scope: bytes, checkpoint_payload: dict) -> bytes:
    preimage = {"version": 1, "scope": scope, "checkpoint_payload": checkpoint_payload}
    return domain_separated_sha256(TAG_TRELLIS_CHECKPOINT_V1, dcbor(preimage))


def merkle_leaf_hash(canonical_hash: bytes) -> bytes:
    return domain_separated_sha256(TAG_TRELLIS_MERKLE_LEAF_V1, canonical_hash)


def merkle_interior_hash(left_hash: bytes, right_hash: bytes) -> bytes:
    return domain_separated_sha256(TAG_TRELLIS_MERKLE_INTERIOR_V1, left_hash + right_hash)


def merkle_root(leaf_hashes: list[bytes]) -> bytes:
    if len(leaf_hashes) == 1:
        return leaf_hashes[0]
    if len(leaf_hashes) == 2:
        return merkle_interior_hash(leaf_hashes[0], leaf_hashes[1])
    raise ValueError("generator only needs tree sizes 1 or 2")


def inclusion_proofs(leaf_hashes: list[bytes]) -> dict:
    if len(leaf_hashes) == 1:
        return {
            0: {
                "leaf_index": 0,
                "tree_size": 1,
                "leaf_hash": leaf_hashes[0],
                "audit_path": [],
            }
        }
    if len(leaf_hashes) == 2:
        return {
            0: {
                "leaf_index": 0,
                "tree_size": 2,
                "leaf_hash": leaf_hashes[0],
                "audit_path": [leaf_hashes[1]],
            },
            1: {
                "leaf_index": 1,
                "tree_size": 2,
                "leaf_hash": leaf_hashes[1],
                "audit_path": [leaf_hashes[0]],
            },
        }
    raise ValueError("generator only needs tree sizes 1 or 2")


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def write_zip(path: Path, *, root_dir: str, members: list[str], data: dict[str, bytes]) -> bytes:
    with zipfile.ZipFile(path, "w") as zf:
        for member in sorted(members):
            zf.writestr(deterministic_zipinfo(f"{root_dir}/{member}"), data[member])
        for info in zf.filelist:
            info.external_attr = 0
    return path.read_bytes()


def export_members_from_dir(export_dir: Path) -> tuple[str, list[str], dict[str, bytes], dict]:
    ledger_state = cbor2.loads((export_dir / "input-ledger-state.cbor").read_bytes())
    root_dir = ledger_state["root_dir"]
    members = list(ledger_state["members"])
    data = {member: (export_dir / member).read_bytes() for member in members}
    manifest_tag = cbor2.loads(data["000-manifest.cbor"])
    manifest_payload = cbor2.loads(manifest_tag.value[2])
    return root_dir, members, data, manifest_payload


def build_signing_key_registry(kid: bytes, pubkey: bytes, valid_from: int) -> bytes:
    entry = {
        "kid": kid,
        "pubkey": pubkey,
        "suite_id": SUITE_ID_PHASE_1,
        "status": 0,
        "valid_from": valid_from,
        "valid_to": None,
        "supersedes": None,
        "attestation": None,
    }
    return dcbor([entry])


def build_domain_registry() -> bytes:
    return dcbor(
        {
            "governance": {
                "ruleset_id": "x-trellis-test/governance-ruleset-intake-v1",
                "ruleset_digest": sha256(b"x-trellis-test/governance-ruleset-intake-v1"),
            },
            "event_types": {
                "wos.kernel.intake_accepted": {
                    "privacy_class": "restricted",
                    "binding_family": "wos.intake",
                },
                "wos.kernel.case_created": {
                    "privacy_class": "restricted",
                    "binding_family": "wos.intake",
                },
            },
            "classifications": ["x-trellis-test/unclassified"],
            "role_vocabulary": ["x-trellis-test/role-intake-worker"],
            "registry_version": "x-trellis-test/registry-intake-v1",
        }
    )


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


def build_payload_ref(ciphertext: bytes) -> dict:
    return {
        "ref_type": "inline",
        "ciphertext": ciphertext,
        "nonce": PAYLOAD_NONCE,
    }


def build_key_bag() -> dict:
    return {"entries": []}


def build_author_event_hash_preimage(
    *,
    scope: bytes,
    sequence: int,
    prev_hash: bytes | None,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
    idempotency_key: bytes,
) -> dict:
    return {
        "version": 1,
        "ledger_scope": scope,
        "sequence": sequence,
        "prev_hash": prev_hash,
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
    *,
    scope: bytes,
    sequence: int,
    prev_hash: bytes | None,
    author_event_hash: bytes,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
    idempotency_key: bytes,
) -> dict:
    return {
        "version": 1,
        "ledger_scope": scope,
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
        "extensions": None,
    }


def wos_idempotency_tuple(case_id: str, record_id: str) -> dict:
    return {"caseId": case_id, "recordId": record_id}


def make_response_payload(response_id: str, *, applicant_name: str, household_size: int) -> tuple[bytes, str]:
    response = {
        "$formspecResponse": "1.0",
        "definitionUrl": WORKFLOW_DEFINITION_URL,
        "definitionVersion": WORKFLOW_DEFINITION_VERSION,
        "id": response_id,
        "status": "completed",
        "data": {
            "applicantName": applicant_name,
            "benefitProgram": "childcare",
            "householdSize": household_size,
        },
    }
    response_bytes = canonical_json_bytes(response)
    return response_bytes, f"sha256:{hashlib.sha256(response_bytes).hexdigest()}"


def workflow_handoff(case_ref: str, response_hash: str) -> dict:
    return {
        "$formspecIntakeHandoff": "1.0",
        "handoffId": "handoff-workflow-2026-0001",
        "initiationMode": "workflowInitiated",
        "caseRef": case_ref,
        "definitionRef": {
            "url": WORKFLOW_DEFINITION_URL,
            "version": WORKFLOW_DEFINITION_VERSION,
        },
        "responseRef": "urn:formspec:response:workflow-2026-0001",
        "responseHash": response_hash,
        "validationReportRef": "urn:formspec:validation-report:workflow-2026-0001",
        "intakeSessionId": "session-workflow-2026-0001",
        "actorRef": "urn:iam:actor:caseworker-123",
        "subjectRef": "urn:party:person:applicant-456",
        "ledgerHeadRef": "urn:formspec:respondent-ledger-event:workflow-2026-0003",
        "occurredAt": "2026-04-23T14:30:00Z",
    }


def public_handoff(response_hash: str) -> dict:
    return {
        "$formspecIntakeHandoff": "1.0",
        "handoffId": "handoff-public-2026-0001",
        "initiationMode": "publicIntake",
        "definitionRef": {
            "url": WORKFLOW_DEFINITION_URL,
            "version": WORKFLOW_DEFINITION_VERSION,
        },
        "responseRef": "urn:formspec:response:public-2026-0001",
        "responseHash": response_hash,
        "validationReportRef": "urn:formspec:validation-report:public-2026-0001",
        "intakeSessionId": "session-public-2026-0001",
        "ledgerHeadRef": "urn:formspec:respondent-ledger-event:public-2026-0003",
        "occurredAt": "2026-04-23T15:30:00Z",
    }


def intake_accepted_record(
    *,
    record_id: str,
    actor_id: str,
    actor_type: str | None = None,
    lifecycle_state: str | None = None,
    timestamp: str,
    handoff_id: str,
    case_intent: str,
    case_disposition: str,
    case_ref: str,
    definition_url: str | None = None,
    definition_version: str | None = None,
    outputs: list[str] | None = None,
) -> dict:
    data = {
        "binding": "formspec",
        "intakeId": handoff_id,
        "caseIntent": case_intent,
        "caseDisposition": case_disposition,
        "caseRef": case_ref,
    }
    if definition_url is not None:
        data["definitionUrl"] = definition_url
    if definition_version is not None:
        data["definitionVersion"] = definition_version
    if outputs is None:
        outputs = [case_ref]
    record = {
        "id": record_id,
        "timestamp": timestamp,
        "actorId": actor_id,
        "auditLayer": "facts",
        "event": "wos.kernel.intake_accepted",
        "data": data,
        "inputs": [handoff_id],
        "outputs": outputs,
    }
    if actor_type is not None:
        record["actorType"] = actor_type
    if lifecycle_state is not None:
        record["lifecycleState"] = lifecycle_state
    return record


def case_created_record(
    *,
    record_id: str,
    actor_id: str,
    actor_type: str | None = None,
    lifecycle_state: str | None = None,
    timestamp: str,
    case_ref: str,
    handoff: dict,
    outputs: list[str] | None = None,
) -> dict:
    if outputs is None:
        outputs = [case_ref]
    record = {
        "id": record_id,
        "timestamp": timestamp,
        "actorId": actor_id,
        "auditLayer": "facts",
        "event": "wos.kernel.case_created",
        "data": {
            "caseRef": case_ref,
            "intakeHandoffRef": handoff["handoffId"],
            "formspecResponseRef": handoff["responseRef"],
            "validationReportRef": handoff["validationReportRef"],
            "ledgerHeadRef": handoff["ledgerHeadRef"],
            "initiationMode": handoff["initiationMode"],
        },
        "inputs": [
            handoff["handoffId"],
            handoff["responseRef"],
            handoff["validationReportRef"],
            handoff["ledgerHeadRef"],
        ],
        "outputs": outputs,
    }
    if actor_type is not None:
        record["actorType"] = actor_type
    if lifecycle_state is not None:
        record["lifecycleState"] = lifecycle_state
    return record


def build_signed_append_event(
    *,
    record: dict,
    case_id: str,
    event_type: bytes,
    authored_at: int,
    sequence: int,
    prev_hash: bytes | None,
) -> dict:
    seed, pubkey = load_seed_and_pubkey(KEY_ISSUER_001)
    kid = derive_kid(SUITE_ID_PHASE_1, pubkey)

    scope = f"wos-case:{case_id}".encode("utf-8")
    record_bytes = dcbor(record)
    tuple_bytes = dcbor(wos_idempotency_tuple(case_id, record["id"]))
    idempotency_key = domain_separated_sha256(TAG_TRELLIS_WOS_IDEMPOTENCY_V1, tuple_bytes)
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, record_bytes)

    header = build_event_header(event_type, authored_at)
    payload_ref = build_payload_ref(record_bytes)
    key_bag = build_key_bag()
    authored_map = build_author_event_hash_preimage(
        scope=scope,
        sequence=sequence,
        prev_hash=prev_hash,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
        idempotency_key=idempotency_key,
    )
    authored_bytes = dcbor(authored_map)
    author_event_preimage = domain_separated_preimage(TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes)
    author_event_hash = hashlib.sha256(author_event_preimage).digest()
    event_payload = build_event_payload(
        scope=scope,
        sequence=sequence,
        prev_hash=prev_hash,
        author_event_hash=author_event_hash,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
        idempotency_key=idempotency_key,
    )
    event_payload_bytes = dcbor(event_payload)
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(
        dcbor(["Signature1", protected_header(kid), b"", event_payload_bytes])
    )
    signed_event = dcbor(
        cbor2.CBORTag(18, [protected_header(kid), {}, event_payload_bytes, signature])
    )
    canonical_hash = canonical_event_hash(scope, event_payload)

    return {
        "scope": scope,
        "record_bytes": record_bytes,
        "tuple_bytes": tuple_bytes,
        "authored_bytes": authored_bytes,
        "author_event_hash": author_event_hash,
        "event_bytes": signed_event,
        "event_payload": event_payload,
        "canonical_event_hash": canonical_hash,
    }


def intake_catalog_entry(
    *,
    intake_event_hash: bytes,
    case_created_event_hash: bytes | None,
    handoff: dict,
    response_bytes: bytes,
) -> dict:
    return {
        "intake_event_hash": intake_event_hash,
        "case_created_event_hash": case_created_event_hash,
        "handoff": handoff,
        "response_bytes": response_bytes,
    }


def build_append_fixture(
    *,
    out_dir: Path,
    fixture_id: str,
    description: str,
    record: dict,
    case_id: str,
    event_type: bytes,
    authored_at: int,
    sequence: int,
    prev_hash: bytes | None,
    derivation_text: str,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    _seed, pubkey = load_seed_and_pubkey(KEY_ISSUER_001)
    kid = derive_kid(SUITE_ID_PHASE_1, pubkey)
    signed = build_signed_append_event(
        record=record,
        case_id=case_id,
        event_type=event_type,
        authored_at=authored_at,
        sequence=sequence,
        prev_hash=prev_hash,
    )
    scope = signed["scope"]
    record_bytes = signed["record_bytes"]
    tuple_bytes = signed["tuple_bytes"]
    authored_bytes = signed["authored_bytes"]
    author_event_hash = signed["author_event_hash"]
    author_event_preimage = domain_separated_preimage(
        TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes
    )
    event_payload = signed["event_payload"]
    event_payload_bytes = dcbor(event_payload)
    signed_event = signed["event_bytes"]
    canonical_hash = signed["canonical_event_hash"]
    append_head = {
        "scope": scope,
        "sequence": sequence,
        "canonical_event_hash": canonical_hash,
    }

    write_bytes(out_dir / "input-wos-record.dcbor", record_bytes)
    write_bytes(out_dir / "input-wos-idempotency-tuple.cbor", tuple_bytes)
    write_bytes(out_dir / "input-author-event-hash-preimage.cbor", authored_bytes)
    write_bytes(out_dir / "author-event-preimage.bin", author_event_preimage)
    write_bytes(out_dir / "author-event-hash.bin", author_event_hash)
    write_bytes(out_dir / "expected-event-payload.cbor", event_payload_bytes)
    write_bytes(
        out_dir / "sig-structure.bin",
        dcbor(["Signature1", protected_header(kid), b"", event_payload_bytes]),
    )
    write_bytes(out_dir / "expected-event.cbor", signed_event)
    write_bytes(out_dir / "expected-append-head.cbor", dcbor(append_head))
    if prev_hash is not None:
        write_bytes(
            out_dir / "input-prior-append-head.cbor",
            dcbor(
                {
                    "scope": scope,
                    "sequence": sequence - 1,
                    "canonical_event_hash": prev_hash,
                }
            ),
        )

    write_text(
        out_dir / "manifest.toml",
        f'''id          = "{fixture_id}"
op          = "append"
status      = "active"
description = """{description}"""

[coverage]
tr_core = [
    "TR-CORE-001",
    "TR-CORE-018",
    "TR-CORE-021",
    "TR-CORE-030",
    "TR-CORE-031",
    "TR-CORE-050",
    "TR-CORE-051",
    "TR-CORE-080",
]

[inputs]
signing_key    = "../../_keys/issuer-001.cose_key"
wos_record     = "input-wos-record.dcbor"
wos_tuple      = "input-wos-idempotency-tuple.cbor"
authored_event = "input-author-event-hash-preimage.cbor"

[expected]
author_event_hash = "author-event-hash.bin"
canonical_event   = "expected-event-payload.cbor"
signed_event      = "expected-event.cbor"
append_head       = "expected-append-head.cbor"

[derivation]
document = "derivation.md"
''',
    )
    write_text(out_dir / "derivation.md", derivation_text)
    return {
        "scope": scope,
        "event_bytes": signed_event,
        "event_payload": event_payload,
        "canonical_event_hash": canonical_hash,
    }


def build_export(
    *,
    out_dir: Path,
    export_id: str,
    description: str,
    scope: bytes,
    generated_at: int,
    checkpoint_timestamp: int,
    events: list[bytes],
    registry_version: str,
    readme_title: str,
    readme_body: str,
    extra_members: dict[str, bytes],
    manifest_extensions: dict,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    seed, pubkey = load_seed_and_pubkey(KEY_ISSUER_001)
    kid = derive_kid(SUITE_ID_PHASE_1, pubkey)

    event_values = [cbor2.loads(event_bytes) for event_bytes in events]
    event_payloads = [cbor2.loads(tag.value[2]) for tag in event_values]
    canonical_hashes = [canonical_event_hash(scope, payload) for payload in event_payloads]
    leaf_hashes = [merkle_leaf_hash(canonical_hash) for canonical_hash in canonical_hashes]
    tree_head_hash = merkle_root(leaf_hashes)

    members_data: dict[str, bytes] = {}
    members_data["010-events.cbor"] = dcbor(event_values)
    members_data["020-inclusion-proofs.cbor"] = dcbor(inclusion_proofs(leaf_hashes))
    members_data["025-consistency-proofs.cbor"] = dcbor([])

    signing_key_registry = build_signing_key_registry(kid, pubkey, min(event["header"]["authored_at"] for event in event_payloads))
    members_data["030-signing-key-registry.cbor"] = signing_key_registry

    checkpoint_payload = {
        "version": 1,
        "scope": scope,
        "tree_size": len(events),
        "tree_head_hash": tree_head_hash,
        "timestamp": checkpoint_timestamp,
        "anchor_ref": None,
        "prev_checkpoint_hash": None,
        "extensions": None,
    }
    head_checkpoint_digest = checkpoint_digest(scope, checkpoint_payload)
    members_data["040-checkpoints.cbor"] = dcbor(
        [cbor2.loads(cose_sign1(seed, kid, dcbor(checkpoint_payload), ARTIFACT_TYPE_CHECKPOINT))]
    )

    domain_registry = build_domain_registry()
    domain_registry_digest = sha256(domain_registry)
    domain_registry_member = f"050-registries/{domain_registry_digest.hex()}.cbor"
    members_data[domain_registry_member] = domain_registry

    members_data["090-verify.sh"] = trellis_cli_verify_script()
    members_data["098-README.md"] = (
        f"# Trellis Export (Fixture) — {readme_title}\n\n{readme_body}\n"
    ).encode("utf-8")

    for name, value in extra_members.items():
        members_data[name] = value

    manifest_payload = {
        "format": "trellis-export/1",
        "version": 1,
        "generator": "x-trellis-test/export-generator-007-intake",
        "generated_at": generated_at,
        "scope": scope,
        "tree_size": len(events),
        "head_checkpoint_digest": head_checkpoint_digest,
        "registry_bindings": [
            {
                "registry_digest": domain_registry_digest,
                "registry_format": 1,
                "registry_version": registry_version,
                "bound_at_sequence": 0,
            }
        ],
        "signing_key_registry_digest": sha256(signing_key_registry),
        "events_digest": sha256(members_data["010-events.cbor"]),
        "checkpoints_digest": sha256(members_data["040-checkpoints.cbor"]),
        "inclusion_proofs_digest": sha256(members_data["020-inclusion-proofs.cbor"]),
        "consistency_proofs_digest": sha256(members_data["025-consistency-proofs.cbor"]),
        "payloads_inlined": False,
        "external_anchors": [],
        "posture_declaration": {
            "provider_readable": True,
            "reader_held": False,
            "delegated_compute": False,
            "external_anchor_required": False,
            "external_anchor_name": None,
            "recovery_without_user": True,
            "metadata_leakage_summary": "Intake-handoff export fixture with readable WOS payload bytes and embedded Formspec response bytes.",
        },
        "head_format_version": 1,
        "omitted_payload_checks": [],
        "extensions": manifest_extensions,
    }
    members_data["000-manifest.cbor"] = cose_sign1(seed, kid, dcbor(manifest_payload), ARTIFACT_TYPE_MANIFEST)

    for member, member_bytes in members_data.items():
        write_bytes(out_dir / member, member_bytes)

    members = sorted(members_data)
    root_dir = f"trellis-export-{scope.decode('utf-8')}-{len(events)}-{tree_head_hash.hex()[:8]}"
    zip_bytes = write_zip(
        out_dir / "expected-export.zip",
        root_dir=root_dir,
        members=members,
        data=members_data,
    )
    ledger_state = {
        "version": 1,
        "scope": scope,
        "tree_size": len(events),
        "root_dir": root_dir,
        "members": members,
        "notes": f"Fixture ledger_state for {export_id}; pack listed members into deterministic ZIP.",
    }
    write_bytes(out_dir / "input-ledger-state.cbor", dcbor(ledger_state))
    write_text(
        out_dir / "manifest.toml",
        f'''id          = "{export_id}"
op          = "export"
status      = "active"
description = """{description}"""

[coverage]
tr_core = [
    "TR-CORE-006",
    "TR-CORE-062",
    "TR-CORE-063",
    "TR-CORE-064",
    "TR-CORE-065",
    "TR-CORE-067",
    "TR-CORE-110",
    "TR-CORE-134",
]
tr_op = ["TR-OP-122"]

[inputs]
ledger_state = "input-ledger-state.cbor"

[expected]
zip        = "expected-export.zip"
zip_sha256 = "{hashlib.sha256(zip_bytes).hexdigest()}"

[derivation]
document = "derivation.md"
''',
    )


def build_vectors() -> None:
    workflow_response_bytes, workflow_response_hash = make_response_payload(
        "resp-workflow-2026-0001",
        applicant_name="Avery Applicant",
        household_size=2,
    )
    public_response_bytes, public_response_hash = make_response_payload(
        "resp-public-2026-0001",
        applicant_name="Parker Public",
        household_size=3,
    )

    workflow = workflow_handoff(WORKFLOW_CASE_ID, workflow_response_hash)
    public = public_handoff(public_response_hash)

    append_020 = build_append_fixture(
        out_dir=APPEND_020,
        fixture_id="append/020-wos-intake-accepted-workflow-attach",
        description="Genesis append of a WOS `intakeAccepted` provenance record for a workflow-initiated Formspec handoff. The handoff already targets an existing governed case, so acceptance attaches evidence without birthing a new case.",
        record=intake_accepted_record(
            record_id=WORKFLOW_INTAKE_RECORD_ID,
            actor_id="caseworker-123",
            actor_type="system",
            lifecycle_state="open",
            timestamp="2026-04-23T14:31:00Z",
            handoff_id=workflow["handoffId"],
            case_intent="attachToExistingCase",
            case_disposition="attachToExistingCase",
            case_ref=WORKFLOW_CASE_ID,
        ),
        case_id=WORKFLOW_CASE_ID,
        event_type=b"wos.kernel.intake_accepted",
        authored_at=WORKFLOW_AUTHORED_AT,
        sequence=0,
        prev_hash=None,
        derivation_text="""# Derivation — `append/020-wos-intake-accepted-workflow-attach`

This fixture wraps a WOS `intakeAccepted` facts-tier record in a Trellis Phase-1
envelope. The authored payload models the ADR 0073 workflow-initiated path:
the Formspec handoff already names the governed case, so the accepted outcome
is `attachToExistingCase` and no `caseCreated` record is emitted.
""",
    )

    append_021 = build_append_fixture(
        out_dir=APPEND_021,
        fixture_id="append/021-wos-intake-accepted-public-create",
        description="Genesis append of a WOS `intakeAccepted` provenance record for a public Formspec handoff that requests governed-case creation. The accepted outcome is `createGovernedCase` and pins the governing Definition tuple in the record data.",
        record=intake_accepted_record(
            record_id=PUBLIC_INTAKE_RECORD_ID,
            actor_id="intake-worker",
            actor_type="system",
            lifecycle_state="open",
            timestamp="2026-04-23T15:31:00Z",
            handoff_id=public["handoffId"],
            case_intent="requestGovernedCaseCreation",
            case_disposition="createGovernedCase",
            case_ref=PUBLIC_CASE_ID,
            definition_url=WORKFLOW_DEFINITION_URL,
            definition_version=WORKFLOW_DEFINITION_VERSION,
        ),
        case_id=PUBLIC_CASE_ID,
        event_type=b"wos.kernel.intake_accepted",
        authored_at=PUBLIC_INTAKE_AUTHORED_AT,
        sequence=0,
        prev_hash=None,
        derivation_text="""# Derivation — `append/021-wos-intake-accepted-public-create`

This fixture wraps a WOS `intakeAccepted` facts-tier record in a Trellis Phase-1
envelope for the ADR 0073 public-intake path. The accepted outcome is
`createGovernedCase`, so the record carries the created case ref and the pinned
Definition URL/version that justified the new governed case.
""",
    )

    append_022 = build_append_fixture(
        out_dir=APPEND_022,
        fixture_id="append/022-wos-case-created-public-intake",
        description="First non-genesis append extending `append/021-wos-intake-accepted-public-create`. Records the governed-case boundary for the same public Formspec handoff as a WOS `caseCreated` provenance record.",
        record=case_created_record(
            record_id=PUBLIC_CASE_CREATED_RECORD_ID,
            actor_id="intake-worker",
            actor_type="system",
            lifecycle_state="open",
            timestamp="2026-04-23T15:32:00Z",
            case_ref=PUBLIC_CASE_ID,
            handoff=public,
        ),
        case_id=PUBLIC_CASE_ID,
        event_type=b"wos.kernel.case_created",
        authored_at=PUBLIC_CASE_CREATED_AUTHORED_AT,
        sequence=1,
        prev_hash=append_021["canonical_event_hash"],
        derivation_text="""# Derivation — `append/022-wos-case-created-public-intake`

This fixture extends `append/021-wos-intake-accepted-public-create` with the
paired WOS `caseCreated` facts-tier record. The Trellis `prev_hash` chain makes
the public-intake acceptance and the governed-case birth verifiable as one
ordered case-ledger slice.
""",
    )

    workflow_catalog = dcbor(
        [
            intake_catalog_entry(
                intake_event_hash=append_020["canonical_event_hash"],
                case_created_event_hash=None,
                handoff=workflow,
                response_bytes=workflow_response_bytes,
            )
        ]
    )
    public_catalog = dcbor(
        [
            intake_catalog_entry(
                intake_event_hash=append_021["canonical_event_hash"],
                case_created_event_hash=append_022["canonical_event_hash"],
                handoff=public,
                response_bytes=public_response_bytes,
            )
        ]
    )

    build_export(
        out_dir=OUT_EXPORT_007,
        export_id="export/007-intake-handoffs-public-create",
        description="Two-event ADR 0073 export carrying a public Formspec handoff, the admitted WOS `intakeAccepted` record, the paired WOS `caseCreated` record, and `063-intake-handoffs.cbor` bound via `trellis.export.intake-handoffs.v1`.",
        scope=append_021["scope"],
        generated_at=GENERATED_AT_PUBLIC,
        checkpoint_timestamp=CHECKPOINT_TIMESTAMP_PUBLIC,
        events=[append_021["event_bytes"], append_022["event_bytes"]],
        registry_version="x-trellis-test/registry-intake-v1",
        readme_title="export/007-intake-handoffs-public-create",
        readme_body=(
            "ADR 0073 public-intake export fixture. `063-intake-handoffs.cbor` binds the\n"
            "Formspec `IntakeHandoff`, the canonical Response bytes used for\n"
            "`responseHash`, and the Trellis event hashes of the WOS `intakeAccepted`\n"
            "and `caseCreated` records so offline verification can replay the whole\n"
            "submission → intake acceptance → governed-case birth path."
        ),
        extra_members={"063-intake-handoffs.cbor": public_catalog},
        manifest_extensions={EXTENSION_KEY: {"intake_catalog_digest": sha256(public_catalog)}},
    )
    write_text(
        OUT_EXPORT_007 / "derivation.md",
        """# Derivation — `export/007-intake-handoffs-public-create`

This fixture realizes the Trellis side of ADR 0073 for the public-intake path.

The export carries two admitted WOS facts-tier events in canonical order:

1. `wos.kernel.intake_accepted`
2. `wos.kernel.case_created`

`063-intake-handoffs.cbor` is chain-derived rather than independently authored:
it names the admitting event hashes, embeds the exact Formspec `IntakeHandoff`,
and carries the exact canonical Response envelope bytes whose SHA-256 digest was
stored in `handoff.responseHash`.
""",
    )

    build_export(
        out_dir=OUT_EXPORT_008,
        export_id="export/008-intake-handoffs-workflow-attach",
        description="Single-event ADR 0073 export carrying a workflow-initiated Formspec handoff and the admitted WOS `intakeAccepted` attach record. The catalog row omits `case_created_event_hash` because no governed-case birth occurs on attach.",
        scope=append_020["scope"],
        generated_at=GENERATED_AT_WORKFLOW,
        checkpoint_timestamp=CHECKPOINT_TIMESTAMP_WORKFLOW,
        events=[append_020["event_bytes"]],
        registry_version="x-trellis-test/registry-intake-v1",
        readme_title="export/008-intake-handoffs-workflow-attach",
        readme_body=(
            "ADR 0073 workflow-initiated export fixture. `063-intake-handoffs.cbor`\n"
            "binds the Formspec `IntakeHandoff`, the canonical Response bytes used\n"
            "for `responseHash`, and the Trellis event hash of the admitted WOS\n"
            "`intakeAccepted` record. No `caseCreated` event appears because the\n"
            "handoff attaches to an existing governed case."
        ),
        extra_members={"063-intake-handoffs.cbor": workflow_catalog},
        manifest_extensions={EXTENSION_KEY: {"intake_catalog_digest": sha256(workflow_catalog)}},
    )
    write_text(
        OUT_EXPORT_008 / "derivation.md",
        """# Derivation — `export/008-intake-handoffs-workflow-attach`

This fixture realizes the Trellis side of ADR 0073 for the workflow-initiated
attach path. The export carries one admitted WOS `intakeAccepted` event and a
catalog row in `063-intake-handoffs.cbor` whose `case_created_event_hash` is
null because no governed-case birth occurred.
""",
    )

    root_dir, members, data, manifest_payload = export_members_from_dir(OUT_EXPORT_007)
    intake_catalog = cbor2.loads(data["063-intake-handoffs.cbor"])
    tampered_catalog = copy.deepcopy(intake_catalog)
    tampered_response = json.loads(tampered_catalog[0]["response_bytes"].decode("utf-8"))
    tampered_response["data"]["householdSize"] = 4
    tampered_catalog[0]["response_bytes"] = canonical_json_bytes(tampered_response)
    catalog_bytes = dcbor(tampered_catalog)

    seed, pubkey = load_seed_and_pubkey(KEY_ISSUER_001)
    kid = derive_kid(SUITE_ID_PHASE_1, pubkey)
    manifest_payload_verify = copy.deepcopy(manifest_payload)
    manifest_payload_verify["extensions"][EXTENSION_KEY]["intake_catalog_digest"] = sha256(
        catalog_bytes
    )

    data_verify = dict(data)
    data_verify["063-intake-handoffs.cbor"] = catalog_bytes
    data_verify["000-manifest.cbor"] = cose_sign1(seed, kid, dcbor(manifest_payload_verify), ARTIFACT_TYPE_MANIFEST)

    OUT_VERIFY_015.mkdir(parents=True, exist_ok=True)
    write_zip(
        OUT_VERIFY_015 / "input-export.zip",
        root_dir=root_dir,
        members=members,
        data=data_verify,
    )
    write_text(
        OUT_VERIFY_015 / "manifest.toml",
        '''id          = "verify/015-export-007-intake-response-hash-mismatch"
op          = "verify"
status      = "active"
description = """Negative verify vector for the ADR 0073 intake-handoff export. Starts from `export/007-intake-handoffs-public-create`, changes the catalog row's embedded Response bytes, and re-signs the manifest so structure stays valid while `handoff.responseHash` no longer matches the response evidence."""

[coverage]
tr_core = ["TR-CORE-067"]
tr_op = ["TR-OP-122"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
first_failure_kind   = "intake_response_hash_mismatch"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_VERIFY_015 / "derivation.md",
        """# Derivation — `verify/015-export-007-intake-response-hash-mismatch`

This fixture starts from `export/007-intake-handoffs-public-create`, mutates
the embedded Response bytes in `063-intake-handoffs.cbor`, recomputes the
catalog digest, and re-signs `000-manifest.cbor`. The ZIP remains structurally
valid, but the Formspec handoff's `responseHash` no longer matches the carried
Response bytes.
""",
    )

    public_empty_intake = intake_accepted_record(
        record_id=PUBLIC_INTAKE_RECORD_ID,
        actor_id="intake-worker",
        actor_type="system",
        lifecycle_state="open",
        timestamp="2026-04-23T15:31:00Z",
        handoff_id=public["handoffId"],
        case_intent="requestGovernedCaseCreation",
        case_disposition="createGovernedCase",
        case_ref=PUBLIC_CASE_ID,
        definition_url=WORKFLOW_DEFINITION_URL,
        definition_version=WORKFLOW_DEFINITION_VERSION,
        outputs=[],
    )
    public_empty_case_created = case_created_record(
        record_id=PUBLIC_CASE_CREATED_RECORD_ID,
        actor_id="intake-worker",
        actor_type="system",
        lifecycle_state="open",
        timestamp="2026-04-23T15:32:00Z",
        case_ref=PUBLIC_CASE_ID,
        handoff=public,
        outputs=[],
    )
    append_021_empty = build_signed_append_event(
        record=public_empty_intake,
        case_id=PUBLIC_CASE_ID,
        event_type=b"wos.kernel.intake_accepted",
        authored_at=PUBLIC_INTAKE_AUTHORED_AT,
        sequence=0,
        prev_hash=None,
    )
    append_022_empty = build_signed_append_event(
        record=public_empty_case_created,
        case_id=PUBLIC_CASE_ID,
        event_type=b"wos.kernel.case_created",
        authored_at=PUBLIC_CASE_CREATED_AUTHORED_AT,
        sequence=1,
        prev_hash=append_021_empty["canonical_event_hash"],
    )
    public_empty_catalog = dcbor(
        [
            intake_catalog_entry(
                intake_event_hash=append_021_empty["canonical_event_hash"],
                case_created_event_hash=append_022_empty["canonical_event_hash"],
                handoff=public,
                response_bytes=public_response_bytes,
            )
        ]
    )

    build_export(
        out_dir=OUT_EXPORT_013,
        export_id="export/013-intake-handoffs-public-create-empty-outputs",
        description="Two-event ADR 0073 export carrying a public Formspec handoff and the admitted WOS intake records with empty outputs arrays. The package is structurally valid, but the WOS payloads are semantically invalid for Trellis intake verification.",
        scope=append_021_empty["scope"],
        generated_at=ts(GENERATED_AT_PUBLIC[0] + 100),
        checkpoint_timestamp=ts(CHECKPOINT_TIMESTAMP_PUBLIC[0] + 100),
        events=[append_021_empty["event_bytes"], append_022_empty["event_bytes"]],
        registry_version="x-trellis-test/registry-intake-v1",
        readme_title="export/013-intake-handoffs-public-create-empty-outputs",
        readme_body=(
            "Negative ADR 0073 export fixture. `063-intake-handoffs.cbor` still\n"
            "binds the same Formspec handoff and canonical Response bytes, but the\n"
            "embedded WOS `intakeAccepted` and `caseCreated` payloads carry empty\n"
            "`outputs` arrays so verifier parsing must fail before handoff matching."
        ),
        extra_members={"063-intake-handoffs.cbor": public_empty_catalog},
        manifest_extensions={EXTENSION_KEY: {"intake_catalog_digest": sha256(public_empty_catalog)}},
    )
    write_text(
        OUT_EXPORT_013 / "derivation.md",
        """# Derivation — `export/013-intake-handoffs-public-create-empty-outputs`

This fixture mirrors `export/007-intake-handoffs-public-create`, but the
embedded WOS `intakeAccepted` and `caseCreated` records carry empty `outputs`
arrays. The archive must still verify structurally, but Trellis intake
verification must reject the payloads before catalog matching.
""",
    )

    OUT_VERIFY_016.mkdir(parents=True, exist_ok=True)
    write_bytes(
        OUT_VERIFY_016 / "input-export.zip",
        (OUT_EXPORT_013 / "expected-export.zip").read_bytes(),
    )
    write_text(
        OUT_VERIFY_016 / "manifest.toml",
        '''id          = "verify/016-export-013-intake-empty-outputs"
op          = "verify"
status      = "active"
description = """Negative verify vector for the ADR 0073 intake-handoff export. Starts from `export/013-intake-handoffs-public-create-empty-outputs`, which keeps the archive structurally valid but emits WOS `intakeAccepted` and `caseCreated` payloads with empty `outputs` arrays so intake verification must fail during payload parsing."""

[coverage]
tr_core = ["TR-CORE-067"]
tr_op = ["TR-OP-122"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
first_failure_kind   = "intake_payload_invalid"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_VERIFY_016 / "derivation.md",
        """# Derivation — `verify/016-export-013-intake-empty-outputs`

This fixture starts from `export/013-intake-handoffs-public-create-empty-outputs`.
The archive is structurally sound, but Trellis intake verification must reject
the first admitted WOS payload because `outputs` is empty on the
`intakeAccepted` record.
""",
    )

    tamper_catalog = copy.deepcopy(intake_catalog)
    tamper_response = json.loads(tamper_catalog[0]["response_bytes"].decode("utf-8"))
    tamper_response["data"]["householdSize"] = 5
    tamper_catalog[0]["response_bytes"] = canonical_json_bytes(tamper_response)
    data_tamper = dict(data)
    data_tamper["063-intake-handoffs.cbor"] = dcbor(tamper_catalog)

    OUT_TAMPER_015.mkdir(parents=True, exist_ok=True)
    write_zip(
        OUT_TAMPER_015 / "input-export.zip",
        root_dir=root_dir,
        members=members,
        data=data_tamper,
    )
    write_text(
        OUT_TAMPER_015 / "manifest.toml",
        '''id          = "tamper/015-intake-handoff-catalog-digest-mismatch"
op          = "tamper"
status      = "active"
description = """ADR 0073 export tamper. Mutates `063-intake-handoffs.cbor` after manifest signing so the archive spine remains intact but the `trellis.export.intake-handoffs.v1.intake_catalog_digest` check fails."""

[coverage]
tr_core = ["TR-CORE-061"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
tamper_kind          = "intake_handoff_catalog_digest_mismatch"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_TAMPER_015 / "derivation.md",
        """# Derivation — `tamper/015-intake-handoff-catalog-digest-mismatch`

This fixture starts from `export/007-intake-handoffs-public-create`, mutates
`063-intake-handoffs.cbor`, and leaves the signed `000-manifest.cbor`
unchanged. The verifier must localize the failure to the intake-handoff catalog
digest bound by `trellis.export.intake-handoffs.v1.intake_catalog_digest`.
""",
    )


def main() -> None:
    build_vectors()


if __name__ == "__main__":
    main()
