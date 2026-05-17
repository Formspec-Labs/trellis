"""Generate the remaining V3 export / verify / tamper vectors.

This script lands:

- export/002-revoked-key-history
- export/003-three-event-transition-chain
- export/004-external-payload-optional-anchor
- verify/010-export-002-revoked-key-after-valid-to
- verify/011-export-003-transition-chain
- verify/012-export-004-optional-anchor
- tamper/009-prev-hash-break
- tamper/010-missing-head
- tamper/011-wrong-scope
- tamper/012-registry-snapshot-swap

Authoring aid only. The committed fixture bytes plus each directory's
`derivation.md` are the reproducible evidence surface. This script is not
normative.
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
    trellis_cli_verify_script_text,
    ts,
)


ROOT = Path(__file__).resolve().parent.parent

APPEND_001 = ROOT / "append" / "001-minimal-inline-payload"
APPEND_003 = ROOT / "append" / "003-external-payload-ref"
APPEND_005 = ROOT / "append" / "005-prior-head-chain"
APPEND_006 = ROOT / "append" / "006-custody-transition-cm-b-to-cm-a"
APPEND_009 = ROOT / "append" / "009-signing-key-revocation"

EXPORT_001 = ROOT / "export" / "001-two-event-chain"

KEY_ISSUER_001 = ROOT / "_keys" / "issuer-001.cose_key"
KEY_ISSUER_002 = ROOT / "_keys" / "issuer-002.cose_key"
EXTERNAL_PAYLOAD_003 = ROOT / "_inputs" / "sample-external-payload-003.bin"

OUT_EXPORT_002 = ROOT / "export" / "002-revoked-key-history"
OUT_EXPORT_003 = ROOT / "export" / "003-three-event-transition-chain"
OUT_EXPORT_004 = ROOT / "export" / "004-external-payload-optional-anchor"

OUT_VERIFY_010 = ROOT / "verify" / "010-export-002-revoked-key-after-valid-to"
OUT_VERIFY_011 = ROOT / "verify" / "011-export-003-transition-chain"
OUT_VERIFY_012 = ROOT / "verify" / "012-export-004-optional-anchor"

OUT_TAMPER_009 = ROOT / "tamper" / "009-prev-hash-break"
OUT_TAMPER_010 = ROOT / "tamper" / "010-missing-head"
OUT_TAMPER_011 = ROOT / "tamper" / "011-wrong-scope"
OUT_TAMPER_012 = ROOT / "tamper" / "012-registry-snapshot-swap"

TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"
TAG_TRELLIS_CHECKPOINT_V1 = "trellis-checkpoint-v1"
TAG_TRELLIS_MERKLE_LEAF_V1 = "trellis-merkle-leaf-v1"
TAG_TRELLIS_MERKLE_INTERIOR_V1 = "trellis-merkle-interior-v1"
TAG_TRELLIS_POSTURE_DECLARATION_V1 = "trellis-posture-declaration-v1"
TAG_TRELLIS_TRANSITION_ATTESTATION_V1 = "trellis-transition-attestation-v1"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def domain_separated_preimage(tag: str, component: bytes) -> bytes:
    tag_bytes = tag.encode("utf-8")
    return (
        len(tag_bytes).to_bytes(4, "big")
        + tag_bytes
        + len(component).to_bytes(4, "big")
        + component
    )


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_text(path: Path, text: str) -> None:
    write_bytes(path, text.encode("utf-8"))


def load_seed_and_pubkey(path: Path) -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(path.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    assert isinstance(seed, bytes) and len(seed) == 32
    assert isinstance(pubkey, bytes) and len(pubkey) == 32
    return seed, pubkey


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    # Preimage uses canonical CBOR unsigned encoding for `suite_id`, matching
    # Rust `trellis_types::encode_uint` / `integrity_cose::derive_kid`.
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
    return cose_sign1_with_protected(seed, protected_header(kid, artifact_type), payload_bytes)


def cose_sign1_with_protected(seed: bytes, protected: bytes, payload_bytes: bytes) -> bytes:
    sig_structure = dcbor(["Signature1", protected, b"", payload_bytes])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    return dcbor(cbor2.CBORTag(CBOR_TAG_COSE_SIGN1, [protected, {}, payload_bytes, signature]))


def load_sign1(sign1_bytes: bytes) -> tuple[bytes, dict]:
    tag = cbor2.loads(sign1_bytes)
    assert isinstance(tag, cbor2.CBORTag) and tag.tag == CBOR_TAG_COSE_SIGN1
    protected = tag.value[0]
    payload = cbor2.loads(tag.value[2])
    return protected, payload


def canonical_event_hash(scope: bytes, event_payload: dict) -> bytes:
    preimage = {"version": 1, "ledger_scope": scope, "event_payload": event_payload}
    return domain_separated_sha256(TAG_TRELLIS_EVENT_V1, dcbor(preimage))


def author_event_hash(author_preimage: dict) -> bytes:
    return domain_separated_sha256(TAG_TRELLIS_AUTHOR_EVENT_V1, dcbor(author_preimage))


def content_hash(ciphertext: bytes) -> bytes:
    return domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, ciphertext)


def merkle_leaf_hash(canonical_hash: bytes) -> bytes:
    return domain_separated_sha256(TAG_TRELLIS_MERKLE_LEAF_V1, canonical_hash)


def merkle_interior_hash(left_hash: bytes, right_hash: bytes) -> bytes:
    return domain_separated_sha256(TAG_TRELLIS_MERKLE_INTERIOR_V1, left_hash + right_hash)


def split_point(length: int) -> int:
    value = 1
    while value << 1 < length:
        value <<= 1
    return value


def merkle_root(leaf_hashes: list[bytes]) -> bytes:
    if len(leaf_hashes) == 1:
        return leaf_hashes[0]
    k = split_point(len(leaf_hashes))
    return merkle_interior_hash(
        merkle_root(leaf_hashes[:k]),
        merkle_root(leaf_hashes[k:]),
    )


def inclusion_path(leaf_hashes: list[bytes], index: int) -> list[bytes]:
    if len(leaf_hashes) == 1:
        return []
    k = split_point(len(leaf_hashes))
    if index < k:
        return inclusion_path(leaf_hashes[:k], index) + [merkle_root(leaf_hashes[k:])]
    return inclusion_path(leaf_hashes[k:], index - k) + [merkle_root(leaf_hashes[:k])]


def checkpoint_digest(scope: bytes, checkpoint_payload: dict) -> bytes:
    preimage = {"version": 1, "scope": scope, "checkpoint_payload": checkpoint_payload}
    return domain_separated_sha256(TAG_TRELLIS_CHECKPOINT_V1, dcbor(preimage))


def build_signing_key_entry(
    kid: bytes,
    pubkey: bytes,
    *,
    valid_from: int,
    status: int = 0,
    valid_to: int | None = None,
) -> dict:
    return {
        "kid": kid,
        "pubkey": pubkey,
        "suite_id": SUITE_ID_PHASE_1,
        "status": status,
        "valid_from": ts(valid_from),
        "valid_to": ts(valid_to) if valid_to is not None else None,
        "supersedes": None,
        "attestation": None,
    }


def build_domain_registry(event_types: list[str], *, version: str) -> bytes:
    event_type_map = {
        name: {
            "privacy_class": "public",
            "commitment_schema": "x-trellis-test/commitment-schema-v1",
        }
        for name in event_types
    }
    registry = {
        "governance": {
            "ruleset_id": "x-trellis-test/governance-ruleset-v1",
            "ruleset_digest": sha256(b"x-trellis-test/governance-ruleset-v1"),
        },
        "event_types": event_type_map,
        "classifications": ["x-trellis-test/unclassified"],
        "role_vocabulary": ["x-trellis-test/role-author"],
        "registry_version": version,
    }
    return dcbor(registry)


def build_checkpoint_series(
    *,
    scope: bytes,
    leaf_hashes: list[bytes],
    timestamps: list[int],
    seed: bytes,
    kid: bytes,
) -> tuple[list[bytes], bytes]:
    checkpoint_bytes = []
    prior_digest = None
    digests: list[bytes] = []
    for idx, timestamp in enumerate(timestamps, start=1):
        payload = {
            "version": 1,
            "scope": scope,
            "tree_size": idx,
            "tree_head_hash": merkle_root(leaf_hashes[:idx]),
            "timestamp": timestamp,
            "anchor_ref": None,
            "prev_checkpoint_hash": prior_digest,
            "extensions": None,
        }
        digest = checkpoint_digest(scope, payload)
        digests.append(digest)
        checkpoint_bytes.append(cose_sign1(seed, kid, dcbor(payload), ARTIFACT_TYPE_CHECKPOINT))
        prior_digest = digest
    checkpoints_cbor = dcbor([cbor2.loads(item) for item in checkpoint_bytes])
    return checkpoint_bytes, checkpoints_cbor


def build_inclusion_proofs(leaf_hashes: list[bytes]) -> bytes:
    proofs = {}
    tree_size = len(leaf_hashes)
    for index, leaf_hash in enumerate(leaf_hashes):
        proofs[index] = {
            "leaf_index": index,
            "tree_size": tree_size,
            "leaf_hash": leaf_hash,
            "audit_path": inclusion_path(leaf_hashes, index),
        }
    return dcbor(proofs)


def build_consistency_proofs(leaf_hashes: list[bytes]) -> bytes:
    proofs = []
    if len(leaf_hashes) >= 2:
        proofs.append({"from_tree_size": 1, "to_tree_size": 2, "proof_path": [leaf_hashes[1]]})
    if len(leaf_hashes) >= 3:
        proofs.append({"from_tree_size": 2, "to_tree_size": 3, "proof_path": [leaf_hashes[2]]})
    return dcbor(proofs)


def export_members_from_dir(export_dir: Path) -> tuple[str, list[str], dict[str, bytes]]:
    ledger_state = cbor2.loads((export_dir / "input-ledger-state.cbor").read_bytes())
    root_dir = ledger_state["root_dir"]
    members = list(ledger_state["members"])
    data = {member: (export_dir / member).read_bytes() for member in members}
    return root_dir, members, data


def write_zip(out_dir: Path, *, root_dir: str, members: list[str], data: dict[str, bytes]) -> bytes:
    zip_path = out_dir / "expected-export.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for member in sorted(members):
            zf.writestr(deterministic_zipinfo(f"{root_dir}/{member}"), data[member])
        for info in zf.filelist:
            info.external_attr = 0
    return zip_path.read_bytes()


def write_input_zip(out_dir: Path, *, root_dir: str, members: list[str], data: dict[str, bytes]) -> bytes:
    zip_path = out_dir / "input-export.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for member in sorted(members):
            zf.writestr(deterministic_zipinfo(f"{root_dir}/{member}"), data[member])
        for info in zf.filelist:
            info.external_attr = 0
    return zip_path.read_bytes()


def write_export_vector(
    *,
    out_dir: Path,
    vector_id: str,
    description: str,
    generator_name: str,
    scope: bytes,
    event_bytes: list[bytes],
    signing_key_registry_bytes: bytes,
    registry_specs: list[dict],
    checkpoint_timestamps: list[int],
    manifest_seed: bytes,
    manifest_kid: bytes,
    posture_declaration: dict,
    external_anchors: list,
    payload_members: dict[str, bytes],
    readme_name: str,
    generated_at: int,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    members_data: dict[str, bytes] = {}

    events_cbor = dcbor([cbor2.loads(item) for item in event_bytes])
    write_bytes(out_dir / "010-events.cbor", events_cbor)
    members_data["010-events.cbor"] = events_cbor

    canonical_hashes = []
    for event_bytes_item in event_bytes:
        _, payload = load_sign1(event_bytes_item)
        canonical_hashes.append(canonical_event_hash(scope, payload))
    leaf_hashes = [merkle_leaf_hash(value) for value in canonical_hashes]
    tree_head_hash = merkle_root(leaf_hashes)

    _checkpoint_items, checkpoints_cbor = build_checkpoint_series(
        scope=scope,
        leaf_hashes=leaf_hashes,
        timestamps=checkpoint_timestamps,
        seed=manifest_seed,
        kid=manifest_kid,
    )
    write_bytes(out_dir / "040-checkpoints.cbor", checkpoints_cbor)
    members_data["040-checkpoints.cbor"] = checkpoints_cbor
    checkpoint_values = cbor2.loads(checkpoints_cbor)
    head_checkpoint_payload = cbor2.loads(checkpoint_values[-1].value[2])
    head_checkpoint_digest = checkpoint_digest(scope, head_checkpoint_payload)

    inclusion_cbor = build_inclusion_proofs(leaf_hashes)
    write_bytes(out_dir / "020-inclusion-proofs.cbor", inclusion_cbor)
    members_data["020-inclusion-proofs.cbor"] = inclusion_cbor

    consistency_cbor = build_consistency_proofs(leaf_hashes)
    write_bytes(out_dir / "025-consistency-proofs.cbor", consistency_cbor)
    members_data["025-consistency-proofs.cbor"] = consistency_cbor

    write_bytes(out_dir / "030-signing-key-registry.cbor", signing_key_registry_bytes)
    members_data["030-signing-key-registry.cbor"] = signing_key_registry_bytes

    registry_bindings = []
    for registry_spec in registry_specs:
        registry_bytes = registry_spec["bytes"]
        registry_digest = sha256(registry_bytes)
        registry_hex = registry_digest.hex()
        member = f"050-registries/{registry_hex}.cbor"
        write_bytes(out_dir / member, registry_bytes)
        members_data[member] = registry_bytes
        registry_bindings.append(
            {
                "registry_digest": registry_digest,
                "registry_format": 1,
                "registry_version": registry_spec["version"],
                "bound_at_sequence": registry_spec["bound_at_sequence"],
            }
        )

    for member, member_bytes in payload_members.items():
        write_bytes(out_dir / member, member_bytes)
        members_data[member] = member_bytes

    write_text(out_dir / "090-verify.sh", trellis_cli_verify_script_text())
    members_data["090-verify.sh"] = (out_dir / "090-verify.sh").read_bytes()

    omitted_payload_checks: list[str] = []
    readme = (
        f"# Trellis Export (Fixture) — {vector_id}\n\n"
        f"- scope (manifest.scope): `{scope.decode('utf-8')}`\n"
        f"- tree_size (manifest.tree_size): `{len(event_bytes)}`\n"
        f"- tree_head_hash: `{tree_head_hash.hex()}`\n"
        f"- head_checkpoint_digest: `{head_checkpoint_digest.hex()}`\n\n"
        "## Posture Declaration (manifest.posture_declaration)\n"
        f"```json\n{json.dumps(posture_declaration, indent=2, sort_keys=True)}\n```\n\n"
        "## Omitted payload checks\n"
        f"```json\n{json.dumps(omitted_payload_checks)}\n```\n\n"
        f"{readme_name}\n"
    )
    write_text(out_dir / "098-README.md", readme)
    members_data["098-README.md"] = (out_dir / "098-README.md").read_bytes()

    manifest_payload = {
        "format": "trellis-export/1",
        "version": 1,
        "generator": generator_name,
        "generated_at": generated_at,
        "scope": scope,
        "tree_size": len(event_bytes),
        "head_checkpoint_digest": head_checkpoint_digest,
        "registry_bindings": registry_bindings,
        "signing_key_registry_digest": sha256(signing_key_registry_bytes),
        "events_digest": sha256(events_cbor),
        "checkpoints_digest": sha256(checkpoints_cbor),
        "inclusion_proofs_digest": sha256(inclusion_cbor),
        "consistency_proofs_digest": sha256(consistency_cbor),
        "payloads_inlined": False,
        "external_anchors": external_anchors,
        "posture_declaration": posture_declaration,
        "head_format_version": 1,
        "omitted_payload_checks": omitted_payload_checks,
        "extensions": None,
    }
    manifest_bytes = cose_sign1(manifest_seed, manifest_kid, dcbor(manifest_payload), ARTIFACT_TYPE_MANIFEST)
    write_bytes(out_dir / "000-manifest.cbor", manifest_bytes)
    members_data["000-manifest.cbor"] = manifest_bytes

    members = sorted(members_data)
    root_dir = f"trellis-export-{scope.decode('utf-8')}-{len(event_bytes)}-{tree_head_hash.hex()[:8]}"
    zip_bytes = write_zip(out_dir, root_dir=root_dir, members=members, data=members_data)
    ledger_state = {
        "version": 1,
        "scope": scope,
        "tree_size": len(event_bytes),
        "root_dir": root_dir,
        "members": members,
        "notes": f"Fixture ledger_state for {vector_id}; pack listed members into deterministic ZIP.",
    }
    write_bytes(out_dir / "input-ledger-state.cbor", dcbor(ledger_state))

    manifest_text = f"""id          = "{vector_id}"
op          = "export"
status      = "active"
description = \"\"\"{description}\"\"\"

[coverage]
tr_core = [
    "TR-CORE-062",
    "TR-CORE-063",
    "TR-CORE-064",
    "TR-CORE-065",
    "TR-CORE-110",
    "TR-CORE-134",
]
tr_op = [
    "TR-OP-073",
    "TR-OP-074",
    "TR-OP-110",
    "TR-OP-122",
    "TR-OP-130",
]

[inputs]
ledger_state = "input-ledger-state.cbor"

[expected]
zip        = "expected-export.zip"
zip_sha256 = "{hashlib.sha256(zip_bytes).hexdigest()}"

[derivation]
document = "derivation.md"
"""
    write_text(out_dir / "manifest.toml", manifest_text)

    derivation = (
        f"# Derivation — `{vector_id}`\n\n"
        f"{description}\n\n"
        "This fixture was generated deterministically from committed append bytes and "
        "the pinned key / registry inputs named in the generator source. The archive "
        "members, manifest digests, checkpoint chain, and deterministic ZIP root are "
        "the evidence of record.\n"
    )
    write_text(out_dir / "derivation.md", derivation)


def resign_manifest(manifest_bytes: bytes, payload: dict, seed: bytes) -> bytes:
    tag = cbor2.loads(manifest_bytes)
    protected = tag.value[0]
    return cose_sign1_with_protected(seed, protected, dcbor(payload))


def source_export_payload(export_dir: Path) -> tuple[str, list[str], dict[str, bytes], dict]:
    root_dir, members, data = export_members_from_dir(export_dir)
    manifest_tag = cbor2.loads(data["000-manifest.cbor"])
    manifest_payload = cbor2.loads(manifest_tag.value[2])
    return root_dir, members, data, manifest_payload


def write_verify_vector(
    *,
    out_dir: Path,
    vector_id: str,
    description: str,
    root_dir: str,
    members: list[str],
    data: dict[str, bytes],
    posture_transition_count: int | None = None,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    write_input_zip(out_dir, root_dir=root_dir, members=members, data=data)
    manifest_lines = [
        f'id          = "{vector_id}"',
        'op          = "verify"',
        'status      = "active"',
        f'description = """{description}"""',
        "",
        "[coverage]",
        'tr_core = ["TR-CORE-067"]',
        'tr_op = ["TR-OP-041"]',
        "",
        "[inputs]",
        'export_zip = "input-export.zip"',
        "",
        "[expected.report]",
        "structure_verified   = true",
        "integrity_verified   = true",
        "readability_verified = true",
    ]
    if posture_transition_count is not None:
        manifest_lines.append(f"posture_transition_count = {posture_transition_count}")
    manifest_lines.extend(["", "[derivation]", 'document = "derivation.md"', ""])
    write_text(out_dir / "manifest.toml", "\n".join(manifest_lines))
    write_text(
        out_dir / "derivation.md",
        f"# Derivation — `{vector_id}`\n\n{description}\n",
    )


def write_negative_verify_vector(
    *,
    out_dir: Path,
    vector_id: str,
    description: str,
    root_dir: str,
    members: list[str],
    data: dict[str, bytes],
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    write_input_zip(out_dir, root_dir=root_dir, members=members, data=data)
    write_text(
        out_dir / "manifest.toml",
        f"""id          = "{vector_id}"
op          = "verify"
status      = "active"
description = \"\"\"{description}\"\"\"

[coverage]
tr_core = ["TR-CORE-067"]
tr_op = ["TR-OP-041"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true

[derivation]
document = "derivation.md"
""",
    )
    write_text(
        out_dir / "derivation.md",
        f"# Derivation — `{vector_id}`\n\n{description}\n",
    )


def write_tamper_manifest(
    *,
    out_dir: Path,
    vector_id: str,
    description: str,
    inputs_block: str,
    tamper_kind: str,
    failing_event_id: str | None = None,
) -> None:
    lines = [
        f'id          = "{vector_id}"',
        'op          = "tamper"',
        'status      = "active"',
        f'description = """{description}"""',
        "",
        "[coverage]",
        'tr_core = ["TR-CORE-061"]',
        "",
        inputs_block.strip(),
        "",
        "[expected.report]",
        "structure_verified   = true",
        "integrity_verified   = false",
        "readability_verified = true",
        f'tamper_kind          = "{tamper_kind}"',
    ]
    if failing_event_id is not None:
        lines.append(f'failing_event_id     = "{failing_event_id}"')
    lines.extend(["", "[derivation]", 'document = "derivation.md"', ""])
    write_text(out_dir / "manifest.toml", "\n".join(lines))
    write_text(
        out_dir / "derivation.md",
        f"# Derivation — `{vector_id}`\n\n{description}\n",
    )


def build_transition_event_seq2(seed: bytes, kid: bytes) -> bytes:
    prev_hash = cbor2.loads((APPEND_006 / "expected-append-head.cbor").read_bytes())["canonical_event_hash"]
    declaration_bytes = dcbor(
        {
            "declaration_id": "urn:trellis:declaration:test:003-post",
            "operator_id": "urn:trellis:operator:test",
            "scope": "test-response-ledger",
            "effective_from": ts(1745000400),
            "supersedes": "urn:trellis:declaration:test:003-pre",
            "custody_model": {"custody_model_id": "CM-B"},
            "disclosure_profile": "rl-profile-B",
            "posture_honesty_statement": "test fixture posture declaration",
        }
    )
    declaration_digest = domain_separated_sha256(
        TAG_TRELLIS_POSTURE_DECLARATION_V1,
        declaration_bytes,
    )

    def attestation(authority: str, authority_class: str) -> dict:
        preimage = dcbor(["urn:trellis:transition:test:003b", ts(1745000400), authority_class])
        signing_preimage = domain_separated_preimage(
            TAG_TRELLIS_TRANSITION_ATTESTATION_V1,
            preimage,
        )
        signature = Ed25519PrivateKey.from_private_bytes(seed).sign(signing_preimage)
        return {
            "authority": authority,
            "authority_class": authority_class,
            "signature": signature,
        }

    header = {
        "event_type": b"trellis.custody-model-transition.v1",
        "authored_at":  ts(1745000400),
        "retention_tier": 0,
        "classification": b"x-trellis-test/unclassified",
        "outcome_commitment": None,
        "subject_ref_commitment": None,
        "tag_commitment": None,
        "witness_ref": None,
        "extensions": None,
    }
    payload_ref = {
        "ref_type": "inline",
        "ciphertext": b"custody-transition-003-seq2",
        "nonce": b"\x00" * 12,
    }
    payload_extensions = {
        "trellis.custody-model-transition.v1": {
            "transition_id": "urn:trellis:transition:test:003b",
            "from_custody_model": "CM-A",
            "to_custody_model": "CM-B",
            "transition_actor": "urn:trellis:principal:test-operator",
            "policy_authority": "urn:trellis:authority:test-governance",
            "effective_at": ts(1745000400),
            "reason_code": 2,
            "temporal_scope": "prospective",
            "declaration_doc_digest": declaration_digest,
            "attestations": [
                attestation("urn:trellis:authority:test-cm-b-authority", "new"),
            ],
            "extensions": None,
        }
    }
    payload_ref_ciphertext = payload_ref["ciphertext"]
    computed_content_hash = content_hash(payload_ref_ciphertext)
    author_preimage = {
        "version": 1,
        "ledger_scope": b"test-response-ledger",
        "sequence": 2,
        "prev_hash": prev_hash,
        "causal_deps": None,
        "content_hash": computed_content_hash,
        "header": header,
        "commitments": None,
        "payload_ref": payload_ref,
        "key_bag": {"entries": []},
        "idempotency_key": b"idemp-export-003-seq2",
        "extensions": payload_extensions,
    }
    payload = copy.deepcopy(author_preimage)
    payload["author_event_hash"] = author_event_hash(author_preimage)
    return cose_sign1(seed, kid, dcbor(payload))


def generate_exports() -> None:
    issuer_001_seed, issuer_001_pub = load_seed_and_pubkey(KEY_ISSUER_001)
    issuer_002_seed, issuer_002_pub = load_seed_and_pubkey(KEY_ISSUER_002)
    issuer_001_kid = derive_kid(SUITE_ID_PHASE_1, issuer_001_pub)
    issuer_002_kid = derive_kid(SUITE_ID_PHASE_1, issuer_002_pub)

    # export/002 — revoked key kept for historical verification.
    event_009 = (APPEND_009 / "expected-event.cbor").read_bytes()
    export_002_registry = build_domain_registry(
        ["x-trellis-test/append-minimal"],
        version="x-trellis-test/registry-002-v1",
    )
    signing_key_registry_002 = (APPEND_009 / "input-signing-key-registry-after.cbor").read_bytes()
    posture_002 = {
        "provider_readable": True,
        "reader_held": False,
        "delegated_compute": False,
        "external_anchor_required": False,
        "external_anchor_name": None,
        "recovery_without_user": True,
        "metadata_leakage_summary": "Historical revoked-key export fixture.",
    }
    write_export_vector(
        out_dir=OUT_EXPORT_002,
        vector_id="export/002-revoked-key-history",
        description="Single-event export whose embedded signing-key registry resolves a `Revoked` key with a non-null historical `valid_to`, exercising export-side key-material handling without invalidating pre-compromise signatures.",
        generator_name="x-trellis-test/export-generator-002",
        scope=b"test-revocation-ledger",
        event_bytes=[event_009],
        signing_key_registry_bytes=signing_key_registry_002,
        registry_specs=[
            {"bytes": export_002_registry, "version": "x-trellis-test/registry-002-v1", "bound_at_sequence": 0}
        ],
        checkpoint_timestamps=[ts(1745110060)],
        manifest_seed=issuer_002_seed,
        manifest_kid=issuer_002_kid,
        posture_declaration=posture_002,
        external_anchors=[],
        payload_members={},
        readme_name="Run `./090-verify.sh` from this directory.",
        generated_at=ts(1745110060),
    )

    # export/003 — three-event chain with two custody transitions.
    event_001 = (APPEND_001 / "expected-event.cbor").read_bytes()
    event_006 = (APPEND_006 / "expected-event.cbor").read_bytes()
    event_003_seq2 = build_transition_event_seq2(issuer_001_seed, issuer_001_kid)
    export_003_registry = build_domain_registry(
        ["x-trellis-test/append-minimal", "trellis.custody-model-transition.v1"],
        version="x-trellis-test/registry-003-v1",
    )
    signing_key_registry_003 = dcbor(
        [build_signing_key_entry(issuer_001_kid, issuer_001_pub, valid_from=1745000000)]
    )
    posture_003 = {
        "provider_readable": True,
        "reader_held": False,
        "delegated_compute": False,
        "external_anchor_required": False,
        "external_anchor_name": None,
        "recovery_without_user": True,
        "metadata_leakage_summary": "Transition-chain export fixture.",
    }
    write_export_vector(
        out_dir=OUT_EXPORT_003,
        vector_id="export/003-three-event-transition-chain",
        description="Three-event export over `test-response-ledger`: the append genesis, the committed CM-B → CM-A custody transition, and a generated CM-A → CM-B follow-on transition at sequence 2. Expands the export suite to a larger inclusion/consistency-proof set and the happy-path non-tamper posture-transition surface.",
        generator_name="x-trellis-test/export-generator-003",
        scope=b"test-response-ledger",
        event_bytes=[event_001, event_006, event_003_seq2],
        signing_key_registry_bytes=signing_key_registry_003,
        registry_specs=[
            {"bytes": export_003_registry, "version": "x-trellis-test/registry-003-v1", "bound_at_sequence": 0}
        ],
        checkpoint_timestamps=[ts(1745000050), ts(1745000150), ts(1745000450)],
        manifest_seed=issuer_001_seed,
        manifest_kid=issuer_001_kid,
        posture_declaration=posture_003,
        external_anchors=[],
        payload_members={},
        readme_name="Run `./090-verify.sh` from this directory.",
        generated_at=ts(1745000450),
    )

    # export/004 — bundled PayloadExternal plus optional external-anchor claim.
    event_003 = (APPEND_003 / "expected-event.cbor").read_bytes()
    payload_003 = cbor2.loads((APPEND_003 / "expected-event-payload.cbor").read_bytes())
    external_hash = payload_003["content_hash"].hex()
    export_004_registry = build_domain_registry(
        ["x-trellis-test/append-external"],
        version="x-trellis-test/registry-004-v1",
    )
    posture_004 = {
        "provider_readable": True,
        "reader_held": False,
        "delegated_compute": False,
        "external_anchor_required": False,
        "external_anchor_name": "x-trellis-test/optional-anchor",
        "recovery_without_user": True,
        "metadata_leakage_summary": "PayloadExternal export fixture with optional anchor semantics.",
    }
    write_export_vector(
        out_dir=OUT_EXPORT_004,
        vector_id="export/004-external-payload-optional-anchor",
        description="Single-event export that bundles a `PayloadExternal` body under `060-payloads/<content_hash>.bin` and declares optional external anchoring (`external_anchor_required = false`) in the manifest posture declaration. Exercises export ZIP member variety and manifest-variant coverage without forcing an anchor-resolution failure.",
        generator_name="x-trellis-test/export-generator-004",
        scope=b"test-response-ledger",
        event_bytes=[event_003],
        signing_key_registry_bytes=signing_key_registry_003,
        registry_specs=[
            {"bytes": export_004_registry, "version": "x-trellis-test/registry-004-v1", "bound_at_sequence": 0}
        ],
        checkpoint_timestamps=[ts(1745000063)],
        manifest_seed=issuer_001_seed,
        manifest_kid=issuer_001_kid,
        posture_declaration=posture_004,
        external_anchors=[],
        payload_members={f"060-payloads/{external_hash}.bin": EXTERNAL_PAYLOAD_003.read_bytes()},
        readme_name="Run `./090-verify.sh` from this directory.",
        generated_at=ts(1745000063),
    )


def generate_verify_vectors() -> None:
    issuer_002_seed, _ = load_seed_and_pubkey(KEY_ISSUER_002)

    root_dir_002, members_002, data_002, manifest_002 = source_export_payload(OUT_EXPORT_002)
    registry_after = cbor2.loads(data_002["030-signing-key-registry.cbor"])
    registry_after[0]["valid_to"] = ts(1745109999)
    registry_after_bytes = dcbor(registry_after)
    manifest_002["signing_key_registry_digest"] = sha256(registry_after_bytes)
    manifest_002_bytes = resign_manifest(data_002["000-manifest.cbor"], manifest_002, issuer_002_seed)
    data_010 = dict(data_002)
    data_010["030-signing-key-registry.cbor"] = registry_after_bytes
    data_010["000-manifest.cbor"] = manifest_002_bytes
    write_negative_verify_vector(
        out_dir=OUT_VERIFY_010,
        vector_id="verify/010-export-002-revoked-key-after-valid-to",
        description="Negative-non-tamper verify vector for Core §19 step 4.a. Starts from `export/002-revoked-key-history`, moves the embedded revoked signing-key entry's `valid_to` earlier than the event's `authored_at`, updates the manifest digest binding, and re-signs the manifest so the verifier reaches the event-level `revoked_authority` branch instead of failing archive integrity earlier.",
        root_dir=root_dir_002,
        members=members_002,
        data=data_010,
    )

    root_dir_003, members_003, data_003, _manifest_003 = source_export_payload(OUT_EXPORT_003)
    write_verify_vector(
        out_dir=OUT_VERIFY_011,
        vector_id="verify/011-export-003-transition-chain",
        description="Happy-path verify vector for Core §19 step 6. Reuses `export/003-three-event-transition-chain` intact so the verifier emits two clean `PostureTransitionOutcome` records in event order while preserving full archive, checkpoint, and proof integrity.",
        root_dir=root_dir_003,
        members=members_003,
        data=data_003,
        posture_transition_count=2,
    )

    root_dir_004, members_004, data_004, _manifest_004 = source_export_payload(OUT_EXPORT_004)
    write_verify_vector(
        out_dir=OUT_VERIFY_012,
        vector_id="verify/012-export-004-optional-anchor",
        description="Happy-path verify vector for Core §19 step 8 optional external-anchor handling. Reuses `export/004-external-payload-optional-anchor` intact: payload bytes are present under `060-payloads/`, `external_anchor_required = false`, and no anchor-resolution failure is expected.",
        root_dir=root_dir_004,
        members=members_004,
        data=data_004,
    )


def generate_tamper_vectors() -> None:
    issuer_001_seed, issuer_001_pub = load_seed_and_pubkey(KEY_ISSUER_001)
    issuer_001_kid = derive_kid(SUITE_ID_PHASE_1, issuer_001_pub)

    # tamper/009 — mutate prev_hash, recompute author_event_hash, re-sign.
    OUT_TAMPER_009.mkdir(parents=True, exist_ok=True)
    event_001_bytes = (APPEND_001 / "expected-event.cbor").read_bytes()
    event_005_bytes = (APPEND_005 / "expected-event.cbor").read_bytes()
    protected_005, payload_005 = load_sign1(event_005_bytes)
    payload_005["prev_hash"] = payload_005["prev_hash"][:-1] + bytes([payload_005["prev_hash"][-1] ^ 0x01])
    author_preimage = copy.deepcopy(payload_005)
    author_preimage.pop("author_event_hash")
    payload_005["author_event_hash"] = author_event_hash(author_preimage)
    tampered_event_009 = cose_sign1_with_protected(issuer_001_seed, protected_005, dcbor(payload_005))
    tampered_event_payload_hash = canonical_event_hash(payload_005["ledger_scope"], payload_005).hex()
    tampered_ledger_009 = dcbor([cbor2.loads(event_001_bytes), cbor2.loads(tampered_event_009)])
    signing_key_registry = dcbor(
        [build_signing_key_entry(issuer_001_kid, issuer_001_pub, valid_from=1745000000)]
    )
    write_bytes(OUT_TAMPER_009 / "input-tampered-event.cbor", tampered_event_009)
    write_bytes(OUT_TAMPER_009 / "input-tampered-ledger.cbor", tampered_ledger_009)
    write_bytes(OUT_TAMPER_009 / "input-signing-key-registry.cbor", signing_key_registry)
    write_tamper_manifest(
        out_dir=OUT_TAMPER_009,
        vector_id="tamper/009-prev-hash-break",
        description="Mutates `append/005-prior-head-chain`'s `prev_hash`, recomputes the dependent `author_event_hash`, and re-signs the event so the verifier reaches the dedicated `prev_hash_break` branch instead of failing signature or author-hash integrity earlier.",
        inputs_block="""
[inputs]
ledger               = "input-tampered-ledger.cbor"
tampered_event       = "input-tampered-event.cbor"
signing_key_registry = "input-signing-key-registry.cbor"
""",
        tamper_kind="prev_hash_break",
        failing_event_id=tampered_event_payload_hash,
    )

    # tamper/010 — truncate checkpoints to remove the head.
    root_dir_001, members_001, data_001, manifest_001 = source_export_payload(EXPORT_001)
    checkpoints = cbor2.loads(data_001["040-checkpoints.cbor"])
    checkpoints_truncated = dcbor([checkpoints[0]])
    manifest_010 = copy.deepcopy(manifest_001)
    manifest_010["checkpoints_digest"] = sha256(checkpoints_truncated)
    manifest_010_bytes = resign_manifest(
        data_001["000-manifest.cbor"],
        manifest_010,
        issuer_001_seed,
    )
    data_010 = dict(data_001)
    data_010["040-checkpoints.cbor"] = checkpoints_truncated
    data_010["000-manifest.cbor"] = manifest_010_bytes
    OUT_TAMPER_010.mkdir(parents=True, exist_ok=True)
    write_input_zip(OUT_TAMPER_010, root_dir=root_dir_001, members=members_001, data=data_010)
    write_tamper_manifest(
        out_dir=OUT_TAMPER_010,
        vector_id="tamper/010-missing-head",
        description="Checkpoint-aware export tamper. Starts from `export/001-two-event-chain`, removes the head checkpoint from `040-checkpoints.cbor`, updates the manifest's `checkpoints_digest`, and re-signs the manifest while leaving `head_checkpoint_digest` pinned to the missing head. The verifier therefore reaches `head_checkpoint_digest_mismatch` as the first integrity failure.",
        inputs_block="""
[inputs]
export_zip = "input-export.zip"
""",
        tamper_kind="head_checkpoint_digest_mismatch",
    )

    # tamper/011 — mutate manifest scope only.
    manifest_011 = copy.deepcopy(manifest_001)
    manifest_011["scope"] = b"test-response-ledger-wrong-scope"
    manifest_011_bytes = resign_manifest(
        data_001["000-manifest.cbor"],
        manifest_011,
        issuer_001_seed,
    )
    data_011 = dict(data_001)
    data_011["000-manifest.cbor"] = manifest_011_bytes
    OUT_TAMPER_011.mkdir(parents=True, exist_ok=True)
    write_input_zip(OUT_TAMPER_011, root_dir=root_dir_001, members=members_001, data=data_011)
    write_tamper_manifest(
        out_dir=OUT_TAMPER_011,
        vector_id="tamper/011-wrong-scope",
        description="Manifest-only scope tamper. Re-signs `export/001-two-event-chain` after changing `manifest.scope` to a different ledger-scope byte string, leaving event, checkpoint, and proof material untouched so the first localizable failure is the verifier's scope check.",
        inputs_block="""
[inputs]
export_zip = "input-export.zip"
""",
        tamper_kind="scope_mismatch",
    )

    # tamper/012 — swap in a registry that cannot resolve custody-transition event types.
    root_dir_003, members_003, data_003, manifest_003 = source_export_payload(OUT_EXPORT_003)
    swapped_registry = (APPEND_009 / "input-domain-registry.cbor").read_bytes()
    old_registry_member = next(member for member in members_003 if member.startswith("050-registries/"))
    new_registry_digest = sha256(swapped_registry)
    new_registry_member = f"050-registries/{new_registry_digest.hex()}.cbor"
    manifest_012 = copy.deepcopy(manifest_003)
    manifest_012["registry_bindings"][0]["registry_digest"] = new_registry_digest
    manifest_012["registry_bindings"][0]["registry_version"] = "x-trellis-test/registry-009-v1"
    manifest_012_bytes = resign_manifest(
        data_003["000-manifest.cbor"],
        manifest_012,
        issuer_001_seed,
    )
    data_012 = dict(data_003)
    del data_012[old_registry_member]
    data_012[new_registry_member] = swapped_registry
    data_012["000-manifest.cbor"] = manifest_012_bytes
    members_012 = [new_registry_member if member == old_registry_member else member for member in members_003]
    OUT_TAMPER_012.mkdir(parents=True, exist_ok=True)
    write_input_zip(OUT_TAMPER_012, root_dir=root_dir_003, members=members_012, data=data_012)
    write_tamper_manifest(
        out_dir=OUT_TAMPER_012,
        vector_id="tamper/012-registry-snapshot-swap",
        description="Registry-binding tamper over `export/003-three-event-transition-chain`. Replaces the bound registry snapshot with the minimal append-only registry from `append/009-signing-key-revocation`, updates the manifest binding digest and member path, and re-signs the manifest. Digest bindings remain valid, but the transition event types are no longer resolvable under the embedded registry snapshot, so Core §19 step 4.j records `registry_digest_mismatch`.",
        inputs_block="""
[inputs]
export_zip = "input-export.zip"
""",
        tamper_kind="registry_digest_mismatch",
    )


def main() -> None:
    generate_exports()
    generate_verify_vectors()
    generate_tamper_vectors()


if __name__ == "__main__":
    main()
