"""Generate ADR 0072 attachment export / verify / tamper vectors.

Authoring aid only. The committed fixture bytes and derivation notes are the
evidence surface; this script exists so the CBOR and ZIP bytes are reproducible.
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
APPEND_018 = ROOT / "append" / "018-attachment-bound"
KEY_ISSUER_001 = ROOT / "_keys" / "issuer-001.cose_key"

OUT_EXPORT_005 = ROOT / "export" / "005-attachments-inline"
OUT_VERIFY_013 = ROOT / "verify" / "013-export-005-missing-attachment-body"
OUT_TAMPER_013 = ROOT / "tamper" / "013-attachment-manifest-digest-mismatch"

TAG_TRELLIS_CHECKPOINT_V1 = "trellis-checkpoint-v1"
TAG_TRELLIS_MERKLE_LEAF_V1 = "trellis-merkle-leaf-v1"
EXTENSION_KEY = "trellis.export.attachments.v1"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


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


def load_sign1_payload(sign1_bytes: bytes) -> dict:
    tag = cbor2.loads(sign1_bytes)
    assert isinstance(tag, cbor2.CBORTag) and tag.tag == CBOR_TAG_COSE_SIGN1
    return cbor2.loads(tag.value[2])


def checkpoint_digest(scope: bytes, checkpoint_payload: dict) -> bytes:
    preimage = {"version": 1, "scope": scope, "checkpoint_payload": checkpoint_payload}
    return domain_separated_sha256(TAG_TRELLIS_CHECKPOINT_V1, dcbor(preimage))


def merkle_leaf_hash(canonical_hash: bytes) -> bytes:
    return domain_separated_sha256(TAG_TRELLIS_MERKLE_LEAF_V1, canonical_hash)


def parse_hash(value: str) -> bytes:
    prefix, digest = value.split(":", 1)
    assert prefix == "sha256"
    out = bytes.fromhex(digest)
    assert len(out) == 32
    return out


def build_signing_key_registry(kid: bytes, pubkey: bytes) -> bytes:
    entry = {
        "kid": kid,
        "pubkey": pubkey,
        "suite_id": SUITE_ID_PHASE_1,
        "status": 0,
        "valid_from": ts(1776866400),
        "valid_to": None,
        "supersedes": None,
        "attestation": None,
    }
    return dcbor([entry])


def build_domain_registry() -> bytes:
    return dcbor(
        {
            "governance": {
                "ruleset_id": "x-trellis-test/governance-ruleset-attachments-v1",
                "ruleset_digest": sha256(b"x-trellis-test/governance-ruleset-attachments-v1"),
            },
            "event_types": {
                "formspec.attachment.added": {
                    "privacy_class": "restricted",
                    "commitment_schema": "formspec.respondent-ledger/EvidenceAttachmentBinding",
                }
            },
            "classifications": ["x-trellis-test/unclassified"],
            "role_vocabulary": ["x-trellis-test/role-respondent"],
            "registry_version": "x-trellis-test/registry-attachments-v1",
        }
    )


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


def build_export_005() -> None:
    OUT_EXPORT_005.mkdir(parents=True, exist_ok=True)

    seed, pubkey = load_seed_and_pubkey(KEY_ISSUER_001)
    kid = derive_kid(SUITE_ID_PHASE_1, pubkey)

    event_bytes = (APPEND_018 / "expected-event.cbor").read_bytes()
    event_payload = load_sign1_payload(event_bytes)
    scope = event_payload["ledger_scope"]
    canonical_event_hash = cbor2.loads((APPEND_018 / "expected-append-head.cbor").read_bytes())[
        "canonical_event_hash"
    ]
    leaf_hash = merkle_leaf_hash(canonical_event_hash)
    attachment_ciphertext = (APPEND_018 / "input-attachment-ciphertext.bin").read_bytes()
    attachment_binding = cbor2.loads((APPEND_018 / "input-evidence-attachment-binding.cbor").read_bytes())
    content_hash = event_payload["content_hash"]
    assert content_hash == parse_hash(attachment_binding["payload_content_hash"])

    members_data: dict[str, bytes] = {}

    events_cbor = dcbor([cbor2.loads(event_bytes)])
    members_data["010-events.cbor"] = events_cbor

    inclusion_proofs = dcbor(
        {
            0: {
                "leaf_index": 0,
                "tree_size": 1,
                "leaf_hash": leaf_hash,
                "audit_path": [],
            }
        }
    )
    members_data["020-inclusion-proofs.cbor"] = inclusion_proofs

    consistency_proofs = dcbor([])
    members_data["025-consistency-proofs.cbor"] = consistency_proofs

    signing_key_registry = build_signing_key_registry(kid, pubkey)
    members_data["030-signing-key-registry.cbor"] = signing_key_registry

    checkpoint_payload = {
        "version": 1,
        "scope": scope,
        "tree_size": 1,
        "tree_head_hash": leaf_hash,
        "timestamp": ts(1776866460),
        "anchor_ref": None,
        "prev_checkpoint_hash": None,
        "extensions": None,
    }
    head_checkpoint_digest = checkpoint_digest(scope, checkpoint_payload)
    members_data["040-checkpoints.cbor"] = dcbor([cbor2.loads(cose_sign1(seed, kid, dcbor(checkpoint_payload), ARTIFACT_TYPE_CHECKPOINT))])

    domain_registry = build_domain_registry()
    domain_registry_digest = sha256(domain_registry)
    domain_registry_member = f"050-registries/{domain_registry_digest.hex()}.cbor"
    members_data[domain_registry_member] = domain_registry

    payload_member = f"060-payloads/{content_hash.hex()}.bin"
    members_data[payload_member] = attachment_ciphertext

    attachment_entry = {
        "binding_event_hash": canonical_event_hash,
        "attachment_id": attachment_binding["attachment_id"],
        "slot_path": attachment_binding["slot_path"],
        "media_type": attachment_binding["media_type"],
        "byte_length": attachment_binding["byte_length"],
        "attachment_sha256": parse_hash(attachment_binding["attachment_sha256"]),
        "payload_content_hash": content_hash,
        "filename": attachment_binding["filename"],
        "prior_binding_hash": None,
    }
    attachment_manifest = dcbor([attachment_entry])
    members_data["061-attachments.cbor"] = attachment_manifest

    members_data["090-verify.sh"] = trellis_cli_verify_script()
    members_data["098-README.md"] = (
        "# Trellis Export (Fixture) — export/005-attachments-inline\n\n"
        "ADR 0072 attachment-binding export fixture. The attachment ciphertext is "
        "present under `060-payloads/`, and `061-attachments.cbor` is bound by "
        "`ExportManifestPayload.extensions[\"trellis.export.attachments.v1\"]`.\n"
    ).encode("utf-8")

    manifest_payload = {
        "format": "trellis-export/1",
        "version": 1,
        "generator": "x-trellis-test/export-generator-005-attachments",
        "generated_at": ts(1776866460),
        "scope": scope,
        "tree_size": 1,
        "head_checkpoint_digest": head_checkpoint_digest,
        "registry_bindings": [
            {
                "registry_digest": domain_registry_digest,
                "registry_format": 1,
                "registry_version": "x-trellis-test/registry-attachments-v1",
                "bound_at_sequence": 0,
            }
        ],
        "signing_key_registry_digest": sha256(signing_key_registry),
        "events_digest": sha256(events_cbor),
        "checkpoints_digest": sha256(members_data["040-checkpoints.cbor"]),
        "inclusion_proofs_digest": sha256(inclusion_proofs),
        "consistency_proofs_digest": sha256(consistency_proofs),
        "payloads_inlined": True,
        "external_anchors": [],
        "posture_declaration": {
            "provider_readable": True,
            "reader_held": False,
            "delegated_compute": False,
            "external_anchor_required": False,
            "external_anchor_name": None,
            "recovery_without_user": True,
            "metadata_leakage_summary": "ADR 0072 attachment export fixture.",
        },
        "head_format_version": 1,
        "omitted_payload_checks": [],
        "extensions": {
            EXTENSION_KEY: {
                "attachment_manifest_digest": sha256(attachment_manifest),
                "inline_attachments": True,
            }
        },
    }
    members_data["000-manifest.cbor"] = cose_sign1(seed, kid, dcbor(manifest_payload), ARTIFACT_TYPE_MANIFEST)

    for member, member_bytes in members_data.items():
        write_bytes(OUT_EXPORT_005 / member, member_bytes)

    members = sorted(members_data)
    root_dir = f"trellis-export-{scope.decode('utf-8')}-1-{leaf_hash.hex()[:8]}"
    zip_bytes = write_zip(
        OUT_EXPORT_005 / "expected-export.zip",
        root_dir=root_dir,
        members=members,
        data=members_data,
    )
    ledger_state = {
        "version": 1,
        "scope": scope,
        "tree_size": 1,
        "root_dir": root_dir,
        "members": members,
        "notes": "Fixture ledger_state for export/005-attachments-inline; pack listed members into deterministic ZIP.",
    }
    write_bytes(OUT_EXPORT_005 / "input-ledger-state.cbor", dcbor(ledger_state))
    write_text(
        OUT_EXPORT_005 / "manifest.toml",
        f'''id          = "export/005-attachments-inline"
op          = "export"
status      = "active"
description = """Single-event ADR 0072 export that carries a Formspec attachment-binding event, bundles the attachment ciphertext under `060-payloads/`, and binds `061-attachments.cbor` through `trellis.export.attachments.v1`."""

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
''',
    )
    write_text(
        OUT_EXPORT_005 / "derivation.md",
        """# Derivation — `export/005-attachments-inline`

This fixture realizes the Trellis side of ADR 0072 for export bundles.

It starts from `append/018-attachment-bound`, packages that canonical event
as the only event in the export, includes the attachment ciphertext at
`060-payloads/<payload_content_hash>.bin`, derives `061-attachments.cbor`
from the chain-authored `EvidenceAttachmentBinding`, and binds that derived
manifest through `ExportManifestPayload.extensions["trellis.export.attachments.v1"]`.

The attachment manifest is a dCBOR array of `AttachmentManifestEntry` maps.
The entry's `binding_event_hash` is the canonical event hash of `append/018`,
and its `payload_content_hash` equals both the event `content_hash` and the
`PayloadExternal.content_hash`.
""",
    )


def write_verify_vector() -> None:
    root_dir, members, data, _manifest_payload = export_members_from_dir(OUT_EXPORT_005)
    payload_member = next(member for member in members if member.startswith("060-payloads/"))
    members_without_payload = [member for member in members if member != payload_member]
    data_without_payload = dict(data)
    del data_without_payload[payload_member]

    OUT_VERIFY_013.mkdir(parents=True, exist_ok=True)
    write_zip(
        OUT_VERIFY_013 / "input-export.zip",
        root_dir=root_dir,
        members=members_without_payload,
        data=data_without_payload,
    )
    write_text(
        OUT_VERIFY_013 / "manifest.toml",
        '''id          = "verify/013-export-005-missing-attachment-body"
op          = "verify"
status      = "active"
description = """Negative verify vector for ADR 0072 inline attachment carriage. Starts from `export/005-attachments-inline` and removes the `060-payloads/<payload_content_hash>.bin` body while leaving `inline_attachments = true` and all manifest signatures intact."""

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
''',
    )
    write_text(
        OUT_VERIFY_013 / "derivation.md",
        """# Derivation — `verify/013-export-005-missing-attachment-body`

This fixture starts from `export/005-attachments-inline`, removes only the
`060-payloads/<payload_content_hash>.bin` member, and keeps the signed manifest
unchanged. The regular required-member digest checks still pass; the verifier
must fail the ADR 0072 inline-attachment obligation because the manifest
extension declares `inline_attachments = true`.
""",
    )


def write_tamper_vector() -> None:
    root_dir, members, data, _manifest_payload = export_members_from_dir(OUT_EXPORT_005)
    attachment_manifest = cbor2.loads(data["061-attachments.cbor"])
    tampered_attachment_manifest = copy.deepcopy(attachment_manifest)
    tampered_attachment_manifest[0]["byte_length"] += 1
    data_tampered = dict(data)
    data_tampered["061-attachments.cbor"] = dcbor(tampered_attachment_manifest)

    OUT_TAMPER_013.mkdir(parents=True, exist_ok=True)
    write_zip(
        OUT_TAMPER_013 / "input-export.zip",
        root_dir=root_dir,
        members=members,
        data=data_tampered,
    )
    write_text(
        OUT_TAMPER_013 / "manifest.toml",
        '''id          = "tamper/013-attachment-manifest-digest-mismatch"
op          = "tamper"
status      = "active"
description = """ADR 0072 export tamper. Mutates `061-attachments.cbor` after manifest signing so the required archive spine remains intact but the `trellis.export.attachments.v1.attachment_manifest_digest` check fails."""

[coverage]
tr_core = ["TR-CORE-061"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
tamper_kind          = "attachment_manifest_digest_mismatch"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_TAMPER_013 / "derivation.md",
        """# Derivation — `tamper/013-attachment-manifest-digest-mismatch`

This fixture starts from `export/005-attachments-inline`, increments the
`byte_length` field inside `061-attachments.cbor`, and leaves the signed
`000-manifest.cbor` unchanged. The verifier must localize the failure to the
ADR 0072 attachment-manifest digest bound by
`trellis.export.attachments.v1.attachment_manifest_digest`.
""",
    )


def main() -> None:
    build_export_005()
    write_verify_vector()
    write_tamper_vector()


if __name__ == "__main__":
    main()
