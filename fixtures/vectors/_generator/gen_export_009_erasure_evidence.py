"""Generate export/009-erasure-evidence-inline and tamper/019-erasure-catalog-digest-mismatch.

Authoring aid only. The export chain is a single genesis `trellis.erasure-evidence.v1`
event taken from `tamper/017-erasure-post-use` event 0 (valid standalone chain).

Uses `trellis_py` only to recompute `canonical_event_hash` identically to the Rust verifier.
"""
from __future__ import annotations

import copy
import hashlib
import struct
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
TAMPER_017 = ROOT / "tamper" / "017-erasure-post-use"
KEY_ISSUER_001 = ROOT / "_keys" / "issuer-001.cose_key"

OUT_EXPORT_009 = ROOT / "export" / "009-erasure-evidence-inline"
OUT_TAMPER_019 = ROOT / "tamper" / "019-erasure-catalog-digest-mismatch"

TAG_TRELLIS_CHECKPOINT_V1 = "trellis-checkpoint-v1"
TAG_TRELLIS_MERKLE_LEAF_V1 = "trellis-merkle-leaf-v1"
EXTENSION_KEY = "trellis.export.erasure-evidence.v1"
EVENT_DOMAIN = "trellis-event-v1"


def _encode_major_len(major: int, value: int) -> bytes:
    header = major << 5
    if value <= 23:
        return bytes([header | value])
    if value <= 0xFF:
        return bytes([header | 24, value])
    if value <= 0xFFFF:
        return bytes([header | 25]) + struct.pack(">H", value)
    if value <= 0xFFFF_FFFF:
        return bytes([header | 26]) + struct.pack(">I", value)
    return bytes([header | 27]) + struct.pack(">Q", value)


def _encode_bstr(data: bytes) -> bytes:
    return _encode_major_len(2, len(data)) + data


def _encode_tstr(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _encode_major_len(3, len(raw)) + raw


def _encode_uint(value: int) -> bytes:
    return _encode_major_len(0, value)


def _canonical_event_hash(scope: bytes, event_payload_bytes: bytes) -> bytes:
    preimage = bytearray()
    preimage.append(0xA3)
    preimage.extend(_encode_tstr("version"))
    preimage.extend(_encode_uint(1))
    preimage.extend(_encode_tstr("ledger_scope"))
    preimage.extend(_encode_bstr(scope))
    preimage.extend(_encode_tstr("event_payload"))
    preimage.extend(event_payload_bytes)
    return domain_separated_sha256(EVENT_DOMAIN, bytes(preimage))


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


def checkpoint_digest(scope: bytes, checkpoint_payload: dict) -> bytes:
    preimage = {"version": 1, "scope": scope, "checkpoint_payload": checkpoint_payload}
    return domain_separated_sha256(TAG_TRELLIS_CHECKPOINT_V1, dcbor(preimage))


def merkle_leaf_hash(canonical_hash: bytes) -> bytes:
    return domain_separated_sha256(TAG_TRELLIS_MERKLE_LEAF_V1, canonical_hash)


def build_domain_registry() -> bytes:
    return dcbor(
        {
            "governance": {
                "ruleset_id": "x-trellis-test/governance-ruleset-erasure-export-009",
                "ruleset_digest": sha256(b"x-trellis-test/governance-ruleset-erasure-export-009"),
            },
            "event_types": {
                "trellis.erasure-evidence.v1": {
                    "privacy_class": "restricted",
                    "binding_family": "trellis.erasure-evidence",
                }
            },
            "classifications": ["x-trellis-test/unclassified"],
            "role_vocabulary": ["x-trellis-test/role-author"],
            "registry_version": "x-trellis-test/registry-erasure-export-009-v1",
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


def erasure_catalog_row(canonical_event_hash: bytes, erasure: dict) -> dict:
    """Build one `ErasureEvidenceCatalogEntry` map (ADR 0005)."""
    ss = erasure["subject_scope"]
    return {
        "canonical_event_hash": canonical_event_hash,
        "evidence_id": erasure["evidence_id"],
        "kid_destroyed": erasure["kid_destroyed"],
        "destroyed_at": erasure["destroyed_at"],
        "completion_mode": erasure["completion_mode"],
        "cascade_scopes": erasure["cascade_scopes"],
        "subject_scope_kind": ss["kind"],
    }


def build_export_009() -> None:
    OUT_EXPORT_009.mkdir(parents=True, exist_ok=True)

    seed, pubkey = load_seed_and_pubkey(KEY_ISSUER_001)
    kid = derive_kid(SUITE_ID_PHASE_1, pubkey)

    ledger = cbor2.loads((TAMPER_017 / "input-tampered-ledger.cbor").read_bytes())
    event0 = ledger[0]
    sign1_bytes = dcbor(event0)
    sign1 = cbor2.loads(sign1_bytes)
    event_payload_bytes = sign1.value[2]
    payload = cbor2.loads(event_payload_bytes)
    scope = payload["ledger_scope"]
    canonical_event_hash = _canonical_event_hash(scope, event_payload_bytes)
    erasure = payload["extensions"]["trellis.erasure-evidence.v1"]

    members_data: dict[str, bytes] = {}

    events_cbor = dcbor([event0])
    members_data["010-events.cbor"] = events_cbor

    leaf_hash = merkle_leaf_hash(canonical_event_hash)
    members_data["020-inclusion-proofs.cbor"] = dcbor(
        {
            0: {
                "leaf_index": 0,
                "tree_size": 1,
                "leaf_hash": leaf_hash,
                "audit_path": [],
            }
        }
    )
    members_data["025-consistency-proofs.cbor"] = dcbor([])

    members_data["030-signing-key-registry.cbor"] = (TAMPER_017 / "input-signing-key-registry.cbor").read_bytes()

    checkpoint_payload = {
        "version": 1,
        "scope": scope,
        "tree_size": 1,
        "tree_head_hash": leaf_hash,
        "timestamp": ts(1745000200),
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

    catalog = dcbor([erasure_catalog_row(canonical_event_hash, erasure)])
    members_data["064-erasure-evidence.cbor"] = catalog

    members_data["090-verify.sh"] = trellis_cli_verify_script()
    members_data["098-README.md"] = (
        "# Trellis Export — export/009-erasure-evidence-inline\n\n"
        "Single genesis erasure-evidence event (from `tamper/017` event 0) plus "
        "`064-erasure-evidence.cbor` bound via `trellis.export.erasure-evidence.v1`.\n"
    ).encode("utf-8")

    manifest_payload = {
        "format": "trellis-export/1",
        "version": 1,
        "generator": "x-trellis-test/export-generator-009-erasure",
        "generated_at": ts(1745000200),
        "scope": scope,
        "tree_size": 1,
        "head_checkpoint_digest": head_checkpoint_digest,
        "registry_bindings": [
            {
                "registry_digest": domain_registry_digest,
                "registry_format": 1,
                "registry_version": "x-trellis-test/registry-erasure-export-009-v1",
                "bound_at_sequence": 0,
            }
        ],
        "signing_key_registry_digest": sha256(members_data["030-signing-key-registry.cbor"]),
        "events_digest": sha256(events_cbor),
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
            "metadata_leakage_summary": "ADR 0005 erasure export catalog fixture (single genesis event).",
        },
        "head_format_version": 1,
        "omitted_payload_checks": [],
        "extensions": {
            EXTENSION_KEY: {
                "catalog_ref": "064-erasure-evidence.cbor",
                "catalog_digest": sha256(catalog),
                "entry_count": 1,
            }
        },
    }
    members_data["000-manifest.cbor"] = cose_sign1(seed, kid, dcbor(manifest_payload), ARTIFACT_TYPE_MANIFEST)

    for member, member_bytes in members_data.items():
        write_bytes(OUT_EXPORT_009 / member, member_bytes)

    members = sorted(members_data)
    root_dir = f"trellis-export-{scope.decode('utf-8')}-1-{leaf_hash.hex()[:8]}"
    zip_bytes = write_zip(
        OUT_EXPORT_009 / "expected-export.zip",
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
        "notes": "Fixture ledger_state for export/009-erasure-evidence-inline; pack listed members into deterministic ZIP.",
    }
    write_bytes(OUT_EXPORT_009 / "input-ledger-state.cbor", dcbor(ledger_state))
    write_text(
        OUT_EXPORT_009 / "manifest.toml",
        f'''id          = "export/009-erasure-evidence-inline"
op          = "export"
status      = "active"
description = """Single genesis `trellis.erasure-evidence.v1` event (pinned to `tamper/017-erasure-post-use` event 0) with `064-erasure-evidence.cbor` catalog bound through `trellis.export.erasure-evidence.v1` (ADR 0005 / Core §18.2)."""

[coverage]
tr_core = [
    "TR-CORE-006",
    "TR-CORE-062",
    "TR-CORE-063",
    "TR-CORE-064",
    "TR-CORE-065",
    "TR-CORE-110",
    "TR-CORE-134",
]
tr_op = [
    "TR-OP-105",
    "TR-OP-106",
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
        OUT_EXPORT_009 / "derivation.md",
        """# Derivation — `export/009-erasure-evidence-inline`

Single-event export: `010-events.cbor` contains only `tamper/017-erasure-post-use` chain
event 0 (genesis erasure host). Domain registry admits `trellis.erasure-evidence.v1`.
`064-erasure-evidence.cbor` is a one-row chain-derived catalog; the manifest extension
`trellis.export.erasure-evidence.v1` binds its digest and `entry_count`.

Generator: `fixtures/vectors/_generator/gen_export_009_erasure_evidence.py`.
""",
    )


def export_members_from_dir(export_dir: Path) -> tuple[str, list[str], dict[str, bytes], dict]:
    ledger_state = cbor2.loads((export_dir / "input-ledger-state.cbor").read_bytes())
    root_dir = ledger_state["root_dir"]
    members = list(ledger_state["members"])
    data = {member: (export_dir / member).read_bytes() for member in members}
    manifest_tag = cbor2.loads(data["000-manifest.cbor"])
    manifest_payload = cbor2.loads(manifest_tag.value[2])
    return root_dir, members, data, manifest_payload


def write_tamper_019() -> None:
    root_dir, members, data, _manifest_payload = export_members_from_dir(OUT_EXPORT_009)
    catalog = cbor2.loads(data["064-erasure-evidence.cbor"])
    tampered = copy.deepcopy(catalog)
    tampered[0]["evidence_id"] = "urn:trellis:erasure:tampered:019"
    data_tampered = dict(data)
    data_tampered["064-erasure-evidence.cbor"] = dcbor(tampered)

    OUT_TAMPER_019.mkdir(parents=True, exist_ok=True)
    write_zip(
        OUT_TAMPER_019 / "input-export.zip",
        root_dir=root_dir,
        members=members,
        data=data_tampered,
    )
    write_text(
        OUT_TAMPER_019 / "manifest.toml",
        '''id          = "tamper/019-erasure-catalog-digest-mismatch"
op          = "tamper"
status      = "active"
description = """Mutates `064-erasure-evidence.cbor` after manifest signing so `trellis.export.erasure-evidence.v1.catalog_digest` fails (ADR 0005 export catalog pattern)."""

[coverage]
tr_core = ["TR-CORE-061"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
tamper_kind          = "erasure_evidence_catalog_digest_mismatch"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_TAMPER_019 / "derivation.md",
        """# Derivation — `tamper/019-erasure-catalog-digest-mismatch`

Starts from `export/009-erasure-evidence-inline`, changes `evidence_id` in the first
catalog row (so catalog bytes change) while leaving `000-manifest.cbor` unchanged.
The verifier must fail with `erasure_evidence_catalog_digest_mismatch`.
""",
    )


def main() -> None:
    build_export_009()
    write_tamper_019()


if __name__ == "__main__":
    main()
