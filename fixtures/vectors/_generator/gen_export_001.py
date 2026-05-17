"""Generate byte-exact reference vector `export/001-two-event-chain`.

Authoring aid only. Every construction block carries an inline Core-? citation
naming the normative paragraph that determines the bytes. This script is NOT
normative; `derivation.md` is the spec-prose reproduction evidence. If this
script and Core disagree, Core wins.

Determinism: two runs of this script produce byte-identical output. No
randomness, no wall-clock reads, no environment lookups beyond pinned inputs.

Scope decision. This first export vector is intentionally **optimal** rather
than minimal: it exercises the export spine plus the smallest non-trivial
append chain.

- one ledger scope (`test-response-ledger`) with **two** Events:
  `append/001` (sequence 0) and `append/005` (sequence 1),
- two Checkpoints (tree_size = 1 and tree_size = 2) with the required
  `prev_checkpoint_hash` link,
- inclusion proofs for both leaves (audit_path length 1),
- one consistency proof record from 1 to 2 (RFC 6962 semantics),
- full manifest digest bindings and registry snapshot binding,
- no bundled verifier binaries (099-* optional members omitted).

It DOES exercise the full Phase-1 export package spine:
deterministic ZIP layout (?18.1), required archive members (?18.2), manifest
COSE_Sign1 signature (?18.3, ?7.4), digest bindings (?19 step 3), registry
snapshot binding (?14), and checkpoint/inclusion proof material (?11, ?18.5).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path

# Runnable as `python3 fixtures/vectors/_generator/gen_export_001.py` or with
# `--out-dir PATH`; extend `sys.path` so sibling `_lib` is importable without install.
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
    ZIP_FIXED_DATETIME,
    dcbor,
    deterministic_zipinfo,
    domain_separated_sha256,
    trellis_cli_verify_script,
    ts,
)


# ---------------------------------------------------------------------------
# Pinned inputs + output locations.
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent  # fixtures/vectors/
SOURCE_EVENT_001_DIR = ROOT / "append" / "001-minimal-inline-payload"
SOURCE_EVENT_005_DIR = ROOT / "append" / "005-prior-head-chain"
SOURCE_EVENT_001_FILE = SOURCE_EVENT_001_DIR / "expected-event.cbor"
SOURCE_EVENT_005_FILE = SOURCE_EVENT_005_DIR / "expected-event.cbor"
SOURCE_EVENT_001_PAYLOAD_FILE = SOURCE_EVENT_001_DIR / "expected-event-payload.cbor"
SOURCE_EVENT_005_PAYLOAD_FILE = SOURCE_EVENT_005_DIR / "expected-event-payload.cbor"

SOURCE_DOMAIN_REGISTRY_FILE = (
    ROOT / "append" / "009-signing-key-revocation" / "input-domain-registry.cbor"
)

KEY_FILE = ROOT / "_keys" / "issuer-001.cose_key"

_DEFAULT_EXPORT_001_VECTOR_DIR = ROOT / "export" / "001-two-event-chain"


# ---------------------------------------------------------------------------
# Core pins (Phase 1).
# ---------------------------------------------------------------------------

# SUITE_ID, ALG_EDDSA, COSE_LABEL_*, CBOR_TAG_COSE_SIGN1, and ZIP_FIXED_DATETIME
# are imported from `_lib.byte_utils`; those are registry-fixed numeric
# values (RFC 9052 + Core section references in byte_utils), not spec interpretations.
SUITE_ID = SUITE_ID_PHASE_1

# Pinned timestamps for manifest/checkpoint (Unix seconds UTC).
AUTHORED_AT = ts(1745000000)
GENERATED_AT = ts(1745000060)
CHECKPOINT_TIMESTAMP_1 = ts(1745000050)
CHECKPOINT_TIMESTAMP_2 = ts(1745000060)

# ---------------------------------------------------------------------------
# Domain tags (?9.8) and ?9.1 framing.
# ---------------------------------------------------------------------------

TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_CHECKPOINT_V1 = "trellis-checkpoint-v1"
TAG_TRELLIS_MERKLE_LEAF_V1 = "trellis-merkle-leaf-v1"
TAG_TRELLIS_MERKLE_INTERIOR_V1 = "trellis-merkle-interior-v1"
TAG_TRELLIS_EXPORT_MANIFEST_V1 = "trellis-export-manifest-v1"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# COSE / keys (?7.4, ?8.3).
# ---------------------------------------------------------------------------


def load_issuer_key() -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    assert isinstance(seed, bytes) and len(seed) == 32
    assert isinstance(pubkey, bytes) and len(pubkey) == 32
    return seed, pubkey


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    # ?8.3 derived-kid: SHA-256(dCBOR(uint(suite_id)) || pubkey_raw)[:16]
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def build_protected_header(kid: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> dict:
    # ?7.4 / ADR 0109 substrate headers; dCBOR map-key ordering handled at encode.
    return {
        COSE_LABEL_ALG: ALG_EDDSA,
        COSE_LABEL_KID: kid,
        COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
    }


def build_sig_structure(protected_bstr: bytes, payload_bstr: bytes) -> bytes:
    # RFC 9052 ?4.4 Sig_structure for COSE_Sign1:
    #   ["Signature1", protected, external_aad, payload]
    # Core ?7.4: external_aad is the zero-length bstr for Phase 1.
    return dcbor(["Signature1", protected_bstr, b"", payload_bstr])


def cose_sign1(seed: bytes, kid: bytes, payload_bytes: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> bytes:
    protected_map_bytes = dcbor(build_protected_header(kid, artifact_type))
    sig_structure = build_sig_structure(protected_map_bytes, payload_bytes)
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    sign1 = [protected_map_bytes, {}, payload_bytes, signature]
    return dcbor(cbor2.CBORTag(CBOR_TAG_COSE_SIGN1, sign1))


# ---------------------------------------------------------------------------
# ?9.2 canonical_event_hash and ?11 Merkle.
# ---------------------------------------------------------------------------


def canonical_event_hash(ledger_scope: bytes, event_payload: dict) -> bytes:
    preimage = {"version": 1, "ledger_scope": ledger_scope, "event_payload": event_payload}
    return domain_separated_sha256(TAG_TRELLIS_EVENT_V1, dcbor(preimage))


def merkle_leaf_hash(canonical_hash: bytes) -> bytes:
    return domain_separated_sha256(TAG_TRELLIS_MERKLE_LEAF_V1, canonical_hash)

def merkle_interior_hash(left_hash: bytes, right_hash: bytes) -> bytes:
    # ?11.3: domain-separated over (left_hash || right_hash) as one component.
    return domain_separated_sha256(
        TAG_TRELLIS_MERKLE_INTERIOR_V1, left_hash + right_hash
    )


# ---------------------------------------------------------------------------
# ?11.2 checkpoint and ?9.6 digest.
# ---------------------------------------------------------------------------


def checkpoint_digest(ledger_scope: bytes, checkpoint_payload: dict) -> bytes:
    preimage = {"version": 1, "scope": ledger_scope, "checkpoint_payload": checkpoint_payload}
    return domain_separated_sha256(TAG_TRELLIS_CHECKPOINT_V1, dcbor(preimage))


# ---------------------------------------------------------------------------
# ?9.7 export manifest digest (for README convenience, not required by verifier).
# ---------------------------------------------------------------------------


def export_manifest_digest(ledger_scope: bytes, manifest_payload: dict) -> bytes:
    preimage = {"version": 1, "scope": ledger_scope, "manifest_payload": manifest_payload}
    return domain_separated_sha256(TAG_TRELLIS_EXPORT_MANIFEST_V1, dcbor(preimage))


# ---------------------------------------------------------------------------
# Deterministic ZIP writer (?18.1).
# `deterministic_zipinfo` is imported from `_lib.byte_utils`.
# ---------------------------------------------------------------------------


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1) Load source events + payloads (append/001 and append/005).
    event_001_bytes = SOURCE_EVENT_001_FILE.read_bytes()
    event_005_bytes = SOURCE_EVENT_005_FILE.read_bytes()
    payload_001 = cbor2.loads(SOURCE_EVENT_001_PAYLOAD_FILE.read_bytes())
    payload_005 = cbor2.loads(SOURCE_EVENT_005_PAYLOAD_FILE.read_bytes())

    ledger_scope = payload_001["ledger_scope"]
    assert ledger_scope == b"test-response-ledger"
    assert payload_001["sequence"] == 0
    assert payload_001["header"]["authored_at"] == AUTHORED_AT
    assert payload_005["ledger_scope"] == ledger_scope
    assert payload_005["sequence"] == 1

    # 2) Build 010-events.cbor (Core ?18.4): 2-element dCBOR array of Event.
    events_cbor = b"\x82" + event_001_bytes + event_005_bytes

    # 3) Canonical event hashes (Core ?9.2) and Merkle leaf hashes (Core ?11.3).
    canon_hash_0 = canonical_event_hash(ledger_scope, payload_001)
    canon_hash_1 = canonical_event_hash(ledger_scope, payload_005)
    leaf_hash_0 = merkle_leaf_hash(canon_hash_0)
    leaf_hash_1 = merkle_leaf_hash(canon_hash_1)
    tree_head_hash_1 = leaf_hash_0
    tree_head_hash_2 = merkle_interior_hash(leaf_hash_0, leaf_hash_1)

    # 4) Domain registry snapshot (Core ?14.2) and binding (Core ?14.3).
    domain_registry_bytes = SOURCE_DOMAIN_REGISTRY_FILE.read_bytes()
    registry_digest = sha256(domain_registry_bytes)
    registry_digest_hex = registry_digest.hex()
    registry_binding = {
        "registry_digest": registry_digest,
        "registry_format": 1,  # ?14.3: 1 = dCBOR
        "registry_version": "x-trellis-test/registry-009-v1",
        "bound_at_sequence": 0,
    }

    write_bytes(out_dir / "050-registries" / f"{registry_digest_hex}.cbor", domain_registry_bytes)

    # 5) Signing-key registry snapshot (Core ?8.5).
    seed, pubkey_raw = load_issuer_key()
    kid = derive_kid(SUITE_ID, pubkey_raw)
    signing_key_entry = {
        "kid": kid,
        "pubkey": pubkey_raw,
        "suite_id": SUITE_ID,
        "status": 0,  # Active
        "valid_from": AUTHORED_AT,
        "valid_to": None,
        "supersedes": None,
        "attestation": None,
    }
    signing_key_registry_cbor = dcbor([signing_key_entry])

    # 6) Checkpoints (Core ?11.2) + signed checkpoint COSE_Sign1 (Core ?7.4).
    checkpoint_payload_1 = {
        "version": 1,
        "scope": ledger_scope,
        "tree_size": 1,
        "tree_head_hash": tree_head_hash_1,
        "timestamp": CHECKPOINT_TIMESTAMP_1,
        "anchor_ref": None,
        "prev_checkpoint_hash": None,
        "extensions": None,
    }
    digest_1 = checkpoint_digest(ledger_scope, checkpoint_payload_1)
    checkpoint_payload_2 = {
        "version": 1,
        "scope": ledger_scope,
        "tree_size": 2,
        "tree_head_hash": tree_head_hash_2,
        "timestamp": CHECKPOINT_TIMESTAMP_2,
        "anchor_ref": None,
        "prev_checkpoint_hash": digest_1,
        "extensions": None,
    }
    digest_2 = checkpoint_digest(ledger_scope, checkpoint_payload_2)
    checkpoint_1_bytes = cose_sign1(seed, kid, dcbor(checkpoint_payload_1), ARTIFACT_TYPE_CHECKPOINT)
    checkpoint_2_bytes = cose_sign1(seed, kid, dcbor(checkpoint_payload_2), ARTIFACT_TYPE_CHECKPOINT)
    checkpoints_cbor = b"\x82" + checkpoint_1_bytes + checkpoint_2_bytes
    head_checkpoint_digest = digest_2

    # 7) Inclusion proofs (?18.5): map leaf_index -> InclusionProof.
    inclusion_proofs_obj = {
        0: {
            "leaf_index": 0,
            "tree_size": 2,
            "leaf_hash": leaf_hash_0,
            "audit_path": [leaf_hash_1],
        },
        1: {
            "leaf_index": 1,
            "tree_size": 2,
            "leaf_hash": leaf_hash_1,
            "audit_path": [leaf_hash_0],
        },
    }
    inclusion_proofs_cbor = dcbor(inclusion_proofs_obj)

    # 8) Consistency proofs (Core sec.18.5): one record linking tree_size 1 to 2 (RFC 6962 semantics).
    consistency_proofs_obj = [
        {"from_tree_size": 1, "to_tree_size": 2, "proof_path": [leaf_hash_1]}
    ]
    consistency_proofs_cbor = dcbor(consistency_proofs_obj)

    # 9) Write the non-manifest archive members that the manifest will digest-bind.
    write_bytes(out_dir / "010-events.cbor", events_cbor)
    write_bytes(out_dir / "020-inclusion-proofs.cbor", inclusion_proofs_cbor)
    write_bytes(out_dir / "025-consistency-proofs.cbor", consistency_proofs_cbor)
    write_bytes(out_dir / "030-signing-key-registry.cbor", signing_key_registry_cbor)
    write_bytes(out_dir / "040-checkpoints.cbor", checkpoints_cbor)

    # 10) Human-facing members (?18.8, ?18.9).
    write_bytes(out_dir / "090-verify.sh", trellis_cli_verify_script())

    # README fields are normative (?18.9): scope, tree_size, head hash, posture,
    # omitted checks, and verification invocation.
    posture_declaration = {
        "provider_readable": True,
        "reader_held": False,
        "delegated_compute": False,
        "external_anchor_required": False,
        "external_anchor_name": None,
        "recovery_without_user": True,
        "metadata_leakage_summary": (
            "Fixture export: envelope reveals event_type, authored_at (1s granularity), "
            "retention_tier, classification, ledger_scope, and COSE kid."
        ),
    }
    omitted_payload_checks = []
    # ?18.9 README: human-facing JSON block must be real JSON (lowercase
    # true/false/null), not a Python dict repr. sort_keys=True keeps two
    # runs byte-identical.
    posture_json = json.dumps(posture_declaration, indent=2, sort_keys=True)
    readme = (
        "# Trellis Export (Fixture) \u2014 export/001-two-event-chain\n"
        "\n"
        f"- scope (manifest.scope): `{ledger_scope.decode('utf-8')}`\n"
        "- tree_size (manifest.tree_size): `2`\n"
        f"- tree_head_hash (checkpoint[1].tree_head_hash): `{tree_head_hash_2.hex()}`\n"
        f"- head_checkpoint_digest: `{head_checkpoint_digest.hex()}`\n"
        f"- registry_digest: `{registry_digest_hex}`\n"
        "\n"
        "## Posture Declaration (manifest.posture_declaration)\n"
        f"```json\n{posture_json}\n```\n"
        "\n"
        "## Omitted payload checks\n"
        "```json\n"
        f"{json.dumps(omitted_payload_checks)}\n"
        "```\n"
        "\n"
        "## Verify\n"
        "Run `./090-verify.sh` from this directory (or run your verifier directly).\n"
    ).encode("utf-8")
    write_bytes(out_dir / "098-README.md", readme)

    # 11) Compute manifest digests (?18.3, ?19 step 3) and write 000-manifest.cbor.
    manifest_payload = {
        "format": "trellis-export/1",
        "version": 1,
        "generator": "x-trellis-test/export-generator-001",
        "generated_at": GENERATED_AT,
        "scope": ledger_scope,
        "tree_size": 2,
        "head_checkpoint_digest": head_checkpoint_digest,
        "registry_bindings": [registry_binding],
        "signing_key_registry_digest": sha256(signing_key_registry_cbor),
        "events_digest": sha256(events_cbor),
        "checkpoints_digest": sha256(checkpoints_cbor),
        "inclusion_proofs_digest": sha256(inclusion_proofs_cbor),
        "consistency_proofs_digest": sha256(consistency_proofs_cbor),
        "payloads_inlined": False,
        "external_anchors": [],
        "posture_declaration": posture_declaration,
        "head_format_version": 1,
        "omitted_payload_checks": omitted_payload_checks,
        "extensions": None,
    }
    manifest_payload_bytes = dcbor(manifest_payload)
    signed_manifest_bytes = cose_sign1(seed, kid, manifest_payload_bytes, ARTIFACT_TYPE_MANIFEST)
    write_bytes(out_dir / "000-manifest.cbor", signed_manifest_bytes)

    # 12) Assemble deterministic ZIP (?18.1, ?18.2).
    root_dir = f"trellis-export-{ledger_scope.decode('utf-8')}-2-{tree_head_hash_2.hex()[:8]}"
    members = [
        "000-manifest.cbor",
        "010-events.cbor",
        "020-inclusion-proofs.cbor",
        "025-consistency-proofs.cbor",
        "030-signing-key-registry.cbor",
        "040-checkpoints.cbor",
        f"050-registries/{registry_digest_hex}.cbor",
        "090-verify.sh",
        "098-README.md",
    ]

    zip_path = out_dir / "expected-export.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for member in sorted(members):
            data = (out_dir / member).read_bytes()
            arcname = f"{root_dir}/{member}"
            # ?18.1: arcnames MUST be ASCII so the ZIP "language encoding flag"
            # (general-purpose bit 11) stays cleared and two runs produce
            # byte-identical output under CPython's zipfile defaults.
            assert arcname.isascii(), arcname
            zf.writestr(deterministic_zipinfo(arcname), data)
        # ?18.1: external file attributes MUST be zero. CPython's
        # ZipFile._open_to_write overwrites any zero external_attr to
        # 0o600 << 16 before the central-directory entry is built; patch it
        # back to zero on every ZipInfo so the central directory bytes match
        # the spec. Applied after all writes, before close flushes the CD.
        for info in zf.filelist:
            info.external_attr = 0

    # 13) Write a minimal ledger_state input describing the build inputs.
    # This file is a fixture-runner convenience only; Core defines the export
    # package bytes, not the internal "ledger state" API.
    ledger_state = {
        "version": 1,
        "scope": ledger_scope,
        "tree_size": 2,
        "root_dir": root_dir,
        "members": members,
        "notes": "Fixture ledger_state for export/001; pack listed members into deterministic ZIP.",
    }
    write_bytes(out_dir / "input-ledger-state.cbor", dcbor(ledger_state))

    # 14) Convenience: print stable digests for authoring `manifest.toml` and derivation.
    zip_digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    manifest_digest = export_manifest_digest(ledger_scope, manifest_payload).hex()
    print(f"export/001: zip_sha256={zip_digest}")
    print(f"export/001: export_manifest_digest={manifest_digest}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Regenerate fixtures/vectors/export/001-two-event-chain generator outputs "
            "(authoring aid; not normative)."
        )
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=_DEFAULT_EXPORT_001_VECTOR_DIR,
        help=(
            "Directory to receive generated artifact files "
            "(default: committed fixture directory export/001-two-event-chain/)."
        ),
    )
    args = parser.parse_args()
    main(args.out_dir.resolve())
