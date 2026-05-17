"""Generate the six negative verify vectors derived from export/001.

Each output vector mutates a single surface of the happy-path export so the
verifier hits a specific §19 failure path, then re-signs whatever COSE
envelope the mutation touched so the remaining §19 steps run to their
intended point.

Outputs (all read from `export/001-two-event-chain/` as ground truth):
- verify/002-export-001-manifest-sigflip           (fatal, §19 step 2.c)
- verify/003-export-001-missing-registry-snapshot  (fatal, §19 step 3.f)
- verify/004-export-001-unsupported-suite          (fatal, §19 step 2.b)
- verify/005-export-001-unresolvable-manifest-kid  (fatal, §19 step 2.a)
- verify/006-export-001-checkpoint-root-mismatch   (localizable, §19 step 5.c + 7.b)
- verify/007-export-001-inclusion-proof-mismatch   (localizable, §19 step 7.b)
- verify/008-export-001-prev-checkpoint-hash-mismatch (localizable, §19 step 5.d)
- verify/009-export-001-consistency-proof-mismatch (localizable, §19 step 5.e)

Authoring aid only. This script is NOT normative; the vectors' derivation.md
documents cite Core § prose as the reproduction authority.

Determinism: two runs produce byte-identical ZIP outputs.
"""

from __future__ import annotations

import hashlib
import sys
from collections.abc import Mapping
from pathlib import Path

# Sibling `_lib` package import (same pattern as gen_export_001.py).
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
    dcbor,
    deterministic_zipinfo,
    domain_separated_sha256,
)


ROOT = Path(__file__).resolve().parent.parent  # fixtures/vectors/
SOURCE_EXPORT_DIR = ROOT / "export" / "001-two-event-chain"
LEDGER_STATE_FILE = SOURCE_EXPORT_DIR / "input-ledger-state.cbor"
KEY_FILE = ROOT / "_keys" / "issuer-001.cose_key"

OUT_SIGFLIP = ROOT / "verify" / "002-export-001-manifest-sigflip"
OUT_MISSING_REGISTRY = ROOT / "verify" / "003-export-001-missing-registry-snapshot"
OUT_UNSUPPORTED_SUITE = ROOT / "verify" / "004-export-001-unsupported-suite"
OUT_UNRESOLVABLE_KID = ROOT / "verify" / "005-export-001-unresolvable-manifest-kid"
OUT_CHECKPOINT_ROOT_MISMATCH = ROOT / "verify" / "006-export-001-checkpoint-root-mismatch"
OUT_INCLUSION_PROOF_MISMATCH = ROOT / "verify" / "007-export-001-inclusion-proof-mismatch"
OUT_PREV_CHECKPOINT_HASH_MISMATCH = ROOT / "verify" / "008-export-001-prev-checkpoint-hash-mismatch"
OUT_CONSISTENCY_PROOF_MISMATCH = ROOT / "verify" / "009-export-001-consistency-proof-mismatch"


SUITE_UNSUPPORTED = 999
TAG_TRELLIS_CHECKPOINT_V1 = "trellis-checkpoint-v1"


def checkpoint_digest(scope: bytes, checkpoint_payload: dict) -> bytes:
    preimage = {"version": 1, "scope": scope, "checkpoint_payload": checkpoint_payload}
    return domain_separated_sha256(TAG_TRELLIS_CHECKPOINT_V1, dcbor(preimage))


def flip_last_byte(data: bytes) -> bytes:
    if not data:
        raise ValueError("cannot flip last byte of empty input")
    last = data[-1] ^ 0x01
    return data[:-1] + bytes([last])


def load_seed() -> bytes:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    seed = cose_key[-4]
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError("issuer-001 seed not found in COSE_Key label -4")
    return seed


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def cose_sign1(seed: bytes, *, protected: bytes, payload: bytes) -> bytes:
    # gen_verify flavor: accepts pre-encoded `protected` bytes so re-signs
    # can preserve an existing protected map byte-for-byte. This signature
    # differs from gen_export_001.cose_sign1's `(seed, kid, payload)`, so
    # the helper is intentionally kept local rather than pushed into _lib.
    sig_structure = dcbor(["Signature1", protected, b"", payload])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    sign1 = [protected, {}, payload, signature]
    return dcbor(cbor2.CBORTag(CBOR_TAG_COSE_SIGN1, sign1))

def resign_with_same_protected(sign1_bytes: bytes, *, new_payload: bytes) -> bytes:
    tag = cbor2.loads(sign1_bytes)
    if not isinstance(tag, cbor2.CBORTag) or tag.tag != CBOR_TAG_COSE_SIGN1:
        raise ValueError("input must be a COSE_Sign1 tag-18 envelope")
    array = tag.value
    if not isinstance(array, (list, tuple)) or len(array) != 4:
        raise ValueError("COSE_Sign1 must be a 4-element array")
    protected_bstr = array[0]
    if not isinstance(protected_bstr, bytes):
        raise ValueError("protected header must be a bstr")
    return cose_sign1(load_seed(), protected=protected_bstr, payload=new_payload)

def mutate_manifest(
    manifest_bytes: bytes,
    *,
    new_kid: bytes | None = None,
    new_suite_id: int | None = None,
) -> bytes:
    tag = cbor2.loads(manifest_bytes)
    if not isinstance(tag, cbor2.CBORTag) or tag.tag != CBOR_TAG_COSE_SIGN1:
        raise ValueError("manifest must be a COSE_Sign1 tag-18 envelope")
    array = tag.value
    if not isinstance(array, (list, tuple)) or len(array) != 4:
        raise ValueError("COSE_Sign1 must be a 4-element array")
    protected_bstr = array[0]
    payload = array[2]
    if not isinstance(protected_bstr, bytes) or not isinstance(payload, bytes):
        raise ValueError("unexpected COSE_Sign1 protected/payload types")
    protected_map = cbor2.loads(protected_bstr)
    if not isinstance(protected_map, Mapping):
        raise ValueError("protected header must decode to a CBOR map")
    protected_map = dict(protected_map)

    if new_kid is not None:
        if not isinstance(new_kid, bytes) or len(new_kid) != 16:
            raise ValueError("kid must be 16 bytes per Phase 1")
        protected_map[COSE_LABEL_KID] = new_kid
    if new_suite_id is not None:
        protected_map[COSE_LABEL_SUITE_ID] = int(new_suite_id)
    # Keep alg pinned to EdDSA so the only failure surface is suite-id (or kid).
    protected_map[COSE_LABEL_ALG] = ALG_EDDSA

    protected_new = dcbor(protected_map)
    return cose_sign1(load_seed(), protected=protected_new, payload=payload)


def write_zip(out_dir: Path, *, root_dir: str, members: list[str], overrides: dict[str, bytes]):
    import zipfile

    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / "input-export.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for member in sorted(members):
            if member in overrides:
                payload = overrides[member]
            else:
                payload = (SOURCE_EXPORT_DIR / member).read_bytes()
            arcname = f"{root_dir}/{member}"
            # §18.1: ASCII arcnames only (keeps general-purpose bit 11 cleared).
            assert arcname.isascii(), arcname
            zf.writestr(deterministic_zipinfo(arcname), payload)
        # §18.1: external file attributes MUST be zero. See gen_export_001.py
        # for the CPython workaround rationale.
        for info in zf.filelist:
            info.external_attr = 0


def main() -> None:
    ledger_state = cbor2.loads(LEDGER_STATE_FILE.read_bytes())
    root_dir = ledger_state["root_dir"]
    members = list(ledger_state["members"])

    # verify/002: flip one bit in the manifest signature (COSE_Sign1 last byte).
    manifest_bytes = (SOURCE_EXPORT_DIR / "000-manifest.cbor").read_bytes()
    tampered_manifest = flip_last_byte(manifest_bytes)
    write_zip(
        OUT_SIGFLIP,
        root_dir=root_dir,
        members=members,
        overrides={"000-manifest.cbor": tampered_manifest},
    )

    # verify/003: omit the required registry snapshot file referenced by the manifest.
    registry_members = [m for m in members if m.startswith("050-registries/")]
    if len(registry_members) != 1:
        raise ValueError(f"expected exactly 1 registry member, found {registry_members}")
    missing_members = [m for m in members if m not in set(registry_members)]
    write_zip(
        OUT_MISSING_REGISTRY,
        root_dir=root_dir,
        members=missing_members,
        overrides={},
    )

    # verify/004: unsupported suite_id in the manifest protected header (§19 step 2.b).
    manifest_unsupported_suite = mutate_manifest(manifest_bytes, new_suite_id=SUITE_UNSUPPORTED)
    write_zip(
        OUT_UNSUPPORTED_SUITE,
        root_dir=root_dir,
        members=members,
        overrides={"000-manifest.cbor": manifest_unsupported_suite},
    )

    # verify/005: unresolvable manifest kid (§19 step 2.a).
    manifest_unresolvable_kid = mutate_manifest(
        manifest_bytes, new_kid=(b"\x00" * 16)
    )
    write_zip(
        OUT_UNRESOLVABLE_KID,
        root_dir=root_dir,
        members=members,
        overrides={"000-manifest.cbor": manifest_unresolvable_kid},
    )

    # verify/006: checkpoint root mismatch (step 5.c localizable failure).
    checkpoints_bytes = (SOURCE_EXPORT_DIR / "040-checkpoints.cbor").read_bytes()
    checkpoints = cbor2.loads(checkpoints_bytes)
    if not isinstance(checkpoints, (list, tuple)) or len(checkpoints) != 2:
        raise ValueError("export/001 expected 2 checkpoints")
    head_checkpoint = checkpoints[1]
    if not isinstance(head_checkpoint, cbor2.CBORTag) or head_checkpoint.tag != CBOR_TAG_COSE_SIGN1:
        raise ValueError("checkpoint must be COSE_Sign1 tag-18")
    head_array = head_checkpoint.value
    head_payload_bstr = head_array[2]
    head_payload = dict(cbor2.loads(head_payload_bstr))
    # Flip one bit of tree_head_hash while preserving digest length.
    thh = head_payload["tree_head_hash"]
    if not isinstance(thh, bytes) or len(thh) != 32:
        raise ValueError("expected 32-byte tree_head_hash")
    head_payload["tree_head_hash"] = thh[:-1] + bytes([thh[-1] ^ 0x01])
    head_payload_new = dcbor(head_payload)
    head_checkpoint_bytes = dcbor(head_checkpoint)
    head_checkpoint_resigned = resign_with_same_protected(
        head_checkpoint_bytes, new_payload=head_payload_new
    )
    # Rebuild the checkpoints array by byte-concatenating an untouched
    # checkpoint[0] and the resigned head checkpoint under the 2-element
    # CBOR array header 0x82. Mirrors gen_export_001.py's events_cbor
    # construction and avoids an unnecessary cbor2.loads/dumps round-trip
    # over checkpoint[0]'s already-canonical bytes.
    checkpoint_0_bytes = dcbor(checkpoints[0])
    checkpoints_new = b"\x82" + checkpoint_0_bytes + head_checkpoint_resigned

    manifest_bytes = (SOURCE_EXPORT_DIR / "000-manifest.cbor").read_bytes()
    manifest_tag = cbor2.loads(manifest_bytes)
    manifest_payload_bstr = manifest_tag.value[2]
    manifest_payload = dict(cbor2.loads(manifest_payload_bstr))
    manifest_payload["checkpoints_digest"] = sha256(checkpoints_new)
    manifest_payload["head_checkpoint_digest"] = checkpoint_digest(
        manifest_payload["scope"], head_payload
    )
    manifest_payload_new = dcbor(manifest_payload)
    manifest_resigned = resign_with_same_protected(
        manifest_bytes, new_payload=manifest_payload_new
    )
    write_zip(
        OUT_CHECKPOINT_ROOT_MISMATCH,
        root_dir=root_dir,
        members=members,
        overrides={
            "000-manifest.cbor": manifest_resigned,
            "040-checkpoints.cbor": checkpoints_new,
        },
    )

    # verify/007: inclusion proof mismatch (step 7.b localizable failure).
    inclusion_bytes = (SOURCE_EXPORT_DIR / "020-inclusion-proofs.cbor").read_bytes()
    inclusion = cbor2.loads(inclusion_bytes)
    if not isinstance(inclusion, Mapping) or 0 not in inclusion:
        raise ValueError("export/001 expected inclusion proof map with key 0")
    inclusion = dict(inclusion)
    ip0 = dict(inclusion[0])
    # Flip one bit in leaf_hash.
    leaf_hash = ip0["leaf_hash"]
    if not isinstance(leaf_hash, bytes) or len(leaf_hash) != 32:
        raise ValueError("expected 32-byte InclusionProof.leaf_hash")
    ip0["leaf_hash"] = leaf_hash[:-1] + bytes([leaf_hash[-1] ^ 0x01])
    inclusion[0] = ip0
    inclusion_new = dcbor(inclusion)

    manifest_tag = cbor2.loads(manifest_bytes)
    manifest_payload = dict(cbor2.loads(manifest_tag.value[2]))
    manifest_payload["inclusion_proofs_digest"] = sha256(inclusion_new)
    manifest_payload_new = dcbor(manifest_payload)
    manifest_resigned = resign_with_same_protected(
        manifest_bytes, new_payload=manifest_payload_new
    )
    write_zip(
        OUT_INCLUSION_PROOF_MISMATCH,
        root_dir=root_dir,
        members=members,
        overrides={
            "000-manifest.cbor": manifest_resigned,
            "020-inclusion-proofs.cbor": inclusion_new,
        },
    )

    # verify/008: prev_checkpoint_hash mismatch (step 5.d localizable failure).
    checkpoints_bytes = (SOURCE_EXPORT_DIR / "040-checkpoints.cbor").read_bytes()
    checkpoints = cbor2.loads(checkpoints_bytes)
    if not isinstance(checkpoints, (list, tuple)) or len(checkpoints) != 2:
        raise ValueError("export/001 expected 2 checkpoints")
    head_checkpoint = checkpoints[1]
    if not isinstance(head_checkpoint, cbor2.CBORTag) or head_checkpoint.tag != CBOR_TAG_COSE_SIGN1:
        raise ValueError("checkpoint must be COSE_Sign1 tag-18")
    head_array = head_checkpoint.value
    head_payload_bstr = head_array[2]
    head_payload = dict(cbor2.loads(head_payload_bstr))
    prev_checkpoint_hash = head_payload["prev_checkpoint_hash"]
    if not isinstance(prev_checkpoint_hash, bytes) or len(prev_checkpoint_hash) != 32:
        raise ValueError("expected 32-byte prev_checkpoint_hash")
    head_payload["prev_checkpoint_hash"] = prev_checkpoint_hash[:-1] + bytes(
        [prev_checkpoint_hash[-1] ^ 0x01]
    )
    head_payload_new = dcbor(head_payload)
    head_checkpoint_bytes = dcbor(head_checkpoint)
    head_checkpoint_resigned = resign_with_same_protected(
        head_checkpoint_bytes, new_payload=head_payload_new
    )
    checkpoint_0_bytes = dcbor(checkpoints[0])
    checkpoints_new = b"\x82" + checkpoint_0_bytes + head_checkpoint_resigned

    manifest_tag = cbor2.loads(manifest_bytes)
    manifest_payload = dict(cbor2.loads(manifest_tag.value[2]))
    manifest_payload["checkpoints_digest"] = sha256(checkpoints_new)
    manifest_payload["head_checkpoint_digest"] = checkpoint_digest(
        manifest_payload["scope"], head_payload
    )
    manifest_payload_new = dcbor(manifest_payload)
    manifest_resigned = resign_with_same_protected(
        manifest_bytes, new_payload=manifest_payload_new
    )
    write_zip(
        OUT_PREV_CHECKPOINT_HASH_MISMATCH,
        root_dir=root_dir,
        members=members,
        overrides={
            "000-manifest.cbor": manifest_resigned,
            "040-checkpoints.cbor": checkpoints_new,
        },
    )

    # verify/009: consistency proof mismatch (step 5.e localizable failure).
    consistency_bytes = (SOURCE_EXPORT_DIR / "025-consistency-proofs.cbor").read_bytes()
    consistency = cbor2.loads(consistency_bytes)
    if not isinstance(consistency, (list, tuple)) or len(consistency) != 1:
        raise ValueError("export/001 expected 1 consistency proof record")
    consistency = list(consistency)
    proof_record = consistency[0]
    if not isinstance(proof_record, Mapping):
        raise ValueError("consistency proof record must be a map")
    proof_record = dict(proof_record)
    proof_path = proof_record["proof_path"]
    if not isinstance(proof_path, (list, tuple)) or len(proof_path) != 1:
        raise ValueError("export/001 expected 1 proof_path node")
    proof_path = list(proof_path)
    sibling = proof_path[0]
    if not isinstance(sibling, bytes) or len(sibling) != 32:
        raise ValueError("expected 32-byte consistency proof node")
    proof_path[0] = sibling[:-1] + bytes([sibling[-1] ^ 0x01])
    proof_record["proof_path"] = proof_path
    consistency[0] = proof_record
    consistency_new = dcbor(consistency)

    manifest_tag = cbor2.loads(manifest_bytes)
    manifest_payload = dict(cbor2.loads(manifest_tag.value[2]))
    manifest_payload["consistency_proofs_digest"] = sha256(consistency_new)
    manifest_payload_new = dcbor(manifest_payload)
    manifest_resigned = resign_with_same_protected(
        manifest_bytes, new_payload=manifest_payload_new
    )
    write_zip(
        OUT_CONSISTENCY_PROOF_MISMATCH,
        root_dir=root_dir,
        members=members,
        overrides={
            "000-manifest.cbor": manifest_resigned,
            "025-consistency-proofs.cbor": consistency_new,
        },
    )


if __name__ == "__main__":
    main()
