"""Generate supersession-graph export vectors for ADR 0066 / TR-CORE-170.

Outputs:
- verify/017-export-015-supersession-graph
- tamper/046-supersession-graph-linkage-mismatch
- tamper/047-supersession-graph-cycle
- tamper/048-supersession-predecessor-checkpoint-mismatch
- tamper/049-supersession-graph-nested-cycle

The positive export is a one-event export built from `append/015-supersession`.
The tamper vector keeps the graph manifest-bound and well-formed but changes
the predecessor checkpoint hash so Core §19 step 6e must raise
`supersession_graph_linkage_mismatch`.
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
    trellis_cli_verify_script,
    ts,
)


ROOT = Path(__file__).resolve().parent.parent
SOURCE_EVENT_DIR = ROOT / "append" / "015-supersession"
KEY_FILE = ROOT / "_keys" / "issuer-001.cose_key"

OUT_VERIFY = ROOT / "verify" / "017-export-015-supersession-graph"
OUT_TAMPER = ROOT / "tamper" / "046-supersession-graph-linkage-mismatch"
OUT_CYCLE = ROOT / "tamper" / "047-supersession-graph-cycle"
OUT_PREDECESSOR_MISSING = (
    ROOT / "tamper" / "048-supersession-predecessor-checkpoint-mismatch"
)
OUT_NESTED_CYCLE = ROOT / "tamper" / "049-supersession-graph-nested-cycle"

TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"
TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_CHECKPOINT_V1 = "trellis-checkpoint-v1"
TAG_TRELLIS_MERKLE_LEAF_V1 = "trellis-merkle-leaf-v1"
TAG_TRELLIS_EXPORT_MANIFEST_V1 = "trellis-export-manifest-v1"

SUPERSEDES_CHAIN_ID_EVENT_EXTENSION = "trellis.supersedes-chain-id.v1"
SUPERSESSION_GRAPH_EXPORT_EXTENSION = "trellis.export.supersession-graph.v1"

GENERATED_AT = ts(1777000090)
CHECKPOINT_TIMESTAMP = ts(1777000020)


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
    return hashlib.sha256(dcbor(SUITE_ID_PHASE_1) + pubkey_raw).digest()[:16]


def cose_sign1(seed: bytes, kid: bytes, payload_bytes: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> bytes:
    protected = dcbor({
        COSE_LABEL_ALG: ALG_EDDSA,
        COSE_LABEL_KID: kid,
        COSE_LABEL_SUITE_ID: SUITE_ID_PHASE_1, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
    })
    sig_structure = dcbor(["Signature1", protected, b"", payload_bytes])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    return dcbor(cbor2.CBORTag(CBOR_TAG_COSE_SIGN1, [protected, {}, payload_bytes, signature]))


def canonical_event_hash(ledger_scope: bytes, event_payload: dict) -> bytes:
    preimage = {"version": 1, "ledger_scope": ledger_scope, "event_payload": event_payload}
    return domain_separated_sha256(TAG_TRELLIS_EVENT_V1, dcbor(preimage))


def merkle_leaf_hash(canonical_hash: bytes) -> bytes:
    return domain_separated_sha256(TAG_TRELLIS_MERKLE_LEAF_V1, canonical_hash)


def checkpoint_digest(ledger_scope: bytes, checkpoint_payload: dict) -> bytes:
    preimage = {"version": 1, "scope": ledger_scope, "checkpoint_payload": checkpoint_payload}
    return domain_separated_sha256(TAG_TRELLIS_CHECKPOINT_V1, dcbor(preimage))


def export_manifest_digest(ledger_scope: bytes, manifest_payload: dict) -> bytes:
    preimage = {"version": 1, "scope": ledger_scope, "manifest_payload": manifest_payload}
    return domain_separated_sha256(TAG_TRELLIS_EXPORT_MANIFEST_V1, dcbor(preimage))


def build_event_payload(
    *,
    ledger_scope: bytes,
    authored_at: list,
    supersedes_chain_id: bytes,
    supersedes_checkpoint_hash: bytes,
    idempotency_key: bytes,
    payload_marker: bytes,
) -> tuple[dict, bytes, bytes]:
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_marker)
    header = {
        "event_type": b"wos.kernel.supersession_started",
        "extensions": None,
        "authored_at": authored_at,
        "witness_ref": None,
        "classification": b"x-trellis-test/unclassified",
        "retention_tier": 0,
        "tag_commitment": None,
        "outcome_commitment": None,
        "subject_ref_commitment": None,
    }
    payload_ref = {
        "ref_type": "inline",
        "ciphertext": payload_marker,
        "nonce": b"adr0066-nested-cycle-nonce-0001",
    }
    extensions = {
        SUPERSEDES_CHAIN_ID_EVENT_EXTENSION: {
            "chain_id": supersedes_chain_id,
            "checkpoint_hash": supersedes_checkpoint_hash,
        }
    }
    authored_map = {
        "version": 1,
        "ledger_scope": ledger_scope,
        "sequence": 0,
        "prev_hash": None,
        "causal_deps": None,
        "content_hash": content_hash,
        "header": header,
        "commitments": None,
        "payload_ref": payload_ref,
        "key_bag": {"entries": []},
        "idempotency_key": idempotency_key,
        "extensions": extensions,
    }
    author_event_hash = domain_separated_sha256(TAG_TRELLIS_AUTHOR_EVENT_V1, dcbor(authored_map))
    event_payload = {
        "version": 1,
        "ledger_scope": ledger_scope,
        "sequence": 0,
        "prev_hash": None,
        "causal_deps": None,
        "author_event_hash": author_event_hash,
        "content_hash": content_hash,
        "header": header,
        "commitments": None,
        "payload_ref": payload_ref,
        "key_bag": {"entries": []},
        "idempotency_key": idempotency_key,
        "extensions": extensions,
    }
    event_payload_bytes = dcbor(event_payload)
    return event_payload, event_payload_bytes, canonical_event_hash(ledger_scope, event_payload)


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def canonical_graph_json(
    *,
    head_chain_id: bytes,
    rows: list[dict],
) -> bytes:
    # Trellis canonical JSON for this member sorts row keys as
    # bundle_path, chain_id, checkpoint_hash and carries one trailing LF.
    rendered_rows: list[str] = []
    for row in rows:
        bundle_path = row["bundle_path"]
        if bundle_path is None:
            bundle_text = "null"
        else:
            bundle_text = '"' + bundle_path + '"'
        rendered_rows.append(
            '{"bundle_path":'
            + bundle_text
            + ',"chain_id":"'
            + row["chain_id"].hex()
            + '","checkpoint_hash":"'
            + row["checkpoint_hash"].hex()
            + '"}'
        )
    return (
        '{"head_chain_id":"'
        + head_chain_id.hex()
        + '","predecessors":['
        + ",".join(rendered_rows)
        + "]}\n"
    ).encode("utf-8")


def write_zip(out_dir: Path, *, root_dir: str, members: list[str]) -> None:
    with zipfile.ZipFile(out_dir / "input-export.zip", "w") as zf:
        for member in sorted(members):
            arcname = f"{root_dir}/{member}"
            assert arcname.isascii(), arcname
            zf.writestr(deterministic_zipinfo(arcname), (out_dir / member).read_bytes())
        for info in zf.filelist:
            info.external_attr = 0


def build_custom_export(
    out_dir: Path,
    *,
    event_payload: dict,
    event_payload_bytes: bytes,
    canonical_hash: bytes,
    graph_rows: list[dict],
) -> tuple[bytes, bytes]:
    out_dir.mkdir(parents=True, exist_ok=True)
    ledger_scope = event_payload["ledger_scope"]
    leaf_hash = merkle_leaf_hash(canonical_hash)
    seed, pubkey_raw = load_issuer_key()
    kid = derive_kid(pubkey_raw)
    event_bytes = cose_sign1(seed, kid, event_payload_bytes)
    events_cbor = dcbor([cbor2.loads(event_bytes)])
    signing_key_registry_cbor = dcbor([{
        "kid": kid,
        "pubkey": pubkey_raw,
        "suite_id": SUITE_ID_PHASE_1,
        "status": 0,
        "valid_from": event_payload["header"]["authored_at"],
        "valid_to": None,
        "supersedes": None,
        "attestation": None,
    }])
    domain_registry = {
        "governance": {
            "ruleset_id": "x-trellis-test/governance-ruleset-v1",
            "ruleset_digest": sha256(b"adr0066-supersession-graph-ruleset"),
        },
        "event_types": {
            "wos.kernel.supersession_started": {
                "privacy_class": "public",
                "commitment_schema": "x-trellis-test/adr0066-supersession-started-v1",
            }
        },
        "classifications": ["x-trellis-test/unclassified"],
        "role_vocabulary": ["x-trellis-test/role-author"],
    }
    domain_registry_cbor = dcbor(domain_registry)
    registry_digest = sha256(domain_registry_cbor)
    registry_binding = {
        "registry_digest": registry_digest,
        "registry_format": 1,
        "registry_version": "x-trellis-test/adr0066-registry-v1",
        "bound_at_sequence": 0,
    }
    checkpoint_payload = {
        "version": 1,
        "scope": ledger_scope,
        "tree_size": 1,
        "tree_head_hash": leaf_hash,
        "timestamp": CHECKPOINT_TIMESTAMP,
        "anchor_ref": None,
        "prev_checkpoint_hash": None,
        "extensions": None,
    }
    head_checkpoint_digest = checkpoint_digest(ledger_scope, checkpoint_payload)
    checkpoints_cbor = dcbor([cbor2.loads(cose_sign1(seed, kid, dcbor(checkpoint_payload), ARTIFACT_TYPE_CHECKPOINT))])
    inclusion_proofs_cbor = dcbor({0: {
        "leaf_index": 0,
        "tree_size": 1,
        "leaf_hash": leaf_hash,
        "audit_path": [],
    }})
    consistency_proofs_cbor = dcbor([])
    graph_json = canonical_graph_json(head_chain_id=ledger_scope, rows=graph_rows)
    graph_digest = sha256(graph_json)

    write_bytes(out_dir / "010-events.cbor", events_cbor)
    write_bytes(out_dir / "020-inclusion-proofs.cbor", inclusion_proofs_cbor)
    write_bytes(out_dir / "025-consistency-proofs.cbor", consistency_proofs_cbor)
    write_bytes(out_dir / "030-signing-key-registry.cbor", signing_key_registry_cbor)
    write_bytes(out_dir / "040-checkpoints.cbor", checkpoints_cbor)
    write_bytes(out_dir / "050-registries" / f"{registry_digest.hex()}.cbor", domain_registry_cbor)
    write_bytes(out_dir / "064-supersession-graph.json", graph_json)
    write_bytes(out_dir / "090-verify.sh", b"#!/bin/sh\nset -eu\n")
    write_bytes(out_dir / "098-README.md", b"# Nested supersession export fixture\n")

    manifest_payload = {
        "format": "trellis-export/1",
        "version": 1,
        "generator": "x-trellis-test/supersession-graph-nested-generator",
        "generated_at": GENERATED_AT,
        "scope": ledger_scope,
        "tree_size": 1,
        "head_checkpoint_digest": head_checkpoint_digest,
        "registry_bindings": [registry_binding],
        "signing_key_registry_digest": sha256(signing_key_registry_cbor),
        "events_digest": sha256(events_cbor),
        "checkpoints_digest": sha256(checkpoints_cbor),
        "inclusion_proofs_digest": sha256(inclusion_proofs_cbor),
        "consistency_proofs_digest": sha256(consistency_proofs_cbor),
        "payloads_inlined": False,
        "external_anchors": [],
        "posture_declaration": {
            "provider_readable": True,
            "reader_held": False,
            "delegated_compute": False,
            "external_anchor_required": False,
            "external_anchor_name": None,
            "recovery_without_user": True,
            "metadata_leakage_summary": "ADR 0066 nested supersession graph fixture.",
        },
        "head_format_version": 1,
        "omitted_payload_checks": [],
        "extensions": {
            SUPERSESSION_GRAPH_EXPORT_EXTENSION: {
                "graph_digest": graph_digest,
                "predecessor_count": len(graph_rows),
            }
        },
    }
    write_bytes(out_dir / "000-manifest.cbor", cose_sign1(seed, kid, dcbor(manifest_payload), ARTIFACT_TYPE_MANIFEST))
    root_dir = f"trellis-export-{ledger_scope.decode('utf-8')}-1-{leaf_hash.hex()[:8]}"
    members = [
        "000-manifest.cbor",
        "010-events.cbor",
        "020-inclusion-proofs.cbor",
        "025-consistency-proofs.cbor",
        "030-signing-key-registry.cbor",
        "040-checkpoints.cbor",
        f"050-registries/{registry_digest.hex()}.cbor",
        "064-supersession-graph.json",
        "090-verify.sh",
        "098-README.md",
    ]
    write_zip(out_dir, root_dir=root_dir, members=members)
    return head_checkpoint_digest, (out_dir / "input-export.zip").read_bytes()


def build_export(out_dir: Path, *, graph_variant: str) -> tuple[str, bytes, bytes]:
    out_dir.mkdir(parents=True, exist_ok=True)

    event_bytes = (SOURCE_EVENT_DIR / "expected-event.cbor").read_bytes()
    event_payload = cbor2.loads((SOURCE_EVENT_DIR / "expected-event-payload.cbor").read_bytes())
    ledger_scope = event_payload["ledger_scope"]
    extension = event_payload["extensions"][SUPERSEDES_CHAIN_ID_EVENT_EXTENSION]
    predecessor_chain_id = extension["chain_id"]
    predecessor_checkpoint_hash = extension["checkpoint_hash"]
    assert isinstance(predecessor_chain_id, bytes)
    assert isinstance(predecessor_checkpoint_hash, bytes) and len(predecessor_checkpoint_hash) == 32

    events_cbor = dcbor([cbor2.loads(event_bytes)])
    canon_hash = canonical_event_hash(ledger_scope, event_payload)
    leaf_hash = merkle_leaf_hash(canon_hash)

    seed, pubkey_raw = load_issuer_key()
    kid = derive_kid(pubkey_raw)
    signing_key_registry_cbor = dcbor([{
        "kid": kid,
        "pubkey": pubkey_raw,
        "suite_id": SUITE_ID_PHASE_1,
        "status": 0,
        "valid_from": event_payload["header"]["authored_at"],
        "valid_to": None,
        "supersedes": None,
        "attestation": None,
    }])

    domain_registry = {
        "governance": {
            "ruleset_id": "x-trellis-test/governance-ruleset-v1",
            "ruleset_digest": sha256(b"adr0066-supersession-graph-ruleset"),
        },
        "event_types": {
            "wos.kernel.supersession_started": {
                "privacy_class": "public",
                "commitment_schema": "x-trellis-test/adr0066-supersession-started-v1",
            }
        },
        "classifications": ["x-trellis-test/unclassified"],
        "role_vocabulary": ["x-trellis-test/role-author"],
    }
    domain_registry_cbor = dcbor(domain_registry)
    registry_digest = sha256(domain_registry_cbor)
    registry_binding = {
        "registry_digest": registry_digest,
        "registry_format": 1,
        "registry_version": "x-trellis-test/adr0066-registry-v1",
        "bound_at_sequence": 0,
    }

    checkpoint_payload = {
        "version": 1,
        "scope": ledger_scope,
        "tree_size": 1,
        "tree_head_hash": leaf_hash,
        "timestamp": CHECKPOINT_TIMESTAMP,
        "anchor_ref": None,
        "prev_checkpoint_hash": None,
        "extensions": None,
    }
    head_checkpoint_digest = checkpoint_digest(ledger_scope, checkpoint_payload)
    checkpoint_bytes = cose_sign1(seed, kid, dcbor(checkpoint_payload), ARTIFACT_TYPE_CHECKPOINT)
    checkpoints_cbor = dcbor([cbor2.loads(checkpoint_bytes)])

    inclusion_proofs_cbor = dcbor({0: {
        "leaf_index": 0,
        "tree_size": 1,
        "leaf_hash": leaf_hash,
        "audit_path": [],
    }})
    consistency_proofs_cbor = dcbor([])
    extra_members: list[str] = []
    graph_rows = [{
        "bundle_path": None,
        "chain_id": predecessor_chain_id,
        "checkpoint_hash": predecessor_checkpoint_hash,
    }]
    if graph_variant == "linkage-mismatch":
        graph_rows = [{
            "bundle_path": None,
            "chain_id": predecessor_chain_id,
            "checkpoint_hash": b"\x00" * 32,
        }]
    elif graph_variant == "cycle":
        graph_rows.append({
            "bundle_path": None,
            "chain_id": ledger_scope,
            "checkpoint_hash": predecessor_checkpoint_hash,
        })
    elif graph_variant == "predecessor-missing":
        graph_rows = [{
            "bundle_path": "070-predecessors/missing.zip",
            "chain_id": predecessor_chain_id,
            "checkpoint_hash": predecessor_checkpoint_hash,
        }]
    elif graph_variant == "nested-cycle":
        nested_scope = b"wos-case:adr0066-fixture-nested-predecessor"
        nested_event, nested_event_bytes, nested_canonical_hash = build_event_payload(
            ledger_scope=nested_scope,
            authored_at=ts(1777000030),
            supersedes_chain_id=ledger_scope,
            supersedes_checkpoint_hash=head_checkpoint_digest,
            idempotency_key=b"adr0066-nested-cycle-event",
            payload_marker=b"adr0066 nested cycle predecessor payload",
        )
        nested_build_dir = out_dir / "_nested-predecessor-build"
        if nested_build_dir.exists():
            shutil.rmtree(nested_build_dir)
        nested_head_digest, nested_zip = build_custom_export(
            nested_build_dir,
            event_payload=nested_event,
            event_payload_bytes=nested_event_bytes,
            canonical_hash=nested_canonical_hash,
            graph_rows=[{
                "bundle_path": None,
                "chain_id": ledger_scope,
                "checkpoint_hash": head_checkpoint_digest,
            }],
        )
        write_bytes(out_dir / "070-predecessors" / "nested-cycle.zip", nested_zip)
        shutil.rmtree(nested_build_dir)
        graph_rows.append({
            "bundle_path": "070-predecessors/nested-cycle.zip",
            "chain_id": nested_scope,
            "checkpoint_hash": nested_head_digest,
        })
        extra_members.append("070-predecessors/nested-cycle.zip")
    elif graph_variant != "valid":
        raise ValueError(f"unknown graph variant {graph_variant!r}")
    graph_json = canonical_graph_json(
        head_chain_id=ledger_scope,
        rows=graph_rows,
    )
    graph_digest = sha256(graph_json)

    write_bytes(out_dir / "010-events.cbor", events_cbor)
    write_bytes(out_dir / "020-inclusion-proofs.cbor", inclusion_proofs_cbor)
    write_bytes(out_dir / "025-consistency-proofs.cbor", consistency_proofs_cbor)
    write_bytes(out_dir / "030-signing-key-registry.cbor", signing_key_registry_cbor)
    write_bytes(out_dir / "040-checkpoints.cbor", checkpoints_cbor)
    write_bytes(out_dir / "050-registries" / f"{registry_digest.hex()}.cbor", domain_registry_cbor)
    write_bytes(out_dir / "064-supersession-graph.json", graph_json)

    readme = (
        "# Trellis Export (Fixture) - verify/017 supersession graph\n"
        "\n"
        f"- scope: `{ledger_scope.decode('utf-8')}`\n"
        f"- head_checkpoint_digest: `{head_checkpoint_digest.hex()}`\n"
        f"- superseded_chain_id: `{predecessor_chain_id.hex()}`\n"
        f"- graph_digest: `{graph_digest.hex()}`\n"
    ).encode("utf-8")
    write_bytes(out_dir / "090-verify.sh", trellis_cli_verify_script())
    write_bytes(out_dir / "098-README.md", readme)

    manifest_payload = {
        "format": "trellis-export/1",
        "version": 1,
        "generator": "x-trellis-test/supersession-graph-generator-015",
        "generated_at": GENERATED_AT,
        "scope": ledger_scope,
        "tree_size": 1,
        "head_checkpoint_digest": head_checkpoint_digest,
        "registry_bindings": [registry_binding],
        "signing_key_registry_digest": sha256(signing_key_registry_cbor),
        "events_digest": sha256(events_cbor),
        "checkpoints_digest": sha256(checkpoints_cbor),
        "inclusion_proofs_digest": sha256(inclusion_proofs_cbor),
        "consistency_proofs_digest": sha256(consistency_proofs_cbor),
        "payloads_inlined": False,
        "external_anchors": [],
        "posture_declaration": {
            "provider_readable": True,
            "reader_held": False,
            "delegated_compute": False,
            "external_anchor_required": False,
            "external_anchor_name": None,
            "recovery_without_user": True,
            "metadata_leakage_summary": "ADR 0066 supersession graph fixture.",
        },
        "head_format_version": 1,
        "omitted_payload_checks": [],
        "extensions": {
            SUPERSESSION_GRAPH_EXPORT_EXTENSION: {
                "graph_digest": graph_digest,
                "predecessor_count": len(graph_rows),
            }
        },
    }
    manifest_bytes = cose_sign1(seed, kid, dcbor(manifest_payload), ARTIFACT_TYPE_MANIFEST)
    write_bytes(out_dir / "000-manifest.cbor", manifest_bytes)

    root_dir = f"trellis-export-{ledger_scope.decode('utf-8')}-1-{leaf_hash.hex()[:8]}"
    members = [
        "000-manifest.cbor",
        "010-events.cbor",
        "020-inclusion-proofs.cbor",
        "025-consistency-proofs.cbor",
        "030-signing-key-registry.cbor",
        "040-checkpoints.cbor",
        f"050-registries/{registry_digest.hex()}.cbor",
        "064-supersession-graph.json",
        *extra_members,
        "090-verify.sh",
        "098-README.md",
    ]
    write_zip(out_dir, root_dir=root_dir, members=members)
    write_bytes(out_dir / "input-ledger-state.cbor", dcbor({
        "version": 1,
        "scope": ledger_scope,
        "tree_size": 1,
        "root_dir": root_dir,
        "members": members,
    }))
    return root_dir, predecessor_checkpoint_hash, canon_hash


def write_manifest(
    out_dir: Path,
    *,
    op: str,
    title: str,
    tamper_kind: str | None,
    failure_location: str | None,
) -> None:
    coverage = """[coverage]
tr_core = [
    "TR-CORE-001",
    "TR-CORE-018",
    "TR-CORE-030",
    "TR-CORE-050",
    "TR-CORE-068",
    "TR-CORE-169",
    "TR-CORE-170",
]
"""
    report_lines = [
        "[expected.report]",
        "structure_verified  = true",
        f"integrity_verified  = {'false' if tamper_kind else 'true'}",
        "readability_verified = true",
    ]
    if tamper_kind is not None:
        report_lines.append(f'tamper_kind = "{tamper_kind}"')
    if failure_location is not None:
        report_lines.append(f'failing_event_id = "{failure_location}"')
    manifest = (
        f'id          = "{out_dir.parent.name}/{out_dir.name}"\n'
        f'op          = "{op}"\n'
        'status      = "active"\n'
        f'description = """{title}"""\n'
        "\n"
        + coverage
        + "\n[inputs]\n"
        + 'export_zip = "input-export.zip"\n'
        + "\n"
        + "\n".join(report_lines)
        + "\n\n[derivation]\n"
        + 'document = "derivation.md"\n'
    )
    write_bytes(out_dir / "manifest.toml", manifest.encode("utf-8"))


def write_derivation(out_dir: Path, *, tampered: bool) -> None:
    body = (
        f"# Derivation - `{out_dir.parent.name}/{out_dir.name}`\n\n"
        "This vector is generated by `fixtures/vectors/_generator/"
        "gen_supersession_graph_export_015.py` from `append/015-supersession`.\n\n"
        "It packages the supersession-start event into a deterministic Trellis "
        "export ZIP with `064-supersession-graph.json` bound by "
        "`ExportManifestPayload.extensions[\"trellis.export.supersession-graph.v1\"].graph_digest`.\n\n"
    )
    if tampered:
        if out_dir == OUT_TAMPER:
            body += (
                "The graph remains canonical JSON and the manifest digest is recomputed, "
                "but the predecessor `checkpoint_hash` is replaced with 32 zero bytes. "
                "The verifier must therefore reject the export with "
                "`supersession_graph_linkage_mismatch` because the graph row no longer "
                "byte-matches the event's `trellis.supersedes-chain-id.v1` extension.\n"
            )
        elif out_dir == OUT_CYCLE:
            body += (
                "The graph remains canonical JSON and carries the correct predecessor "
                "row, then adds a second predecessor row whose `chain_id` equals the "
                "exported head chain. The verifier must reject this direct traversal "
                "cycle with `supersession_graph_cycle`.\n"
            )
        elif out_dir == OUT_PREDECESSOR_MISSING:
            body += (
                "The graph row byte-matches the event extension and names a non-null "
                "`bundle_path`, but the referenced predecessor ZIP is absent from the "
                "archive. The verifier must reject this packaging omission with "
                "`supersession_predecessor_checkpoint_mismatch`.\n"
            )
        else:
            body += (
                "The exported graph embeds `070-predecessors/nested-cycle.zip`. The "
                "nested predecessor export is valid by itself, but its own "
                "`064-supersession-graph.json` points back to the parent chain. The "
                "path-aware verifier must reject the multi-hop traversal with "
                "`supersession_graph_cycle`.\n"
            )
    else:
        body += (
            "The graph `head_chain_id` equals `manifest.scope`, and its only "
            "predecessor row byte-matches the event's "
            "`trellis.supersedes-chain-id.v1` extension.\n"
        )
    write_bytes(out_dir / "derivation.md", body.encode("utf-8"))


def main() -> None:
    _, expected_checkpoint_hash, canon_hash = build_export(
        OUT_VERIFY,
        graph_variant="valid",
    )
    assert expected_checkpoint_hash == cbor2.loads(
        (SOURCE_EVENT_DIR / "input-supersedes-chain-id.cbor").read_bytes()
    )["checkpoint_hash"]
    write_manifest(
        OUT_VERIFY,
        op="verify",
        title="Positive ADR 0066 export with manifest-bound supersession graph.",
        tamper_kind=None,
        failure_location=None,
    )
    write_derivation(OUT_VERIFY, tampered=False)

    build_export(OUT_TAMPER, graph_variant="linkage-mismatch")
    write_manifest(
        OUT_TAMPER,
        op="tamper",
        title="Manifest-bound supersession graph whose predecessor row does not byte-match the event extension.",
        tamper_kind="supersession_graph_linkage_mismatch",
        failure_location=canon_hash.hex(),
    )
    write_derivation(OUT_TAMPER, tampered=True)

    build_export(OUT_CYCLE, graph_variant="cycle")
    write_manifest(
        OUT_CYCLE,
        op="tamper",
        title="Manifest-bound supersession graph with a direct cycle back to the exported head chain.",
        tamper_kind="supersession_graph_cycle",
        failure_location="064-supersession-graph.json",
    )
    write_derivation(OUT_CYCLE, tampered=True)

    build_export(OUT_PREDECESSOR_MISSING, graph_variant="predecessor-missing")
    write_manifest(
        OUT_PREDECESSOR_MISSING,
        op="tamper",
        title="Manifest-bound supersession graph whose predecessor bundle path is absent.",
        tamper_kind="supersession_predecessor_checkpoint_mismatch",
        failure_location="070-predecessors/missing.zip",
    )
    write_derivation(OUT_PREDECESSOR_MISSING, tampered=True)

    build_export(OUT_NESTED_CYCLE, graph_variant="nested-cycle")
    write_manifest(
        OUT_NESTED_CYCLE,
        op="tamper",
        title="Embedded predecessor graph that cycles back to the parent chain.",
        tamper_kind="supersession_graph_cycle",
        failure_location="064-supersession-graph.json",
    )
    write_derivation(OUT_NESTED_CYCLE, tampered=True)

    print(f"verify/017 zip_sha256={sha256((OUT_VERIFY / 'input-export.zip').read_bytes()).hex()}")
    print(f"tamper/046 zip_sha256={sha256((OUT_TAMPER / 'input-export.zip').read_bytes()).hex()}")
    print(f"tamper/047 zip_sha256={sha256((OUT_CYCLE / 'input-export.zip').read_bytes()).hex()}")
    print(f"tamper/048 zip_sha256={sha256((OUT_PREDECESSOR_MISSING / 'input-export.zip').read_bytes()).hex()}")
    print(f"tamper/049 zip_sha256={sha256((OUT_NESTED_CYCLE / 'input-export.zip').read_bytes()).hex()}")
    print(f"export_manifest_digest={export_manifest_digest(cbor2.loads((SOURCE_EVENT_DIR / 'expected-event-payload.cbor').read_bytes())['ledger_scope'], cbor2.loads(cbor2.loads((OUT_VERIFY / '000-manifest.cbor').read_bytes()).value[2])).hex()}")


if __name__ == "__main__":
    main()
