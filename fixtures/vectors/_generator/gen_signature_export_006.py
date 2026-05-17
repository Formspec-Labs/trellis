"""Generate Trellis signature-affirmation export / verify / tamper vectors.

Authoring aid only. The committed fixture bytes and derivation notes are the
evidence surface; this script exists so the CBOR and ZIP bytes are
reproducible.
"""

from __future__ import annotations

import copy
import hashlib
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
APPEND_019 = ROOT / "append" / "019-wos-signature-affirmation"
KEY_ISSUER_001 = ROOT / "_keys" / "issuer-001.cose_key"

OUT_EXPORT_006 = ROOT / "export" / "006-signature-affirmations-inline"
OUT_VERIFY_014 = ROOT / "verify" / "014-export-006-signature-row-mismatch"
OUT_VERIFY_019 = ROOT / "verify" / "019-export-006-signed-acts-projection-mismatch"
OUT_TAMPER_014 = ROOT / "tamper" / "014-signature-catalog-digest-mismatch"
OUT_TAMPER_055 = ROOT / "tamper" / "055-signed-acts-catalog-digest-mismatch"
OUT_TAMPER_056 = ROOT / "tamper" / "056-policy-closure-digest-mismatch"

TAG_TRELLIS_CHECKPOINT_V1 = "trellis-checkpoint-v1"
TAG_TRELLIS_MERKLE_LEAF_V1 = "trellis-merkle-leaf-v1"
EXTENSION_KEY = "trellis.export.signature-affirmations.v1"
SIGNED_ACTS_EXTENSION_KEY = "trellis.export.signed-acts.v1"
SIGNED_ACTS_MEMBER = "066-signed-acts.cbor"
SIGNED_ACTS_DERIVATION_RULE = "signed-act-projection-wos-formspec-v1"
POLICY_CLOSURE_EXTENSION_KEY = "trellis.export.policy-closure.v1"
POLICY_CLOSURE_MEMBER = "067-policy-closure.cbor"
POLICY_CLOSURE_VERSION = "wos-formspec-signature-policy-closure-2026-05-16"
POLICY_CLOSURE_ARTIFACT_KINDS = [
    "formspec.signing-intent-registry.v1",
    "formspec.signature-method-registry.v1",
    "wos.signature-posture-floors.v1",
    "wos.signer-authority-shape.v1",
    "wos.identity-proofing-primitives.v1",
    "wos.signature-defaults.v1",
    "wos.signature-deny-rules.v1",
    "wos.signature-tombstones.v1",
]


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


def build_signing_key_registry(kid: bytes, pubkey: bytes) -> bytes:
    entry = {
        "kid": kid,
        "pubkey": pubkey,
        "suite_id": SUITE_ID_PHASE_1,
        "status": 0,
        "valid_from": ts(1776877800),
        "valid_to": None,
        "supersedes": None,
        "attestation": None,
    }
    return dcbor([entry])


def build_domain_registry() -> bytes:
    return dcbor(
        {
            "governance": {
                "ruleset_id": "x-trellis-test/governance-ruleset-signature-v1",
                "ruleset_digest": sha256(b"x-trellis-test/governance-ruleset-signature-v1"),
            },
            "event_types": {
                "wos.kernel.signature_affirmation": {
                    "privacy_class": "restricted",
                    "binding_family": "wos.signatureProfile",
                }
            },
            "classifications": ["x-trellis-test/unclassified"],
            "role_vocabulary": ["x-trellis-test/role-applicant-signer"],
            "registry_version": "x-trellis-test/registry-signature-v1",
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


def signature_catalog_entry(canonical_event_hash: bytes, wos_record: dict) -> dict:
    data = wos_record["data"]
    signing_act_id = data.get("signingActId") or data.get("sourceSignatureId") or "signing-act-1"
    presentation_hash = data.get("presentationHash") or data["documentHash"]
    signing_act_id = str(signing_act_id)
    presentation_hash = str(presentation_hash)
    entry = {
        "canonical_event_hash": canonical_event_hash,
        "signing_act_id": signing_act_id,
        "presentation_hash": presentation_hash,
        "signer_id": data["signerId"],
        "role_id": data["roleId"],
        "role": data["role"],
        "document_id": data["documentId"],
        "document_hash": data["documentHash"],
        "document_hash_algorithm": data["documentHashAlgorithm"],
        "signed_at": data["signedAt"],
        "identity_binding": data["identityBinding"],
        "consent_reference": data["consentReference"],
        "signature_provider": data["signatureProvider"],
        "ceremony_id": data["ceremonyId"],
        "profile_ref": data["profileRef"],
        "formspec_response_ref": data.get("sourceResponseRef") or data["formspecResponseRef"],
    }
    for source_key, catalog_key in [
        ("sourceSignatureSystem", "source_signature_system"),
        ("sourceSignatureId", "source_signature_id"),
        ("signedPayloadDigest", "signed_payload_digest"),
        ("signedPayloadDigestAlgorithm", "signed_payload_digest_algorithm"),
        ("signingIntent", "signing_intent"),
        ("profileKey", "profile_key"),
        ("witnessedSignatureRef", "witnessed_signature_ref"),
    ]:
        if source_key in data:
            entry[catalog_key] = data[source_key]
    return entry


def source_ref(canonical_event_hash: bytes, kind: str) -> dict:
    return {
        "layer": "wos",
        "kind": kind,
        "ref": canonical_event_hash,
    }


def sorted_source_refs(refs: list[dict]) -> list[dict]:
    return sorted(
        refs,
        key=lambda ref: (
            ref["layer"],
            ref["kind"],
            dcbor(ref["ref"]),
        ),
    )


def signed_act_projection(canonical_event_hash: bytes, wos_record: dict) -> dict:
    data = wos_record["data"]
    source_response_ref = data.get("sourceResponseRef") or data["formspecResponseRef"]
    return {
        "act_id": data["signingActId"],
        "signer": {
            "id": data["signerId"],
            "role": data["role"],
            "role_ref": data["roleId"],
            "identity_evidence_refs": [],
        },
        "bound": {
            "subject_kind": "formspec-response",
            "subject_hash": data.get("signedPayloadDigest"),
            "subject_hash_algorithm": data.get("signedPayloadDigestAlgorithm"),
            "presentation_hash": data["presentationHash"],
            "document_id": data["documentId"],
            "document_ref": data.get("documentRef"),
            "content_hash": data["documentHash"],
            "content_hash_algorithm": data["documentHashAlgorithm"],
        },
        "intent": data["signingIntent"],
        "consent": data["consentReference"],
        "admission": {
            "outcome": "admitted",
            "source_response_ref": source_response_ref,
            "source_signature_system": data.get("sourceSignatureSystem"),
            "source_signature_id": data.get("sourceSignatureId"),
            "signature_provider": data["signatureProvider"],
            "ceremony_id": data["ceremonyId"],
            "profile_ref": data.get("profileRef"),
            "profile_key": data.get("profileKey"),
            "signed_payload_digest": data.get("signedPayloadDigest"),
            "signed_payload_digest_algorithm": data.get("signedPayloadDigestAlgorithm"),
            "primitive_verification": data.get("primitiveVerification"),
            "failure_reason": None,
        },
        "witness_of": data.get("witnessedSignatureRef"),
        "signed_at": data["signedAt"],
        "source_refs": sorted_source_refs(
            [source_ref(canonical_event_hash, "signature-affirmation")]
        ),
    }


def signed_acts_catalog(canonical_event_hash: bytes, wos_record: dict) -> bytes:
    acts = [signed_act_projection(canonical_event_hash, wos_record)]
    acts.sort(
        key=lambda act: (
            act["act_id"],
            act["signed_at"],
            dcbor(act["source_refs"][0]),
        )
    )
    return dcbor(
        {
            "projection_schema_version": 1,
            "derivation_rule_id": SIGNED_ACTS_DERIVATION_RULE,
            "acts": acts,
        }
    )


def owner_for_policy_artifact(kind: str) -> str:
    return "formspec" if kind.startswith("formspec.") else "wos"


def policy_artifact(kind: str, index: int, domain_registry_digest: bytes) -> dict:
    return {
        "owner": owner_for_policy_artifact(kind),
        "kind": kind,
        "version": "2026-05-16",
        "ref": f"urn:formspec-stack:test-policy:{kind}:2026-05-16",
        "digest_algorithm": "sha-256",
        "digest": sha256(kind.encode("utf-8") + domain_registry_digest + bytes([index])),
        "valid_from": "2026-05-16T00:00:00Z",
        "valid_to": None,
    }


def policy_closure(domain_registry_digest: bytes) -> bytes:
    return dcbor(
        {
            "closure_schema_version": 1,
            "closure_version": POLICY_CLOSURE_VERSION,
            "sealed_at": "2026-05-16T18:31:00Z",
            "owner_scope": "wos.case.signature-admission",
            "verifier_boundary": {
                "bundle_admission_policy_evidence": True,
                "bundle_trust_roots_authoritative": False,
                "verifier_supplied_trust_roots_required": True,
                "verifier_supplied_adapter_allowlists_required": True,
                "server_operational_config_included": False,
            },
            "artifacts": [
                policy_artifact(kind, index, domain_registry_digest)
                for index, kind in enumerate(POLICY_CLOSURE_ARTIFACT_KINDS)
            ],
        }
    )


def build_export_006() -> None:
    OUT_EXPORT_006.mkdir(parents=True, exist_ok=True)

    seed, pubkey = load_seed_and_pubkey(KEY_ISSUER_001)
    kid = derive_kid(SUITE_ID_PHASE_1, pubkey)

    event_bytes = (APPEND_019 / "expected-event.cbor").read_bytes()
    event_payload = load_sign1_payload(event_bytes)
    scope = event_payload["ledger_scope"]
    canonical_event_hash = cbor2.loads((APPEND_019 / "expected-append-head.cbor").read_bytes())[
        "canonical_event_hash"
    ]
    leaf_hash = merkle_leaf_hash(canonical_event_hash)
    wos_record = cbor2.loads((APPEND_019 / "input-wos-record.dcbor").read_bytes())

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
        "timestamp": ts(1776877860),
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

    signature_catalog = dcbor([signature_catalog_entry(canonical_event_hash, wos_record)])
    members_data["062-signature-affirmations.cbor"] = signature_catalog
    signed_acts = signed_acts_catalog(canonical_event_hash, wos_record)
    members_data[SIGNED_ACTS_MEMBER] = signed_acts
    policy_closure_bytes = policy_closure(domain_registry_digest)
    members_data[POLICY_CLOSURE_MEMBER] = policy_closure_bytes

    members_data["090-verify.sh"] = trellis_cli_verify_script()
    members_data["098-README.md"] = (
        "# Trellis Export (Fixture) — export/006-signature-affirmations-inline\n\n"
        "WOS-T4 signature export fixture. `062-signature-affirmations.cbor` is a "
        "chain-derived catalog over a readable WOS `SignatureAffirmation` payload "
        "and `066-signed-acts.cbor` is the verifier-facing signing projection. "
        "`067-policy-closure.cbor` carries the effective admission-policy evidence "
        "used at export time, while verifier trust roots and adapter allowlists "
        "remain verifier-supplied configuration.\n"
    ).encode("utf-8")

    manifest_payload = {
        "format": "trellis-export/1",
        "version": 1,
        "generator": "x-trellis-test/export-generator-006-signature",
        "generated_at": ts(1776877860),
        "scope": scope,
        "tree_size": 1,
        "head_checkpoint_digest": head_checkpoint_digest,
        "registry_bindings": [
            {
                "registry_digest": domain_registry_digest,
                "registry_format": 1,
                "registry_version": "x-trellis-test/registry-signature-v1",
                "bound_at_sequence": 0,
            }
        ],
        "signing_key_registry_digest": sha256(signing_key_registry),
        "events_digest": sha256(events_cbor),
        "checkpoints_digest": sha256(members_data["040-checkpoints.cbor"]),
        "inclusion_proofs_digest": sha256(inclusion_proofs),
        "consistency_proofs_digest": sha256(consistency_proofs),
        "payloads_inlined": False,
        "external_anchors": [],
        "posture_declaration": {
            "provider_readable": True,
            "reader_held": False,
            "delegated_compute": False,
            "external_anchor_required": False,
            "external_anchor_name": None,
            "recovery_without_user": True,
            "metadata_leakage_summary": "WOS-T4 signature export fixture with readable WOS payload bytes.",
        },
        "head_format_version": 1,
        "omitted_payload_checks": [],
        "extensions": {
            EXTENSION_KEY: {
                "signature_catalog_digest": sha256(signature_catalog),
            },
            SIGNED_ACTS_EXTENSION_KEY: {
                "catalog_digest": sha256(signed_acts),
                "catalog_ref": SIGNED_ACTS_MEMBER,
                "derivation_rule": SIGNED_ACTS_DERIVATION_RULE,
            },
            POLICY_CLOSURE_EXTENSION_KEY: {
                "closure_digest": sha256(policy_closure_bytes),
                "closure_ref": POLICY_CLOSURE_MEMBER,
                "closure_version": POLICY_CLOSURE_VERSION,
            },
        },
    }
    members_data["000-manifest.cbor"] = cose_sign1(seed, kid, dcbor(manifest_payload), ARTIFACT_TYPE_MANIFEST)

    for member, member_bytes in members_data.items():
        write_bytes(OUT_EXPORT_006 / member, member_bytes)

    members = sorted(members_data)
    root_dir = f"trellis-export-{scope.decode('utf-8')}-1-{leaf_hash.hex()[:8]}"
    zip_bytes = write_zip(
        OUT_EXPORT_006 / "expected-export.zip",
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
        "notes": "Fixture ledger_state for export/006-signature-affirmations-inline; pack listed members into deterministic ZIP.",
    }
    write_bytes(OUT_EXPORT_006 / "input-ledger-state.cbor", dcbor(ledger_state))
    write_text(
        OUT_EXPORT_006 / "manifest.toml",
        f'''id          = "export/006-signature-affirmations-inline"
op          = "export"
status      = "active"
description = """Single-event WOS-T4 export that carries a WOS `SignatureAffirmation` event, binds `062-signature-affirmations.cbor` through `trellis.export.signature-affirmations.v1`, binds verifier-facing `066-signed-acts.cbor` through `trellis.export.signed-acts.v1`, and binds effective policy evidence through `067-policy-closure.cbor` / `trellis.export.policy-closure.v1`."""

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
tr_op = [
    "TR-OP-072",
    "TR-OP-122",
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
        OUT_EXPORT_006 / "derivation.md",
        """# Derivation — `export/006-signature-affirmations-inline`

This fixture realizes the Trellis side of the WOS-T4 signature export contract.

It starts from `append/019-wos-signature-affirmation`, packages that canonical
event as the only event in the export, and derives
`062-signature-affirmations.cbor` from the readable WOS-authored
`SignatureAffirmation` payload already carried inside the signed event.
It also derives `066-signed-acts.cbor`, a verifier-facing projection over the
same signed record with nested signer, bound-subject, consent, admission, and
source-reference sections.
The export also includes `067-policy-closure.cbor`, the effective
admission-policy evidence snapshot for this signing profile. That closure
records intent/method registries, posture floors, authority shape, defaults,
deny rules, tombstones, and validity windows, but it explicitly leaves trust
roots, adapter allowlists, and server operational configuration to the verifier
or runtime environment.

Both catalogs are chain-derived rather than independently authored. Each row names
the admitting `canonical_event_hash` and repeats the WOS evidence fields needed
for verifier/reporting surfaces to summarize the signing act without redefining
canonical authority. The policy closure is evidence, not executable verifier
configuration. The human-facing certificate remains a derived artifact; the
signed Trellis export remains the authority.
""",
    )


def write_verify_vector() -> None:
    root_dir, members, data, manifest_payload = export_members_from_dir(OUT_EXPORT_006)
    catalog = cbor2.loads(data["062-signature-affirmations.cbor"])
    tampered_catalog = copy.deepcopy(catalog)
    tampered_catalog[0]["signing_act_id"] = "signing-act-tampered"
    catalog_bytes = dcbor(tampered_catalog)
    data_verify = dict(data)
    data_verify["062-signature-affirmations.cbor"] = catalog_bytes

    seed, pubkey = load_seed_and_pubkey(KEY_ISSUER_001)
    kid = derive_kid(SUITE_ID_PHASE_1, pubkey)
    manifest_payload_verify = copy.deepcopy(manifest_payload)
    manifest_payload_verify["extensions"][EXTENSION_KEY]["signature_catalog_digest"] = sha256(
        catalog_bytes
    )
    data_verify["000-manifest.cbor"] = cose_sign1(seed, kid, dcbor(manifest_payload_verify), ARTIFACT_TYPE_MANIFEST)

    OUT_VERIFY_014.mkdir(parents=True, exist_ok=True)
    write_zip(
        OUT_VERIFY_014 / "input-export.zip",
        root_dir=root_dir,
        members=members,
        data=data_verify,
    )
    write_text(
        OUT_VERIFY_014 / "manifest.toml",
        '''id          = "verify/014-export-006-signature-row-mismatch"
op          = "verify"
status      = "active"
description = """Negative verify vector for the WOS-T4 signature export catalog. Starts from `export/006-signature-affirmations-inline`, changes the catalog row signing act id, and re-signs the export manifest so structure stays valid while the catalog no longer matches the chain-authored WOS record."""

[coverage]
tr_core = ["TR-CORE-067"]
tr_op = ["TR-OP-122"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
first_failure_kind   = "signature_catalog_mismatch"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_VERIFY_014 / "derivation.md",
        """# Derivation — `verify/014-export-006-signature-row-mismatch`

This fixture starts from `export/006-signature-affirmations-inline`, mutates the
`signing_act_id` in `062-signature-affirmations.cbor`, recomputes the catalog
digest, and re-signs `000-manifest.cbor`. The ZIP remains structurally valid
and all manifest digests match the archive contents, but the signature catalog
no longer matches the chain-authored WOS `SignatureAffirmation` payload.
""",
    )


def write_signed_acts_verify_vector() -> None:
    root_dir, members, data, manifest_payload = export_members_from_dir(OUT_EXPORT_006)
    catalog = cbor2.loads(data[SIGNED_ACTS_MEMBER])
    tampered_catalog = copy.deepcopy(catalog)
    tampered_catalog["acts"][0]["signer"]["id"] = "delegate"
    catalog_bytes = dcbor(tampered_catalog)
    data_verify = dict(data)
    data_verify[SIGNED_ACTS_MEMBER] = catalog_bytes

    seed, pubkey = load_seed_and_pubkey(KEY_ISSUER_001)
    kid = derive_kid(SUITE_ID_PHASE_1, pubkey)
    manifest_payload_verify = copy.deepcopy(manifest_payload)
    manifest_payload_verify["extensions"][SIGNED_ACTS_EXTENSION_KEY][
        "catalog_digest"
    ] = sha256(catalog_bytes)
    data_verify["000-manifest.cbor"] = cose_sign1(
        seed, kid, dcbor(manifest_payload_verify), ARTIFACT_TYPE_MANIFEST
    )

    OUT_VERIFY_019.mkdir(parents=True, exist_ok=True)
    write_zip(
        OUT_VERIFY_019 / "input-export.zip",
        root_dir=root_dir,
        members=members,
        data=data_verify,
    )
    write_text(
        OUT_VERIFY_019 / "manifest.toml",
        '''id          = "verify/019-export-006-signed-acts-projection-mismatch"
op          = "verify"
status      = "active"
description = """Negative verify vector for the verifier-facing SignedAct projection. Starts from `export/006-signature-affirmations-inline`, mutates `066-signed-acts.cbor`, recomputes its manifest extension digest, and re-signs the export manifest so archive structure stays valid while the projection no longer matches signed WOS source records."""

[coverage]
tr_core = ["TR-CORE-067"]
tr_op = ["TR-OP-122"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
first_failure_kind   = "signed_acts_projection_mismatch"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_VERIFY_019 / "derivation.md",
        """# Derivation — `verify/019-export-006-signed-acts-projection-mismatch`

This fixture starts from `export/006-signature-affirmations-inline`, mutates
`066-signed-acts.cbor`, recomputes the `catalog_digest` under
`trellis.export.signed-acts.v1`, and re-signs `000-manifest.cbor`. The ZIP
remains structurally valid and all manifest digests match archive contents, but
the SignedAct projection no longer matches the signed WOS
`SignatureAffirmation` payload.
""",
    )


def write_tamper_vector() -> None:
    root_dir, members, data, _manifest_payload = export_members_from_dir(OUT_EXPORT_006)
    catalog = cbor2.loads(data["062-signature-affirmations.cbor"])
    tampered_catalog = copy.deepcopy(catalog)
    tampered_catalog[0]["document_hash_algorithm"] = "sha-512"
    data_tampered = dict(data)
    data_tampered["062-signature-affirmations.cbor"] = dcbor(tampered_catalog)

    OUT_TAMPER_014.mkdir(parents=True, exist_ok=True)
    write_zip(
        OUT_TAMPER_014 / "input-export.zip",
        root_dir=root_dir,
        members=members,
        data=data_tampered,
    )
    write_text(
        OUT_TAMPER_014 / "manifest.toml",
        '''id          = "tamper/014-signature-catalog-digest-mismatch"
op          = "tamper"
status      = "active"
description = """WOS-T4 export tamper. Mutates `062-signature-affirmations.cbor` after manifest signing so the required archive spine remains intact but the `trellis.export.signature-affirmations.v1.signature_catalog_digest` check fails."""

[coverage]
tr_core = ["TR-CORE-061"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
tamper_kind          = "signature_catalog_digest_mismatch"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_TAMPER_014 / "derivation.md",
        """# Derivation — `tamper/014-signature-catalog-digest-mismatch`

This fixture starts from `export/006-signature-affirmations-inline`, mutates
`062-signature-affirmations.cbor`, and leaves the signed `000-manifest.cbor`
unchanged. The verifier must localize the failure to the signature catalog
digest bound by `trellis.export.signature-affirmations.v1.signature_catalog_digest`.
""",
    )


def write_signed_acts_tamper_vector() -> None:
    root_dir, members, data, _manifest_payload = export_members_from_dir(OUT_EXPORT_006)
    catalog = cbor2.loads(data[SIGNED_ACTS_MEMBER])
    tampered_catalog = copy.deepcopy(catalog)
    tampered_catalog["acts"][0]["admission"]["outcome"] = "rejected"
    data_tampered = dict(data)
    data_tampered[SIGNED_ACTS_MEMBER] = dcbor(tampered_catalog)

    OUT_TAMPER_055.mkdir(parents=True, exist_ok=True)
    write_zip(
        OUT_TAMPER_055 / "input-export.zip",
        root_dir=root_dir,
        members=members,
        data=data_tampered,
    )
    write_text(
        OUT_TAMPER_055 / "manifest.toml",
        '''id          = "tamper/055-signed-acts-catalog-digest-mismatch"
op          = "tamper"
status      = "active"
description = """SignedAct projection export tamper. Mutates `066-signed-acts.cbor` after manifest signing so the required archive spine remains intact but the `trellis.export.signed-acts.v1.catalog_digest` check fails."""

[coverage]
tr_core = ["TR-CORE-061"]
tr_op = ["TR-OP-122"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
tamper_kind          = "signed_acts_catalog_digest_mismatch"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_TAMPER_055 / "derivation.md",
        """# Derivation — `tamper/055-signed-acts-catalog-digest-mismatch`

This fixture starts from `export/006-signature-affirmations-inline`, mutates
`066-signed-acts.cbor`, and leaves the signed `000-manifest.cbor` unchanged.
The verifier must localize the failure to the SignedAct projection catalog
digest bound by `trellis.export.signed-acts.v1.catalog_digest`.
""",
    )


def write_policy_closure_tamper_vector() -> None:
    root_dir, members, data, _manifest_payload = export_members_from_dir(OUT_EXPORT_006)
    closure = cbor2.loads(data[POLICY_CLOSURE_MEMBER])
    tampered_closure = copy.deepcopy(closure)
    tampered_closure["artifacts"][0]["version"] = "2026-05-17"
    data_tampered = dict(data)
    data_tampered[POLICY_CLOSURE_MEMBER] = dcbor(tampered_closure)

    OUT_TAMPER_056.mkdir(parents=True, exist_ok=True)
    write_zip(
        OUT_TAMPER_056 / "input-export.zip",
        root_dir=root_dir,
        members=members,
        data=data_tampered,
    )
    write_text(
        OUT_TAMPER_056 / "manifest.toml",
        '''id          = "tamper/056-policy-closure-digest-mismatch"
op          = "tamper"
status      = "active"
description = """Policy-closure export tamper. Mutates `067-policy-closure.cbor` after manifest signing so the required archive spine remains intact but the `trellis.export.policy-closure.v1.closure_digest` check fails."""

[coverage]
tr_core = ["TR-CORE-061"]
tr_op = ["TR-OP-122"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
tamper_kind          = "policy_closure_digest_mismatch"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_TAMPER_056 / "derivation.md",
        """# Derivation — `tamper/056-policy-closure-digest-mismatch`

This fixture starts from `export/006-signature-affirmations-inline`, mutates
`067-policy-closure.cbor`, and leaves the signed `000-manifest.cbor` unchanged.
The verifier must localize the failure to the effective policy-closure evidence
digest bound by `trellis.export.policy-closure.v1.closure_digest`.
""",
    )


def main() -> None:
    build_export_006()
    write_verify_vector()
    write_signed_acts_verify_vector()
    write_tamper_vector()
    write_signed_acts_tamper_vector()
    write_policy_closure_tamper_vector()


if __name__ == "__main__":
    main()
