"""Generate `export/010-certificate-of-completion-inline` plus the three
export-bundle ADR 0007 tamper vectors `tamper/020`, `tamper/022`, `tamper/024`,
`tamper/052`.

Authoring aid only. The committed fixture bytes and per-vector
`derivation.md` files are the evidence surface; this script exists so
the CBOR + ZIP output is reproducible.

Chain shape (single ledger_scope `trellis-cert:export-010`):

  | seq | event                           | event_type                              |
  |-----|---------------------------------|----------------------------------------|
  | 0   | attachment-binding event        | formspec.attachment.added              |
  | 1   | WOS SignatureAffirmation event  | wos.kernel.signature_affirmation        |
  | 2   | certificate-of-completion event | trellis.certificate-of-completion.v1   |

Event 0 binds the attachment that carries the presentation-artifact bytes
(ADR 0072). Event 1 is the signing event referenced by the certificate's
`signing_events[0]`. Event 2 is the certificate; its
`presentation_artifact.attachment_id` matches event 0's `attachment_id`.

For full ADR 0007 step 7 coverage (`response_ref` cross-check), event 1's
`data.signedPayloadDigest` is a 32-byte sha-256 hex digest. This lets the
verifier prove the certificate's response_ref matches the signer-assented
payload digest without overloading `sourceResponseRef` or Formspec handoff
`responseHash`. Event 2 either echoes that digest (positive path in export/010)
or carries a different digest (tamper/024).

Per ADR 0007 §"Export manifest catalog", the optional
`trellis.export.certificates-of-completion.v1` extension binds
`065-certificates-of-completion.cbor` via `catalog_digest = SHA-256(catalog
bytes)` (bare hash, no domain tag — sibling-catalog convention; see
`gen_export_009_erasure_evidence.py`).

Tamper variants surgically mutate ONE field in the unsigned export-bundle
state and re-pack the ZIP without re-signing the manifest:

* tamper/020 — flip `presentation_artifact.content_hash` in the certificate
  payload. Verifier emits `presentation_artifact_content_mismatch` from
  `verify_certificate_attachment_lineage` (ADR 0007 step 4).
* tamper/022 — flip `signing_events[0]` to an unresolvable digest. Verifier
  emits `signing_event_unresolved` from
  `finalize_certificates_of_completion` (ADR 0007 step 5).
* tamper/024 — flip `chain_summary.response_ref` to a digest the linked
  SignatureAffirmation does not carry. Verifier emits `response_ref_mismatch`
  from `finalize_certificates_of_completion` (ADR 0007 step 7).

Each tamper also re-signs the certificate event (its content_hash and
canonical_event_hash change with the payload mutation).
"""
from __future__ import annotations

import copy
import hashlib
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cbor2  # noqa: E402
from cbor2 import CBORTag  # noqa: E402
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
KEY_ISSUER = ROOT / "_keys" / "issuer-001.cose_key"

OUT_EXPORT_010 = ROOT / "export" / "010-certificate-of-completion-inline"
OUT_TAMPER_020 = ROOT / "tamper" / "020-cert-content-hash-mismatch"
OUT_TAMPER_022 = ROOT / "tamper" / "022-cert-signing-event-unresolved"
OUT_TAMPER_024 = ROOT / "tamper" / "024-cert-response-ref-mismatch"
OUT_TAMPER_052 = ROOT / "tamper" / "052-cert-response-ref-malformed-digest"

LEDGER_SCOPE = b"trellis-cert:export-010"
GENERATED_AT = ts(1_776_900_500)
SUITE_ID = SUITE_ID_PHASE_1

CERTIFICATE_EVENT_EXTENSION = "trellis.certificate-of-completion.v1"
CERTIFICATE_EXPORT_EXTENSION = "trellis.export.certificates-of-completion.v1"
ATTACHMENT_EVENT_EXTENSION = "trellis.evidence-attachment-binding.v1"
PRESENTATION_ARTIFACT_DOMAIN = "trellis-presentation-artifact-v1"
TRANSITION_ATTESTATION_DOMAIN = "trellis-transition-attestation-v1"

TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"
TAG_TRELLIS_CHECKPOINT_V1 = "trellis-checkpoint-v1"
TAG_TRELLIS_MERKLE_LEAF_V1 = "trellis-merkle-leaf-v1"
TAG_TRELLIS_WOS_IDEMPOTENCY_V1 = "trellis-wos-idempotency-v1"

# Reference signed-payload digest the SignatureAffirmation event covers.
# This is intentionally a deterministic test marker; ADR 0007 step 7 only
# requires that `response_ref == record.signedPayloadDigest` for sha-256 records.
RESPONSE_HASH_HEX = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
RESPONSE_HASH = bytes.fromhex(RESPONSE_HASH_HEX)

# The presentation artifact bytes (committed inline in the export ZIP).
PRESENTATION_ARTIFACT_BYTES = (
    b"trellis-certificate-of-completion-export-010-pdf-fixture\n"
    + bytes(range(64))
)

ATTACHMENT_ID = "urn:trellis:attachment:cert-export-010"
CERTIFICATE_ID = "urn:trellis:certificate:export-010"
CASE_REF = "urn:trellis:case:export-010"

CLASSIFICATION_BINDING = "x-trellis-test/unclassified"
CLASSIFICATION_SIGAFF = "x-trellis-test/unclassified"
CLASSIFICATION_CERT = "x-trellis-test/unclassified"

PAYLOAD_NONCE = b"\x00" * 12
RETENTION_TIER = 0


# ---------------------------------------------------------------------------
# Generic helpers (mirror gen_export_009 / gen_attachment_export_005).
# ---------------------------------------------------------------------------


def domain_separated_preimage(tag: str, component: bytes) -> bytes:
    tag_bytes = tag.encode("utf-8")
    return (
        len(tag_bytes).to_bytes(4, "big")
        + tag_bytes
        + len(component).to_bytes(4, "big")
        + component
    )


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def load_seed_and_pubkey(path: Path) -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(path.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    assert len(seed) == 32 and len(pubkey) == 32
    return seed, pubkey


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def protected_header(kid: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> bytes:
    return dcbor(
        {
            COSE_LABEL_ALG: ALG_EDDSA,
            COSE_LABEL_KID: kid,
            COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
        }
    )


def cose_sign1(seed: bytes, kid: bytes, payload_bytes: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> bytes:
    protected = protected_header(kid, artifact_type)
    sig_structure = dcbor(["Signature1", protected, b"", payload_bytes])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    return dcbor(CBORTag(CBOR_TAG_COSE_SIGN1, [protected, {}, payload_bytes, signature]))


def checkpoint_digest(scope: bytes, checkpoint_payload: dict) -> bytes:
    preimage = {"version": 1, "scope": scope, "checkpoint_payload": checkpoint_payload}
    return domain_separated_sha256(TAG_TRELLIS_CHECKPOINT_V1, dcbor(preimage))


def merkle_leaf_hash(canonical_hash: bytes) -> bytes:
    return domain_separated_sha256(TAG_TRELLIS_MERKLE_LEAF_V1, canonical_hash)


def merkle_interior(left: bytes, right: bytes) -> bytes:
    return domain_separated_sha256("trellis-merkle-interior-v1", left + right)


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return bytes(32)
    if len(leaves) == 1:
        return leaves[0]
    level = list(leaves)
    while len(level) > 1:
        nxt: list[bytes] = []
        i = 0
        while i < len(level):
            if i + 1 == len(level):
                nxt.append(level[i])
            else:
                nxt.append(merkle_interior(level[i], level[i + 1]))
            i += 2
        level = nxt
    return level[0]


def root_from_inclusion_proof(
    leaf_index: int, tree_size: int, leaf_hash: bytes, audit_path: list[bytes]
) -> bytes:
    """Compute the Merkle root from an inclusion-proof per the same rule
    the verifier uses (Core §10). Mirrors `_root_from_inclusion_proof` in
    `trellis-py.verify`."""
    h = leaf_hash
    fn = leaf_index
    sn = tree_size - 1
    for sibling in audit_path:
        if fn % 2 == 1 or fn == sn:
            h = merkle_interior(sibling, h)
            while fn % 2 == 0 and fn != 0:
                fn //= 2
                sn //= 2
        else:
            h = merkle_interior(h, sibling)
        fn //= 2
        sn //= 2
    return h


def build_signing_key_registry_export_shape(kid: bytes, pubkey: bytes) -> bytes:
    """Export-bundle shape mirrors gen_attachment_export_005: includes
    `suite_id` field (status = 0 = Active by Phase-1 export convention)."""
    return dcbor(
        [
            {
                "kid":         kid,
                "pubkey":      pubkey,
                "suite_id":    SUITE_ID,
                "status":      0,
                "valid_from":  ts(GENERATED_AT[0] - 1000),
                "valid_to":    None,
                "supersedes":  None,
                "attestation": None,
            }
        ]
    )


def build_domain_registry() -> bytes:
    return dcbor(
        {
            "governance": {
                "ruleset_id": "x-trellis-test/governance-ruleset-cert-export-010",
                "ruleset_digest": sha256(
                    b"x-trellis-test/governance-ruleset-cert-export-010"
                ),
            },
            "event_types": {
                "formspec.attachment.added": {
                    "privacy_class": "restricted",
                    "binding_family": "trellis.attachment-binding",
                },
                "wos.kernel.signature_affirmation": {
                    "privacy_class": "restricted",
                    "binding_family": "wos.signature-affirmation",
                },
                CERTIFICATE_EVENT_EXTENSION: {
                    "privacy_class": "restricted",
                    "binding_family": "trellis.certificate-of-completion",
                },
            },
            "classifications": ["x-trellis-test/unclassified"],
            "role_vocabulary": ["x-trellis-test/role-author"],
            "registry_version": "x-trellis-test/registry-cert-export-010-v1",
        }
    )


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def write_zip(
    path: Path, *, root_dir: str, members: list[str], data: dict[str, bytes]
) -> bytes:
    with zipfile.ZipFile(path, "w") as zf:
        for member in sorted(members):
            zf.writestr(deterministic_zipinfo(f"{root_dir}/{member}"), data[member])
        for info in zf.filelist:
            info.external_attr = 0
    return path.read_bytes()


# ---------------------------------------------------------------------------
# Event-payload builder (used for all three event types in the chain).
# ---------------------------------------------------------------------------


def build_event_payload(
    *,
    sequence: int,
    prev_hash: bytes | None,
    authored_at: int,
    event_type: str,
    classification: str,
    content_hash: bytes,
    payload_ref: dict,
    extensions: dict | None,
    idempotency_key: bytes,
) -> tuple[dict, bytes, bytes, bytes]:
    """Builds AuthorEventHashPreimage → EventPayload → canonical_event_hash.

    Returns (event_payload_map, event_payload_bytes, author_event_hash,
    canonical_event_hash).
    """
    header = {
        "event_type":             event_type.encode("utf-8"),
        "authored_at":             authored_at,
        "retention_tier":          RETENTION_TIER,
        "classification":          classification.encode("utf-8"),
        "outcome_commitment":      None,
        "subject_ref_commitment":  None,
        "tag_commitment":          None,
        "witness_ref":             None,
        "extensions":              None,
    }
    key_bag = {"entries": []}
    authored_map = {
        "version":         1,
        "ledger_scope":    LEDGER_SCOPE,
        "sequence":        sequence,
        "prev_hash":       prev_hash,
        "causal_deps":     None,
        "content_hash":    content_hash,
        "header":          header,
        "commitments":     None,
        "payload_ref":     payload_ref,
        "key_bag":         key_bag,
        "idempotency_key": idempotency_key,
        "extensions":      extensions,
    }
    authored_bytes = dcbor(authored_map)
    author_event_hash = hashlib.sha256(
        domain_separated_preimage(TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes)
    ).digest()
    event_payload = {
        "version":           1,
        "ledger_scope":      LEDGER_SCOPE,
        "sequence":          sequence,
        "prev_hash":         prev_hash,
        "causal_deps":       None,
        "author_event_hash": author_event_hash,
        "content_hash":      content_hash,
        "header":            header,
        "commitments":       None,
        "payload_ref":       payload_ref,
        "key_bag":           key_bag,
        "idempotency_key":   idempotency_key,
        "extensions":        extensions,
    }
    event_payload_bytes = dcbor(event_payload)
    canonical_preimage = dcbor(
        {
            "version":       1,
            "ledger_scope":  LEDGER_SCOPE,
            "event_payload": event_payload,
        }
    )
    canonical_hash = domain_separated_sha256(TAG_TRELLIS_EVENT_V1, canonical_preimage)
    return event_payload, event_payload_bytes, author_event_hash, canonical_hash


# ---------------------------------------------------------------------------
# Per-event builders.
# ---------------------------------------------------------------------------


def build_attestation(
    *,
    seed: bytes,
    authority: str,
    authority_class: str,
    transition_id: str,
    effective_at: int,
) -> dict:
    preimage_inner = dcbor([transition_id, effective_at, authority_class])
    signing_preimage = domain_separated_preimage(
        TRANSITION_ATTESTATION_DOMAIN, preimage_inner
    )
    sig = Ed25519PrivateKey.from_private_bytes(seed).sign(signing_preimage)
    return {
        "authority":       authority,
        "authority_class": authority_class,
        "signature":       sig,
    }


def build_binding_event(*, seed: bytes, kid: bytes) -> dict:
    """Event 0 — formspec.attachment.added carrying ADR 0072 binding for
    the presentation-artifact bytes. `payload_ref = PayloadExternal` whose
    content_hash equals the `payload_content_hash` in the binding extension.
    Mirrors the shape used by `append/018-attachment-bound`."""
    artifact_bytes = PRESENTATION_ARTIFACT_BYTES
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, artifact_bytes)
    artifact_sha256_text = f"sha256:{sha256(artifact_bytes).hex()}"
    binding = {
        "filename":             None,
        "slot_path":            "certificates.completion[0]",
        "media_type":           "application/pdf",
        "byte_length":          len(artifact_bytes),
        "attachment_id":        ATTACHMENT_ID,
        "attachment_sha256":    artifact_sha256_text,
        "prior_binding_hash":   None,
        "payload_content_hash": f"sha256:{content_hash.hex()}",
    }
    extensions = {ATTACHMENT_EVENT_EXTENSION: binding}
    payload_ref = {
        "ref_type":      "external",
        "content_hash":  content_hash,
        "availability":  0,
        "retrieval_hint": None,
    }
    event_payload, event_payload_bytes, aeh, canonical_hash = build_event_payload(
        sequence=0,
        prev_hash=None,
        authored_at=ts(GENERATED_AT[0] - 100),
        event_type="formspec.attachment.added",
        classification=CLASSIFICATION_BINDING,
        content_hash=content_hash,
        payload_ref=payload_ref,
        extensions=extensions,
        idempotency_key=b"export-010-binding-event-0",
    )
    signed = cose_sign1(seed, kid, event_payload_bytes)
    return {
        "signed":               signed,
        "event_payload":        event_payload,
        "event_payload_bytes":  event_payload_bytes,
        "author_event_hash":    aeh,
        "canonical_event_hash": canonical_hash,
        "content_hash":         content_hash,
        "binding":              binding,
        "artifact_bytes":       artifact_bytes,
    }


def build_signature_affirmation_event(
    *,
    seed: bytes,
    kid: bytes,
    prev_hash: bytes,
    signed_payload_digest_override: str | None = None,
    idempotency_preimage_record_id: str = "export-010-prov-001",
) -> dict:
    """Event 1 — wos.kernel.signature_affirmation Facts-tier provenance.
    Mirrors `append/019-wos-signature-affirmation` shape, but uses the
    deterministic `signedPayloadDigest` marker so ADR 0007 step 7 has
    parseable sha-256 input without overloading `sourceResponseRef`.

    `signed_payload_digest_override` lets tamper variants substitute a
    malformed digest text (still claiming `signedPayloadDigestAlgorithm
    = "sha-256"`) so the WOS resolver fails-closed on hex parse rather
    than silent-skipping. `idempotency_preimage_record_id` keeps the
    SignatureAffirmation event idempotency-distinct from the positive
    fixture when a tamper variant reuses everything else.
    """
    record = {
        "id":          idempotency_preimage_record_id,
        "event":       "wos.kernel.signature_affirmation",
        "timestamp":   "2026-04-22T14:30:00Z",
        "actorId":     "applicant",
        "auditLayer":  "facts",
        "data": {
            "signerId":              "applicant",
            "roleId":                "applicantSigner",
            "role":                  "signer",
            "documentId":            "benefitsApplication",
            "documentHash":          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "documentHashAlgorithm": "sha-256",
            "sourceSignatureSystem": "formspec",
            "sourceSignatureId":     "sig-export-010",
            "signedPayloadDigest":   signed_payload_digest_override or RESPONSE_HASH_HEX,
            "signedPayloadDigestAlgorithm": "sha-256",
            "signingIntent":         "urn:wos:signing-intent:applicant-signature",
            "signedAt":              "2026-04-22T12:00:00Z",
            "identityBinding": {
                "method":          "email-otp",
                "assuranceLevel":  "standard",
                "providerRef":     "urn:agency.gov:identity:providers:email-otp",
            },
            "consentReference": {
                "consentTextRef":  "urn:agency.gov:consent:esign-benefits:v1",
                "consentVersion":  "1.0.0",
                "acceptedAtPath":  "authoredSignatures[0].signedAt",
                "affirmationPath": "authoredSignatures[0].consentAccepted",
            },
            "signatureProvider":   "urn:agency.gov:signature:providers:formspec",
            "ceremonyId":          "ceremony-export-010",
            "profileRef":          "urn:agency.gov:wos:signature-profile:benefits:v1",
            "sourceResponseRef":    "urn:formspec:response:export-010",
            "custodyHookEligible": True,
        },
    }
    record_bytes = dcbor(record)
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, record_bytes)
    payload_ref = {
        "ref_type":   "inline",
        "ciphertext": record_bytes,
        "nonce":      PAYLOAD_NONCE,
    }
    idempotency_preimage = dcbor(
        {
            "caseId":   "export-010-case",
            "recordId": idempotency_preimage_record_id,
        }
    )
    idempotency_key = domain_separated_sha256(
        TAG_TRELLIS_WOS_IDEMPOTENCY_V1, idempotency_preimage
    )
    assert len(idempotency_key) == 32

    event_payload, event_payload_bytes, aeh, canonical_hash = build_event_payload(
        sequence=1,
        prev_hash=prev_hash,
        authored_at=ts(GENERATED_AT[0] - 50),
        event_type="wos.kernel.signature_affirmation",
        classification=CLASSIFICATION_SIGAFF,
        content_hash=content_hash,
        payload_ref=payload_ref,
        extensions=None,
        idempotency_key=idempotency_key,
    )
    signed = cose_sign1(seed, kid, event_payload_bytes)
    return {
        "signed":               signed,
        "event_payload":        event_payload,
        "event_payload_bytes":  event_payload_bytes,
        "author_event_hash":    aeh,
        "canonical_event_hash": canonical_hash,
        "content_hash":         content_hash,
        "authored_at":          ts(GENERATED_AT[0] - 50),
        "record":               record,
    }


def build_certificate_event(
    *,
    seed: bytes,
    kid: bytes,
    prev_hash: bytes,
    sigaff_canonical_hash: bytes,
    sigaff_authored_at: int,
    presentation_content_hash: bytes,
    presentation_byte_length: int,
    response_ref: bytes | None,
    signing_events: list[bytes] | None = None,
    idempotency_key: bytes = b"export-010-cert-event-2",
) -> dict:
    """Event 2 — `trellis.certificate-of-completion.v1` payload pinning the
    presentation-artifact via `attachment_id` (resolved through event 0's
    binding) and `signing_events[0] = sigaff_canonical_hash`. Tamper
    variants override `presentation_content_hash`, `signing_events`, or
    `response_ref` to drive the targeted §"Verifier obligations" failure."""
    if signing_events is None:
        signing_events = [sigaff_canonical_hash]
    cert_payload = {
        "certificate_id":        CERTIFICATE_ID,
        "case_ref":              CASE_REF,
        "completed_at":          ts(GENERATED_AT[0] - 75),
        "presentation_artifact": {
            "content_hash":  presentation_content_hash,
            "media_type":    "application/pdf",
            "byte_length":   presentation_byte_length,
            "attachment_id": ATTACHMENT_ID,
            "template_id":   None,
            "template_hash": None,
        },
        "chain_summary": {
            "signer_count":    len(signing_events),
            "signer_display":  [
                {
                    "principal_ref": "applicant",
                    "display_name":  "Applicant Test User",
                    "display_role":  "applicant",
                    "signed_at":     sigaff_authored_at,
                }
                for _ in signing_events
            ],
            "response_ref":    response_ref,
            "workflow_status": "completed",
            "impact_level":    None,
            "covered_claims":  [],
        },
        "signing_events": signing_events,
        "workflow_ref":   None,
        "attestations": [
            build_attestation(
                seed=seed,
                authority="urn:trellis:authority:test-cm-a-authority",
                authority_class="new",
                transition_id="urn:trellis:certificate:export-010",
                effective_at=ts(GENERATED_AT[0] - 75),
            )
        ],
        "extensions": None,
    }
    extensions = {CERTIFICATE_EVENT_EXTENSION: cert_payload}
    payload_marker = b"certificate-of-completion-marker-export-010"
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_marker)
    payload_ref = {
        "ref_type":   "inline",
        "ciphertext": payload_marker,
        "nonce":      PAYLOAD_NONCE,
    }
    event_payload, event_payload_bytes, aeh, canonical_hash = build_event_payload(
        sequence=2,
        prev_hash=prev_hash,
        authored_at=ts(GENERATED_AT[0]),
        event_type=CERTIFICATE_EVENT_EXTENSION,
        classification=CLASSIFICATION_CERT,
        content_hash=content_hash,
        payload_ref=payload_ref,
        extensions=extensions,
        idempotency_key=idempotency_key,
    )
    signed = cose_sign1(seed, kid, event_payload_bytes)
    return {
        "signed":               signed,
        "event_payload":        event_payload,
        "event_payload_bytes":  event_payload_bytes,
        "author_event_hash":    aeh,
        "canonical_event_hash": canonical_hash,
        "content_hash":         content_hash,
        "cert_payload":         cert_payload,
    }


# ---------------------------------------------------------------------------
# Catalog row builder.
# ---------------------------------------------------------------------------


def cert_catalog_row(canonical_event_hash: bytes, cert_payload: dict) -> dict:
    pa = cert_payload["presentation_artifact"]
    cs = cert_payload["chain_summary"]
    return {
        "canonical_event_hash":  canonical_event_hash,
        "certificate_id":        cert_payload["certificate_id"],
        "completed_at":          cert_payload["completed_at"],
        "signer_count":          cs["signer_count"],
        "media_type":            pa["media_type"],
        "attachment_id":         pa["attachment_id"],
        "workflow_status":       cs["workflow_status"],
    }


# ---------------------------------------------------------------------------
# Export ZIP composer.
# ---------------------------------------------------------------------------


def compose_export_members(
    *,
    seed: bytes,
    kid: bytes,
    pubkey: bytes,
    binding: dict,
    sigaff: dict,
    cert: dict,
    description_suffix: str,
) -> tuple[dict[str, bytes], dict, list[str], str]:
    """Build the `members_data` map, manifest payload, member ordering, and
    `root_dir` for the export ZIP. Returns (members_data, manifest_payload,
    members_sorted, root_dir).

    `description_suffix` shows up in `098-README.md` / `posture_declaration`
    so tamper variants are textually distinguishable from the positive
    export inside the ZIP without changing the signed manifest of the
    positive export. (Tampers reuse the SAME manifest signed bytes from the
    positive export when only catalog content changes; here every tamper
    re-signs the certificate event, so we re-pack the manifest separately.)
    """
    members_data: dict[str, bytes] = {}

    events_cbor = dcbor(
        [
            cbor2.loads(binding["signed"]),
            cbor2.loads(sigaff["signed"]),
            cbor2.loads(cert["signed"]),
        ]
    )
    members_data["010-events.cbor"] = events_cbor

    # Per-event leaf hashes for the Merkle tree (3 leaves).
    leaf_hashes = [
        merkle_leaf_hash(binding["canonical_event_hash"]),
        merkle_leaf_hash(sigaff["canonical_event_hash"]),
        merkle_leaf_hash(cert["canonical_event_hash"]),
    ]
    tree_size = 3
    tree_root = merkle_root(leaf_hashes)

    # Inclusion proofs — one per event. Audit path siblings per Core §10:
    # for tree_size = 3, leaf 0 pairs with leaf 1 → interior(0,1); leaf 2
    # rides solo at level 0. Root = interior(interior(0,1), leaf2).
    interior_01 = merkle_interior(leaf_hashes[0], leaf_hashes[1])
    inclusion_proofs = {
        0: {
            "leaf_index": 0,
            "tree_size":  tree_size,
            "leaf_hash":  leaf_hashes[0],
            "audit_path": [leaf_hashes[1], leaf_hashes[2]],
        },
        1: {
            "leaf_index": 1,
            "tree_size":  tree_size,
            "leaf_hash":  leaf_hashes[1],
            "audit_path": [leaf_hashes[0], leaf_hashes[2]],
        },
        2: {
            "leaf_index": 2,
            "tree_size":  tree_size,
            "leaf_hash":  leaf_hashes[2],
            "audit_path": [interior_01],
        },
    }
    members_data["020-inclusion-proofs.cbor"] = dcbor(inclusion_proofs)
    members_data["025-consistency-proofs.cbor"] = dcbor([])

    signing_key_registry = build_signing_key_registry_export_shape(kid, pubkey)
    members_data["030-signing-key-registry.cbor"] = signing_key_registry

    checkpoint_payload = {
        "version":              1,
        "scope":                LEDGER_SCOPE,
        "tree_size":            tree_size,
        "tree_head_hash":       tree_root,
        "timestamp":            ts(GENERATED_AT[0]),
        "anchor_ref":           None,
        "prev_checkpoint_hash": None,
        "extensions":           None,
    }
    head_checkpoint_digest = checkpoint_digest(LEDGER_SCOPE, checkpoint_payload)
    members_data["040-checkpoints.cbor"] = dcbor(
        [cbor2.loads(cose_sign1(seed, kid, dcbor(checkpoint_payload), ARTIFACT_TYPE_CHECKPOINT))]
    )

    domain_registry = build_domain_registry()
    domain_registry_digest = sha256(domain_registry)
    domain_registry_member = f"050-registries/{domain_registry_digest.hex()}.cbor"
    members_data[domain_registry_member] = domain_registry

    # 060-payloads: the binding's PayloadExternal content_hash names the
    # presentation-artifact ciphertext member.
    payload_member = f"060-payloads/{binding['content_hash'].hex()}.bin"
    members_data[payload_member] = binding["artifact_bytes"]

    # 061-attachments.cbor catalog (ADR 0072 mirror).
    bd = binding["binding"]
    att_entry = {
        "binding_event_hash":    binding["canonical_event_hash"],
        "attachment_id":         ATTACHMENT_ID,
        "slot_path":             bd["slot_path"],
        "media_type":            bd["media_type"],
        "byte_length":           bd["byte_length"],
        "attachment_sha256":     bytes.fromhex(bd["attachment_sha256"].split(":", 1)[1]),
        "payload_content_hash":  binding["content_hash"],
        "filename":              bd["filename"],
        "prior_binding_hash":    None,
    }
    attachment_manifest = dcbor([att_entry])
    members_data["061-attachments.cbor"] = attachment_manifest

    # 065-certificates-of-completion.cbor — ADR 0007 catalog.
    catalog = dcbor([cert_catalog_row(cert["canonical_event_hash"], cert["cert_payload"])])
    members_data["065-certificates-of-completion.cbor"] = catalog

    members_data["090-verify.sh"] = trellis_cli_verify_script()

    members_data["098-README.md"] = (
        "# Trellis Export — export/010-certificate-of-completion-inline\n\n"
        "Three-event chain (binding + SignatureAffirmation + certificate) plus "
        "`065-certificates-of-completion.cbor` bound via "
        "`trellis.export.certificates-of-completion.v1`. ADR 0007 §\"Export "
        f"manifest catalog\" reference shape. {description_suffix}\n"
    ).encode("utf-8")

    manifest_payload = {
        "format":                     "trellis-export/1",
        "version":                    1,
        "generator":                  "x-trellis-test/export-generator-010-cert",
        "generated_at":               ts(GENERATED_AT[0]),
        "scope":                      LEDGER_SCOPE,
        "tree_size":                  tree_size,
        "head_checkpoint_digest":     head_checkpoint_digest,
        "registry_bindings": [
            {
                "registry_digest":   domain_registry_digest,
                "registry_format":   1,
                "registry_version":  "x-trellis-test/registry-cert-export-010-v1",
                "bound_at_sequence": 0,
            }
        ],
        "signing_key_registry_digest": sha256(signing_key_registry),
        "events_digest":               sha256(events_cbor),
        "checkpoints_digest":          sha256(members_data["040-checkpoints.cbor"]),
        "inclusion_proofs_digest":     sha256(members_data["020-inclusion-proofs.cbor"]),
        "consistency_proofs_digest":   sha256(members_data["025-consistency-proofs.cbor"]),
        "payloads_inlined":            True,
        "external_anchors":            [],
        "posture_declaration": {
            "provider_readable":         True,
            "reader_held":               False,
            "delegated_compute":         False,
            "external_anchor_required":  False,
            "external_anchor_name":      None,
            "recovery_without_user":     True,
            "metadata_leakage_summary":  f"ADR 0007 certificate-of-completion export fixture. {description_suffix}",
        },
        "head_format_version":   1,
        "omitted_payload_checks": [],
        "extensions": {
            "trellis.export.attachments.v1": {
                "attachment_manifest_digest": sha256(attachment_manifest),
                "inline_attachments":          True,
            },
            CERTIFICATE_EXPORT_EXTENSION: {
                "catalog_ref":    "065-certificates-of-completion.cbor",
                "catalog_digest": sha256(catalog),
                "entry_count":    1,
            },
        },
    }
    members_data["000-manifest.cbor"] = cose_sign1(seed, kid, dcbor(manifest_payload), ARTIFACT_TYPE_MANIFEST)

    members = sorted(members_data)
    root_dir = (
        f"trellis-export-{LEDGER_SCOPE.decode('utf-8')}-{tree_size}-{tree_root.hex()[:8]}"
    )
    return members_data, manifest_payload, members, root_dir


# ---------------------------------------------------------------------------
# Build positive export/010.
# ---------------------------------------------------------------------------


def build_export_010(
    *, seed: bytes, kid: bytes, pubkey: bytes
) -> tuple[dict, bytes, dict[str, bytes], list[str], str]:
    print(f"\ngenerating export/010 at {OUT_EXPORT_010.relative_to(ROOT.parent.parent)}/")
    OUT_EXPORT_010.mkdir(parents=True, exist_ok=True)

    binding = build_binding_event(seed=seed, kid=kid)
    sigaff = build_signature_affirmation_event(
        seed=seed, kid=kid, prev_hash=binding["canonical_event_hash"]
    )
    presentation_content_hash = domain_separated_sha256(
        PRESENTATION_ARTIFACT_DOMAIN, PRESENTATION_ARTIFACT_BYTES
    )
    cert = build_certificate_event(
        seed=seed,
        kid=kid,
        prev_hash=sigaff["canonical_event_hash"],
        sigaff_canonical_hash=sigaff["canonical_event_hash"],
        sigaff_authored_at=sigaff["authored_at"],
        presentation_content_hash=presentation_content_hash,
        presentation_byte_length=len(PRESENTATION_ARTIFACT_BYTES),
        response_ref=RESPONSE_HASH,
    )

    members_data, manifest_payload, members, root_dir = compose_export_members(
        seed=seed,
        kid=kid,
        pubkey=pubkey,
        binding=binding,
        sigaff=sigaff,
        cert=cert,
        description_suffix="Positive corpus.",
    )

    for member, member_bytes in members_data.items():
        write_bytes(OUT_EXPORT_010 / member, member_bytes)

    zip_bytes = write_zip(
        OUT_EXPORT_010 / "expected-export.zip",
        root_dir=root_dir,
        members=members,
        data=members_data,
    )

    ledger_state = {
        "version":   1,
        "scope":     LEDGER_SCOPE,
        "tree_size": 3,
        "root_dir":  root_dir,
        "members":   members,
        "notes":     "Fixture ledger_state for export/010-certificate-of-completion-inline; pack listed members into deterministic ZIP.",
    }
    write_bytes(OUT_EXPORT_010 / "input-ledger-state.cbor", dcbor(ledger_state))
    write_text(
        OUT_EXPORT_010 / "manifest.toml",
        f'''id          = "export/010-certificate-of-completion-inline"
op          = "export"
status      = "active"
description = """ADR 0007 §"Export manifest catalog" positive vector. Three-event chain `[attachment-binding, wos.kernel.signature_affirmation, trellis.certificate-of-completion.v1]` with `065-certificates-of-completion.cbor` bound through `trellis.export.certificates-of-completion.v1`. Exercises the full ADR 0007 verifier-obligations path: step 4 (attachment lineage + content-hash recompute), step 5 (signing-event resolution), step 6 (timestamp equivalence), step 7 (response_ref cross-check)."""

[coverage]
tr_core = [
    "TR-CORE-018",
    "TR-CORE-021",
    "TR-CORE-030",
    "TR-CORE-031",
    "TR-CORE-035",
    "TR-CORE-062",
    "TR-CORE-063",
    "TR-CORE-064",
    "TR-CORE-065",
    "TR-CORE-110",
    "TR-CORE-134",
    "TR-CORE-146",
    "TR-CORE-147",
    "TR-CORE-148",
    "TR-CORE-149",
    "TR-CORE-150",
    "TR-CORE-151",
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
        OUT_EXPORT_010 / "derivation.md",
        f"""# Derivation — `export/010-certificate-of-completion-inline`

ADR 0007 §"Export manifest catalog" reference export. The chain carries
three events on `ledger_scope = {LEDGER_SCOPE!r}`:

1. **Event 0 (sequence 0).** `formspec.attachment.added` binding event
   (ADR 0072 mirror) — `payload_ref = PayloadExternal` whose
   `content_hash = SHA-256(presentation-artifact-bytes, domain
   "trellis-content-v1")`. The `trellis.evidence-attachment-binding.v1`
   extension declares `attachment_id = {ATTACHMENT_ID!r}`.

2. **Event 1 (sequence 1).** `wos.kernel.signature_affirmation` Facts-tier
   provenance record. `data.signedPayloadDigest = "{RESPONSE_HASH_HEX}"` —
   a 32-byte sha-256 hex digest so ADR 0007 step 7 cross-check has parseable
   input. The certificate's `chain_summary.response_ref` echoes the same
   digest as bytes.

3. **Event 2 (sequence 2).** `trellis.certificate-of-completion.v1` —
   `presentation_artifact.attachment_id` resolves through event 0's
   binding; `presentation_artifact.content_hash =
   SHA-256(presentation-artifact-bytes, domain
   "trellis-presentation-artifact-v1")`; `signing_events[0] = canonical_event_hash(event 1)`.

The export ZIP carries `065-certificates-of-completion.cbor` (one row),
bound through `trellis.export.certificates-of-completion.v1` with
`catalog_digest = SHA-256(catalog bytes)` (bare, no domain tag).

The presentation-artifact bytes are the **same** bytes the binding event's
`PayloadExternal.content_hash` covers — but the certificate's
`presentation_artifact.content_hash` is computed under a DIFFERENT domain
tag (`trellis-presentation-artifact-v1`), giving a different digest. The
verifier resolves this via `verify_certificate_attachment_lineage`:
`payload_blobs[binding.payload_content_hash]` returns the bytes,
`SHA-256(bytes, "trellis-presentation-artifact-v1")` recomputes the
certificate's content_hash, and equality flips
`outcome.attachment_resolved = true`.

Generator: `_generator/gen_export_010_certificate_of_completion.py`.
""",
    )

    return cert, zip_bytes, members_data, members, root_dir


# ---------------------------------------------------------------------------
# Tamper builders. Each takes the positive base, surgically mutates ONE
# field, re-signs the certificate event (its content_hash + canonical hash
# change with the payload), and re-packs the ZIP with a fresh manifest
# signature so the archive-spine digest checks still pass — the targeted
# failure surfaces in `verify_certificate_*` paths only.
# ---------------------------------------------------------------------------


def build_tamper_export(
    *,
    seed: bytes,
    kid: bytes,
    pubkey: bytes,
    out_dir: Path,
    description: str,
    tamper_kind: str,
    failing_event_id: str,
    coverage_tr_core: list[str],
    coverage_tr_op: list[str],
    cert_overrides: dict,
    description_suffix: str,
    derivation: str,
    sigaff_signed_payload_digest_override: str | None = None,
    sigaff_idempotency_preimage_record_id: str = "export-010-prov-001",
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {out_dir.relative_to(ROOT.parent.parent)}/")

    binding = build_binding_event(seed=seed, kid=kid)
    sigaff = build_signature_affirmation_event(
        seed=seed,
        kid=kid,
        prev_hash=binding["canonical_event_hash"],
        signed_payload_digest_override=sigaff_signed_payload_digest_override,
        idempotency_preimage_record_id=sigaff_idempotency_preimage_record_id,
    )
    presentation_content_hash = domain_separated_sha256(
        PRESENTATION_ARTIFACT_DOMAIN, PRESENTATION_ARTIFACT_BYTES
    )

    cert_kwargs = dict(
        seed=seed,
        kid=kid,
        prev_hash=sigaff["canonical_event_hash"],
        sigaff_canonical_hash=sigaff["canonical_event_hash"],
        sigaff_authored_at=sigaff["authored_at"],
        presentation_content_hash=presentation_content_hash,
        presentation_byte_length=len(PRESENTATION_ARTIFACT_BYTES),
        response_ref=RESPONSE_HASH,
        idempotency_key=cert_overrides.pop("idempotency_key", b"export-010-cert-event-2"),
    )
    cert_kwargs.update(cert_overrides)
    cert = build_certificate_event(**cert_kwargs)

    members_data, manifest_payload, members, root_dir = compose_export_members(
        seed=seed,
        kid=kid,
        pubkey=pubkey,
        binding=binding,
        sigaff=sigaff,
        cert=cert,
        description_suffix=description_suffix,
    )

    write_zip(
        out_dir / "input-export.zip",
        root_dir=root_dir,
        members=members,
        data=members_data,
    )

    tr_core_lines = ",\n    ".join(f'"{x}"' for x in coverage_tr_core)
    coverage_block = f"tr_core = [\n    {tr_core_lines},\n]"
    if coverage_tr_op:
        tr_op_lines = ",\n    ".join(f'"{x}"' for x in coverage_tr_op)
        coverage_block += f"\ntr_op = [\n    {tr_op_lines},\n]"

    failing = failing_event_id if failing_event_id else cert["canonical_event_hash"].hex()
    rel_id = f"tamper/{out_dir.name}"
    manifest = f'''id          = "{rel_id}"
op          = "tamper"
status      = "active"
description = """{description}"""

[coverage]
{coverage_block}

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
tamper_kind          = "{tamper_kind}"
failing_event_id     = "{failing}"

[derivation]
document = "derivation.md"
'''
    out_dir.joinpath("manifest.toml").write_text(manifest)
    out_dir.joinpath("derivation.md").write_text(derivation)


def gen_tamper_020(*, seed: bytes, kid: bytes, pubkey: bytes) -> None:
    """presentation_artifact.content_hash flipped → recompute mismatches."""
    flipped = bytes(b ^ 0xFF for b in domain_separated_sha256(
        PRESENTATION_ARTIFACT_DOMAIN, PRESENTATION_ARTIFACT_BYTES
    ))
    build_tamper_export(
        seed=seed,
        kid=kid,
        pubkey=pubkey,
        out_dir=OUT_TAMPER_020,
        description=(
            'ADR 0007 §"Verifier obligations" step 4 violation: certificate `presentation_artifact.content_hash` '
            'is flipped from the correct `SHA-256(bytes, "trellis-presentation-artifact-v1")` digest. '
            'The export ZIP still ships the resolvable attachment lineage; `verify_certificate_attachment_lineage` '
            'recomputes the digest from the bound bytes, finds the mismatch, and flips `attachment_resolved = false` '
            'with `presentation_artifact_content_mismatch`. Generator: `_generator/gen_export_010_certificate_of_completion.py`.'
        ),
        tamper_kind="presentation_artifact_content_mismatch",
        failing_event_id="",  # filled with cert canonical hash inside builder
        coverage_tr_core=["TR-CORE-018", "TR-CORE-030", "TR-CORE-035", "TR-CORE-148"],
        coverage_tr_op=[],
        cert_overrides={
            "presentation_content_hash": flipped,
            "idempotency_key": b"tamper-020-cert-content-hash",
        },
        description_suffix="Tamper: presentation_artifact.content_hash flipped (tamper/020).",
        derivation=(
            "# Derivation — `tamper/020-cert-content-hash-mismatch`\n\n"
            "Starts from `export/010-certificate-of-completion-inline`. The certificate event's "
            "`presentation_artifact.content_hash` is XOR-flipped from the correct value "
            "(`SHA-256(presentation-artifact-bytes, \"trellis-presentation-artifact-v1\")`). The bound "
            "attachment bytes in `060-payloads/` are unchanged.\n\n"
            "`verify_certificate_attachment_lineage` resolves the attachment via "
            "`presentation_artifact.attachment_id` → binding event → `payload_blobs`, then recomputes "
            "the digest under the certificate's domain tag and finds it disagrees with the certificate's "
            "claim. ADR 0007 step 4 fails closed with `presentation_artifact_content_mismatch`, "
            "distinct from `presentation_artifact_attachment_missing` (which fires when bytes are absent "
            "or lineage is unresolvable).\n\n"
            "Generator: `_generator/gen_export_010_certificate_of_completion.py`.\n"
        ),
    )


def gen_tamper_022(*, seed: bytes, kid: bytes, pubkey: bytes) -> None:
    """signing_events[0] flipped to a digest no event in the chain carries."""
    unresolvable = bytes(b ^ 0xFF for b in bytes(32))
    # `signing_event_unresolved` localizes by the SIGNING-EVENT digest hex,
    # not the certificate's canonical_event_hash (verifier emits the failure
    # at the unresolvable hash). Pin failing_event_id explicitly.
    build_tamper_export(
        seed=seed,
        kid=kid,
        pubkey=pubkey,
        out_dir=OUT_TAMPER_022,
        description=(
            'ADR 0007 §"Verifier obligations" step 5 violation: certificate `signing_events[0]` '
            'is rewritten to a 32-byte all-`0xff` digest that no event in the chain carries. '
            '`finalize_certificates_of_completion` walks the chain, fails to resolve the digest to '
            'a SignatureAffirmation event, and emits `signing_event_unresolved`. Generator: '
            '`_generator/gen_export_010_certificate_of_completion.py`.'
        ),
        tamper_kind="signing_event_unresolved",
        failing_event_id=unresolvable.hex(),
        coverage_tr_core=["TR-CORE-018", "TR-CORE-030", "TR-CORE-035", "TR-CORE-149"],
        coverage_tr_op=[],
        cert_overrides={
            "signing_events": [unresolvable],
            "idempotency_key": b"tamper-022-cert-sig-unresolved",
        },
        description_suffix="Tamper: signing_events[0] unresolvable (tamper/022).",
        derivation=(
            "# Derivation — `tamper/022-cert-signing-event-unresolved`\n\n"
            "Starts from `export/010-certificate-of-completion-inline`. The certificate event's "
            "`signing_events[0]` is rewritten to `0xff…ff` (32 bytes). The chain still carries the "
            "original SignatureAffirmation event at sequence 1, but its `canonical_event_hash` does "
            "not match the rewritten digest.\n\n"
            "`finalize_certificates_of_completion` runs step 5 (signing-event resolution) over the full "
            "chain context provided by the export-bundle path, fails to find a matching event in "
            "`event_by_hash`, and emits `signing_event_unresolved` localized to the unresolvable "
            "digest hex. ADR 0007 step 5 also covers wrong-event-type resolution (a digest pointing at "
            "a non-SignatureAffirmation event); this vector exercises the missing-event sub-case.\n\n"
            "Generator: `_generator/gen_export_010_certificate_of_completion.py`.\n"
        ),
    )


def gen_tamper_024(*, seed: bytes, kid: bytes, pubkey: bytes) -> None:
    """chain_summary.response_ref flipped to disagree with the SignatureAffirmation's
    `data.signedPayloadDigest`."""
    bad_response = bytes(b ^ 0xAA for b in RESPONSE_HASH)
    build_tamper_export(
        seed=seed,
        kid=kid,
        pubkey=pubkey,
        out_dir=OUT_TAMPER_024,
        description=(
            'ADR 0007 §"Verifier obligations" step 7 violation: certificate `chain_summary.response_ref` '
            'is XOR-flipped so it disagrees with the resolved SignatureAffirmation event\'s '
            '`data.signedPayloadDigest`. `finalize_certificates_of_completion` parses the '
            'SignatureAffirmation record, finds at least one resolvable response digest, fails to '
            'find a match, and emits `response_ref_mismatch`. Generator: `_generator/gen_export_010_certificate_of_completion.py`.'
        ),
        tamper_kind="response_ref_mismatch",
        failing_event_id="",
        coverage_tr_core=["TR-CORE-018", "TR-CORE-030", "TR-CORE-035", "TR-CORE-150"],
        coverage_tr_op=[],
        cert_overrides={
            "response_ref": bad_response,
            "idempotency_key": b"tamper-024-cert-response",
        },
        description_suffix="Tamper: chain_summary.response_ref mismatched (tamper/024).",
        derivation=(
            "# Derivation — `tamper/024-cert-response-ref-mismatch`\n\n"
            "Starts from `export/010-certificate-of-completion-inline`. The certificate event's "
            "`chain_summary.response_ref` is XOR-flipped (`b ^ 0xAA` for each byte) so its 32-byte digest "
            "disagrees with the SignatureAffirmation record's `data.signedPayloadDigest = "
            f'"{RESPONSE_HASH_HEX}"`.\n\n'
            "`finalize_certificates_of_completion` runs step 7 (response_ref equivalence): walks the "
            "chain-resolved SignatureAffirmation events, parses each `data.signedPayloadDigest` as "
            "sha-256 hex, records `had_resolvable_response = true`, finds no match, and emits "
            "`response_ref_mismatch` localized to the certificate's canonical_event_hash.\n\n"
            "Generator: `_generator/gen_export_010_certificate_of_completion.py`.\n"
        ),
    )


def gen_tamper_052(*, seed: bytes, kid: bytes, pubkey: bytes) -> None:
    """SignatureAffirmation `data.signedPayloadDigest` mutated to non-hex
    text while `signedPayloadDigestAlgorithm = "sha-256"` is preserved.
    Phase N posture: the WOS resolver fails closed with
    `MalformedResponseDigestError` and the verifier emits
    `malformed_response_digest`."""
    # 64-character non-hex marker. `Z` is intentionally outside the hex
    # alphabet so `parse_sha256_hex` rejects on the first nibble.
    bad_digest = "Z" * 64
    build_tamper_export(
        seed=seed,
        kid=kid,
        pubkey=pubkey,
        out_dir=OUT_TAMPER_052,
        description=(
            'ADR 0007 §"Verifier obligations" step 7 / Phase-N malformed-digest '
            'posture: SignatureAffirmation `data.signedPayloadDigest` carries '
            f'a 64-character non-hex marker (`{bad_digest}`) while '
            '`signedPayloadDigestAlgorithm = "sha-256"`. The WOS resolver '
            'recognizes the payload as a sha-256-claimed signing event but '
            'fails closed on hex parse; `finalize_certificates_of_completion` '
            'emits `malformed_response_digest` localized to the certificate '
            "event's canonical_event_hash. Generator: "
            "`_generator/gen_export_010_certificate_of_completion.py`."
        ),
        tamper_kind="malformed_response_digest",
        failing_event_id="",  # filled with cert canonical hash inside builder
        coverage_tr_core=[
            "TR-CORE-018",
            "TR-CORE-030",
            "TR-CORE-035",
            "TR-CORE-150",
            "TR-CORE-175",
        ],
        coverage_tr_op=[],
        cert_overrides={
            # The certificate's `response_ref` stays well-formed; the
            # malformed digest lives on the SignatureAffirmation record.
            "idempotency_key": b"tamper-052-cert-malformed-digest",
        },
        sigaff_signed_payload_digest_override=bad_digest,
        sigaff_idempotency_preimage_record_id="tamper-052-prov-001",
        description_suffix="Tamper: SignatureAffirmation signedPayloadDigest non-hex (tamper/052).",
        derivation=(
            "# Derivation — `tamper/052-cert-response-ref-malformed-digest`\n\n"
            "Starts from `export/010-certificate-of-completion-inline`. Event 1's "
            "`data.signedPayloadDigest` is rewritten to a 64-character non-hex marker "
            f"(`{bad_digest}`) while `signedPayloadDigestAlgorithm = \"sha-256\"` is "
            "preserved, so the WOS resolver still recognizes the payload as a sha-256-claimed "
            "signing event but cannot parse the digest as hex.\n\n"
            "Phase-N posture (Trellis review F2): the resolver returns "
            "`Err(ResolverError::MalformedResponseDigest)` (Rust) / raises "
            "`MalformedResponseDigestError` (Python) instead of silent-skipping. "
            "`finalize_certificates_of_completion` translates this into a fail-closed "
            "`malformed_response_digest` failure localized to the certificate event's "
            "`canonical_event_hash`.\n\n"
            "The certificate event itself carries a well-formed `chain_summary.response_ref` "
            "(byte-equal to the positive fixture); only the SignatureAffirmation record's "
            "digest text is malformed. This isolates the malformed-digest path from the "
            "mismatched-digest path covered by `tamper/024-cert-response-ref-mismatch`.\n\n"
            "Generator: `_generator/gen_export_010_certificate_of_completion.py`.\n"
        ),
    )


# ---------------------------------------------------------------------------
# Top-level main.
# ---------------------------------------------------------------------------


def main() -> None:
    seed, pubkey = load_seed_and_pubkey(KEY_ISSUER)
    kid = derive_kid(SUITE_ID, pubkey)

    build_export_010(seed=seed, kid=kid, pubkey=pubkey)
    gen_tamper_020(seed=seed, kid=kid, pubkey=pubkey)
    gen_tamper_022(seed=seed, kid=kid, pubkey=pubkey)
    gen_tamper_024(seed=seed, kid=kid, pubkey=pubkey)
    gen_tamper_052(seed=seed, kid=kid, pubkey=pubkey)


if __name__ == "__main__":
    main()
