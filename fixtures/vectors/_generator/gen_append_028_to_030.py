"""Generate byte-exact reference vectors `append/028..030` — ADR 0007
certificate-of-completion-composition positive corpus.

Authoring aid only. Each vector's `derivation.md` is the spec-prose
reproduction evidence. Determinism: two runs produce byte-identical output.

Vector matrix (ADR 0007 §"Fixture plan"):

  | dir                                                  | media         | signers | template_id | template_hash | extra                          |
  |------------------------------------------------------|---------------|---------|-------------|----------------|--------------------------------|
  | 028-certificate-of-completion-minimal-pdf            | application/pdf | 1     | null        | null           | intake-record-scoped           |
  | 029-certificate-of-completion-dual-signer-pdf        | application/pdf | 2     | reference   | non-null       | countersigned + case_ref       |
  | 030-certificate-of-completion-html-template          | text/html       | 1     | null        | non-null       | HTML→template_hash NOT NULL    |

Per ADR 0007 §"Wire shape" `PresentationArtifact.template_hash`: when
`media_type = "text/html"`, `template_hash` MUST be non-null even when
`template_id` is null. Vector 030 exercises that path.

All three vectors:

* Are independent genesis appends on distinct `ledger_scope` values
  (sequence = 0, prev_hash = null). Per-event `signing_events[i]` digests
  reference `append/019-wos-signature-affirmation`'s canonical event hash;
  in the genesis-append context the verifier explicitly skips step-5/6/7
  resolution (see `finalize_certificates_of_completion` Phase-1 chain-context
  posture in `integrity-verify::trellis`). Export-bundle resolution
  (Deliverable 3) ships in `export/010-certificate-of-completion-inline`.
* Sign the COSE_Sign1 envelope with `_keys/issuer-001.cose_key`.
* Carry the `trellis.certificate-of-completion.v1` payload under
  `EventPayload.extensions` (Core §6.7).
* Use `_keys/issuer-001.cose_key` for the operator attestation
  (`authority_class = "new"`); vector 029 also signs a second attestation
  under the same key for the countersigned posture (Phase-1 reference verifier
  is structural-only on attestation crypto — `attestation_signatures_well_formed`
  is the gate, not Ed25519 validity over `trellis-transition-attestation-v1`).
* Carry a 64-byte deterministic `presentation-artifact.bin` whose
  `presentation_artifact.content_hash` is SHA-256 under domain tag
  `trellis-presentation-artifact-v1` (ADR 0007 §"Wire shape" / Core §9.8).
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cbor2  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from _lib.byte_utils import (  # noqa: E402
    ALG_EDDSA,
    COSE_LABEL_ALG,
    COSE_LABEL_KID,
    COSE_LABEL_SUITE_ID,
    ARTIFACT_TYPE_CHECKPOINT,
    ARTIFACT_TYPE_EVENT,
    ARTIFACT_TYPE_MANIFEST,
    COSE_LABEL_ARTIFACT_TYPE,
    SUITE_ID_PHASE_1,
    dcbor,
    domain_separated_sha256,
    ts,
)


# ---------------------------------------------------------------------------
# Pinned paths.
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent  # fixtures/vectors/
KEY_ISSUER = ROOT / "_keys" / "issuer-001.cose_key"
SIGNATURE_AFFIRMATION_VECTOR = ROOT / "append" / "019-wos-signature-affirmation"


# ---------------------------------------------------------------------------
# Pinned constants shared across all three vectors.
# ---------------------------------------------------------------------------

CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0
EVENT_TYPE = b"trellis.certificate-of-completion.v1"
PAYLOAD_NONCE = b"\x00" * 12

# Event headers reuse the same authored_at; per-vector ledger_scope
# guarantees genesis sequence = 0 on each.
HOST_AUTHORED_AT = ts(1_776_900_000)
COMPLETED_AT = ts(1_776_899_500)     # ≤ HOST_AUTHORED_AT (causality)

SUITE_ID = SUITE_ID_PHASE_1

TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"
TAG_TRELLIS_TRANSITION_ATTESTATION_V1 = "trellis-transition-attestation-v1"
TAG_TRELLIS_PRESENTATION_ARTIFACT_V1 = "trellis-presentation-artifact-v1"

REFERENCE_TEMPLATE_ID = "trellis.reference.certificate-of-completion.v1"
# Pinned reference-template hash bytes; vector 029 + vector 030 cite the
# same `template_hash` value so the corpus is internally consistent. The
# bytes are an opaque 32-byte test marker, not derived from the actual
# reference template HTML — Deliverable 6 ships the real template, and a
# follow-on commit can re-tie this constant to the published hash. Until
# then, the template_hash field is a wire-shape pin (non-null fixity is
# what TR-OP-131 / ADR 0007 §"Wire shape" tests; byte equality with the
# published reference template is checked at deployment time).
REFERENCE_TEMPLATE_HASH_HEX = (
    "f1" * 32  # deterministic placeholder — see comment above
)


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def domain_separated_preimage(tag: str, component: bytes) -> bytes:
    tag_bytes = tag.encode("utf-8")
    return (
        len(tag_bytes).to_bytes(4, "big")
        + tag_bytes
        + len(component).to_bytes(4, "big")
        + component
    )


def load_cose_key(path: Path) -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(path.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    assert len(seed) == 32 and len(pubkey) == 32
    return seed, pubkey


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def load_signature_affirmation_canonical_hash() -> bytes:
    head = cbor2.loads((SIGNATURE_AFFIRMATION_VECTOR / "expected-append-head.cbor").read_bytes())
    digest = head["canonical_event_hash"]
    assert isinstance(digest, bytes) and len(digest) == 32
    return digest


def load_signature_affirmation_authored_at() -> list:
    """Per ADR 0007 step 6: `signer_display[i].signed_at` MUST exactly equal
    the resolved SignatureAffirmation event header's `authored_at`. Genesis
    fixtures don't exercise that path (cross-event resolution is deferred to
    the export-bundle path), but we set `signed_at` to the right value so
    the export-bundle vector (Deliverable 3) can reuse this fixture's shape
    without per-field re-stitching."""
    payload = cbor2.loads(
        (SIGNATURE_AFFIRMATION_VECTOR / "expected-event-payload.cbor").read_bytes()
    )
    authored_at = payload["header"]["authored_at"]
    assert isinstance(authored_at, list) and len(authored_at) == 2
    return authored_at


# ---------------------------------------------------------------------------
# Attestation builder (Companion Appendix A.5 shape, reused by ADR 0007).
# ---------------------------------------------------------------------------


def build_attestation(
    *,
    authority: str,
    authority_class: str,
    signing_seed: bytes,
    transition_id: str,
    effective_at,
) -> dict:
    """Per ADR 0007 §"Verifier obligations" step 3: attestations reuse the
    Companion §A.5 shape verbatim, signed under
    `trellis-transition-attestation-v1` over
    `dCBOR([transition_id, effective_at, authority_class])`."""
    preimage_inner = dcbor([transition_id, effective_at, authority_class])
    signing_preimage = domain_separated_preimage(
        TAG_TRELLIS_TRANSITION_ATTESTATION_V1, preimage_inner,
    )
    sk = Ed25519PrivateKey.from_private_bytes(signing_seed)
    signature = sk.sign(signing_preimage)
    assert len(signature) == 64
    return {
        "authority":       authority,
        "authority_class": authority_class,
        "signature":       signature,
    }


# ---------------------------------------------------------------------------
# Presentation-artifact builder.
# ---------------------------------------------------------------------------


def build_presentation_artifact_bytes(vector_id: str) -> bytes:
    """64-byte deterministic test artifact. The ASCII content names the
    vector so a byte-level inspection makes the binding obvious; the rest
    is null-padding to 64 bytes total."""
    body = f"trellis-certificate-of-completion-test-artifact-{vector_id}\n".encode("utf-8")
    assert len(body) <= 64, f"artifact body too long: {len(body)} bytes"
    return body + b"\x00" * (64 - len(body))


def presentation_artifact_content_hash(artifact_bytes: bytes) -> bytes:
    """ADR 0007 §"Wire shape" `PresentationArtifact.content_hash`:
    SHA-256 under domain tag `trellis-presentation-artifact-v1`."""
    return domain_separated_sha256(TAG_TRELLIS_PRESENTATION_ARTIFACT_V1, artifact_bytes)


# ---------------------------------------------------------------------------
# Certificate payload builder (ADR 0007 §"Wire shape").
# ---------------------------------------------------------------------------


def build_signer_display_entry(
    *,
    principal_ref: str,
    display_name: str,
    display_role: str | None,
    signed_at: int,
) -> dict:
    return {
        "principal_ref": principal_ref,
        "display_name":  display_name,
        "display_role":  display_role,
        "signed_at":     signed_at,
    }


def build_chain_summary(
    *,
    signer_count: int,
    signer_display: list[dict],
    response_ref: bytes | None,
    workflow_status: str,
    impact_level: str | None,
    covered_claims: list[str],
) -> dict:
    return {
        "signer_count":    signer_count,
        "signer_display":  signer_display,
        "response_ref":    response_ref,
        "workflow_status": workflow_status,
        "impact_level":    impact_level,
        "covered_claims":  covered_claims,
    }


def build_presentation_artifact(
    *,
    content_hash: bytes,
    media_type: str,
    byte_length: int,
    attachment_id: str,
    template_id: str | None,
    template_hash: bytes | None,
) -> dict:
    return {
        "content_hash":  content_hash,
        "media_type":    media_type,
        "byte_length":   byte_length,
        "attachment_id": attachment_id,
        "template_id":   template_id,
        "template_hash": template_hash,
    }


def build_certificate_payload(
    *,
    certificate_id: str,
    case_ref: str | None,
    completed_at: int,
    presentation_artifact: dict,
    chain_summary: dict,
    signing_events: list[bytes],
    workflow_ref: str | None,
    attestations: list[dict],
) -> dict:
    return {
        "certificate_id":        certificate_id,
        "case_ref":              case_ref,
        "completed_at":          completed_at,
        "presentation_artifact": presentation_artifact,
        "chain_summary":         chain_summary,
        "signing_events":        signing_events,
        "workflow_ref":          workflow_ref,
        "attestations":          attestations,
        "extensions":            None,
    }


# ---------------------------------------------------------------------------
# Event envelope builders (mirror gen_append_023_to_027 shape).
# ---------------------------------------------------------------------------


def build_event_header() -> dict:
    return {
        "event_type":             EVENT_TYPE,
        "authored_at":             HOST_AUTHORED_AT,
        "retention_tier":          RETENTION_TIER,
        "classification":          CLASSIFICATION,
        "outcome_commitment":      None,
        "subject_ref_commitment":  None,
        "tag_commitment":          None,
        "witness_ref":             None,
        "extensions":              None,
    }


def build_payload_ref(payload_marker: bytes) -> dict:
    return {
        "ref_type":   "inline",
        "ciphertext": payload_marker,
        "nonce":      PAYLOAD_NONCE,
    }


def build_key_bag() -> dict:
    return {"entries": []}


def build_author_event_hash_preimage(
    *,
    ledger_scope: bytes,
    sequence: int,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
    extensions: dict,
    idempotency_key: bytes,
) -> dict:
    return {
        "version":         1,
        "ledger_scope":    ledger_scope,
        "sequence":        sequence,
        "prev_hash":       None,
        "causal_deps":     None,
        "content_hash":    content_hash,
        "header":          header,
        "commitments":     None,
        "payload_ref":     payload_ref,
        "key_bag":         key_bag,
        "idempotency_key": idempotency_key,
        "extensions":      extensions,
    }


def build_event_payload(
    *,
    ledger_scope: bytes,
    sequence: int,
    author_event_hash: bytes,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
    extensions: dict,
    idempotency_key: bytes,
) -> dict:
    return {
        "version":           1,
        "ledger_scope":      ledger_scope,
        "sequence":          sequence,
        "prev_hash":         None,
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


def build_canonical_event_hash_preimage(
    ledger_scope: bytes, event_payload: dict
) -> dict:
    return {
        "version":       1,
        "ledger_scope":  ledger_scope,
        "event_payload": event_payload,
    }


def build_protected_header(kid: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> dict:
    return {
        COSE_LABEL_ALG:      ALG_EDDSA,
        COSE_LABEL_KID:      kid,
        COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
    }


def build_sig_structure(protected_bstr: bytes, payload_bstr: bytes) -> bytes:
    return dcbor(["Signature1", protected_bstr, b"", payload_bstr])


def build_append_head(scope: bytes, sequence: int, canonical_event_hash: bytes) -> dict:
    return {
        "scope":                scope,
        "sequence":             sequence,
        "canonical_event_hash": canonical_event_hash,
    }


def write_bytes(out_dir: Path, name: str, data: bytes) -> str:
    path = out_dir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"  {name:55s}  {len(data):>5d} bytes  sha256={digest}")
    return digest


def write_text(out_dir: Path, name: str, text: str) -> None:
    path = out_dir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


# ---------------------------------------------------------------------------
# Per-vector specs.
# ---------------------------------------------------------------------------


def vector_specs(
    *,
    sigaff_canonical_hash: bytes,
    sigaff_authored_at: int,
) -> list[dict]:
    """Pinned spec for each of append/028..030.

    `signing_events[0]` references the canonical event hash of
    `append/019-wos-signature-affirmation`. Vector 029 lists it twice
    (single underlying ceremony, two signers in workflow order); the
    Phase-1 reference verifier doesn't crypto-distinguish duplicate
    signing-event references — it cross-checks each `signer_display[i]`
    against the resolved event's principal/timestamp."""
    template_hash = bytes.fromhex(REFERENCE_TEMPLATE_HASH_HEX)

    return [
        {
            "dir":              "append/028-certificate-of-completion-minimal-pdf",
            "ledger_scope":     b"trellis-cert:test:028-minimal",
            "vector_id":        "028",
            "certificate_id":   "urn:trellis:certificate:test:028",
            "transition_id":    "urn:trellis:certificate:test:028",
            "case_ref":         None,                          # intake-record-scoped
            "media_type":       "application/pdf",
            "template_id":      None,
            "template_hash":    None,
            "workflow_status":  "completed",
            "impact_level":     None,                          # signing-only
            "workflow_ref":     None,
            "response_ref":     None,
            "covered_claims":   [],
            "signing_events":   [sigaff_canonical_hash],
            "signer_display":   [
                build_signer_display_entry(
                    principal_ref="applicant",
                    display_name="Applicant Test User",
                    display_role="applicant",
                    signed_at=sigaff_authored_at,
                ),
            ],
            "attestation_classes": ["new"],
            "idempotency_key":  b"idemp-append-028",
            "attachment_id":    "urn:trellis:attachment:cert-028",
        },
        {
            "dir":              "append/029-certificate-of-completion-dual-signer-pdf",
            "ledger_scope":     b"trellis-cert:test:029-dual",
            "vector_id":        "029",
            "certificate_id":   "urn:trellis:certificate:test:029",
            "transition_id":    "urn:trellis:certificate:test:029",
            "case_ref":         "urn:trellis:case:test-cert-029",
            "media_type":       "application/pdf",
            "template_id":      REFERENCE_TEMPLATE_ID,
            "template_hash":    template_hash,                 # non-null per ADR 0007
            "workflow_status":  "countersigned",
            "impact_level":     "moderate",
            "workflow_ref":     "urn:wos:workflow-execution:test-cert-029",
            "response_ref":     None,                          # SigAff covers a URL, not sha256:
            "covered_claims":   [],
            "signing_events":   [sigaff_canonical_hash, sigaff_canonical_hash],
            "signer_display":   [
                build_signer_display_entry(
                    principal_ref="applicant",
                    display_name="Applicant Test User",
                    display_role="applicant",
                    signed_at=sigaff_authored_at,
                ),
                build_signer_display_entry(
                    principal_ref="applicant",
                    display_name="Counter-Signer Test User",
                    display_role="witness",
                    signed_at=sigaff_authored_at,
                ),
            ],
            "attestation_classes": ["new", "new"],             # operator + counter-signer
            "idempotency_key":  b"idemp-append-029",
            "attachment_id":    "urn:trellis:attachment:cert-029",
        },
        {
            "dir":              "append/030-certificate-of-completion-html-template",
            "ledger_scope":     b"trellis-cert:test:030-html",
            "vector_id":        "030",
            "certificate_id":   "urn:trellis:certificate:test:030",
            "transition_id":    "urn:trellis:certificate:test:030",
            "case_ref":         None,
            "media_type":       "text/html",
            "template_id":      None,                           # ADR 0007: HTML allows id=null
            "template_hash":    template_hash,                  # but template_hash MUST be non-null
            "workflow_status":  "completed",
            "impact_level":     None,
            "workflow_ref":     None,
            "response_ref":     None,
            "covered_claims":   [],
            "signing_events":   [sigaff_canonical_hash],
            "signer_display":   [
                build_signer_display_entry(
                    principal_ref="applicant",
                    display_name="Applicant Test User",
                    display_role="applicant",
                    signed_at=sigaff_authored_at,
                ),
            ],
            "attestation_classes": ["new"],
            "idempotency_key":  b"idemp-append-030",
            "attachment_id":    "urn:trellis:attachment:cert-030",
        },
    ]


# ---------------------------------------------------------------------------
# Per-vector main.
# ---------------------------------------------------------------------------


def generate_vector(
    spec: dict,
    *,
    issuer_seed: bytes,
    issuer_pub: bytes,
    kid: bytes,
) -> tuple[bytes, str]:
    """Returns (canonical_event_hash, manifest-coverage-tr_op-or-empty)."""
    out_dir = ROOT / spec["dir"]
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating vector at {out_dir.relative_to(ROOT.parent.parent)}/")

    # Presentation artifact bytes (committed alongside the vector).
    artifact_bytes = build_presentation_artifact_bytes(spec["vector_id"])
    write_bytes(out_dir, "presentation-artifact.bin", artifact_bytes)
    pa_content_hash = presentation_artifact_content_hash(artifact_bytes)

    # Build attestations per spec's class list. Each attestation signs the
    # `trellis-transition-attestation-v1` preimage with issuer-001's seed.
    # Phase-1 reference verifier checks structural shape only; A.5 shape pin
    # is enforced via `attestation_signatures_well_formed`.
    attestations: list[dict] = []
    for idx, klass in enumerate(spec["attestation_classes"]):
        # Counter-signer attestation in vector 029 is a separate attestation
        # row; we encode it under the same operator key (test fixture)
        # because Phase-1 attestation-crypto verification is structural-only.
        if idx == 0:
            authority = "urn:trellis:authority:test-cm-a-authority"
        else:
            authority = f"urn:trellis:authority:test-counter-signer-{idx:03d}"
        attestations.append(
            build_attestation(
                authority=authority,
                authority_class=klass,
                signing_seed=issuer_seed,
                transition_id=spec["transition_id"],
                effective_at=COMPLETED_AT,
            )
        )

    # Commit the attestation preimage so reviewers can re-verify the
    # `trellis-transition-attestation-v1` domain-separation by hand. We
    # emit one file per (idx, class) for symmetry with the multi-attestation
    # vectors (029).
    for idx, klass in enumerate(spec["attestation_classes"]):
        preimage_inner = dcbor([spec["transition_id"], COMPLETED_AT, klass])
        write_bytes(
            out_dir,
            f"input-attestation-preimage-{idx:02d}-{klass}.cbor",
            preimage_inner,
        )

    # Build PresentationArtifact + ChainSummary + CertificateOfCompletionPayload.
    presentation_artifact = build_presentation_artifact(
        content_hash=pa_content_hash,
        media_type=spec["media_type"],
        byte_length=len(artifact_bytes),
        attachment_id=spec["attachment_id"],
        template_id=spec["template_id"],
        template_hash=spec["template_hash"],
    )
    chain_summary = build_chain_summary(
        signer_count=len(spec["signing_events"]),
        signer_display=spec["signer_display"],
        response_ref=spec["response_ref"],
        workflow_status=spec["workflow_status"],
        impact_level=spec["impact_level"],
        covered_claims=spec["covered_claims"],
    )
    certificate_payload = build_certificate_payload(
        certificate_id=spec["certificate_id"],
        case_ref=spec["case_ref"],
        completed_at=COMPLETED_AT,
        presentation_artifact=presentation_artifact,
        chain_summary=chain_summary,
        signing_events=spec["signing_events"],
        workflow_ref=spec["workflow_ref"],
        attestations=attestations,
    )
    extensions = {EVENT_TYPE.decode("utf-8"): certificate_payload}

    # Commit the certificate payload preimage so reviewers can inspect it.
    write_bytes(
        out_dir,
        "input-certificate-payload.cbor",
        dcbor(certificate_payload),
    )

    # Minimal PayloadInline — the certificate event carries an opaque
    # marker; the certificate payload IS the extension. Distinct marker per
    # vector so content_hash differs (independent test ledgers).
    payload_marker = (
        f"certificate-of-completion-marker-{spec['vector_id']}".encode("utf-8")
    )
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_marker)

    header = build_event_header()
    payload_ref = build_payload_ref(payload_marker)
    key_bag = build_key_bag()

    # AuthorEventHashPreimage → author_event_hash (Core §9.5, §9.1).
    authored_map = build_author_event_hash_preimage(
        ledger_scope=spec["ledger_scope"],
        sequence=0,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
        extensions=extensions,
        idempotency_key=spec["idempotency_key"],
    )
    authored_bytes = dcbor(authored_map)
    write_bytes(out_dir, "input-author-event-hash-preimage.cbor", authored_bytes)

    author_event_hash = hashlib.sha256(
        domain_separated_preimage(TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes)
    ).digest()
    write_bytes(out_dir, "author-event-hash.bin", author_event_hash)

    # EventPayload (Core §6.1).
    event_payload = build_event_payload(
        ledger_scope=spec["ledger_scope"],
        sequence=0,
        author_event_hash=author_event_hash,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
        extensions=extensions,
        idempotency_key=spec["idempotency_key"],
    )
    event_payload_bytes = dcbor(event_payload)
    write_bytes(out_dir, "expected-event-payload.cbor", event_payload_bytes)

    # Protected header + Sig_structure + Ed25519 signature.
    protected_map = build_protected_header(kid)
    protected_map_bytes = dcbor(protected_map)
    sig_structure = build_sig_structure(protected_map_bytes, event_payload_bytes)
    write_bytes(out_dir, "sig-structure.bin", sig_structure)

    sk = Ed25519PrivateKey.from_private_bytes(issuer_seed)
    signature = sk.sign(sig_structure)
    assert len(signature) == 64

    cose_sign1 = cbor2.CBORTag(
        18, [protected_map_bytes, {}, event_payload_bytes, signature],
    )
    cose_sign1_bytes = dcbor(cose_sign1)
    write_bytes(out_dir, "expected-event.cbor", cose_sign1_bytes)

    # canonical_event_hash + AppendHead.
    canonical_preimage = dcbor(
        build_canonical_event_hash_preimage(spec["ledger_scope"], event_payload)
    )
    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1, canonical_preimage
    )
    append_head = build_append_head(
        spec["ledger_scope"], 0, canonical_event_hash
    )
    write_bytes(out_dir, "expected-append-head.cbor", dcbor(append_head))

    print()
    print(f"  ledger_scope               = {spec['ledger_scope']!r}")
    print(f"  kid                        = {kid.hex()}")
    print(f"  presentation content_hash  = {pa_content_hash.hex()}")
    print(f"  content_hash               = {content_hash.hex()}")
    print(f"  author_event_hash          = {author_event_hash.hex()}")
    print(f"  canonical_event_hash       = {canonical_event_hash.hex()}")

    write_manifest(spec, out_dir)
    write_derivation(spec, out_dir, canonical_event_hash, pa_content_hash)
    return canonical_event_hash, ""


# ---------------------------------------------------------------------------
# manifest.toml + derivation.md per vector.
# ---------------------------------------------------------------------------


def manifest_for(spec: dict) -> str:
    # Per-vector tr_core baseline: every certificate-of-completion vector
    # exercises canonical-append discipline + ADR 0007 wire-shape pin.
    # 029 adds chain-summary invariants (TR-CORE-147). 030 adds HTML
    # template_hash discipline (TR-OP-131).
    base_tr_core = [
        "TR-CORE-001",
        "TR-CORE-018",
        "TR-CORE-021",
        "TR-CORE-030",
        "TR-CORE-031",
        "TR-CORE-035",
        "TR-CORE-050",
        "TR-CORE-051",
        "TR-CORE-080",
        "TR-CORE-146",
    ]
    extra_tr_core: list[str] = []
    extra_tr_op: list[str] = []
    if spec["vector_id"] == "029":
        extra_tr_core.append("TR-CORE-147")  # chain-summary invariants exercised
        extra_tr_core.append("TR-CORE-148")  # template_hash binding (operator-pinned)
    if spec["vector_id"] == "030":
        # HTML wire-shape rule lives on the operator side via TR-OP-131.
        extra_tr_op.append("TR-OP-131")

    tr_core = base_tr_core + extra_tr_core
    tr_op_block = ""
    if extra_tr_op:
        tr_op_lines = ",\n    ".join(f'"{x}"' for x in extra_tr_op)
        tr_op_block = f'tr_op = [\n    {tr_op_lines},\n]\n'

    tr_core_lines = ",\n    ".join(f'"{x}"' for x in tr_core)

    description = {
        "028": (
            "ADR 0007 §\"Wire shape\" minimal-PDF positive vector. Single-signer "
            "certificate-of-completion event (`trellis.certificate-of-completion.v1`) "
            "with `media_type = application/pdf`, `template_id = null`, `template_hash = null`, "
            "`case_ref = null` (intake-record-scoped), one `signing_events` digest pointing at "
            "`append/019-wos-signature-affirmation`, one `attestations` row signed under "
            "`trellis-transition-attestation-v1`. Genesis sequence on its own ledger_scope; "
            "per-event verifier path admits the unresolved `signing_events` reference per "
            "`finalize_certificates_of_completion` Phase-1 chain-context posture."
        ),
        "029": (
            "ADR 0007 §\"Wire shape\" dual-signer countersigned-PDF positive vector. "
            "Two `signing_events` references (workflow order), `workflow_status = countersigned`, "
            "`impact_level = moderate`, `case_ref` set, two attestations, "
            "`template_id` + non-null `template_hash` (operator-pinned reference template)."
        ),
        "030": (
            "ADR 0007 §\"Wire shape\" HTML-template positive vector. `media_type = text/html`, "
            "`template_id = null`, `template_hash` non-null per ADR 0007 §\"Wire shape\" "
            "PresentationArtifact.template_hash (HTML binding requires a template pin even when "
            "`template_id` is null)."
        ),
    }[spec["vector_id"]]

    return f'''id          = "{spec["dir"]}"
op          = "append"
status      = "active"
description = """{description}"""

[coverage]
tr_core = [
    {tr_core_lines},
]
{tr_op_block}[inputs]
signing_key                  = "../../_keys/issuer-001.cose_key"
authored_event               = "input-author-event-hash-preimage.cbor"
certificate_payload          = "input-certificate-payload.cbor"
presentation_artifact        = "presentation-artifact.bin"

[expected]
author_event_hash = "author-event-hash.bin"
canonical_event   = "expected-event-payload.cbor"
signed_event      = "expected-event.cbor"
append_head       = "expected-append-head.cbor"

[derivation]
document = "derivation.md"
'''


def write_manifest(spec: dict, out_dir: Path) -> None:
    write_text(out_dir, "manifest.toml", manifest_for(spec))


def derivation_for(
    spec: dict, canonical_event_hash: bytes, pa_content_hash: bytes
) -> str:
    return f"""# Derivation — `{spec["dir"]}`

ADR 0007 §\"Wire shape\" positive vector for `trellis.certificate-of-completion.v1`.

## Inputs

- Issuer key: `_keys/issuer-001.cose_key` (Ed25519 / suite-id 1).
- Presentation artifact: `presentation-artifact.bin` (64 deterministic bytes).
- Reference SignatureAffirmation: `append/019-wos-signature-affirmation`'s
  canonical event hash is the value of every `signing_events[i]` digest.

## Construction

1. **Presentation artifact content_hash.** Apply Core §9.1 domain-separated
   SHA-256 with tag `trellis-presentation-artifact-v1` over the artifact
   bytes. Result: `{pa_content_hash.hex()}`.

2. **CertificateOfCompletionPayload.** Build per ADR 0007 §\"Wire shape\".
   Field choices:
   - `certificate_id` = `{spec["certificate_id"]}`
   - `case_ref` = `{spec["case_ref"]!r}`
   - `completed_at` = `{COMPLETED_AT}`
   - `presentation_artifact.media_type` = `{spec["media_type"]!r}`
   - `presentation_artifact.template_id` = `{spec["template_id"]!r}`
   - `presentation_artifact.template_hash` = `{
        "non-null (32 bytes)" if spec["template_hash"] is not None else "null"
   }`
   - `chain_summary.signer_count` = `{len(spec["signing_events"])}`
   - `chain_summary.workflow_status` = `{spec["workflow_status"]!r}`
   - `chain_summary.impact_level` = `{spec["impact_level"]!r}`
   - `signing_events` = [`<append/019 canonical_event_hash>` × {len(spec["signing_events"])}]
   - `attestations` = {len(spec["attestation_classes"])} × `Attestation` row
     (Companion §A.5 shape; signed under `trellis-transition-attestation-v1`).

3. **EventPayload.extensions** carries the certificate payload under key
   `trellis.certificate-of-completion.v1` (Core §6.7 registration row).

4. **Envelope.** Genesis sequence = 0, `prev_hash = null`, `ledger_scope =
   {spec["ledger_scope"]!r}`. Standard Trellis Core §6 envelope; signed under
   `_keys/issuer-001.cose_key` (Ed25519, suite-id 1).

5. **Hashes.** Author/canonical hashes follow Core §9.5 / §9.1 framing.
   Final `canonical_event_hash` = `{canonical_event_hash.hex()}`.

## Phase-1 verifier posture

Per `finalize_certificates_of_completion` in `integrity-verify::trellis`:
genesis-append context skips step 5 / 6 / 7 cross-event resolution because
the in-scope `events` slice does not carry the referenced
SignatureAffirmation. Step 4 (attachment lineage + content-hash recompute)
is wholly deferred to the export-bundle path — see
`export/010-certificate-of-completion-inline` for the resolvable lineage.

This vector therefore exercises:
- CDDL decode (step 1)
- Per-event chain-summary invariants (step 2 first clause):
  `signer_count == len(signing_events) == len(signer_display)`.
- Phase-1 structural attestation contract (step 3): each attestation row is
  64 bytes signed over the A.5 preimage.
- HTML→template_hash non-null rule (ADR 0007 §\"Wire shape\") iff
  `media_type = text/html` (vector 030).

Generator: `fixtures/vectors/_generator/gen_append_028_to_030.py`.
"""


def write_derivation(
    spec: dict, out_dir: Path, canonical_event_hash: bytes, pa_content_hash: bytes
) -> None:
    write_text(
        out_dir,
        "derivation.md",
        derivation_for(spec, canonical_event_hash, pa_content_hash),
    )


# ---------------------------------------------------------------------------
# Top-level main: runs all three.
# ---------------------------------------------------------------------------


def main() -> None:
    issuer_seed, issuer_pub = load_cose_key(KEY_ISSUER)
    kid = derive_kid(SUITE_ID, issuer_pub)
    sigaff_canonical = load_signature_affirmation_canonical_hash()
    sigaff_authored_at = load_signature_affirmation_authored_at()

    for spec in vector_specs(
        sigaff_canonical_hash=sigaff_canonical,
        sigaff_authored_at=sigaff_authored_at,
    ):
        generate_vector(
            spec,
            issuer_seed=issuer_seed,
            issuer_pub=issuer_pub,
            kid=kid,
        )


if __name__ == "__main__":
    main()
