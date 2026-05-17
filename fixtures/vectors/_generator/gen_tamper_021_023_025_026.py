"""Generate ledger-only ADR 0007 tamper vectors:
`tamper/021-cert-signer-count-mismatch`,
`tamper/023-cert-attestation-malformed`,
`tamper/025-cert-html-missing-template-hash`,
`tamper/026-cert-certificate-id-collision`.

These four tampers run through `verify_tampered_ledger` (no export ZIP).
The other three certificate tampers (`020`, `022`, `024`) require
export-bundle context (attachment lineage / chain-resolved
SignatureAffirmation) and live in `gen_export_010_certificate_of_completion.py`.

Per-vector strategy:

* `tamper/021` — start from `append/029` (dual-signer); rewrite the
  certificate payload's `chain_summary.signer_count` from 2 to 3 while
  leaving `signing_events` length at 2. Structural CDDL decode fails
  per ADR 0007 §"Verifier obligations" step 2; verifier emits
  `certificate_chain_summary_mismatch`.

* `tamper/023` — start from `append/028` (single-signer); truncate the
  attestation `signature` from 64 to 63 bytes. Phase-1 verifier checks
  structural shape (`signature.len() == 64`); short signatures flip
  `attestation_signatures_well_formed = false` → `attestation_insufficient`
  per `finalize_certificates_of_completion` step 3. (Crypto-verification
  rides Phase-2+; a single-byte flip on a 64-byte signature would not
  trigger the Phase-1 structural failure mode — only length deviation
  does — so we exercise the operative path.)

* `tamper/025` — start from `append/030` (HTML); rewrite the
  presentation_artifact's `template_hash` from non-null to null while
  leaving `media_type = "text/html"`. ADR 0007 §"Wire shape" requires
  non-null template_hash for HTML; verifier emits `malformed_cose` per
  the §19.1 generic-structure-failure clause (no dedicated tamper_kind
  for this case in the current registry).

* `tamper/026` — chain two byte-different certificate events with the same
  `certificate_id` (one based on append/028 shape, one with a different
  presentation_artifact.content_hash). ADR 0007 §"Field semantics"
  `certificate_id` clause: the verifier emits `certificate_id_collision`
  for the second event's canonical hash.

Each tamper resigns the COSE_Sign1 envelope after the payload mutation.
Idempotency keys per tamper are pinned distinct from the source vector
to avoid §17.3 collision under combined replay.
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


ROOT = Path(__file__).resolve().parent.parent
KEY_ISSUER = ROOT / "_keys" / "issuer-001.cose_key"

CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0
EVENT_TYPE = b"trellis.certificate-of-completion.v1"
PAYLOAD_NONCE = b"\x00" * 12
SUITE_ID = SUITE_ID_PHASE_1

TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"


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
    return cose_key[-4], cose_key[-2]


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


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


def cose_sign1(seed: bytes, kid: bytes, payload_bytes: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> bytes:
    protected = dcbor(
        {
            COSE_LABEL_ALG: ALG_EDDSA,
            COSE_LABEL_KID: kid,
            COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
        }
    )
    sig_structure = dcbor(["Signature1", protected, b"", payload_bytes])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    return dcbor(
        cbor2.CBORTag(18, [protected, {}, payload_bytes, signature])
    )


def build_signing_key_registry(kid: bytes, pubkey: bytes) -> bytes:
    """Phase-1 flat signing-key registry (Core §8.2 legacy shape; mirrors
    the shape used by `gen_tamper_017_to_018`)."""
    return dcbor(
        [
            {
                "kid":     kid,
                "pubkey":  pubkey,
                "status":  1,                       # Active
                "valid_to": None,
            }
        ]
    )


def build_event_header(authored_at: list) -> dict:
    return {
        "event_type":             EVENT_TYPE,
        "authored_at":             authored_at,
        "retention_tier":          RETENTION_TIER,
        "classification":          CLASSIFICATION,
        "outcome_commitment":      None,
        "subject_ref_commitment":  None,
        "tag_commitment":          None,
        "witness_ref":             None,
        "extensions":              None,
    }


def build_event_payload(
    *,
    ledger_scope: bytes,
    sequence: int,
    prev_hash: bytes | None,
    authored_at: list,
    certificate_payload: dict,
    idempotency_key: bytes,
    payload_marker: bytes,
) -> tuple[dict, bytes, bytes, bytes]:
    """Builds the AuthorEventHashPreimage → EventPayload pair, returning
    (event_payload_map, event_payload_bytes, author_event_hash, canonical_event_hash).
    """
    extensions = {EVENT_TYPE.decode("utf-8"): certificate_payload}
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_marker)
    header = build_event_header(authored_at)
    payload_ref = {
        "ref_type":   "inline",
        "ciphertext": payload_marker,
        "nonce":      PAYLOAD_NONCE,
    }
    key_bag = {"entries": []}
    authored_map = {
        "version":         1,
        "ledger_scope":    ledger_scope,
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
        "ledger_scope":      ledger_scope,
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
            "ledger_scope":  ledger_scope,
            "event_payload": event_payload,
        }
    )
    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1, canonical_preimage
    )
    return event_payload, event_payload_bytes, author_event_hash, canonical_event_hash


def load_certificate_payload(append_dir: Path) -> dict:
    """Read the source vector's certificate payload preimage and return it
    as a Python dict (mutable). Mirrors the in-memory shape used by
    `gen_append_028_to_030`."""
    return cbor2.loads((append_dir / "input-certificate-payload.cbor").read_bytes())


def load_source_event_metadata(append_dir: Path) -> dict:
    """Pull the ledger_scope, authored_at, sequence, prev_hash from the
    source vector. We re-stitch the envelope around the mutated payload."""
    payload = cbor2.loads((append_dir / "expected-event-payload.cbor").read_bytes())
    return {
        "ledger_scope": payload["ledger_scope"],
        "authored_at":  payload["header"]["authored_at"],
        "payload_marker": payload["payload_ref"]["ciphertext"],
    }


# ---------------------------------------------------------------------------
# tamper/021 — chain_summary.signer_count rewritten 2 → 3.
# ---------------------------------------------------------------------------


def gen_tamper_021(*, issuer_seed: bytes, issuer_pub: bytes, kid: bytes) -> str:
    src = ROOT / "append" / "029-certificate-of-completion-dual-signer-pdf"
    out_dir = ROOT / "tamper" / "021-cert-signer-count-mismatch"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {out_dir.relative_to(ROOT.parent.parent)}/")

    cert = load_certificate_payload(src)
    meta = load_source_event_metadata(src)
    # Mutation: signer_count 2 → 3 while signing_events stays at len 2.
    # ADR 0007 §"Verifier obligations" step 2 first clause violates;
    # `decode_certificate_payload` returns Err with kind
    # `certificate_chain_summary_mismatch`.
    cert["chain_summary"]["signer_count"] = 3

    _, payload_bytes, author_event_hash, canonical_hash = build_event_payload(
        ledger_scope=meta["ledger_scope"],
        sequence=0,
        prev_hash=None,
        authored_at=meta["authored_at"],
        certificate_payload=cert,
        idempotency_key=b"tamper-021-cert-signer-count",
        payload_marker=meta["payload_marker"],
    )
    signed = cose_sign1(issuer_seed, kid, payload_bytes)
    ledger = dcbor([cbor2.loads(signed)])
    write_bytes(out_dir, "input-tampered-ledger.cbor", ledger)
    write_bytes(
        out_dir,
        "input-signing-key-registry.cbor",
        build_signing_key_registry(kid, issuer_pub),
    )
    write_bytes(out_dir, "input-tampered-event.cbor", signed)

    write_text(
        out_dir,
        "manifest.toml",
        f'''id          = "tamper/021-cert-signer-count-mismatch"
op          = "tamper"
status      = "active"
description = """ADR 0007 §"Verifier obligations" step 2 violation: certificate `chain_summary.signer_count = 3` but `len(signing_events) = 2` (and `len(signer_display) = 2`). Source: `append/029-certificate-of-completion-dual-signer-pdf` with `signer_count` rewritten to 3. CDDL decode flips integrity via `certificate_chain_summary_mismatch`. Generator: `_generator/gen_tamper_021_023_025_026.py`."""

[coverage]
tr_core = ["TR-CORE-018", "TR-CORE-030", "TR-CORE-035", "TR-CORE-147"]

[inputs]
ledger               = "input-tampered-ledger.cbor"
tampered_event       = "input-tampered-event.cbor"
signing_key_registry = "input-signing-key-registry.cbor"

[expected.report]
structure_verified   = false
integrity_verified   = false
readability_verified = false
tamper_kind          = "certificate_chain_summary_mismatch"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        out_dir,
        "derivation.md",
        f"""# Derivation — `tamper/021-cert-signer-count-mismatch`

Starts from `append/029-certificate-of-completion-dual-signer-pdf`, rewrites
`chain_summary.signer_count` from `2` to `3` while `signing_events` length
stays `2`. Per ADR 0007 §"Verifier obligations" step 2 first invariant
(`signer_count == len(signing_events)`), `decode_certificate_payload`
returns `Err(VerifyError::with_kind(..., "certificate_chain_summary_mismatch"))`,
which `_verify_event_set` surfaces as a fatal `tamper_kind`.

Failing canonical_event_hash: `{canonical_hash.hex()}`.

Generator: `_generator/gen_tamper_021_023_025_026.py`.
""",
    )
    return canonical_hash.hex()


# ---------------------------------------------------------------------------
# tamper/023 — attestations[0].signature truncated 64 → 63 bytes.
# ---------------------------------------------------------------------------


def gen_tamper_023(*, issuer_seed: bytes, issuer_pub: bytes, kid: bytes) -> str:
    src = ROOT / "append" / "028-certificate-of-completion-minimal-pdf"
    out_dir = ROOT / "tamper" / "023-cert-attestation-malformed"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {out_dir.relative_to(ROOT.parent.parent)}/")

    cert = load_certificate_payload(src)
    meta = load_source_event_metadata(src)
    # Mutation: truncate attestations[0].signature to 63 bytes. Phase-1
    # verifier flips `attestation_signatures_well_formed = false` →
    # `attestation_insufficient` per `finalize_certificates_of_completion`
    # step 3 (Phase-1 structural attestation contract; crypto verification
    # rides Phase-2+).
    sig = cert["attestations"][0]["signature"]
    assert isinstance(sig, bytes) and len(sig) == 64
    cert["attestations"][0]["signature"] = sig[:63]

    _, payload_bytes, author_event_hash, canonical_hash = build_event_payload(
        ledger_scope=meta["ledger_scope"],
        sequence=0,
        prev_hash=None,
        authored_at=meta["authored_at"],
        certificate_payload=cert,
        idempotency_key=b"tamper-023-cert-attestation",
        payload_marker=meta["payload_marker"],
    )
    signed = cose_sign1(issuer_seed, kid, payload_bytes)
    ledger = dcbor([cbor2.loads(signed)])
    write_bytes(out_dir, "input-tampered-ledger.cbor", ledger)
    write_bytes(
        out_dir,
        "input-signing-key-registry.cbor",
        build_signing_key_registry(kid, issuer_pub),
    )
    write_bytes(out_dir, "input-tampered-event.cbor", signed)

    write_text(
        out_dir,
        "manifest.toml",
        f'''id          = "tamper/023-cert-attestation-malformed"
op          = "tamper"
status      = "active"
description = """ADR 0007 §"Verifier obligations" step 3 violation: certificate `attestations[0].signature` truncated from 64 → 63 bytes. Source: `append/028-certificate-of-completion-minimal-pdf` with attestation signature shortened. Phase-1 reference verifier emits `attestation_insufficient` (existing Core §19.1 kind, reused per ADR 0007 §"Verifier obligations" step 3). Generator: `_generator/gen_tamper_021_023_025_026.py`."""

[coverage]
tr_core = ["TR-CORE-018", "TR-CORE-030", "TR-CORE-035", "TR-CORE-146"]

[inputs]
ledger               = "input-tampered-ledger.cbor"
tampered_event       = "input-tampered-event.cbor"
signing_key_registry = "input-signing-key-registry.cbor"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
tamper_kind          = "attestation_insufficient"
failing_event_id     = "{canonical_hash.hex()}"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        out_dir,
        "derivation.md",
        f"""# Derivation — `tamper/023-cert-attestation-malformed`

Starts from `append/028-certificate-of-completion-minimal-pdf`. Truncates
`attestations[0].signature` from 64 to 63 bytes (Ed25519 signatures are
fixed-size 64-byte values per RFC 8032). Phase-1 reference verifier checks
structural shape only — it does not crypto-verify attestation signatures
(see `finalize_certificates_of_completion` step 3 docstring in
`integrity-verify::trellis`). The structural check is `signature.len()
== 64`; truncation flips `attestation_signatures_well_formed = false`,
yielding `attestation_insufficient` per ADR 0007 §"Verifier obligations"
step 3 (existing Core §19.1 tamper_kind reused).

A single-byte flip on a 64-byte signature would NOT trigger the Phase-1
structural failure mode — the length stays 64, so the verifier would admit
the malformed signature pending Phase-2+ crypto verification. Truncation
exercises the operative Phase-1 path.

Failing canonical_event_hash: `{canonical_hash.hex()}`.

Generator: `_generator/gen_tamper_021_023_025_026.py`.
""",
    )
    return canonical_hash.hex()


# ---------------------------------------------------------------------------
# tamper/025 — HTML certificate with template_hash = null.
# ---------------------------------------------------------------------------


def gen_tamper_025(*, issuer_seed: bytes, issuer_pub: bytes, kid: bytes) -> str:
    src = ROOT / "append" / "030-certificate-of-completion-html-template"
    out_dir = ROOT / "tamper" / "025-cert-html-missing-template-hash"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {out_dir.relative_to(ROOT.parent.parent)}/")

    cert = load_certificate_payload(src)
    meta = load_source_event_metadata(src)
    # Mutation: template_hash non-null → null while media_type remains "text/html".
    # ADR 0007 §"Wire shape" PresentationArtifact.template_hash: HTML binding
    # requires a template pin even when template_id is null. The verifier
    # enforces this in `decode_certificate_payload` and surfaces the failure
    # as `malformed_cose` (no dedicated tamper_kind in §19.1 yet).
    assert cert["presentation_artifact"]["media_type"] == "text/html"
    assert cert["presentation_artifact"]["template_hash"] is not None
    cert["presentation_artifact"]["template_hash"] = None

    _, payload_bytes, author_event_hash, canonical_hash = build_event_payload(
        ledger_scope=meta["ledger_scope"],
        sequence=0,
        prev_hash=None,
        authored_at=meta["authored_at"],
        certificate_payload=cert,
        idempotency_key=b"tamper-025-cert-html",
        payload_marker=meta["payload_marker"],
    )
    signed = cose_sign1(issuer_seed, kid, payload_bytes)
    ledger = dcbor([cbor2.loads(signed)])
    write_bytes(out_dir, "input-tampered-ledger.cbor", ledger)
    write_bytes(
        out_dir,
        "input-signing-key-registry.cbor",
        build_signing_key_registry(kid, issuer_pub),
    )
    write_bytes(out_dir, "input-tampered-event.cbor", signed)

    write_text(
        out_dir,
        "manifest.toml",
        f'''id          = "tamper/025-cert-html-missing-template-hash"
op          = "tamper"
status      = "active"
description = """ADR 0007 §"Wire shape" PresentationArtifact.template_hash violation: `media_type = "text/html"` with `template_hash = null`. ADR 0007 requires non-null template_hash for HTML even when template_id is null. Source: `append/030-certificate-of-completion-html-template` with template_hash zeroed. Verifier emits `malformed_cose` per Core §19.1 generic-structure-failure clause (no dedicated tamper_kind for this case in the current registry). Generator: `_generator/gen_tamper_021_023_025_026.py`."""

[coverage]
tr_core = ["TR-CORE-018", "TR-CORE-030", "TR-CORE-035", "TR-CORE-146"]
tr_op = ["TR-OP-131"]

[inputs]
ledger               = "input-tampered-ledger.cbor"
tampered_event       = "input-tampered-event.cbor"
signing_key_registry = "input-signing-key-registry.cbor"

[expected.report]
structure_verified   = false
integrity_verified   = false
readability_verified = false
tamper_kind          = "malformed_cose"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        out_dir,
        "derivation.md",
        f"""# Derivation — `tamper/025-cert-html-missing-template-hash`

Starts from `append/030-certificate-of-completion-html-template`. Sets
`presentation_artifact.template_hash = null` while leaving
`presentation_artifact.media_type = "text/html"`.

Per ADR 0007 §"Wire shape" `PresentationArtifact.template_hash`:

> When media_type = "text/html", MUST be non-null even if template_id is
> null (HTML binding requires a template pin)

`decode_certificate_payload` enforces this at decode time, returning
`Err(VerifyError::with_kind(..., "malformed_cose"))`. The §19.1 enum has
no dedicated tamper_kind for this case; the generic structure-failure
kind is correct for a CDDL-shape rejection at decode.

TR-OP-131 covers the operator-side discipline: HTML presentations MUST
ship with template_hash. This vector is the verifier-side gate.

Failing canonical_event_hash: `{canonical_hash.hex()}`.

Generator: `_generator/gen_tamper_021_023_025_026.py`.
""",
    )
    return canonical_hash.hex()


# ---------------------------------------------------------------------------
# tamper/026 — two certificate events, same certificate_id, different payloads.
# ---------------------------------------------------------------------------


def gen_tamper_026(*, issuer_seed: bytes, issuer_pub: bytes, kid: bytes) -> str:
    src = ROOT / "append" / "028-certificate-of-completion-minimal-pdf"
    out_dir = ROOT / "tamper" / "026-cert-certificate-id-collision"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {out_dir.relative_to(ROOT.parent.parent)}/")

    # Distinct ledger_scope so both events are genesis (sequence 0) on
    # their own scope chains — `verify_tampered_ledger` walks the array
    # in order; the second event's `prev_hash = None` is admissible because
    # the chain treats both as sequence-0 events under DIFFERENT scopes.
    # Wait — `_verify_event_set` admits per-event `scope` regardless of
    # cross-event continuity for tamper inputs (it's a tamper ledger, not
    # a strict chain). The collision detection runs in
    # `finalize_certificates_of_completion` which walks the full payload
    # set and flags the duplicate `certificate_id`.
    #
    # We use the same ledger_scope + sequence chaining (event 0 sequence 0,
    # event 1 sequence 1, prev_hash linkage) to keep `_verify_event_set`'s
    # prev_hash check happy. Both certificates declare the SAME
    # `certificate_id` but have byte-different presentation_artifact bytes
    # (different content_hash via different payload_marker on event 1).

    src_cert = load_certificate_payload(src)
    src_meta = load_source_event_metadata(src)
    ledger_scope = src_meta["ledger_scope"]

    # Event 0: clone of append/028's certificate.
    cert_a = cbor2.loads(cbor2.dumps(src_cert, canonical=True))
    payload_marker_a = src_meta["payload_marker"]
    _, payload_bytes_a, _, canonical_a = build_event_payload(
        ledger_scope=ledger_scope,
        sequence=0,
        prev_hash=None,
        authored_at=src_meta["authored_at"],
        certificate_payload=cert_a,
        idempotency_key=b"tamper-026-event-0",
        payload_marker=payload_marker_a,
    )
    signed_a = cose_sign1(issuer_seed, kid, payload_bytes_a)

    # Event 1: same certificate_id, different presentation_artifact.content_hash.
    # Mutation makes the canonical certificate payload BYTE-DIFFERENT, which
    # `finalize_certificates_of_completion` detects as
    # `certificate_id_collision`.
    cert_b = cbor2.loads(cbor2.dumps(src_cert, canonical=True))
    cert_b["presentation_artifact"]["content_hash"] = (
        b"\xff" * 32  # distinct from cert_a's content_hash
    )
    payload_marker_b = b"certificate-of-completion-marker-026B"
    _, payload_bytes_b, _, canonical_b = build_event_payload(
        ledger_scope=ledger_scope,
        sequence=1,
        prev_hash=canonical_a,
        authored_at=ts(src_meta["authored_at"][0] + 1),
        certificate_payload=cert_b,
        idempotency_key=b"tamper-026-event-1",
        payload_marker=payload_marker_b,
    )
    signed_b = cose_sign1(issuer_seed, kid, payload_bytes_b)

    ledger = dcbor([cbor2.loads(signed_a), cbor2.loads(signed_b)])
    write_bytes(out_dir, "input-tampered-ledger.cbor", ledger)
    write_bytes(
        out_dir,
        "input-signing-key-registry.cbor",
        build_signing_key_registry(kid, issuer_pub),
    )
    # The "tampered event" file is the second one — the collision is
    # detected when we discover the duplicate certificate_id. Verifier
    # localizes the failure to event 1's canonical_event_hash.
    write_bytes(out_dir, "input-tampered-event.cbor", signed_b)

    write_text(
        out_dir,
        "manifest.toml",
        f'''id          = "tamper/026-cert-certificate-id-collision"
op          = "tamper"
status      = "active"
description = """ADR 0007 §"Field semantics" `certificate_id` clause: two events on the same chain share `certificate_id = "urn:trellis:certificate:test:028"` but their canonical certificate payloads disagree (event 1 mutates `presentation_artifact.content_hash`). `finalize_certificates_of_completion` flips integrity via `certificate_id_collision`. Generator: `_generator/gen_tamper_021_023_025_026.py`."""

[coverage]
tr_core = ["TR-CORE-018", "TR-CORE-030", "TR-CORE-035", "TR-CORE-147"]
tr_op = ["TR-OP-131"]

[inputs]
ledger               = "input-tampered-ledger.cbor"
tampered_event       = "input-tampered-event.cbor"
signing_key_registry = "input-signing-key-registry.cbor"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
tamper_kind          = "certificate_id_collision"
failing_event_id     = "{canonical_b.hex()}"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        out_dir,
        "derivation.md",
        f"""# Derivation — `tamper/026-cert-certificate-id-collision`

Two-event chain on a single ledger_scope. Both events share
`certificate_id = "urn:trellis:certificate:test:028"`. Event 0 is a byte-
exact clone of `append/028-certificate-of-completion-minimal-pdf`'s payload
(idempotency_key tweaked to dodge §17.3 collision under combined replay).
Event 1 mutates `presentation_artifact.content_hash` to a 32-byte all-`0xff`
value, making its canonical certificate payload byte-different from event
0's. The `prev_hash` chain links event 1 to event 0 normally so
`_verify_event_set` admits the structural form.

Per ADR 0007 §"Field semantics" `certificate_id` clause:

> If the operator re-emits the same certificate_id with a different payload
> (different content_hash, signing_events, or chain_summary), that is a
> chain policy violation: the verifier treats the duplicate as
> certificate_id_collision and flips integrity_verified = false.

`finalize_certificates_of_completion` collects all in-scope certificate
events and runs the collision pass; it reports
`certificate_id_collision` localized to event 1's canonical_event_hash.

Event 0 canonical_event_hash: `{canonical_a.hex()}`
Event 1 canonical_event_hash: `{canonical_b.hex()}` (failing event)

Generator: `_generator/gen_tamper_021_023_025_026.py`.
""",
    )
    return canonical_b.hex()


# ---------------------------------------------------------------------------
# Top-level main.
# ---------------------------------------------------------------------------


def main() -> dict[str, str]:
    issuer_seed, issuer_pub = load_cose_key(KEY_ISSUER)
    kid = derive_kid(SUITE_ID, issuer_pub)
    out: dict[str, str] = {}
    out["021"] = gen_tamper_021(issuer_seed=issuer_seed, issuer_pub=issuer_pub, kid=kid)
    out["023"] = gen_tamper_023(issuer_seed=issuer_seed, issuer_pub=issuer_pub, kid=kid)
    out["025"] = gen_tamper_025(issuer_seed=issuer_seed, issuer_pub=issuer_pub, kid=kid)
    out["026"] = gen_tamper_026(issuer_seed=issuer_seed, issuer_pub=issuer_pub, kid=kid)
    return out


if __name__ == "__main__":
    out = main()
    print()
    for k, v in out.items():
        print(f"  tamper/0{k} failing canonical_event_hash = {v}")
