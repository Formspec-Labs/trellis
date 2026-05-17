"""Generate byte-exact reference vectors `append/023..027` — ADR 0005 erasure-evidence.

Authoring aid only. Every construction block carries an inline ADR / Core /
Companion citation naming the normative paragraph that determines the bytes.
This script is NOT normative; each vector's `derivation.md` is the spec-prose
reproduction evidence.

Determinism: two runs produce byte-identical output. No randomness, no
wall-clock reads, no environment lookups beyond pinned inputs.

Vector matrix (ADR 0005 §"Fixture plan"):

  | dir                                                | scope            | cascade   | mode         | extra                |
  |----------------------------------------------------|------------------|-----------|--------------|----------------------|
  | 023-erasure-evidence-per-subject-cs-03             | per-subject      | CS-03     | complete     | minimum positive     |
  | 024-erasure-evidence-per-subject-full-cascade      | per-subject      | CS-01..06 | complete     | full A.7 enumeration |
  | 025-erasure-evidence-per-tenant                    | per-tenant       | CS-01..06 | complete     | dual attestation     |
  | 026-erasure-evidence-in-progress                   | per-subject      | CS-03     | in-progress  | partial-cascade      |
  | 027-erasure-evidence-hsm-receipt                   | per-subject      | CS-03     | complete     | hsm_receipt opaque   |

All five vectors:

  * Chain from `append/001-minimal-inline-payload` head (sequence = N
    relative to that genesis; we use sequence = 1 for each since they are
    independent test ledgers — distinct erasure events do not stack onto a
    single chain in this corpus).
  * Sign the COSE_Sign1 envelope with `_keys/issuer-001.cose_key`.
  * Carry the `trellis.erasure-evidence.v1` payload under
    `EventPayload.extensions` per Core §6.5 / §6.7.
  * Use `_keys/issuer-001.cose_key` for the `authority_class="new"`
    attestation. Per-tenant 025 also signs a `prior` attestation under
    `_keys/attestation-authority-cm-b-001.cose_key` (dual attestation
    SHOULD per OC-143 for `subject_scope.kind = per-tenant`; we land it
    here as a fixture so the dual-attestation surface gets byte coverage
    even though Phase-1 verifier dispatch is structural-only).
  * Use distinct `idempotency_key` per vector to avoid cross-vector
    collision under §17.3.

`destroyed_at` < hosting `authored_at` per ADR 0005 step 4. The cascade
scope `CS-03` (snapshots-only) reuses the canonical Phase-1 example from
the ADR's *Fixture plan* table.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cbor2  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from _lib.byte_utils import ts  # noqa: E402

# ---------------------------------------------------------------------------
# Pinned paths.
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent           # fixtures/vectors/
KEY_ISSUER = ROOT / "_keys" / "issuer-001.cose_key"
KEY_ATTESTATION_AUTHORITY_PRIOR = (
    ROOT / "_keys" / "attestation-authority-cm-b-001.cose_key"
)
PRIOR_VECTOR_DIR = ROOT / "append" / "001-minimal-inline-payload"

# ---------------------------------------------------------------------------
# Pinned constants shared across all five vectors.
# ---------------------------------------------------------------------------

LEDGER_SCOPE = b"test-response-ledger"
SEQUENCE = 1
HOST_TIMESTAMP = ts(1_745_000_200)             # > append/001's authored_at
DESTROYED_AT_TIMESTAMP = ts(1_745_000_100)     # < HOST_TIMESTAMP per step 4
EVENT_TYPE = b"trellis.erasure-evidence.v1"
CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0

PAYLOAD_NONCE = b"\x00" * 12
PAYLOAD_MARKER = b"erasure-event"           # 13-byte opaque marker; the
                                            # erasure event carries no user
                                            # payload — the payload IS the
                                            # extension.

SUITE_ID = 1
ALG_EDDSA = -8
COSE_LABEL_ALG = 1
COSE_LABEL_KID = 4
COSE_LABEL_SUITE_ID = -65537
COSE_LABEL_ARTIFACT_TYPE = -65538
ARTIFACT_TYPE_EVENT = "event"
ARTIFACT_TYPE_CHECKPOINT = "checkpoint"
ARTIFACT_TYPE_MANIFEST = "manifest"

TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"
TAG_TRELLIS_TRANSITION_ATTESTATION_V1 = "trellis-transition-attestation-v1"

POLICY_AUTHORITY = "urn:trellis:authority:test-governance"
DESTRUCTION_ACTOR = "urn:trellis:principal:test-operator"


# ---------------------------------------------------------------------------
# dCBOR + §9.1 helpers (consistent with gen_append_006).
# ---------------------------------------------------------------------------


def dcbor(value: object) -> bytes:
    return cbor2.dumps(value, canonical=True)


def domain_separated_preimage(tag: str, component: bytes) -> bytes:
    tag_bytes = tag.encode("utf-8")
    return (
        len(tag_bytes).to_bytes(4, "big")
        + tag_bytes
        + len(component).to_bytes(4, "big")
        + component
    )


def domain_separated_sha256(tag: str, component: bytes) -> bytes:
    return hashlib.sha256(domain_separated_preimage(tag, component)).digest()


def load_cose_key(path: Path) -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(path.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    assert len(seed) == 32 and len(pubkey) == 32
    return seed, pubkey


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def load_prior_canonical_event_hash() -> bytes:
    prior_head = cbor2.loads((PRIOR_VECTOR_DIR / "expected-append-head.cbor").read_bytes())
    assert prior_head["scope"] == LEDGER_SCOPE
    assert prior_head["sequence"] == SEQUENCE - 1
    return prior_head["canonical_event_hash"]


# ---------------------------------------------------------------------------
# Attestation builder (Companion Appendix A.5 shared rule, reused by ADR 0005).
# ---------------------------------------------------------------------------


def build_attestation(
    *,
    authority: str,
    authority_class: str,
    signing_seed: bytes,
    transition_id: str,
    effective_at: int,
) -> dict:
    """Per ADR 0005 §"Wire shape": attestation reuses A.5 shape verbatim,
    signed under `trellis-transition-attestation-v1` over
    `dCBOR([transition_id, effective_at, authority_class])`.
    """
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
# Erasure-evidence payload builder (ADR 0005 §"Wire shape").
# ---------------------------------------------------------------------------


def build_erasure_payload(
    *,
    evidence_id: str,
    kid_destroyed: bytes,
    key_class: str,
    destroyed_at: int,
    cascade_scopes: list[str],
    completion_mode: str,
    reason_code: int,
    subject_scope: dict,
    hsm_receipt: bytes | None,
    hsm_receipt_kind: str | None,
    attestations: list[dict],
) -> dict:
    return {
        "evidence_id":          evidence_id,
        "kid_destroyed":        kid_destroyed,
        "key_class":            key_class,
        "destroyed_at":         destroyed_at,
        "cascade_scopes":       cascade_scopes,
        "completion_mode":      completion_mode,
        "destruction_actor":    DESTRUCTION_ACTOR,
        "policy_authority":     POLICY_AUTHORITY,
        "reason_code":          reason_code,
        "subject_scope":        subject_scope,
        "hsm_receipt":          hsm_receipt,
        "hsm_receipt_kind":     hsm_receipt_kind,
        "attestations":         attestations,
        "extensions":           None,
    }


# ---------------------------------------------------------------------------
# Subject-scope shape builders (ADR 0005 step 3).
# ---------------------------------------------------------------------------


def per_subject_scope(refs: list[str]) -> dict:
    return {
        "kind":          "per-subject",
        "subject_refs":  refs,
        "ledger_scopes": None,
        "tenant_refs":   None,
    }


def per_tenant_scope(refs: list[str]) -> dict:
    return {
        "kind":          "per-tenant",
        "subject_refs":  None,
        "ledger_scopes": None,
        "tenant_refs":   refs,
    }


# ---------------------------------------------------------------------------
# Event envelope builders (mirror gen_append_006).
# ---------------------------------------------------------------------------


def build_event_header() -> dict:
    return {
        "event_type":             EVENT_TYPE,
        "authored_at":             HOST_TIMESTAMP,
        "retention_tier":          RETENTION_TIER,
        "classification":          CLASSIFICATION,
        "outcome_commitment":      None,
        "subject_ref_commitment":  None,
        "tag_commitment":          None,
        "witness_ref":             None,
        "extensions":              None,
    }


def build_payload_ref() -> dict:
    return {
        "ref_type":   "inline",
        "ciphertext": PAYLOAD_MARKER,
        "nonce":      PAYLOAD_NONCE,
    }


def build_key_bag() -> dict:
    return {"entries": []}


def build_author_event_hash_preimage(
    *,
    prev_hash: bytes,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
    extensions: dict,
    idempotency_key: bytes,
) -> dict:
    return {
        "version":         1,
        "ledger_scope":    LEDGER_SCOPE,
        "sequence":        SEQUENCE,
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


def build_event_payload(
    *,
    prev_hash: bytes,
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
        "ledger_scope":      LEDGER_SCOPE,
        "sequence":          SEQUENCE,
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


def build_canonical_event_hash_preimage(event_payload: dict) -> dict:
    return {
        "version":       1,
        "ledger_scope":  LEDGER_SCOPE,
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
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"  {name:55s}  {len(data):>5d} bytes  sha256={digest}")
    return digest


# ---------------------------------------------------------------------------
# Per-vector specs.
# ---------------------------------------------------------------------------


def vector_specs() -> list[dict]:
    """Pinned spec for each of append/023..027.

    `kid_destroyed` for each vector is a **distinct** opaque 16-byte value
    chosen so that no vector's destroyed kid resolves into any committed
    signing-key registry. ADR 0005 step 2 / OC-146 specifically allows the
    Phase-1 opaque-kid path (when the destroyed key is a subject/HPKE
    recipient not yet on the registry, or — for these fixtures — a
    test-only signing key the operator never registered). The verifier
    skips registry-bind in step 2 but still runs steps 1 / 3 / 4 / 5 / 6
    / 7 / 8 (for `signing` and `subject`). For step 8 to NOT trigger a
    post-erasure flag on this same event, we require
    `authored_at <= destroyed_at` is false (i.e. authored_at >
    destroyed_at) is NOT what we want — actually we want authored_at >
    destroyed_at AND the carrying event to be allowed. Per ADR 0005 step
    8 *Comparison rule*: "the erasure event itself may carry that kid
    until a future spec tightens this" — but only when the host event
    SIGNS under that kid. The host events here sign under the issuer kid,
    not under kid_destroyed, so there is no post-erasure-use even when
    authored_at > destroyed_at. ✓
    """
    return [
        {
            "dir": "append/023-erasure-evidence-per-subject-cs-03",
            "evidence_id": "urn:trellis:erasure:test:023",
            "transition_id": "urn:trellis:erasure:test:023",  # reused as attestation-preimage tid
            "kid_destroyed": bytes.fromhex("a1" * 16),
            "key_class": "subject",
            "cascade_scopes": ["CS-03"],
            "completion_mode": "complete",
            "reason_code": 1,  # retention-expired
            "subject_scope": per_subject_scope(["urn:trellis:subject:test-applicant-001"]),
            "hsm_receipt": None,
            "hsm_receipt_kind": None,
            "attestation_classes": ["new"],
            "idempotency_key": b"idemp-append-023",
        },
        {
            "dir": "append/024-erasure-evidence-per-subject-full-cascade",
            "evidence_id": "urn:trellis:erasure:test:024",
            "transition_id": "urn:trellis:erasure:test:024",
            "kid_destroyed": bytes.fromhex("a2" * 16),
            "key_class": "subject",
            "cascade_scopes": ["CS-01", "CS-02", "CS-03", "CS-04", "CS-05", "CS-06"],
            "completion_mode": "complete",
            "reason_code": 2,  # subject-requested-erasure
            "subject_scope": per_subject_scope(["urn:trellis:subject:test-applicant-002"]),
            "hsm_receipt": None,
            "hsm_receipt_kind": None,
            "attestation_classes": ["new"],
            "idempotency_key": b"idemp-append-024",
        },
        {
            "dir": "append/025-erasure-evidence-per-tenant",
            "evidence_id": "urn:trellis:erasure:test:025",
            "transition_id": "urn:trellis:erasure:test:025",
            "kid_destroyed": bytes.fromhex("a3" * 16),
            "key_class": "subject",
            "cascade_scopes": ["CS-01", "CS-02", "CS-03", "CS-04", "CS-05", "CS-06"],
            "completion_mode": "complete",
            "reason_code": 4,  # operator-initiated-policy-change
            "subject_scope": per_tenant_scope(["urn:trellis:tenant:test-tenant-eu"]),
            "hsm_receipt": None,
            "hsm_receipt_kind": None,
            "attestation_classes": ["prior", "new"],   # SHOULD per OC-143
            "idempotency_key": b"idemp-append-025",
        },
        {
            "dir": "append/026-erasure-evidence-in-progress",
            "evidence_id": "urn:trellis:erasure:test:026",
            "transition_id": "urn:trellis:erasure:test:026",
            "kid_destroyed": bytes.fromhex("a4" * 16),
            "key_class": "subject",
            "cascade_scopes": ["CS-03"],
            "completion_mode": "in-progress",
            "reason_code": 1,  # retention-expired
            "subject_scope": per_subject_scope(["urn:trellis:subject:test-applicant-003"]),
            "hsm_receipt": None,
            "hsm_receipt_kind": None,
            "attestation_classes": ["new"],
            "idempotency_key": b"idemp-append-026",
        },
        {
            "dir": "append/027-erasure-evidence-hsm-receipt",
            "evidence_id": "urn:trellis:erasure:test:027",
            "transition_id": "urn:trellis:erasure:test:027",
            "kid_destroyed": bytes.fromhex("a5" * 16),
            "key_class": "subject",
            "cascade_scopes": ["CS-03"],
            "completion_mode": "complete",
            "reason_code": 1,
            "subject_scope": per_subject_scope(["urn:trellis:subject:test-applicant-004"]),
            "hsm_receipt": b"opaque-hsm-receipt-test-027-vendor-bytes",
            "hsm_receipt_kind": "opaque-vendor-receipt-v1",
            "attestation_classes": ["new"],
            "idempotency_key": b"idemp-append-027",
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
    prior_authority_seed: bytes,
    prior_authority_pub: bytes,
    kid: bytes,
    prev_hash: bytes,
) -> None:
    out_dir = ROOT / spec["dir"]
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating vector at {out_dir.relative_to(ROOT.parent.parent)}/")

    prior_head_bytes = (PRIOR_VECTOR_DIR / "expected-append-head.cbor").read_bytes()
    write_bytes(out_dir, "input-prior-append-head.cbor", prior_head_bytes)

    # Build attestations per spec's class list.
    attestations: list[dict] = []
    for klass in spec["attestation_classes"]:
        seed = issuer_seed if klass == "new" else prior_authority_seed
        authority = (
            f"urn:trellis:authority:test-{klass}-027"
            if klass == "prior"
            else f"urn:trellis:authority:test-cm-a-authority"
        )
        if klass == "prior":
            authority = "urn:trellis:authority:test-cm-b-authority"
        attestations.append(
            build_attestation(
                authority=authority,
                authority_class=klass,
                signing_seed=seed,
                transition_id=spec["transition_id"],
                effective_at=DESTROYED_AT_TIMESTAMP,
            )
        )

    # Commit attestation preimages so reviewers can re-verify the
    # `trellis-transition-attestation-v1` domain-separation by hand.
    for klass in spec["attestation_classes"]:
        preimage_inner = dcbor([spec["transition_id"], DESTROYED_AT_TIMESTAMP, klass])
        write_bytes(
            out_dir,
            f"input-attestation-preimage-{klass}.cbor",
            preimage_inner,
        )

    # Build the erasure-evidence payload (ADR 0005 §"Wire shape").
    erasure_payload = build_erasure_payload(
        evidence_id=spec["evidence_id"],
        kid_destroyed=spec["kid_destroyed"],
        key_class=spec["key_class"],
        destroyed_at=DESTROYED_AT_TIMESTAMP,
        cascade_scopes=spec["cascade_scopes"],
        completion_mode=spec["completion_mode"],
        reason_code=spec["reason_code"],
        subject_scope=spec["subject_scope"],
        hsm_receipt=spec["hsm_receipt"],
        hsm_receipt_kind=spec["hsm_receipt_kind"],
        attestations=attestations,
    )
    extensions = {EVENT_TYPE.decode("utf-8"): erasure_payload}

    # Minimal PayloadInline — the erasure event is the payload.
    payload_bytes = PAYLOAD_MARKER
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_bytes)

    header = build_event_header()
    payload_ref = build_payload_ref()
    key_bag = build_key_bag()

    # AuthorEventHashPreimage → author_event_hash (§9.5, §9.1).
    authored_map = build_author_event_hash_preimage(
        prev_hash=prev_hash,
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

    # EventPayload (§6.1).
    event_payload = build_event_payload(
        prev_hash=prev_hash,
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
    canonical_preimage = dcbor(build_canonical_event_hash_preimage(event_payload))
    canonical_event_hash = domain_separated_sha256(TAG_TRELLIS_EVENT_V1, canonical_preimage)
    append_head = build_append_head(LEDGER_SCOPE, SEQUENCE, canonical_event_hash)
    write_bytes(out_dir, "expected-append-head.cbor", dcbor(append_head))

    print()
    print(f"  prev_hash                  = {prev_hash.hex()}")
    print(f"  kid                        = {kid.hex()}")
    print(f"  kid_destroyed              = {spec['kid_destroyed'].hex()}")
    print(f"  destroyed_at               = {DESTROYED_AT_TIMESTAMP}")
    print(f"  host authored_at           = {HOST_TIMESTAMP}")
    print(f"  content_hash               = {content_hash.hex()}")
    print(f"  author_event_hash          = {author_event_hash.hex()}")
    print(f"  canonical_event_hash       = {canonical_event_hash.hex()}")


# ---------------------------------------------------------------------------
# Top-level main: runs all five.
# ---------------------------------------------------------------------------


def main() -> None:
    issuer_seed, issuer_pub = load_cose_key(KEY_ISSUER)
    prior_authority_seed, prior_authority_pub = load_cose_key(KEY_ATTESTATION_AUTHORITY_PRIOR)
    kid = derive_kid(SUITE_ID, issuer_pub)
    prev_hash = load_prior_canonical_event_hash()

    for spec in vector_specs():
        generate_vector(
            spec,
            issuer_seed=issuer_seed,
            issuer_pub=issuer_pub,
            prior_authority_seed=prior_authority_seed,
            prior_authority_pub=prior_authority_pub,
            kid=kid,
            prev_hash=prev_hash,
        )


if __name__ == "__main__":
    main()
