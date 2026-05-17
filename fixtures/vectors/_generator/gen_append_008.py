"""Generate byte-exact reference vector `append/008-disclosure-profile-transition-a-to-b`.

Authoring aid only. NOT normative — `derivation.md` carries the spec-prose
reproduction evidence. Determinism: two runs produce byte-identical output.

Scope decision: third O-5 Posture-transition vector. Pins the sibling wire
shape to 006/007 — the `trellis.disclosure-profile-transition.v1` CDDL
(Companion Appendix A.5.2). The transition moves the Respondent Ledger Profile
A/B/C axis from `rl-profile-A` to `rl-profile-B`; this is classified as
`scope_change = "Orthogonal"` (Appendix A.5.2) because profiles A and B trade
axes on the privacy × identity × integrity-anchoring triple rather than one
being a subset of the other. Per Appendix A.5.3 step 4 Orthogonal branch,
Orthogonal transitions require dual attestation — the non-narrowing default.

Structural shape parallels `gen_append_006.py` (dual attestation + both
keys). Deltas: the event_type string, the extension key, the transition
payload CDDL (includes `scope_change`, drops `from/to_custody_model`), and
the transition identifiers.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cbor2  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from _lib.byte_utils import ts  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
KEY_ISSUER = ROOT / "_keys" / "issuer-001.cose_key"
KEY_ATTESTATION_AUTHORITY_CM_B = (
    ROOT / "_keys" / "attestation-authority-cm-b-001.cose_key"
)
PRIOR_VECTOR_DIR = ROOT / "append" / "001-minimal-inline-payload"
OUT_DIR = ROOT / "append" / "008-disclosure-profile-transition-a-to-b"

LEDGER_SCOPE = b"test-response-ledger"
SEQUENCE = 1
TIMESTAMP = ts(1745000300)
EVENT_TYPE = b"trellis.disclosure-profile-transition.v1"
CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0
IDEMPOTENCY_KEY = b"idemp-append-008"

PAYLOAD_NONCE = b"\x00" * 12
PAYLOAD_MARKER = b"disclosure-profile-transition"

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
TAG_TRELLIS_POSTURE_DECLARATION_V1 = "trellis-posture-declaration-v1"
TAG_TRELLIS_TRANSITION_ATTESTATION_V1 = "trellis-transition-attestation-v1"

TRANSITION_ID = "urn:trellis:transition:test:008"
FROM_DISCLOSURE_PROFILE = "rl-profile-A"
TO_DISCLOSURE_PROFILE = "rl-profile-B"
SCOPE_CHANGE = "Orthogonal"                             # §A.5.2 enum
REASON_CODE = 4                                         # governance-policy-change
TEMPORAL_SCOPE = "prospective"
TRANSITION_ACTOR = "urn:trellis:principal:test-operator"
POLICY_AUTHORITY = "urn:trellis:authority:test-governance"
ATTESTATION_AUTHORITY_PRIOR = "urn:trellis:authority:test-rl-profile-a-authority"
ATTESTATION_AUTHORITY_NEW = "urn:trellis:authority:test-rl-profile-b-authority"


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
    return cose_key[-4], cose_key[-2]


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def load_prior_canonical_event_hash() -> bytes:
    prior_head = cbor2.loads((PRIOR_VECTOR_DIR / "expected-append-head.cbor").read_bytes())
    assert prior_head["scope"] == LEDGER_SCOPE
    assert prior_head["sequence"] == SEQUENCE - 1
    return prior_head["canonical_event_hash"]


def build_posture_declaration_bytes() -> bytes:
    return dcbor({
        "declaration_id":            "urn:trellis:declaration:test:008-post",
        "operator_id":               "urn:trellis:operator:test",
        "scope":                     "test-response-ledger",
        "effective_from":            TIMESTAMP,
        "supersedes":                "urn:trellis:declaration:test:008-pre",
        "custody_model":             {"custody_model_id": "CM-B"},
        "disclosure_profile":        TO_DISCLOSURE_PROFILE,
        "posture_honesty_statement": "test fixture posture declaration",
    })


def build_attestation(
    authority: str,
    authority_class: str,
    signing_seed: bytes,
) -> dict:
    preimage = dcbor([TRANSITION_ID, TIMESTAMP, authority_class])
    signing_preimage = domain_separated_preimage(
        TAG_TRELLIS_TRANSITION_ATTESTATION_V1, preimage,
    )
    signature = Ed25519PrivateKey.from_private_bytes(signing_seed).sign(signing_preimage)
    assert len(signature) == 64
    return {"authority": authority, "authority_class": authority_class, "signature": signature}


def write_bytes(name: str, data: bytes) -> None:
    path = OUT_DIR / name
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"  {name:55s}  {len(data):>5d} bytes  sha256={digest}")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"generating vector at {OUT_DIR.relative_to(ROOT.parent.parent)}/")

    issuer_seed, issuer_pub = load_cose_key(KEY_ISSUER)
    prior_authority_seed, _ = load_cose_key(KEY_ATTESTATION_AUTHORITY_CM_B)
    kid = derive_kid(SUITE_ID, issuer_pub)

    prev_hash = load_prior_canonical_event_hash()
    prior_head_bytes = (PRIOR_VECTOR_DIR / "expected-append-head.cbor").read_bytes()
    write_bytes("input-prior-append-head.cbor", prior_head_bytes)

    declaration_bytes = build_posture_declaration_bytes()
    write_bytes("input-posture-declaration.bin", declaration_bytes)
    declaration_digest = domain_separated_sha256(
        TAG_TRELLIS_POSTURE_DECLARATION_V1, declaration_bytes,
    )

    # Orthogonal requires dual attestation (Appendix A.5.3 step 4 Orthogonal).
    attestation_prior = build_attestation(
        ATTESTATION_AUTHORITY_PRIOR, "prior", prior_authority_seed,
    )
    attestation_new = build_attestation(
        ATTESTATION_AUTHORITY_NEW, "new", issuer_seed,
    )
    write_bytes("input-attestation-preimage-prior.cbor",
                dcbor([TRANSITION_ID, TIMESTAMP, "prior"]))
    write_bytes("input-attestation-preimage-new.cbor",
                dcbor([TRANSITION_ID, TIMESTAMP, "new"]))

    # DisclosureProfileTransitionPayload (Companion Appendix A.5.2).
    transition_payload = {
        "transition_id":           TRANSITION_ID,
        "from_disclosure_profile": FROM_DISCLOSURE_PROFILE,
        "to_disclosure_profile":   TO_DISCLOSURE_PROFILE,
        "effective_at":            TIMESTAMP,
        "reason_code":             REASON_CODE,
        "declaration_doc_digest":  declaration_digest,
        "scope_change":            SCOPE_CHANGE,
        "transition_actor":        TRANSITION_ACTOR,
        "policy_authority":        POLICY_AUTHORITY,
        "temporal_scope":          TEMPORAL_SCOPE,
        "attestations":            [attestation_prior, attestation_new],
        "extensions":              None,
    }
    extensions = {EVENT_TYPE.decode("utf-8"): transition_payload}

    payload_bytes = PAYLOAD_MARKER
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_bytes)

    header = {
        "event_type":             EVENT_TYPE,
        "authored_at":            TIMESTAMP,
        "retention_tier":         RETENTION_TIER,
        "classification":         CLASSIFICATION,
        "outcome_commitment":     None,
        "subject_ref_commitment": None,
        "tag_commitment":         None,
        "witness_ref":            None,
        "extensions":             None,
    }
    payload_ref = {"ref_type": "inline", "ciphertext": payload_bytes, "nonce": PAYLOAD_NONCE}
    key_bag = {"entries": []}

    authored_bytes = dcbor({
        "version": 1,
        "ledger_scope": LEDGER_SCOPE,
        "sequence": SEQUENCE,
        "prev_hash": prev_hash,
        "causal_deps": None,
        "content_hash": content_hash,
        "header": header,
        "commitments": None,
        "payload_ref": payload_ref,
        "key_bag": key_bag,
        "idempotency_key": IDEMPOTENCY_KEY,
        "extensions": extensions,
    })
    write_bytes("input-author-event-hash-preimage.cbor", authored_bytes)

    author_event_hash = hashlib.sha256(
        domain_separated_preimage(TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes)
    ).digest()
    write_bytes("author-event-hash.bin", author_event_hash)

    event_payload = {
        "version": 1,
        "ledger_scope": LEDGER_SCOPE,
        "sequence": SEQUENCE,
        "prev_hash": prev_hash,
        "causal_deps": None,
        "author_event_hash": author_event_hash,
        "content_hash": content_hash,
        "header": header,
        "commitments": None,
        "payload_ref": payload_ref,
        "key_bag": key_bag,
        "idempotency_key": IDEMPOTENCY_KEY,
        "extensions": extensions,
    }
    event_payload_bytes = dcbor(event_payload)
    write_bytes("expected-event-payload.cbor", event_payload_bytes)

    protected_map_bytes = dcbor({
        COSE_LABEL_ALG: ALG_EDDSA, COSE_LABEL_KID: kid, COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: ARTIFACT_TYPE_EVENT,
    })
    sig_structure = dcbor(["Signature1", protected_map_bytes, b"", event_payload_bytes])
    write_bytes("sig-structure.bin", sig_structure)

    signature = Ed25519PrivateKey.from_private_bytes(issuer_seed).sign(sig_structure)
    cose_sign1_bytes = dcbor(cbor2.CBORTag(
        18, [protected_map_bytes, {}, event_payload_bytes, signature],
    ))
    write_bytes("expected-event.cbor", cose_sign1_bytes)

    canonical_preimage = dcbor({
        "version": 1, "ledger_scope": LEDGER_SCOPE, "event_payload": event_payload,
    })
    canonical_event_hash = domain_separated_sha256(TAG_TRELLIS_EVENT_V1, canonical_preimage)
    write_bytes("expected-append-head.cbor", dcbor({
        "scope": LEDGER_SCOPE, "sequence": SEQUENCE, "canonical_event_hash": canonical_event_hash,
    }))

    print()
    print(f"  prev_hash                  = {prev_hash.hex()}")
    print(f"  kid                        = {kid.hex()}")
    print(f"  declaration_digest         = {declaration_digest.hex()}")
    print(f"  author_event_hash          = {author_event_hash.hex()}")
    print(f"  canonical_event_hash       = {canonical_event_hash.hex()}")


if __name__ == "__main__":
    main()
