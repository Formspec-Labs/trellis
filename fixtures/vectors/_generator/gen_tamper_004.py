"""Generate byte-exact reference vector `tamper/004-transition-declaration-digest-mismatch`.

Authoring aid only. NOT normative — `derivation.md` carries the spec-prose
reproduction evidence. Determinism: two runs produce byte-identical output.

Scope decision: third O-5 verifier-side (tamper) vector. Exercises Core §19
step 6.c — the declaration-digest-mismatch tamper-evidence branch.

Construction: the event's `declaration_doc_digest` is computed over
declaration A (the "intended" post-transition declaration; SHA-256 under
`trellis-posture-declaration-v1` over dCBOR(declaration_A)). The export,
however, ships declaration B — bit-flipped bytes versus declaration A.
A conforming verifier following §19 step 6.c recomputes the digest over
declaration B and compares against the stored digest. They differ. Step
6.c names this explicitly as tamper evidence: it sets BOTH
`declaration_resolved = false` AND `continuity_verified = false` in the
same transition's outcome record. The latter feeds §19 step 9's
`integrity_verified` conjunction → false.

The event is otherwise well-formed: signature valid, `from_custody_model`
matches the initial declaration (step 6.b passes on its own merit, and
the digest tamper overrides to false via step 6.c), attestations
complete and valid (step 6.d passes).
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
OUT_DIR = ROOT / "tamper" / "004-transition-declaration-digest-mismatch"

LEDGER_SCOPE = b"test-response-ledger"
SEQUENCE = 1
TIMESTAMP = ts(1745000600)
EVENT_TYPE = b"trellis.custody-model-transition.v1"
CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0
IDEMPOTENCY_KEY = b"tamper-transition-004"

PAYLOAD_NONCE = b"\x00" * 12
PAYLOAD_MARKER = b"custody-transition"

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

TRANSITION_ID = "urn:trellis:transition:test:tamper-004"
INITIAL_CUSTODY_MODEL = "CM-B"
FROM_CUSTODY_MODEL = "CM-B"
TO_CUSTODY_MODEL = "CM-A"
REASON_CODE = 3
TEMPORAL_SCOPE = "prospective"
TRANSITION_ACTOR = "urn:trellis:principal:test-operator"
POLICY_AUTHORITY = "urn:trellis:authority:test-governance"
ATTESTATION_AUTHORITY_PRIOR = "urn:trellis:authority:test-cm-b-authority"
ATTESTATION_AUTHORITY_NEW = "urn:trellis:authority:test-cm-a-authority"


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
    return prior_head["canonical_event_hash"]


def build_initial_declaration_bytes() -> bytes:
    return dcbor({
        "declaration_id":            "urn:trellis:declaration:test:tamper-004-initial",
        "operator_id":               "urn:trellis:operator:test",
        "scope":                     "test-response-ledger",
        "effective_from":            ts(1745000000),
        "supersedes":                None,
        "custody_model":             {"custody_model_id": INITIAL_CUSTODY_MODEL},
        "disclosure_profile":        "rl-profile-A",
        "posture_honesty_statement": "test fixture initial posture declaration",
    })


def build_intended_declaration_bytes() -> bytes:
    """Declaration A — the one the event's `declaration_doc_digest` pins.

    This is what the operator *claims* the post-transition declaration
    contains. Its SHA-256 under `trellis-posture-declaration-v1` is what
    the event embeds. This file is NOT shipped in the export — it exists
    here only to construct the digest. (A conforming generator emits it
    as a sibling derivation artifact so a human reviewer can inspect the
    preimage the digest came from.)
    """
    return dcbor({
        "declaration_id":            "urn:trellis:declaration:test:tamper-004-intended",
        "operator_id":               "urn:trellis:operator:test",
        "scope":                     "test-response-ledger",
        "effective_from":            TIMESTAMP,
        "supersedes":                "urn:trellis:declaration:test:tamper-004-initial",
        "custody_model":             {"custody_model_id": TO_CUSTODY_MODEL},
        "disclosure_profile":        "rl-profile-A",
        "posture_honesty_statement": "test fixture post-transition posture declaration",
    })


def build_shipped_declaration_bytes() -> bytes:
    """Declaration B — the one the export actually ships.

    Differs from declaration A in the `posture_honesty_statement` field
    (one-word edit). When a verifier recomputes the digest over these
    bytes under `trellis-posture-declaration-v1`, the result does NOT
    equal the event's `declaration_doc_digest`. §19 step 6.c marks this
    as tamper evidence.
    """
    return dcbor({
        "declaration_id":            "urn:trellis:declaration:test:tamper-004-intended",
        "operator_id":               "urn:trellis:operator:test",
        "scope":                     "test-response-ledger",
        "effective_from":            TIMESTAMP,
        "supersedes":                "urn:trellis:declaration:test:tamper-004-initial",
        "custody_model":             {"custody_model_id": TO_CUSTODY_MODEL},
        "disclosure_profile":        "rl-profile-A",
        # TAMPER: the operator has edited the honesty statement without
        # re-issuing the transition event. Any single-byte change in the
        # declaration preimage propagates through SHA-256; the mismatch
        # at step 6.c is catastrophic (tamper evidence).
        "posture_honesty_statement": "test fixture SUBSTITUTED posture declaration",
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

    initial_declaration_bytes = build_initial_declaration_bytes()
    write_bytes("input-initial-posture-declaration.bin", initial_declaration_bytes)

    # Intended declaration: the one the event's digest was computed over.
    # Committed as a sibling so a human reviewer can verify the digest pins.
    intended_declaration_bytes = build_intended_declaration_bytes()
    write_bytes("intended-posture-declaration.bin", intended_declaration_bytes)
    declaration_digest = domain_separated_sha256(
        TAG_TRELLIS_POSTURE_DECLARATION_V1, intended_declaration_bytes,
    )

    # Shipped declaration: what the export actually carries. The verifier
    # recomputes the digest over THESE bytes — which do not match the
    # event's embedded digest.
    shipped_declaration_bytes = build_shipped_declaration_bytes()
    write_bytes("input-posture-declaration.bin", shipped_declaration_bytes)
    shipped_digest = domain_separated_sha256(
        TAG_TRELLIS_POSTURE_DECLARATION_V1, shipped_declaration_bytes,
    )
    assert declaration_digest != shipped_digest, (
        "tamper invariant: the intended and shipped declarations MUST "
        "produce distinct digests under the trellis-posture-declaration-v1 "
        "domain tag — otherwise there is no declaration-digest mismatch"
    )

    attestation_prior = build_attestation(
        ATTESTATION_AUTHORITY_PRIOR, "prior", prior_authority_seed,
    )
    attestation_new = build_attestation(
        ATTESTATION_AUTHORITY_NEW, "new", issuer_seed,
    )

    transition_payload = {
        "transition_id":          TRANSITION_ID,
        "from_custody_model":     FROM_CUSTODY_MODEL,
        "to_custody_model":       TO_CUSTODY_MODEL,
        "effective_at":           TIMESTAMP,
        "reason_code":            REASON_CODE,
        "declaration_doc_digest": declaration_digest,    # pinned to INTENDED
        "transition_actor":       TRANSITION_ACTOR,
        "policy_authority":       POLICY_AUTHORITY,
        "temporal_scope":         TEMPORAL_SCOPE,
        "attestations":           [attestation_prior, attestation_new],
        "extensions":             None,
    }
    extensions = {EVENT_TYPE.decode("utf-8"): transition_payload}

    prev_hash = load_prior_canonical_event_hash()
    payload_bytes = PAYLOAD_MARKER
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_bytes)

    header = {
        "event_type":             EVENT_TYPE,
        "authored_at":             TIMESTAMP,
        "retention_tier":          RETENTION_TIER,
        "classification":          CLASSIFICATION,
        "outcome_commitment":      None,
        "subject_ref_commitment":  None,
        "tag_commitment":          None,
        "witness_ref":             None,
        "extensions":              None,
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
    author_event_hash = hashlib.sha256(
        domain_separated_preimage(TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes)
    ).digest()

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

    protected_map_bytes = dcbor({
        COSE_LABEL_ALG: ALG_EDDSA, COSE_LABEL_KID: kid, COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: ARTIFACT_TYPE_EVENT,
    })
    sig_structure = dcbor(["Signature1", protected_map_bytes, b"", event_payload_bytes])
    signature = Ed25519PrivateKey.from_private_bytes(issuer_seed).sign(sig_structure)
    cose_sign1_bytes = dcbor(cbor2.CBORTag(
        18, [protected_map_bytes, {}, event_payload_bytes, signature],
    ))
    write_bytes("input-tampered-event.cbor", cose_sign1_bytes)

    ledger_bytes = dcbor([cbor2.loads(cose_sign1_bytes)])
    write_bytes("input-tampered-ledger.cbor", ledger_bytes)

    registry_entry = {
        "kid":         kid,
        "pubkey":      issuer_pub,
        "suite_id":    SUITE_ID,
        "status":      0,
        "valid_from":  ts(1745000000),
        "valid_to":    None,
        "supersedes":  None,
        "attestation": None,
    }
    registry_bytes = dcbor([registry_entry])
    write_bytes("input-signing-key-registry.cbor", registry_bytes)

    canonical_preimage = dcbor({
        "version": 1, "ledger_scope": LEDGER_SCOPE, "event_payload": event_payload,
    })
    canonical_event_hash = domain_separated_sha256(TAG_TRELLIS_EVENT_V1, canonical_preimage)

    print()
    print(f"  failing_event_id (canonical_event_hash) = {canonical_event_hash.hex()}")
    print(f"  declaration_digest (intended)           = {declaration_digest.hex()}")
    print(f"  recomputed_digest (shipped)             = {shipped_digest.hex()}")


if __name__ == "__main__":
    main()
