"""Generate byte-exact reference vector `append/007-custody-transition-cm-c-narrowing`.

Authoring aid only. NOT normative — `derivation.md` carries the spec-prose
reproduction evidence. Determinism: two runs produce byte-identical output.

Scope decision: second O-5 Posture-transition vector. Covers the *narrowing*
branch of Companion §10.4 / OC-11: a transition from CM-C (Delegated Compute)
to CM-B (Reader-Held with Recovery Assistance) contracts the delegated-compute
plaintext surface and so qualifies as a narrowing transition under
`reason_code = key-custody-change` (2). Appendix A.5.3 step 4 permits narrowing
transitions to be attested by the new authority alone; this vector exercises
that single-attestation branch.

Structural shape is identical to `gen_append_006.py` — same event envelope,
same dCBOR / domain-separation / COSE discipline, same `ledger_scope` and
`prev_hash` (also chaining from `append/001`). Only the transition payload's
fields and the attestation count differ. The two generators are intentionally
kept as parallel self-contained files (rather than factoring a shared
`_lib/`) so each remains a standalone reading of Core + Companion per the
stranger-test discipline in the fixture-system design.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cbor2  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from _lib.byte_utils import ts  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent           # fixtures/vectors/
KEY_ISSUER = ROOT / "_keys" / "issuer-001.cose_key"
PAYLOAD_FILE = ROOT / "_inputs" / "sample-payload-001.bin"  # unused but kept for parity
PRIOR_VECTOR_DIR = ROOT / "append" / "001-minimal-inline-payload"
OUT_DIR = ROOT / "append" / "007-custody-transition-cm-c-narrowing"

LEDGER_SCOPE = b"test-response-ledger"
SEQUENCE = 1
TIMESTAMP = ts(1745000200)                                  # +200s vs 001
EVENT_TYPE = b"trellis.custody-model-transition.v1"
CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0
IDEMPOTENCY_KEY = b"idemp-append-007"

PAYLOAD_NONCE = b"\x00" * 12
PAYLOAD_MARKER = b"custody-transition"                  # same marker as 006

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

# Transition pinned values (Companion A.5.1). Narrowing: CM-C → CM-B.
TRANSITION_ID = "urn:trellis:transition:test:007"
FROM_CUSTODY_MODEL = "CM-C"
TO_CUSTODY_MODEL = "CM-B"
REASON_CODE = 2                                         # key-custody-change
TEMPORAL_SCOPE = "prospective"
TRANSITION_ACTOR = "urn:trellis:principal:test-operator"
POLICY_AUTHORITY = "urn:trellis:authority:test-governance"
ATTESTATION_AUTHORITY_NEW = "urn:trellis:authority:test-cm-b-authority"


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
    assert len(prior_head["canonical_event_hash"]) == 32
    return prior_head["canonical_event_hash"]


def build_posture_declaration_bytes() -> bytes:
    # Declaration in force AFTER the transition → custody_model = CM-B.
    return dcbor({
        "declaration_id":            "urn:trellis:declaration:test:007-post",
        "operator_id":               "urn:trellis:operator:test",
        "scope":                     "test-response-ledger",
        "effective_from":            TIMESTAMP,
        "supersedes":                "urn:trellis:declaration:test:007-pre",
        "custody_model":             {"custody_model_id": TO_CUSTODY_MODEL},
        "disclosure_profile":        "rl-profile-B",
        "posture_honesty_statement": "test fixture posture declaration",
    })


def build_attestation(
    authority: str,
    authority_class: str,
    signing_seed: bytes,
    transition_id: str,
    effective_at: int,
) -> dict:
    preimage = dcbor([transition_id, effective_at, authority_class])
    signing_preimage = domain_separated_preimage(
        TAG_TRELLIS_TRANSITION_ATTESTATION_V1, preimage,
    )
    signature = Ed25519PrivateKey.from_private_bytes(signing_seed).sign(signing_preimage)
    assert len(signature) == 64
    return {"authority": authority, "authority_class": authority_class, "signature": signature}


def build_event_header() -> dict:
    return {
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


def build_payload_ref(ciphertext: bytes) -> dict:
    return {"ref_type": "inline", "ciphertext": ciphertext, "nonce": PAYLOAD_NONCE}


def build_author_event_hash_preimage(prev_hash, content_hash, header, payload_ref, key_bag, extensions):
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
        "idempotency_key": IDEMPOTENCY_KEY,
        "extensions":      extensions,
    }


def build_event_payload(prev_hash, author_event_hash, content_hash, header, payload_ref, key_bag, extensions):
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
        "idempotency_key":   IDEMPOTENCY_KEY,
        "extensions":        extensions,
    }


def write_bytes(name: str, data: bytes) -> None:
    path = OUT_DIR / name
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"  {name:55s}  {len(data):>5d} bytes  sha256={digest}")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"generating vector at {OUT_DIR.relative_to(ROOT.parent.parent)}/")

    issuer_seed, issuer_pub = load_cose_key(KEY_ISSUER)
    kid = derive_kid(SUITE_ID, issuer_pub)

    prev_hash = load_prior_canonical_event_hash()
    prior_head_bytes = (PRIOR_VECTOR_DIR / "expected-append-head.cbor").read_bytes()
    write_bytes("input-prior-append-head.cbor", prior_head_bytes)

    declaration_bytes = build_posture_declaration_bytes()
    write_bytes("input-posture-declaration.bin", declaration_bytes)
    declaration_digest = domain_separated_sha256(
        TAG_TRELLIS_POSTURE_DECLARATION_V1, declaration_bytes,
    )

    # Narrowing: single `authority_class="new"` attestation (Companion §10.4,
    # Appendix A.5.3 step 4 narrowing branch; OC-11). The new authority here
    # represents the incoming CM-B authority, signed with issuer-001.
    attestation_new = build_attestation(
        authority=ATTESTATION_AUTHORITY_NEW,
        authority_class="new",
        signing_seed=issuer_seed,
        transition_id=TRANSITION_ID,
        effective_at=TIMESTAMP,
    )
    write_bytes(
        "input-attestation-preimage-new.cbor",
        dcbor([TRANSITION_ID, TIMESTAMP, "new"]),
    )

    transition_payload = {
        "transition_id":          TRANSITION_ID,
        "from_custody_model":     FROM_CUSTODY_MODEL,
        "to_custody_model":       TO_CUSTODY_MODEL,
        "effective_at":           TIMESTAMP,
        "reason_code":            REASON_CODE,
        "declaration_doc_digest": declaration_digest,
        "transition_actor":       TRANSITION_ACTOR,
        "policy_authority":       POLICY_AUTHORITY,
        "temporal_scope":         TEMPORAL_SCOPE,
        "attestations":           [attestation_new],
        "extensions":             None,
    }
    extensions = {EVENT_TYPE.decode("utf-8"): transition_payload}

    payload_bytes = PAYLOAD_MARKER
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_bytes)

    header = build_event_header()
    payload_ref = build_payload_ref(payload_bytes)
    key_bag = {"entries": []}

    authored_bytes = dcbor(build_author_event_hash_preimage(
        prev_hash, content_hash, header, payload_ref, key_bag, extensions,
    ))
    write_bytes("input-author-event-hash-preimage.cbor", authored_bytes)

    author_event_hash = hashlib.sha256(
        domain_separated_preimage(TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes)
    ).digest()
    write_bytes("author-event-hash.bin", author_event_hash)

    event_payload = build_event_payload(
        prev_hash, author_event_hash, content_hash, header, payload_ref, key_bag, extensions,
    )
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
