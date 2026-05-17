"""Generate byte-exact reference vector `tamper/016-disclosure-profile-from-mismatch`.

Authoring aid only. NOT normative — `derivation.md` carries the spec-prose
reproduction evidence. Determinism: two runs produce byte-identical output.

Scope decision: disclosure-profile sibling of `tamper/002-transition-from-mismatch`,
landed to close the G-O-5 retroactive reopen from the 2026-04-23 design-doc
audit. Exercises Core §19 step 6.b — the state-continuity check — on the
`trellis.disclosure-profile-transition.v1` extension (Companion Appendix A.5.2)
rather than the custody-model axis.

Before this vector landed, the Trellis verifier's `decode_transition_details`
handled only custody-model transitions; a tampered `from_disclosure_profile`
value passed verification. The companion Rust fix extends the decode arm to
disclosure-profile transitions, adds a parallel `shadow_disclosure_profile`
baseline, and routes the attestation rule through Appendix A.5.3 step 4's
`scope_change` enum (Narrowing MAY be attested alone; Widening / Orthogonal
MUST be dually attested). This vector is the negative oracle for that code
path: from_disclosure_profile = "rl-profile-C", initial declaration pins
"rl-profile-A", so step 6.b fails with tamper_kind = "state_continuity_mismatch"
exactly as the custody sibling does.

Per Core §19 step 6.b this is a *localizable* failure: structure_verified
= true, integrity_verified = false, readability_verified = true. The event
is re-signed end-to-end so the tamper is purely semantic — not cryptographic.
Dual attestation is present (scope_change = "Orthogonal") so the
attestation-rule step is exercised positively while the continuity step
fails.
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
KEY_ATTESTATION_AUTHORITY_PRIOR = (
    ROOT / "_keys" / "attestation-authority-cm-b-001.cose_key"
)
PRIOR_VECTOR_DIR = ROOT / "append" / "001-minimal-inline-payload"
OUT_DIR = ROOT / "tamper" / "016-disclosure-profile-from-mismatch"

LEDGER_SCOPE = b"test-response-ledger"
SEQUENCE = 1
TIMESTAMP = ts(1745000500)
EVENT_TYPE = b"trellis.disclosure-profile-transition.v1"
CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0
IDEMPOTENCY_KEY = b"tamper-transition-016"

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

# The tamper: the initial declaration pins disclosure_profile = "rl-profile-A".
# The transition event claims from_disclosure_profile = "rl-profile-C". Step
# 6.b catches the mismatch against the shadow_disclosure_profile baseline.
TRANSITION_ID = "urn:trellis:transition:test:tamper-016"
INITIAL_DISCLOSURE_PROFILE = "rl-profile-A"              # in the deployment's initial declaration
CLAIMED_FROM_DISCLOSURE_PROFILE = "rl-profile-C"         # TAMPER — does not match initial
TO_DISCLOSURE_PROFILE = "rl-profile-B"
SCOPE_CHANGE = "Orthogonal"                              # non-narrowing default; dual attestation required
REASON_CODE = 4                                          # governance-policy-change
TEMPORAL_SCOPE = "prospective"
TRANSITION_ACTOR = "urn:trellis:principal:test-operator"
POLICY_AUTHORITY = "urn:trellis:authority:test-governance"
ATTESTATION_AUTHORITY_PRIOR = "urn:trellis:authority:test-profile-a-authority"
ATTESTATION_AUTHORITY_NEW = "urn:trellis:authority:test-profile-b-authority"


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
    """Declaration in force BEFORE any transition; pins disclosure_profile = rl-profile-A.

    The verifier uses this declaration's top-level `disclosure_profile` as
    the shadow-state baseline for step 6.b (parallel to how custody-model
    transitions use `custody_model.custody_model_id`). The tampered event's
    `from_disclosure_profile` MUST equal this value — this vector tampers
    exactly that equality.
    """
    return dcbor({
        "declaration_id":            "urn:trellis:declaration:test:tamper-016-initial",
        "operator_id":               "urn:trellis:operator:test",
        "scope":                     "test-response-ledger",
        "effective_from":            ts(1745000000),
        "supersedes":                None,
        "custody_model":             {"custody_model_id": "CM-B"},
        "disclosure_profile":        INITIAL_DISCLOSURE_PROFILE,
        "posture_honesty_statement": "test fixture initial posture declaration",
    })


def build_post_transition_declaration_bytes() -> bytes:
    """Declaration the transition event's `declaration_doc_digest` points at.

    Pins disclosure_profile = TO_DISCLOSURE_PROFILE. This declaration IS
    correctly byte-matched by the event's digest (only the from_* field
    is tampered; step 6.c passes, step 6.b fails).
    """
    return dcbor({
        "declaration_id":            "urn:trellis:declaration:test:tamper-016-post",
        "operator_id":               "urn:trellis:operator:test",
        "scope":                     "test-response-ledger",
        "effective_from":            TIMESTAMP,
        "supersedes":                "urn:trellis:declaration:test:tamper-016-initial",
        "custody_model":             {"custody_model_id": "CM-B"},
        "disclosure_profile":        TO_DISCLOSURE_PROFILE,
        "posture_honesty_statement": "test fixture post-transition posture declaration",
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
    prior_authority_seed, _ = load_cose_key(KEY_ATTESTATION_AUTHORITY_PRIOR)
    kid = derive_kid(SUITE_ID, issuer_pub)

    # 1. Commit the INITIAL posture declaration (shadow-state baseline).
    initial_declaration_bytes = build_initial_declaration_bytes()
    write_bytes("input-initial-posture-declaration.bin", initial_declaration_bytes)

    # 2. Commit the POST-TRANSITION posture declaration (the one whose
    #    digest the event's `declaration_doc_digest` points at).
    post_declaration_bytes = build_post_transition_declaration_bytes()
    write_bytes("input-posture-declaration.bin", post_declaration_bytes)
    declaration_digest = domain_separated_sha256(
        TAG_TRELLIS_POSTURE_DECLARATION_V1, post_declaration_bytes,
    )

    # 3. Build BOTH attestations. scope_change = "Orthogonal" MUST be dually
    #    attested (Appendix A.5.3 step 4), so both classes are present and
    #    the attestation-rule step passes. The tamper is purely on from_*.
    attestation_prior = build_attestation(
        ATTESTATION_AUTHORITY_PRIOR, "prior", prior_authority_seed,
    )
    attestation_new = build_attestation(
        ATTESTATION_AUTHORITY_NEW, "new", issuer_seed,
    )

    # 4. Tampered transition payload: from_disclosure_profile claims
    #    "rl-profile-C", but the initial declaration pins "rl-profile-A".
    #    This is the load-bearing mutation.
    transition_payload = {
        "transition_id":           TRANSITION_ID,
        "from_disclosure_profile": CLAIMED_FROM_DISCLOSURE_PROFILE,  # TAMPER
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

    # 5. Rebuild the event end-to-end so the signature verifies (the tamper
    #    is semantic, not cryptographic; step 6.b MUST be the failing step).
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

    # 6. Signing-key registry so §19 step 4.a kid resolution succeeds.
    registry_entry = {
        "kid":         kid,
        "pubkey":      issuer_pub,
        "suite_id":    SUITE_ID,
        "status":      0,                   # Active
        "valid_from":  ts(1745000000),
        "valid_to":    None,
        "supersedes":  None,
        "attestation": None,
    }
    registry_bytes = dcbor([registry_entry])
    write_bytes("input-signing-key-registry.cbor", registry_bytes)

    # 7. Compute the post-tamper canonical_event_hash for the expected report.
    canonical_preimage = dcbor({
        "version": 1, "ledger_scope": LEDGER_SCOPE, "event_payload": event_payload,
    })
    canonical_event_hash = domain_separated_sha256(TAG_TRELLIS_EVENT_V1, canonical_preimage)

    print()
    print(f"  failing_event_id (canonical_event_hash)     = {canonical_event_hash.hex()}")
    print(f"  kid                                          = {kid.hex()}")
    print(f"  claimed_from_disclosure_profile              = {CLAIMED_FROM_DISCLOSURE_PROFILE}")
    print(f"  initial_disclosure_profile                   = {INITIAL_DISCLOSURE_PROFILE}")


if __name__ == "__main__":
    main()
