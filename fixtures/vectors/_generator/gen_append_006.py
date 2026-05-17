"""Generate byte-exact reference vector `append/006-custody-transition-cm-b-to-cm-a`.

Authoring aid only. Every construction block carries an inline Core-§ / Companion-§
citation naming the normative paragraph that determines the bytes. This script is
NOT normative; `derivation.md` is the spec-prose reproduction evidence.

Determinism: two runs produce byte-identical output. No randomness, no wall-clock
reads, no environment lookups beyond pinned inputs.

Scope decision: first O-5 posture-transition vector. Extends the non-genesis
chain rooted at `append/001-minimal-inline-payload` (same ledger_scope) by
carrying a `trellis.custody-model-transition.v1` payload under
`EventPayload.extensions`. CM-B → CM-A is Posture-widening (provider-readable
decryptor set expands), so Companion §10.4 / OC-11 / Appendix A.5.3 step 4
require dual attestation (one `authority_class="prior"`, one `authority_class="new"`).

Two keys sign things in this vector:

  * `issuer-001.cose_key` — event COSE_Sign1 envelope issuer AND the
    `authority_class="new"` attester (represents the CM-A authority).
  * `attestation-authority-cm-b-001.cose_key` — the `authority_class="prior"`
    attester (represents the CM-B authority about to be retired).

Attestation signature discipline per Companion Appendix A.5 (shared rule) +
Core §9.8:
    attestation.signature = Ed25519(sk, domain_preimage(
      "trellis-transition-attestation-v1",
      dCBOR([transition_id, effective_at, authority_class])))

The PostureDeclaration bytes (§11.3 / Appendix A.1) are a minimal dCBOR map
committed as `input-posture-declaration.bin`. The spec prose defines the
declaration fields but has NOT pinned its CDDL byte shape (surfaced in
`thoughts/specs/2026-04-18-trellis-core-gaps-surfaced-by-g3.md`). For this
fixture the declaration bytes serve only as the preimage for
`declaration_doc_digest` via the `trellis-posture-declaration-v1` domain tag;
the verifier's obligation is to re-compute the digest and compare, which is
byte-testable regardless of the declaration's internal CDDL.
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
KEY_ATTESTATION_AUTHORITY_CM_B = (
    ROOT / "_keys" / "attestation-authority-cm-b-001.cose_key"
)
PAYLOAD_FILE = ROOT / "_inputs" / "sample-payload-001.bin"
PRIOR_VECTOR_DIR = ROOT / "append" / "001-minimal-inline-payload"
OUT_DIR = ROOT / "append" / "006-custody-transition-cm-b-to-cm-a"

# ---------------------------------------------------------------------------
# Event-level pinned values. sequence = 1; prev_hash from 001.
# (We chain from 001 directly rather than from 005, so this fixture's chain
# stays fully self-contained — only one prior vector needs to be read.)
# ---------------------------------------------------------------------------

LEDGER_SCOPE = b"test-response-ledger"                  # §10.6; equal to 001
SEQUENCE = 1                                            # §10.2 sequence > 0
TIMESTAMP = ts(1745000100)                                # +100s vs 001
EVENT_TYPE = b"trellis.custody-model-transition.v1"     # Core §6.7; Companion A.5.1
CLASSIFICATION = b"x-trellis-test/unclassified"         # §14.6
RETENTION_TIER = 0                                      # §12.1
IDEMPOTENCY_KEY = b"idemp-append-006"                   # §6.1; distinct per §17.3

# §6.4 nonce length 12; irrelevant here (we carry zero-byte ciphertext — the
# payload is the transition event; no encrypted body to transport). We still
# emit a PayloadInline per §6.1 (payload_ref is required). Use a 16-byte
# marker ciphertext that says explicitly "transition-event carries no user
# payload — the payload IS the transition".
PAYLOAD_NONCE = b"\x00" * 12
PAYLOAD_MARKER = b"custody-transition"                  # 18 bytes; opaque bstr

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

# ---------------------------------------------------------------------------
# Transition-specific pinned values (Companion A.5.1).
# ---------------------------------------------------------------------------

TRANSITION_ID = "urn:trellis:transition:test:006"
FROM_CUSTODY_MODEL = "CM-B"
TO_CUSTODY_MODEL = "CM-A"
REASON_CODE = 3                                         # operator-boundary-change
TEMPORAL_SCOPE = "prospective"
TRANSITION_ACTOR = "urn:trellis:principal:test-operator"
POLICY_AUTHORITY = "urn:trellis:authority:test-governance"
ATTESTATION_AUTHORITY_PRIOR = "urn:trellis:authority:test-cm-b-authority"
ATTESTATION_AUTHORITY_NEW = "urn:trellis:authority:test-cm-a-authority"

# ---------------------------------------------------------------------------
# dCBOR (Core §5.1).
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


# ---------------------------------------------------------------------------
# Key loading.
# ---------------------------------------------------------------------------

def load_cose_key(path: Path) -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(path.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    assert len(seed) == 32 and len(pubkey) == 32
    return seed, pubkey


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def load_prior_canonical_event_hash() -> bytes:
    prior_head_path = PRIOR_VECTOR_DIR / "expected-append-head.cbor"
    prior_head = cbor2.loads(prior_head_path.read_bytes())
    assert prior_head["scope"] == LEDGER_SCOPE
    assert prior_head["sequence"] == SEQUENCE - 1
    assert len(prior_head["canonical_event_hash"]) == 32
    return prior_head["canonical_event_hash"]


# ---------------------------------------------------------------------------
# Posture declaration byte bag (Companion A.1).
#
# The declaration's internal CDDL is prose-level in Companion A.1; its byte
# shape is not normatively pinned. For O-5 fixtures we commit a minimal
# dCBOR map mirroring A.1's named fields so the bytes have a reviewer-
# legible structure. The verifier's obligation (§19 step 6.c) is to recompute
# `declaration_doc_digest = SHA-256(domain_sep("trellis-posture-declaration-v1",
# <declaration_bytes>))` and compare — it does NOT need to parse the interior.
# ---------------------------------------------------------------------------

def build_posture_declaration_bytes(
    scope: str,
    custody_model: str,
    disclosure_profile: str,
    effective_from: int,
    declaration_id: str = "urn:trellis:declaration:test:006-post",
) -> bytes:
    decl = {
        "declaration_id":            declaration_id,
        "operator_id":               "urn:trellis:operator:test",
        "scope":                     scope,
        "effective_from":            effective_from,
        "supersedes":                "urn:trellis:declaration:test:005-pre",
        "custody_model":             {"custody_model_id": custody_model},
        "disclosure_profile":        disclosure_profile,
        "posture_honesty_statement": "test fixture posture declaration",
    }
    return dcbor(decl)


# ---------------------------------------------------------------------------
# Attestation builder (Companion A.5 shared rule).
# ---------------------------------------------------------------------------

def build_attestation(
    authority: str,
    authority_class: str,
    signing_seed: bytes,
    transition_id: str,
    effective_at: int,
) -> dict:
    # Preimage per shared Attestation rule: dCBOR([transition_id,
    # effective_at, authority_class]) under the
    # `trellis-transition-attestation-v1` domain tag (Core §9.8).
    attestation_payload = dcbor([transition_id, effective_at, authority_class])
    signing_preimage = domain_separated_preimage(
        TAG_TRELLIS_TRANSITION_ATTESTATION_V1, attestation_payload,
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
# Transition payload (Companion A.5.1).
# ---------------------------------------------------------------------------

def build_custody_model_transition_payload(
    declaration_digest: bytes,
    attestations: list[dict],
) -> dict:
    return {
        "transition_id":          TRANSITION_ID,
        "from_custody_model":     FROM_CUSTODY_MODEL,
        "to_custody_model":       TO_CUSTODY_MODEL,
        "effective_at":           TIMESTAMP,
        "reason_code":            REASON_CODE,
        "declaration_doc_digest": declaration_digest,
        "transition_actor":       TRANSITION_ACTOR,
        "policy_authority":       POLICY_AUTHORITY,
        "temporal_scope":         TEMPORAL_SCOPE,
        "attestations":           attestations,
        "extensions":             None,
    }


# ---------------------------------------------------------------------------
# Event shape (§6.1, §6.8, §9.5).
# ---------------------------------------------------------------------------

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
    return {
        "ref_type":   "inline",
        "ciphertext": ciphertext,
        "nonce":      PAYLOAD_NONCE,
    }


def build_key_bag() -> dict:
    return {"entries": []}


def build_author_event_hash_preimage(
    prev_hash: bytes,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
    extensions: dict,
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
        "idempotency_key": IDEMPOTENCY_KEY,
        "extensions":      extensions,
    }


def build_event_payload(
    prev_hash: bytes,
    author_event_hash: bytes,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
    extensions: dict,
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
        "idempotency_key":   IDEMPOTENCY_KEY,
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


def write_bytes(name: str, data: bytes) -> None:
    path = OUT_DIR / name
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"  {name:55s}  {len(data):>5d} bytes  sha256={digest}")


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"generating vector at {OUT_DIR.relative_to(ROOT.parent.parent)}/")

    issuer_seed, issuer_pub = load_cose_key(KEY_ISSUER)
    prior_authority_seed, _ = load_cose_key(KEY_ATTESTATION_AUTHORITY_CM_B)
    kid = derive_kid(SUITE_ID, issuer_pub)

    # 1. Read prior AppendHead (from 001), propagate prev_hash (§10.2).
    prev_hash = load_prior_canonical_event_hash()
    prior_head_bytes = (PRIOR_VECTOR_DIR / "expected-append-head.cbor").read_bytes()
    write_bytes("input-prior-append-head.cbor", prior_head_bytes)

    # 2. Build + commit the post-transition PostureDeclaration bytes.
    #    Its digest (under the trellis-posture-declaration-v1 domain tag, §9.8)
    #    becomes `declaration_doc_digest` inside the transition payload.
    declaration_bytes = build_posture_declaration_bytes(
        scope="test-response-ledger",
        custody_model=TO_CUSTODY_MODEL,
        disclosure_profile="rl-profile-A",
        effective_from=TIMESTAMP,
    )
    write_bytes("input-posture-declaration.bin", declaration_bytes)
    declaration_digest = domain_separated_sha256(
        TAG_TRELLIS_POSTURE_DECLARATION_V1, declaration_bytes,
    )

    # 3. Build both attestations (prior + new; OC-11 widening rule).
    attestation_prior = build_attestation(
        authority=ATTESTATION_AUTHORITY_PRIOR,
        authority_class="prior",
        signing_seed=prior_authority_seed,
        transition_id=TRANSITION_ID,
        effective_at=TIMESTAMP,
    )
    attestation_new = build_attestation(
        authority=ATTESTATION_AUTHORITY_NEW,
        authority_class="new",
        signing_seed=issuer_seed,
        transition_id=TRANSITION_ID,
        effective_at=TIMESTAMP,
    )
    # Commit the two attestation preimages (human-debuggable bytes).
    attestation_preimages_path = {
        "prior": dcbor([TRANSITION_ID, TIMESTAMP, "prior"]),
        "new":   dcbor([TRANSITION_ID, TIMESTAMP, "new"]),
    }
    write_bytes(
        "input-attestation-preimage-prior.cbor",
        attestation_preimages_path["prior"],
    )
    write_bytes(
        "input-attestation-preimage-new.cbor",
        attestation_preimages_path["new"],
    )

    # 4. Assemble the transition payload (Companion A.5.1) and pack into
    #    EventPayload.extensions per Core §6.5 strict-superset semantics.
    transition_payload = build_custody_model_transition_payload(
        declaration_digest=declaration_digest,
        attestations=[attestation_prior, attestation_new],
    )
    extensions = {EVENT_TYPE.decode("utf-8"): transition_payload}

    # 5. Minimal PayloadInline — the transition is the payload.
    payload_bytes = PAYLOAD_MARKER
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_bytes)

    # 6. AuthorEventHashPreimage → author_event_hash (§9.5, §9.1).
    header = build_event_header()
    payload_ref = build_payload_ref(payload_bytes)
    key_bag = build_key_bag()
    authored_map = build_author_event_hash_preimage(
        prev_hash=prev_hash,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
        extensions=extensions,
    )
    authored_bytes = dcbor(authored_map)
    write_bytes("input-author-event-hash-preimage.cbor", authored_bytes)

    author_event_preimage = domain_separated_preimage(
        TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes,
    )
    author_event_hash = hashlib.sha256(author_event_preimage).digest()
    write_bytes("author-event-hash.bin", author_event_hash)

    # 7. EventPayload (§6.1).
    event_payload = build_event_payload(
        prev_hash=prev_hash,
        author_event_hash=author_event_hash,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
        extensions=extensions,
    )
    event_payload_bytes = dcbor(event_payload)
    write_bytes("expected-event-payload.cbor", event_payload_bytes)

    # 8. Protected header + Sig_structure + Ed25519 signature (§7.4, §7.1).
    protected_map = build_protected_header(kid)
    protected_map_bytes = dcbor(protected_map)
    sig_structure = build_sig_structure(protected_map_bytes, event_payload_bytes)
    write_bytes("sig-structure.bin", sig_structure)

    sk = Ed25519PrivateKey.from_private_bytes(issuer_seed)
    signature = sk.sign(sig_structure)
    assert len(signature) == 64

    # 9. COSE_Sign1 tag-18 envelope (§6.8 signed form, §7.4, RFC 9052 §4.2).
    cose_sign1 = cbor2.CBORTag(
        18, [protected_map_bytes, {}, event_payload_bytes, signature],
    )
    cose_sign1_bytes = dcbor(cose_sign1)
    write_bytes("expected-event.cbor", cose_sign1_bytes)

    # 10. canonical_event_hash (§9.2) + AppendHead (§10.6).
    canonical_preimage = dcbor(build_canonical_event_hash_preimage(event_payload))
    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1, canonical_preimage,
    )
    append_head = build_append_head(LEDGER_SCOPE, SEQUENCE, canonical_event_hash)
    write_bytes("expected-append-head.cbor", dcbor(append_head))

    print()
    print(f"  prev_hash                  = {prev_hash.hex()}")
    print(f"  kid                        = {kid.hex()}")
    print(f"  declaration_digest         = {declaration_digest.hex()}")
    print(f"  content_hash               = {content_hash.hex()}")
    print(f"  author_event_hash          = {author_event_hash.hex()}")
    print(f"  canonical_event_hash       = {canonical_event_hash.hex()}")


if __name__ == "__main__":
    main()
