"""Generate tamper vectors `tamper/017-erasure-post-use` + `tamper/018-erasure-post-wrap`.

ADR 0005 §"Verifier obligations" step 8 chain-walk for
`norm_key_class ∈ {"signing", "subject"}`. Both vectors land a 2-event
chain where:

  - Event 0 (sequence = 0): genesis event that emits a
    `trellis.erasure-evidence.v1` extension declaring some kid was
    destroyed at time `destroyed_at`. The host event's `authored_at`
    equals `destroyed_at` (allowed per ADR 0005 step 4: <=) so the
    payload validates.

  - Event 1 (sequence = 1): a non-genesis event with `authored_at >
    destroyed_at`. For tamper/017, this event is signed under the same
    `kid_destroyed` (post_erasure_use). For tamper/018, this event
    carries a `key_bag.entries[*].recipient` equal to `kid_destroyed`
    (post_erasure_wrap).

Each event's COSE_Sign1 signature is well-formed; the tamper is semantic
(post-erasure use of a destroyed key) — not cryptographic. Per ADR 0005
step 8 the verifier flags `post_erasure_use` / `post_erasure_wrap` and
`integrity_verified` flips to false via the step-10 fold.

Self-contained vectors. No initial posture declaration — `verify_tampered_ledger`
walks the 2-event chain directly.

NOTE: We use `key_class = "signing"` for tamper/017 (so step 8 dispatches)
and `key_class = "subject"` for tamper/018. For tamper/017, `kid_destroyed`
is the issuer's signing kid — i.e. the same one the chain uses to sign.
This is the canonical "I claimed I destroyed this key but then signed
again under it" failure mode.

For tamper/018, `kid_destroyed` is an opaque 16-byte subject kid; the
event-1's `key_bag.entries[0].recipient` is byte-equal to that value.
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

LEDGER_SCOPE = b"test-response-ledger"
EVENT_TYPE_ERASURE = b"trellis.erasure-evidence.v1"
EVENT_TYPE_FOLLOWUP = b"x-trellis-test/post-erasure-use"
CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0

PAYLOAD_NONCE = b"\x00" * 12
PAYLOAD_MARKER_ERASURE = b"erasure-event"
PAYLOAD_MARKER_FOLLOWUP = b"followup-after-erasure"

DESTROYED_AT = ts(1_745_000_100)
HOST_AUTHORED_AT_EVENT0 = ts(1_745_000_100)  # equal — step 4 allows <=
FOLLOWUP_AUTHORED_AT = ts(1_745_000_500)     # > destroyed_at

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


def build_attestation_new(
    *,
    signing_seed: bytes,
    transition_id: str,
    effective_at: int,
) -> dict:
    preimage_inner = dcbor([transition_id, effective_at, "new"])
    signing_preimage = domain_separated_preimage(
        TAG_TRELLIS_TRANSITION_ATTESTATION_V1, preimage_inner,
    )
    sk = Ed25519PrivateKey.from_private_bytes(signing_seed)
    signature = sk.sign(signing_preimage)
    return {
        "authority":       "urn:trellis:authority:test-erasure-authority",
        "authority_class": "new",
        "signature":       signature,
    }


def build_erasure_payload(
    *,
    evidence_id: str,
    kid_destroyed: bytes,
    key_class: str,
    attestation: dict,
) -> dict:
    return {
        "evidence_id":          evidence_id,
        "kid_destroyed":        kid_destroyed,
        "key_class":            key_class,
        "destroyed_at":         DESTROYED_AT,
        "cascade_scopes":       ["CS-03"],
        "completion_mode":      "complete",
        "destruction_actor":    "urn:trellis:principal:test-operator",
        "policy_authority":     "urn:trellis:authority:test-governance",
        "reason_code":          1,
        "subject_scope": {
            "kind":          "per-subject",
            "subject_refs":  ["urn:trellis:subject:test-applicant-tamper"],
            "ledger_scopes": None,
            "tenant_refs":   None,
        },
        "hsm_receipt":          None,
        "hsm_receipt_kind":     None,
        "attestations":         [attestation],
        "extensions":           None,
    }


def build_event(
    *,
    sequence: int,
    prev_hash: bytes | None,
    authored_at: int,
    event_type: bytes,
    payload_marker: bytes,
    extensions: dict | None,
    key_bag: dict,
    idempotency_key: bytes,
    issuer_seed: bytes,
    kid: bytes,
) -> tuple[bytes, bytes, bytes]:
    """Returns (signed_event_bytes, canonical_event_payload_bytes, canonical_event_hash)."""

    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_marker)

    header = {
        "event_type":             event_type,
        "authored_at":             authored_at,
        "retention_tier":          RETENTION_TIER,
        "classification":          CLASSIFICATION,
        "outcome_commitment":      None,
        "subject_ref_commitment":  None,
        "tag_commitment":          None,
        "witness_ref":             None,
        "extensions":              None,
    }
    payload_ref = {
        "ref_type":   "inline",
        "ciphertext": payload_marker,
        "nonce":      PAYLOAD_NONCE,
    }

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
    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1,
        dcbor({
            "version":       1,
            "ledger_scope":  LEDGER_SCOPE,
            "event_payload": event_payload,
        }),
    )

    protected_map = {
        COSE_LABEL_ALG:      ALG_EDDSA,
        COSE_LABEL_KID:      kid,
        COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: ARTIFACT_TYPE_EVENT,
    }
    protected_map_bytes = dcbor(protected_map)
    sig_structure = dcbor(["Signature1", protected_map_bytes, b"", event_payload_bytes])
    sk = Ed25519PrivateKey.from_private_bytes(issuer_seed)
    signature = sk.sign(sig_structure)

    cose_sign1 = cbor2.CBORTag(
        18, [protected_map_bytes, {}, event_payload_bytes, signature],
    )
    return dcbor(cose_sign1), event_payload_bytes, canonical_event_hash


def build_signing_key_registry(kid: bytes, pubkey: bytes) -> bytes:
    """Phase-1 flat signing-key registry (Core §8.2 legacy shape)."""
    return dcbor([
        {
            "kid":     kid,
            "pubkey":  pubkey,
            "status":  1,                 # Active
            "valid_to": None,
        }
    ])


def write_bytes(out_dir: Path, name: str, data: bytes) -> str:
    path = out_dir / name
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"  {name:55s}  {len(data):>5d} bytes  sha256={digest}")
    return digest


def gen_tamper_017(*, issuer_seed: bytes, issuer_pub: bytes, kid: bytes) -> str:
    """tamper/017-erasure-post-use: erasure declares the issuer kid destroyed,
    then a later event is signed under that same kid → post_erasure_use.
    """
    out_dir = ROOT / "tamper" / "017-erasure-post-use"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {out_dir.relative_to(ROOT.parent.parent)}/")

    # Event 0: erasure-evidence event declaring the issuer's kid destroyed.
    # `kid_destroyed = kid` (the issuer's own signing kid).
    attestation = build_attestation_new(
        signing_seed=issuer_seed,
        transition_id="urn:trellis:erasure:test:tamper-017",
        effective_at=DESTROYED_AT,
    )
    erasure_payload = build_erasure_payload(
        evidence_id="urn:trellis:erasure:test:tamper-017",
        kid_destroyed=kid,                              # SAME as issuer kid
        key_class="signing",                            # signing → step 8 dispatches
        attestation=attestation,
    )
    extensions_event0 = {EVENT_TYPE_ERASURE.decode("utf-8"): erasure_payload}
    event0_bytes, event0_payload_bytes, event0_canonical_hash = build_event(
        sequence=0,
        prev_hash=None,
        authored_at=HOST_AUTHORED_AT_EVENT0,
        event_type=EVENT_TYPE_ERASURE,
        payload_marker=PAYLOAD_MARKER_ERASURE,
        extensions=extensions_event0,
        key_bag={"entries": []},
        idempotency_key=b"tamper-017-event0",
        issuer_seed=issuer_seed,
        kid=kid,
    )

    # Event 1: post-erasure event SIGNED UNDER kid_destroyed = kid.
    # authored_at > destroyed_at → step 8 must flag post_erasure_use.
    event1_bytes, _, _ = build_event(
        sequence=1,
        prev_hash=event0_canonical_hash,
        authored_at=FOLLOWUP_AUTHORED_AT,
        event_type=EVENT_TYPE_FOLLOWUP,
        payload_marker=PAYLOAD_MARKER_FOLLOWUP,
        extensions=None,
        key_bag={"entries": []},
        idempotency_key=b"tamper-017-event1",
        issuer_seed=issuer_seed,
        kid=kid,                                       # SAME as kid_destroyed
    )

    # Tampered ledger = dCBOR array of [event0, event1] tag-18 envelopes.
    tampered_ledger = dcbor([
        cbor2.loads(event0_bytes),
        cbor2.loads(event1_bytes),
    ])
    write_bytes(out_dir, "input-tampered-ledger.cbor", tampered_ledger)

    # Signing-key registry: just the issuer.
    write_bytes(
        out_dir,
        "input-signing-key-registry.cbor",
        build_signing_key_registry(kid, issuer_pub),
    )

    # The "tampered event" file (per the tamper/* convention) is the second
    # event — the one that triggers the post_erasure_use flag. Verifier
    # localizes there.
    write_bytes(out_dir, "input-tampered-event.cbor", event1_bytes)

    # Compute the failing canonical_event_hash of event 1 for the manifest.
    _, _, event1_canonical_hash = build_event(
        sequence=1,
        prev_hash=event0_canonical_hash,
        authored_at=FOLLOWUP_AUTHORED_AT,
        event_type=EVENT_TYPE_FOLLOWUP,
        payload_marker=PAYLOAD_MARKER_FOLLOWUP,
        extensions=None,
        key_bag={"entries": []},
        idempotency_key=b"tamper-017-event1",
        issuer_seed=issuer_seed,
        kid=kid,
    )
    print(f"  event0 canonical_event_hash = {event0_canonical_hash.hex()}")
    print(f"  event1 canonical_event_hash = {event1_canonical_hash.hex()}")
    return event1_canonical_hash.hex()


def gen_tamper_018(*, issuer_seed: bytes, issuer_pub: bytes, kid: bytes) -> str:
    """tamper/018-erasure-post-wrap: erasure declares an opaque subject kid
    destroyed, then a later event has key_bag.entries[*].recipient =
    kid_destroyed → post_erasure_wrap.
    """
    out_dir = ROOT / "tamper" / "018-erasure-post-wrap"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {out_dir.relative_to(ROOT.parent.parent)}/")

    # Use a distinct opaque subject-class kid; not in any registry.
    kid_destroyed = bytes.fromhex("b8" * 16)

    attestation = build_attestation_new(
        signing_seed=issuer_seed,
        transition_id="urn:trellis:erasure:test:tamper-018",
        effective_at=DESTROYED_AT,
    )
    erasure_payload = build_erasure_payload(
        evidence_id="urn:trellis:erasure:test:tamper-018",
        kid_destroyed=kid_destroyed,
        key_class="subject",                            # subject → step 8 dispatches
        attestation=attestation,
    )
    extensions_event0 = {EVENT_TYPE_ERASURE.decode("utf-8"): erasure_payload}
    event0_bytes, event0_payload_bytes, event0_canonical_hash = build_event(
        sequence=0,
        prev_hash=None,
        authored_at=HOST_AUTHORED_AT_EVENT0,
        event_type=EVENT_TYPE_ERASURE,
        payload_marker=PAYLOAD_MARKER_ERASURE,
        extensions=extensions_event0,
        key_bag={"entries": []},
        idempotency_key=b"tamper-018-event0",
        issuer_seed=issuer_seed,
        kid=kid,
    )

    # Event 1: post-erasure event with key_bag wrapping under kid_destroyed.
    # Phase-1 KeyBagEntry per Core §8.6: `recipient` is opaque bytes;
    # we put kid_destroyed there to trigger the chain-walk wrap detection.
    post_erasure_key_bag = {
        "entries": [
            {
                "recipient":       kid_destroyed,
                "ephemeral_pubkey": bytes.fromhex("c0" * 32),
                "wrapped_key":      bytes.fromhex("d0" * 48),
            }
        ]
    }
    event1_bytes, _, event1_canonical_hash = build_event(
        sequence=1,
        prev_hash=event0_canonical_hash,
        authored_at=FOLLOWUP_AUTHORED_AT,
        event_type=EVENT_TYPE_FOLLOWUP,
        payload_marker=PAYLOAD_MARKER_FOLLOWUP,
        extensions=None,
        key_bag=post_erasure_key_bag,
        idempotency_key=b"tamper-018-event1",
        issuer_seed=issuer_seed,
        kid=kid,                                       # signed under issuer kid
    )

    tampered_ledger = dcbor([
        cbor2.loads(event0_bytes),
        cbor2.loads(event1_bytes),
    ])
    write_bytes(out_dir, "input-tampered-ledger.cbor", tampered_ledger)
    write_bytes(
        out_dir,
        "input-signing-key-registry.cbor",
        build_signing_key_registry(kid, issuer_pub),
    )
    write_bytes(out_dir, "input-tampered-event.cbor", event1_bytes)

    print(f"  kid_destroyed              = {kid_destroyed.hex()}")
    print(f"  event0 canonical_event_hash = {event0_canonical_hash.hex()}")
    print(f"  event1 canonical_event_hash = {event1_canonical_hash.hex()}")
    return event1_canonical_hash.hex()


def main() -> dict[str, str]:
    issuer_seed, issuer_pub = load_cose_key(KEY_ISSUER)
    kid = derive_kid(SUITE_ID, issuer_pub)
    out: dict[str, str] = {}
    out["017"] = gen_tamper_017(issuer_seed=issuer_seed, issuer_pub=issuer_pub, kid=kid)
    out["018"] = gen_tamper_018(issuer_seed=issuer_seed, issuer_pub=issuer_pub, kid=kid)
    return out


if __name__ == "__main__":
    out = main()
    print()
    for k, v in out.items():
        print(f"  tamper/0{k} failing canonical_event_hash = {v}")
