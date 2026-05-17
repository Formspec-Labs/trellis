"""Generate byte-exact reference vector `shred/001-purge-cascade-minimal`.

Authoring aid only. Every construction carries an inline Core / Companion §
citation naming the normative paragraph that determines the bytes. This script
is NOT normative; `derivation.md` is the spec-prose reproduction evidence. If
this script and the specs disagree, the specs win.

Determinism: two runs produce byte-identical output. No randomness, no
wall-clock reads, no environment lookups beyond pinned inputs.

Scope. First-batch O-3 fixture exercising Test 4 (purge-cascade verification)
per `thoughts/specs/2026-04-18-trellis-o3-projection-conformance.md`. The
fixture carries:

  - a minimal 2-event canonical chain: event 0 appends a PayloadInline
    containing plaintext-bearing ciphertext; event 1 is a canonical crypto-
    shred event referencing event 0's `content_hash` (Companion §20.3),
  - the shred event in isolation (`input-shred-event.cbor`) for runners that
    process the shred fact directly,
  - an expected-cascade-report artifact declaring, for each Appendix A.7
    cascade-scope class declared in `[procedure].cascade_scope`, that
    `invalidated_or_plaintext_absent = true` must hold post-cascade
    (OC-76 / OC-77).

The fixture is minimal: event 1's `content_hash` references event 0's content
by its §9.3 digest (bind-by-digest, no plaintext in the shred event itself),
and cascade scope is limited to classes whose invalidation can be declared
without materializing a further view (CS-01, CS-03, CS-04, CS-05). Companion
§§23–24 classes (CS-06) and evaluator state (CS-02) are in-scope in principle
but belong to later fixtures that also materialize those derived artifacts.
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
# Pinned inputs.
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
KEY_FILE = ROOT / "_keys" / "issuer-001.cose_key"
OUT_DIR = ROOT / "shred" / "001-purge-cascade-minimal"

LEDGER_SCOPE = b"test-shred-ledger"                       # §10.4

# Event 0 — appended plaintext-bearing payload.
EVENT0_SEQUENCE       = 0
EVENT0_PREV_HASH      = None                               # genesis (§10.2)
EVENT0_AUTHORED_AT    = ts(1745100000)
EVENT0_EVENT_TYPE     = b"x-trellis-test/shred-target-append"   # §14.6
EVENT0_CLASSIFICATION = b"x-trellis-test/shreddable"            # §14.6
EVENT0_RETENTION_TIER = 0
EVENT0_IDEMPOTENCY    = b"idemp-shred-tgt0"                # 16 bytes
assert len(EVENT0_IDEMPOTENCY) == 16
# The plaintext-bearing payload. In a structural-only vector this is carried
# as opaque bytes in `PayloadInline.ciphertext`; a production implementation
# would AEAD-encrypt under a DEK, but the §9.3 content_hash construction runs
# over ciphertext bytes in either case. These are the bytes whose DEK the
# shred event destroys.
EVENT0_PAYLOAD_BYTES = b"shred-target-plaintext-bytes-v1".ljust(32, b"\x00")
assert len(EVENT0_PAYLOAD_BYTES) == 32

# Event 1 — canonical crypto-shred event referencing event 0's content_hash.
# Companion §20.3: "cryptographic erasure is incomplete until the purge
# cascade completes across every derived artifact holding plaintext or
# plaintext-derived material subject to the erasure event." The canonical
# event represents the erasure **fact** — the §9.3 content_hash of the target
# is bound into the shred event's payload so a verifier/cascade-enforcer can
# identify which prior event's plaintext is now destroyed.
EVENT1_SEQUENCE       = 1
EVENT1_AUTHORED_AT    = ts(1745100060)
EVENT1_EVENT_TYPE     = b"x-trellis-test/crypto-shred"    # §14.6
EVENT1_CLASSIFICATION = b"x-trellis-test/shred-fact"      # §14.6
EVENT1_RETENTION_TIER = 0
EVENT1_IDEMPOTENCY    = b"idemp-shred-evt1"                # 16 bytes
assert len(EVENT1_IDEMPOTENCY) == 16
# The shred-event's own payload is a small "shred declaration" bstr encoding
# `{target_content_hash: <digest>, reason: "key-destroyed"}`. This is the
# inline payload whose ciphertext bytes §9.3 hashes; the bytes are built at
# runtime since `target_content_hash` depends on Event 0.

# Signature-suite pins (§7.1) — identical to projection/001 / append/001.
SUITE_ID = 1
ALG_EDDSA = -8
COSE_LABEL_ALG = 1
COSE_LABEL_KID = 4
COSE_LABEL_SUITE_ID = -65537
COSE_LABEL_ARTIFACT_TYPE = -65538
ARTIFACT_TYPE_EVENT = "event"
ARTIFACT_TYPE_CHECKPOINT = "checkpoint"
ARTIFACT_TYPE_MANIFEST = "manifest"
PAYLOAD_NONCE = b"\x00" * 12

# Domain-separation tags (§9.8).
TAG_EVENT = "trellis-event-v1"
TAG_AUTHOR = "trellis-author-event-v1"
TAG_CONTENT = "trellis-content-v1"

# Cascade-scope declaration per Companion Appendix A.7. First-batch scope:
# classes whose post-cascade state can be asserted without materializing an
# additional derived artifact in this fixture. CS-02 (evaluator state) and
# CS-06 (respondent-facing views) are in-scope in principle but belong to a
# later fixture that also constructs the relevant artifact.
DECLARED_CASCADE_SCOPE = ["CS-01", "CS-03", "CS-04", "CS-05"]


# ---------------------------------------------------------------------------
# dCBOR (§5.1) + §9.1 domain separation.
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


def ds_sha256(tag: str, component: bytes) -> bytes:
    return hashlib.sha256(domain_separated_preimage(tag, component)).digest()


# ---------------------------------------------------------------------------
# Key load + §8.3 kid derivation.
# ---------------------------------------------------------------------------

def load_issuer_key() -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    return seed, pubkey


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


# ---------------------------------------------------------------------------
# CDDL builders (same shapes as projection/001 / append/001).
# ---------------------------------------------------------------------------

def build_event_header(event_type: bytes, authored_at: int, classification: bytes, retention_tier: int) -> dict:
    return {
        "event_type":             event_type,
        "authored_at":             authored_at,
        "retention_tier":          retention_tier,
        "classification":          classification,
        "outcome_commitment":      None,
        "subject_ref_commitment":  None,
        "tag_commitment":          None,
        "witness_ref":             None,
        "extensions":              None,
    }


def build_payload_inline(ciphertext: bytes) -> dict:
    return {
        "ref_type":   "inline",
        "ciphertext": ciphertext,
        "nonce":      PAYLOAD_NONCE,
    }


def build_key_bag() -> dict:
    return {"entries": []}


def build_authored_preimage(seq: int, prev_hash, content_hash: bytes, header: dict, payload_ref: dict, idempotency: bytes) -> dict:
    return {
        "version":         1,
        "ledger_scope":    LEDGER_SCOPE,
        "sequence":        seq,
        "prev_hash":       prev_hash,
        "causal_deps":     None,
        "content_hash":    content_hash,
        "header":          header,
        "commitments":     None,
        "payload_ref":     payload_ref,
        "key_bag":         build_key_bag(),
        "idempotency_key": idempotency,
        "extensions":      None,
    }


def build_event_payload(seq: int, prev_hash, author_event_hash: bytes, content_hash: bytes, header: dict, payload_ref: dict, idempotency: bytes) -> dict:
    return {
        "version":           1,
        "ledger_scope":      LEDGER_SCOPE,
        "sequence":          seq,
        "prev_hash":         prev_hash,
        "causal_deps":       None,
        "author_event_hash": author_event_hash,
        "content_hash":      content_hash,
        "header":            header,
        "commitments":       None,
        "payload_ref":       payload_ref,
        "key_bag":           build_key_bag(),
        "idempotency_key":   idempotency,
        "extensions":        None,
    }


def build_canonical_preimage(event_payload: dict) -> dict:
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


def sign_cose_sign1(seed: bytes, protected_map_bytes: bytes, payload_bytes: bytes) -> bytes:
    sig_struct = build_sig_structure(protected_map_bytes, payload_bytes)
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    signature = sk.sign(sig_struct)
    envelope = cbor2.CBORTag(18, [protected_map_bytes, {}, payload_bytes, signature])
    return dcbor(envelope)


def emit_event(
    seed: bytes,
    kid: bytes,
    seq: int,
    prev_hash,
    event_type: bytes,
    authored_at: int,
    classification: bytes,
    retention_tier: int,
    idempotency: bytes,
    payload_bytes: bytes,
) -> tuple[bytes, bytes, bytes]:
    """Return (cose_sign1_envelope_bytes, canonical_event_hash, content_hash)."""
    content_hash = ds_sha256(TAG_CONTENT, payload_bytes)
    header = build_event_header(event_type, authored_at, classification, retention_tier)
    payload_ref = build_payload_inline(payload_bytes)
    authored = build_authored_preimage(seq, prev_hash, content_hash, header, payload_ref, idempotency)
    authored_bytes = dcbor(authored)
    author_event_hash = ds_sha256(TAG_AUTHOR, authored_bytes)
    ep = build_event_payload(seq, prev_hash, author_event_hash, content_hash, header, payload_ref, idempotency)
    ep_bytes = dcbor(ep)
    protected_map_bytes = dcbor(build_protected_header(kid))
    envelope_bytes = sign_cose_sign1(seed, protected_map_bytes, ep_bytes)
    canonical_preimage = dcbor(build_canonical_preimage(ep))
    canonical_event_hash = ds_sha256(TAG_EVENT, canonical_preimage)
    return envelope_bytes, canonical_event_hash, content_hash


# ---------------------------------------------------------------------------
# Cascade report builder.
#
# The cascade report is a dCBOR map keyed by Appendix A.7 class identifier.
# Each value asserts `invalidated_or_plaintext_absent = true` for that class
# post-cascade, matching the O-3 design's Test-4 pass criterion (OC-76 /
# OC-77). A conforming implementation rebuilds each in-scope artifact class
# and compares its post-shred state against this report; any class whose
# artifact still contains plaintext or has not been invalidated is a
# conformance failure.
# ---------------------------------------------------------------------------

def build_cascade_report(target_content_hash: bytes, declared_scope: list[str]) -> dict:
    classes = {
        cls: {
            "invalidated_or_plaintext_absent": True,
            "rationale": f"{cls}-in-declared-cascade-scope",
        }
        for cls in declared_scope
    }
    return {
        "target_content_hash": target_content_hash,
        "declared_scope":      declared_scope,
        "expected_post_state": classes,
    }


# ---------------------------------------------------------------------------
# Output.
# ---------------------------------------------------------------------------

def write_bytes(name: str, data: bytes) -> None:
    path = OUT_DIR / name
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"  {name:35s}  {len(data):>5d} bytes  sha256={digest}")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"generating vector at {OUT_DIR.relative_to(ROOT.parent.parent)}/")

    seed, pubkey_raw = load_issuer_key()
    kid = derive_kid(SUITE_ID, pubkey_raw)

    # 1. Event 0 — plaintext-bearing append.
    ev0_bytes, ceh0, ch0 = emit_event(
        seed, kid,
        seq=EVENT0_SEQUENCE,
        prev_hash=EVENT0_PREV_HASH,
        event_type=EVENT0_EVENT_TYPE,
        authored_at=EVENT0_AUTHORED_AT,
        classification=EVENT0_CLASSIFICATION,
        retention_tier=EVENT0_RETENTION_TIER,
        idempotency=EVENT0_IDEMPOTENCY,
        payload_bytes=EVENT0_PAYLOAD_BYTES,
    )

    # 2. Build Event 1's shred-declaration payload: a dCBOR map binding the
    #    target content_hash (event 0's content_hash). This map serves as the
    #    inline ciphertext bytes (opaque from §9.3's perspective; semantically
    #    a plaintext declaration since erasure facts are not themselves
    #    encrypted).
    shred_declaration = {
        "target_content_hash": ch0,
        "reason":              "key-destroyed",
    }
    event1_payload_bytes = dcbor(shred_declaration)

    # 3. Event 1 — canonical crypto-shred event. prev_hash chains to event 0.
    ev1_bytes, ceh1, _ch1 = emit_event(
        seed, kid,
        seq=EVENT1_SEQUENCE,
        prev_hash=ceh0,
        event_type=EVENT1_EVENT_TYPE,
        authored_at=EVENT1_AUTHORED_AT,
        classification=EVENT1_CLASSIFICATION,
        retention_tier=EVENT1_RETENTION_TIER,
        idempotency=EVENT1_IDEMPOTENCY,
        payload_bytes=event1_payload_bytes,
    )

    # 4. Commit the canonical chain.
    chain_structure = [cbor2.loads(ev0_bytes), cbor2.loads(ev1_bytes)]
    write_bytes("input-chain.cbor", dcbor(chain_structure))

    # 5. Commit the shred event in isolation (convenience for runners that
    #    process the shred fact directly — its bytes duplicate the event-1
    #    slot of `input-chain.cbor`).
    write_bytes("input-shred-event.cbor", ev1_bytes)

    # 6. Commit the cascade report — the byte-compare target for Test 4's
    #    `expected.post_state`.
    cascade_report = build_cascade_report(ch0, DECLARED_CASCADE_SCOPE)
    write_bytes("expected-cascade-report.cbor", dcbor(cascade_report))

    # Informational.
    print()
    print(f"  kid                          = {kid.hex()}")
    print(f"  canonical_event_hash[0]      = {ceh0.hex()}")
    print(f"  content_hash[0] (shred-tgt)  = {ch0.hex()}")
    print(f"  canonical_event_hash[1]      = {ceh1.hex()}")


if __name__ == "__main__":
    main()
