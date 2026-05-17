"""Generate byte-exact reference vectors `tamper/023..025` — Phase-1 negatives
for the unified `KeyEntry` taxonomy (ADR 0006 / Core §8.7).

Three tamper vectors covering the class-dispatch surface in §8.7.3:

  * `tamper/023-key-class-mismatch-signing-as-recovery` — a `recovery`-class
    kid in a COSE_Sign1 protected header. Verifier loads the registry, the
    kid is ABSENT from the signing map but PRESENT in the non-signing map
    with `class = "recovery"`, so dispatch fires `key_class_mismatch`
    (TR-CORE-048). Structure-fatal: signature verification is never reached
    because the kid resolves to a class that is not authorized to sign.
  * `tamper/024-key-entry-attributes-shape-mismatch` — a non-signing
    `subject` row missing the required `attributes` map. Registry parse
    fails the §8.7.1 structural-shape gate; verifier reports
    `key_entry_attributes_shape_mismatch` (TR-CORE-048). Structure-fatal.
  * `tamper/025-key-class-mismatch-subject-as-signing` — a `subject`-class
    kid in a COSE_Sign1 protected header. Same dispatch path as 023 but
    different reserved class. The subject row in the registry carries an
    explicit `valid_to` so the wire bytes also exercise the Phase-2+
    `subject_wrap_after_valid_to` enforcement seam (Phase-1 captures
    `valid_to` into `NonSigningKeyEntry.subject_valid_to` per ADR 0006
    *Phase-1 runtime discipline*; runtime enforcement against
    `KeyBagEntry` recipients lifts when Phase-2+ binds the recipient
    reference to a registered subject kid). Structure-fatal today via
    `key_class_mismatch`.

All three borrow `append/032`'s genesis-event byte path (single-event
ledger in `test-key-entry-{subject,...}-ledger`) but tamper the protected
header `kid` to point at the non-signing kid. The signature itself is
still produced by `issuer-001` (so the bytes round-trip cbor cleanly),
but verification never reaches signature-check — the kid resolves to a
non-signing class first.

Determinism: two runs of this script produce byte-identical output. No
randomness, no wall-clock reads, no environment lookups beyond pinned
inputs. The same fixture-only deterministic non-signing pubkey constants
used by `gen_append_032_to_035.py` are re-derived here so 023/025 share
the kids of 035 (recovery) / 032 (subject) by construction.
"""
from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cbor2  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from _lib.byte_utils import ts  # noqa: E402

# ---------------------------------------------------------------------------
# Pinned inputs — mirror gen_append_032_to_035.py constants exactly so the
# non-signing kids in 023/025 byte-equal the corresponding ones in 035/032.
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
KEY_ISSUER_001 = ROOT / "_keys" / "issuer-001.cose_key"
PAYLOAD_FILE = ROOT / "_inputs" / "sample-payload-001.bin"

EVENT_TYPE = b"x-trellis-test/append-minimal"
CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0
PAYLOAD_NONCE = b"\x00" * 12
SUITE_ID = 1
ALG_EDDSA = -8
COSE_LABEL_ALG = 1
COSE_LABEL_KID = 4
COSE_LABEL_SUITE_ID = -65537
COSE_LABEL_ARTIFACT_TYPE = -65538
ARTIFACT_TYPE_EVENT = "event"
ARTIFACT_TYPE_CHECKPOINT = "checkpoint"
ARTIFACT_TYPE_MANIFEST = "manifest"
STATUS_ACTIVE = 0

TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"


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


def fixture_pubkey(marker: str) -> bytes:
    """Mirror of gen_append_032_to_035.py.fixture_pubkey — keeps non-signing
    kid bytes byte-equal across the two scripts so cross-vector reasoning
    holds."""
    return hashlib.sha256(
        f"trellis-fixture-non-signing-pubkey-{marker}".encode()
    ).digest()


def write_bytes(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"  {path.name:50s}  {len(data):>5d} bytes  sha256={digest}")


# ---------------------------------------------------------------------------
# Per-class attribute builders — minimal CDDL-conformant per Core §8.7.2.
# Mirror gen_append_032_to_035.py builders byte-for-byte.
# ---------------------------------------------------------------------------

def build_subject_attrs(valid_to: int | None = None) -> dict:
    return {
        "pubkey":           fixture_pubkey("subject"),
        "subject_ref":      "urn:agency.gov:subject:fixture-025",
        "authorized_for":   [b"x-trellis-test/wrap-cap-1"],
        "effective_from":   ts(1745130000),
        "valid_to":         valid_to,
        "supersedes":       None,
    }


def build_recovery_attrs(authorized_kid: bytes) -> dict:
    return {
        "pubkey":                  fixture_pubkey("recovery"),
        "authorizes_recovery_for": [authorized_kid],
        "activation_quorum":       1,
        "activation_quorum_set":   None,
        "effective_from":          ts(1745130000),
        "supersedes":              None,
    }


def build_signing_entry_legacy(kid: bytes, pubkey: bytes, valid_from: int) -> dict:
    """Legacy `SigningKeyEntry` (no `kind`) — Core §8.2."""
    return {
        "kid":         kid,
        "pubkey":      pubkey,
        "suite_id":    SUITE_ID,
        "status":      STATUS_ACTIVE,
        "valid_from":  valid_from,
        "valid_to":    None,
        "supersedes":  None,
        "attestation": None,
    }


def build_non_signing_entry(kind: str, attrs: dict) -> dict:
    """`KeyEntryNonSigning` per Core §8.7.1."""
    pubkey = attrs["pubkey"]
    kid = derive_kid(SUITE_ID, pubkey)
    return {
        "kind":       kind,
        "kid":        kid,
        "suite_id":   SUITE_ID,
        "attributes": attrs,
        "extensions": None,
    }


# ---------------------------------------------------------------------------
# Event builder — same as gen_append_032 but with a configurable protected-
# header `kid` so the vector can sign with issuer-001's seed under a
# DIFFERENT kid (the non-signing kid). This produces a structurally clean
# COSE_Sign1 envelope whose signature is valid against issuer-001's pubkey
# but whose protected-header kid points at a non-signing class — the
# Phase-1 verifier dispatches on the registry-resolved class FIRST and
# rejects with `key_class_mismatch` before ever attempting signature
# verification (Core §8.7.3 step 4).
# ---------------------------------------------------------------------------

def build_event(
    ledger_scope: bytes,
    timestamp: int,
    idempotency_key: bytes,
    payload_bytes: bytes,
    seed: bytes,
    protected_header_kid: bytes,
) -> tuple[bytes, bytes]:
    """Returns (signed_envelope_bytes, ledger_bytes)."""

    header = {
        "event_type":             EVENT_TYPE,
        "authored_at":            timestamp,
        "retention_tier":         RETENTION_TIER,
        "classification":         CLASSIFICATION,
        "outcome_commitment":     None,
        "subject_ref_commitment": None,
        "tag_commitment":         None,
        "witness_ref":            None,
        "extensions":             None,
    }
    payload_ref = {
        "ref_type":   "inline",
        "ciphertext": payload_bytes,
        "nonce":      PAYLOAD_NONCE,
    }
    key_bag = {"entries": []}
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_bytes)

    authored = {
        "version":         1,
        "ledger_scope":    ledger_scope,
        "sequence":        0,
        "prev_hash":       None,
        "causal_deps":     None,
        "content_hash":    content_hash,
        "header":          header,
        "commitments":     None,
        "payload_ref":     payload_ref,
        "key_bag":         key_bag,
        "idempotency_key": idempotency_key,
        "extensions":      None,
    }
    authored_bytes = dcbor(authored)
    author_event_hash = hashlib.sha256(
        domain_separated_preimage(TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes)
    ).digest()

    event_payload = {
        "version":           1,
        "ledger_scope":      ledger_scope,
        "sequence":          0,
        "prev_hash":         None,
        "causal_deps":       None,
        "author_event_hash": author_event_hash,
        "content_hash":      content_hash,
        "header":            header,
        "commitments":       None,
        "payload_ref":       payload_ref,
        "key_bag":           key_bag,
        "idempotency_key":   idempotency_key,
        "extensions":        None,
    }
    event_payload_bytes = dcbor(event_payload)

    # Protected header carries the OVERRIDE kid (non-signing class), not
    # issuer-001's kid. The signature is still produced by issuer-001's
    # seed — but the verifier will never reach signature-check because
    # the registry dispatch hits the non-signing branch first.
    protected_map_bytes = dcbor({
        COSE_LABEL_ALG:      ALG_EDDSA,
        COSE_LABEL_KID:      protected_header_kid,
        COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: ARTIFACT_TYPE_EVENT,
    })
    sig_structure = dcbor(["Signature1", protected_map_bytes, b"", event_payload_bytes])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    assert len(signature) == 64

    cose_sign1 = cbor2.CBORTag(
        18, [protected_map_bytes, {}, event_payload_bytes, signature],
    )
    signed_envelope_bytes = dcbor(cose_sign1)

    canonical_preimage = {
        "version":       1,
        "ledger_scope":  ledger_scope,
        "event_payload": event_payload,
    }
    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1, dcbor(canonical_preimage),
    )

    ledger_bytes = dcbor([cose_sign1])

    return signed_envelope_bytes, ledger_bytes, canonical_event_hash


# ---------------------------------------------------------------------------
# Vector emitters — one per tamper.
# ---------------------------------------------------------------------------

def emit_023(seed_001: bytes, pubkey_001: bytes, kid_001: bytes,
             payload_bytes: bytes) -> None:
    out_dir = ROOT / "tamper" / "023-key-class-mismatch-signing-as-recovery"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {out_dir.relative_to(ROOT.parent.parent)}/")

    recovery_row = build_non_signing_entry(
        "recovery", build_recovery_attrs(authorized_kid=kid_001),
    )
    recovery_kid: bytes = recovery_row["kid"]

    signed_event, ledger_bytes, canonical_event_hash = build_event(
        ledger_scope=b"test-key-entry-recovery-ledger",
        timestamp=ts(1745130800),
        idempotency_key=b"tamper-key-class-recovery-023",
        payload_bytes=payload_bytes,
        seed=seed_001,
        protected_header_kid=recovery_kid,
    )

    # Registry mirrors append/035: legacy issuer-001 + the recovery row.
    registry = [
        build_signing_entry_legacy(kid_001, pubkey_001, ts(1745130000)),
        recovery_row,
    ]
    registry_bytes = dcbor(registry)

    write_bytes(out_dir / "input-tampered-event.cbor", signed_event)
    write_bytes(out_dir / "input-tampered-ledger.cbor", ledger_bytes)
    write_bytes(out_dir / "input-signing-key-registry.cbor", registry_bytes)

    print(f"  kid(issuer-001)        = {kid_001.hex()}")
    print(f"  kid(recovery)          = {recovery_kid.hex()}")
    print(f"  canonical_event_hash   = {canonical_event_hash.hex()}")


def emit_024(seed_001: bytes, pubkey_001: bytes, kid_001: bytes,
              payload_bytes: bytes) -> None:
    out_dir = ROOT / "tamper" / "024-key-entry-attributes-shape-mismatch"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {out_dir.relative_to(ROOT.parent.parent)}/")

    # The tampered registry: a `subject` row whose `attributes` field is
    # MISSING entirely. Verifier's parse_key_registry hits the §8.7.1
    # structural-shape gate and returns `key_entry_attributes_shape_mismatch`
    # (TR-CORE-048). Structure-fatal — signature verification never runs.
    pubkey_subject = fixture_pubkey("subject")
    kid_subject = derive_kid(SUITE_ID, pubkey_subject)
    malformed_subject_row = {
        "kind":       "subject",
        "kid":        kid_subject,
        "suite_id":   SUITE_ID,
        # attributes intentionally OMITTED
        "extensions": None,
    }
    registry = [
        build_signing_entry_legacy(kid_001, pubkey_001, ts(1745130000)),
        malformed_subject_row,
    ]
    registry_bytes = dcbor(registry)

    # Legitimate issuer-001-signed event so the only signal in the report
    # is the registry's structural-shape failure (not signature_invalid).
    signed_event, ledger_bytes, canonical_event_hash = build_event(
        ledger_scope=b"test-key-entry-024-ledger",
        timestamp=ts(1745131000),
        idempotency_key=b"tamper-key-entry-shape-024",
        payload_bytes=payload_bytes,
        seed=seed_001,
        protected_header_kid=kid_001,
    )

    write_bytes(out_dir / "input-tampered-event.cbor", signed_event)
    write_bytes(out_dir / "input-tampered-ledger.cbor", ledger_bytes)
    write_bytes(out_dir / "input-signing-key-registry.cbor", registry_bytes)

    print(f"  kid(issuer-001)        = {kid_001.hex()}")
    print(f"  kid(subject, malformed)= {kid_subject.hex()}")
    print(f"  canonical_event_hash   = {canonical_event_hash.hex()}")


def emit_025(seed_001: bytes, pubkey_001: bytes, kid_001: bytes,
             payload_bytes: bytes) -> None:
    out_dir = ROOT / "tamper" / "025-subject-key-wrap-after-valid-to"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {out_dir.relative_to(ROOT.parent.parent)}/")

    # Subject row carries an explicit `valid_to` in the past relative to
    # the event's `authored_at` so the bytes also exercise the Phase-2+
    # `subject_wrap_after_valid_to` enforcement seam (captured today as
    # `NonSigningKeyEntry.subject_valid_to`; runtime enforcement against
    # `KeyBagEntry` recipients lifts when Phase-2+ binds the recipient
    # reference to a registered subject kid per ADR 0006). Phase-1
    # detection: signing-class violation when the subject kid is used
    # in a COSE_Sign1 protected header — `key_class_mismatch`.
    subject_row = build_non_signing_entry(
        "subject", build_subject_attrs(valid_to=ts(1745130100)),  # past
    )
    subject_kid: bytes = subject_row["kid"]

    signed_event, ledger_bytes, canonical_event_hash = build_event(
        ledger_scope=b"test-key-entry-025-ledger",
        timestamp=ts(1745131200),  # > subject_valid_to; future Phase-2+ check
        idempotency_key=b"tamper-subject-wrap-after-valid-to-025",
        payload_bytes=payload_bytes,
        seed=seed_001,
        protected_header_kid=subject_kid,
    )

    registry = [
        build_signing_entry_legacy(kid_001, pubkey_001, ts(1745130000)),
        subject_row,
    ]
    registry_bytes = dcbor(registry)

    write_bytes(out_dir / "input-tampered-event.cbor", signed_event)
    write_bytes(out_dir / "input-tampered-ledger.cbor", ledger_bytes)
    write_bytes(out_dir / "input-signing-key-registry.cbor", registry_bytes)

    print(f"  kid(issuer-001)        = {kid_001.hex()}")
    print(f"  kid(subject)           = {subject_kid.hex()}")
    print(f"  subject.valid_to       = 1745130100  (< event.authored_at = 1745131200)")
    print(f"  canonical_event_hash   = {canonical_event_hash.hex()}")


def main() -> None:
    seed_001, pubkey_001 = load_cose_key(KEY_ISSUER_001)
    kid_001 = derive_kid(SUITE_ID, pubkey_001)
    payload_bytes = PAYLOAD_FILE.read_bytes()
    assert len(payload_bytes) == 64

    emit_023(seed_001, pubkey_001, kid_001, payload_bytes)
    emit_024(seed_001, pubkey_001, kid_001, payload_bytes)
    emit_025(seed_001, pubkey_001, kid_001, payload_bytes)


if __name__ == "__main__":
    main()
