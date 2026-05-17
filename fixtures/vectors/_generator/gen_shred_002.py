"""Generate byte-exact reference vector `shred/002-backup-refusal`.

Authoring aid only. Every construction carries an inline Core / Companion §
citation naming the normative paragraph that determines the bytes. This script
is NOT normative; `derivation.md` is the spec-prose reproduction evidence. If
this script and the specs disagree, the specs win.

Determinism: two runs produce byte-identical output. No randomness, no
wall-clock reads, no environment lookups beyond pinned inputs.

Scope. Second-batch O-3 fixture exercising the Test-4 **backup-refusal**
sub-scenario per `thoughts/specs/2026-04-18-trellis-o3-projection-conformance.md`
and Companion §27.3 OC-135 row 3 ("that backup-resurrection is prevented — no
live derived artifact may be restored from backup to a state containing
destroyed plaintext"). The fixture carries:

  - a minimal 2-event canonical chain: event 0 appends a PayloadInline
    containing plaintext-bearing ciphertext; event 1 is a canonical crypto-
    shred event referencing event 0's `content_hash` (Companion §20.3).
  - a pre-shred **backup snapshot** (Companion §16.4 — "snapshot MAY be used
    to accelerate recovery or rebuild of derived artifacts") that materialized
    event 0's plaintext before the shred fact was appended. The snapshot is
    a canonical dCBOR derived-artifact blob and is NOT a canonical event;
    it pins the bytes a backup-restore attempt would reintroduce.
  - an expected-cascade-report that for every declared Appendix A.7 cascade-
    scope class asserts BOTH post-cascade invalidation (OC-76) AND
    `backup_resurrection_refused = true` (§16.5 / §20.5 second sentence /
    §28.6), carrying a rationale identifier keyed to the normative anchor
    so a runner can report the specific refusal grounds.

The fixture is structural-only (opaque `PayloadInline.ciphertext`, no HPKE
wrap) and keeps the same cascade scope as `shred/001` (`CS-01`, `CS-03`,
`CS-04`, `CS-05`). Pins are chosen to be byte-disjoint from `shred/001` so
`content_hash` and `canonical_event_hash` values differ across the two shred
fixtures; this keeps either fixture's byte outputs independently
reader-verifiable.
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
OUT_DIR = ROOT / "shred" / "002-backup-refusal"

LEDGER_SCOPE = b"test-shred-backup-ledger"                 # §10.4, 24 bytes

# Event 0 — plaintext-bearing append whose DEK the shred event destroys.
# Byte-disjoint from `shred/001` so this fixture's content_hash differs.
EVENT0_SEQUENCE       = 0
EVENT0_PREV_HASH      = None                               # genesis (§10.2)
EVENT0_AUTHORED_AT    = ts(1745200000)
EVENT0_EVENT_TYPE     = b"x-trellis-test/backup-target-append"  # §14.6
EVENT0_CLASSIFICATION = b"x-trellis-test/shreddable"            # §14.6
EVENT0_RETENTION_TIER = 0
EVENT0_IDEMPOTENCY    = b"idemp-bkp-tgt-00"                # 16 bytes
assert len(EVENT0_IDEMPOTENCY) == 16
# Plaintext-bearing PayloadInline.ciphertext bytes. These are what the
# pre-shred backup snapshot below captures and what post-cascade MUST NOT be
# restored from backup (§16.5, §20.5, §28.6).
EVENT0_PAYLOAD_BYTES  = b"backup-refusal-plaintext-bytes".ljust(32, b"\x00")
assert len(EVENT0_PAYLOAD_BYTES) == 32

# Event 1 — canonical crypto-shred event referencing event 0's content_hash.
EVENT1_SEQUENCE       = 1
EVENT1_AUTHORED_AT    = ts(1745200060)
EVENT1_EVENT_TYPE     = b"x-trellis-test/crypto-shred"     # §14.6
EVENT1_CLASSIFICATION = b"x-trellis-test/shred-fact"       # §14.6
EVENT1_RETENTION_TIER = 0
EVENT1_IDEMPOTENCY    = b"idemp-bkp-shr-00"                # 16 bytes
assert len(EVENT1_IDEMPOTENCY) == 16

# Signature-suite pins (§7.1) — identical to shred/001 / projection/001.
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

# Cascade-scope declaration per Companion Appendix A.7. Same subset as
# `shred/001`: classes whose post-cascade state can be asserted without
# materializing a further derived view. Backup-refusal is a property of the
# snapshot → live-artifact restore path, so every in-scope class also
# carries the refusal assertion.
DECLARED_CASCADE_SCOPE = ["CS-01", "CS-03", "CS-04", "CS-05"]

# Pre-shred backup snapshot schema identifier. §16.4 names "snapshot as
# recovery substrate"; the bytes below are a minimal stand-in for such a
# snapshot. An A.7 class identifier names the derived-artifact family the
# snapshot belongs to. The fixture picks CS-03 (snapshots retained for
# performance or recovery) as the snapshot's own class, since §16.5 is the
# load-bearing paragraph for the refusal rule.
BACKUP_SNAPSHOT_SCHEMA_ID = "urn:trellis:test:backup-snapshot:v1"
BACKUP_SNAPSHOT_ORIGIN_CLASS = "CS-03"


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
# CDDL builders (same shapes as shred/001 / projection/001 / append/001).
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
# Backup snapshot.
#
# §16.4: "A snapshot MAY be used to accelerate recovery or rebuild of derived
# artifacts." §16.5: "A snapshot MUST NOT be used to resurrect canonically-
# destroyed plaintext into live derived artifacts." The snapshot bytes below
# are what a backup-restore attempt would reintroduce into a live derived
# artifact post-shred; the expected-cascade-report asserts that the restore
# MUST be refused for every in-scope cascade class.
#
# Snapshot shape is a minimal dCBOR map binding:
#   schema_id:           identifier naming this snapshot family,
#   origin_class:        Appendix A.7 class the snapshot belongs to,
#   taken_at_tree_size:  canonical append height the snapshot materialized at,
#   materialized_plaintext: the plaintext from event 0 (what restore would
#                           reintroduce — pinned here so a runner can compare
#                           a post-restore artifact against it and detect
#                           leakage if refusal is not enforced),
#   target_content_hash: event 0's §9.3 digest, binding the snapshot to the
#                        payload whose DEK the shred event destroys.
# ---------------------------------------------------------------------------

def build_backup_snapshot(
    target_content_hash: bytes,
    materialized_plaintext: bytes,
    taken_at_tree_size: int,
) -> dict:
    return {
        "schema_id":              BACKUP_SNAPSHOT_SCHEMA_ID,
        "origin_class":           BACKUP_SNAPSHOT_ORIGIN_CLASS,
        "taken_at_tree_size":     taken_at_tree_size,
        "materialized_plaintext": materialized_plaintext,
        "target_content_hash":    target_content_hash,
    }


# ---------------------------------------------------------------------------
# Cascade report.
#
# Extends shred/001's per-class table with a `backup_resurrection_refused`
# flag and a refusal-rationale anchor. The top-level map adds a
# `backup_snapshot_ref` digest (SHA-256 of input-backup-snapshot.cbor bytes)
# so a runner can bind the report to the specific snapshot file under test.
# ---------------------------------------------------------------------------

def build_cascade_report(
    target_content_hash: bytes,
    declared_scope: list[str],
    backup_snapshot_digest: bytes,
) -> dict:
    classes = {
        cls: {
            "invalidated_or_plaintext_absent": True,
            "backup_resurrection_refused":     True,
            "rationale":                       f"{cls}-backup-restore-refused-per-§16.5",
        }
        for cls in declared_scope
    }
    return {
        "target_content_hash":    target_content_hash,
        "declared_scope":         declared_scope,
        "backup_snapshot_ref":    backup_snapshot_digest,
        "expected_post_state":    classes,
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

    # 2. Pre-shred backup snapshot. Taken at tree_size = 1 (after event 0,
    #    before event 1) — this is the "recovery substrate" §16.4 names and
    #    whose restore §16.5 forbids once event 1 appends.
    snapshot = build_backup_snapshot(
        target_content_hash=ch0,
        materialized_plaintext=EVENT0_PAYLOAD_BYTES,
        taken_at_tree_size=1,
    )
    snapshot_bytes = dcbor(snapshot)
    write_bytes("input-backup-snapshot.cbor", snapshot_bytes)
    snapshot_digest = hashlib.sha256(snapshot_bytes).digest()

    # 3. Event 1's shred-declaration payload: dCBOR map binding event 0's
    #    §9.3 content_hash. Same shape as shred/001; the bytes differ because
    #    event 0's content_hash differs across fixtures.
    shred_declaration = {
        "target_content_hash": ch0,
        "reason":              "key-destroyed",
    }
    event1_payload_bytes = dcbor(shred_declaration)

    # 4. Event 1 — canonical crypto-shred event. prev_hash chains to event 0.
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

    # 5. Commit the canonical chain.
    chain_structure = [cbor2.loads(ev0_bytes), cbor2.loads(ev1_bytes)]
    write_bytes("input-chain.cbor", dcbor(chain_structure))

    # 6. Commit the shred event in isolation.
    write_bytes("input-shred-event.cbor", ev1_bytes)

    # 7. Commit the cascade report — adds per-class
    #    `backup_resurrection_refused = true` plus a digest binding to the
    #    backup snapshot under test.
    cascade_report = build_cascade_report(ch0, DECLARED_CASCADE_SCOPE, snapshot_digest)
    write_bytes("expected-cascade-report.cbor", dcbor(cascade_report))

    # Informational.
    print()
    print(f"  kid                          = {kid.hex()}")
    print(f"  canonical_event_hash[0]      = {ceh0.hex()}")
    print(f"  content_hash[0] (shred-tgt)  = {ch0.hex()}")
    print(f"  canonical_event_hash[1]      = {ceh1.hex()}")
    print(f"  backup_snapshot sha256       = {snapshot_digest.hex()}")


if __name__ == "__main__":
    main()
