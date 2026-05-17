"""Generate byte-exact reference vector `append/031-key-entry-signing-lifecycle`.

Authoring aid only. Every construction block carries an inline Core-§ citation
naming the normative paragraph that determines the bytes. This script is NOT
normative; `derivation.md` is the spec-prose reproduction evidence. If this
script and Core disagree, Core wins.

Determinism: two runs of this script produce byte-identical output. No
randomness, no wall-clock reads, no environment lookups beyond pinned inputs.

Scope — `KeyEntry` taxonomy migration baseline (ADR 0006). This vector is
the load-bearing positive for TR-CORE-039: it re-pins the rotation lifecycle
of `append/002-rotation-signing-key` under the executed unified `KeyEntry`
encoding (Core §8.7). Two events in scope `test-key-entry-ledger`:

  * **Event A** — genesis (sequence = 0), signed by `issuer-001`.
  * **Event B** — sequence = 1, chained from A via §10.2 `prev_hash`,
    signed by `issuer-002` after the registry rotates.

The two committed signing-key registry snapshots are the new-shape
`KeyEntrySigning` arm (Core §8.7.1) — each entry carries a top-level
`kind: "signing"` discriminator alongside the eight legacy fields. The
`registry-after` snapshot retains `issuer-001` with `status = Retired (2)`
and adds `issuer-002` with `supersedes = kid(issuer-001)`. Per ADR 0006
*Wire preservation*, this is **not** byte-equal to 002's flat-shape
registry CBOR; the migration is an explicit registry-snapshot wire
evolution and the new bytes are the golden artifacts.

Invariant #7 (TR-CORE-038) reproduces unchanged: §9.5
`AuthorEventHashPreimage` has no `kid` / no signing-key-registry reference,
so Event A's `author_event_hash` reproduces byte-identically before and
after the registry transition. The verifier loads the post-rotation
`KeyEntry`-shape registry, dispatches on `kind` per Core §8.7.3, and
verifies both events.

Ledger scope `test-key-entry-ledger` is distinct from every other fixture
(test-response-ledger / test-rotation-ledger / test-revocation-ledger /
test-external-ledger / test-hpke-ledger / test-posture-ledger) so 031's
sequence = 0 / 1 do not collide.
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
KEY_ISSUER_001 = ROOT / "_keys" / "issuer-001.cose_key"
KEY_ISSUER_002 = ROOT / "_keys" / "issuer-002.cose_key"
PAYLOAD_FILE = ROOT / "_inputs" / "sample-payload-001.bin"
OUT_DIR = ROOT / "append" / "031-key-entry-signing-lifecycle"

# Event-level pinned values. Own ledger_scope — see file docstring.
LEDGER_SCOPE = b"test-key-entry-ledger"

# Event A: genesis.
EVENT_A_SEQUENCE = 0
EVENT_A_TIMESTAMP = ts(1745120000)
EVENT_A_IDEMPOTENCY_KEY = b"idemp-append-031a"

# Event B: post-rotation, sequence=1.
EVENT_B_SEQUENCE = 1
EVENT_B_TIMESTAMP = ts(1745120120)
EVENT_B_IDEMPOTENCY_KEY = b"idemp-append-031b"

# Rotation timestamp — `valid_to` on issuer-001's post-rotation entry and
# `valid_from` on issuer-002.
ROTATION_TIMESTAMP = ts(1745120060)

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

# Core §8.4 SigningKeyStatus enum.
STATUS_ACTIVE = 0
STATUS_RETIRED = 2

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
    suite_id_dcbor = dcbor(suite_id)
    return hashlib.sha256(suite_id_dcbor + pubkey_raw).digest()[:16]


# ---------------------------------------------------------------------------
# Core §8.7.1 `KeyEntrySigning` (flat signing arm).
#
# The unified `KeyEntry` taxonomy adds a top-level `kind: "signing"`
# discriminator to the legacy `SigningKeyEntry` field set; field set is
# otherwise byte-for-byte identical (kid, pubkey, suite_id, status,
# valid_from, valid_to, supersedes, attestation). dCBOR canonical map
# ordering sorts the nine text-string keys lex: `attestation`, `kid`,
# `kind`, `pubkey`, `status`, `suite_id`, `supersedes`, `valid_from`,
# `valid_to`. The map header byte for nine entries is `0xa9`.
# ---------------------------------------------------------------------------


def build_key_entry_signing(
    kid: bytes,
    pubkey: bytes,
    status: int,
    valid_from: int,
    valid_to: int | None,
    supersedes: bytes | None,
) -> dict:
    return {
        "kind":        "signing",      # ADR 0006 / Core §8.7.1 discriminator.
        "kid":         kid,
        "pubkey":      pubkey,
        "suite_id":    SUITE_ID,
        "status":      status,
        "valid_from":  valid_from,
        "valid_to":    valid_to,
        "supersedes":  supersedes,
        "attestation": None,
    }


def build_event_header(authored_at: int) -> dict:
    return {
        "event_type":             EVENT_TYPE,
        "authored_at":            authored_at,
        "retention_tier":         RETENTION_TIER,
        "classification":         CLASSIFICATION,
        "outcome_commitment":     None,
        "subject_ref_commitment": None,
        "tag_commitment":         None,
        "witness_ref":            None,
        "extensions":             None,
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
    sequence: int,
    prev_hash: bytes | None,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
    idempotency_key: bytes,
) -> dict:
    return {
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
        "extensions":      None,
    }


def build_event_payload(
    sequence: int,
    prev_hash: bytes | None,
    author_event_hash: bytes,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
    idempotency_key: bytes,
) -> dict:
    return {
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
        "extensions":        None,
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


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(message)
    assert len(signature) == 64
    return signature


def write_bytes(name: str, data: bytes) -> None:
    path = OUT_DIR / name
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"  {name:50s}  {len(data):>5d} bytes  sha256={digest}")


def build_event_artifacts(
    seed: bytes,
    kid: bytes,
    sequence: int,
    prev_hash: bytes | None,
    authored_at: int,
    idempotency_key: bytes,
    payload_bytes: bytes,
):
    """Returns (authored_bytes, author_event_hash, event_payload_bytes,
    sig_structure, signed_envelope_bytes, canonical_event_hash, append_head_bytes)
    for one event. Wraps the §6.8 → §9.5 → §6.1 → §7.4 → §7.1 → §6.1 → §9.2 → §10.6
    pipeline that 001/002/009 use, parameterized by per-event fields."""
    header = build_event_header(authored_at)
    payload_ref = build_payload_ref(payload_bytes)
    key_bag = build_key_bag()
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_bytes)

    authored = build_author_event_hash_preimage(
        sequence=sequence,
        prev_hash=prev_hash,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
        idempotency_key=idempotency_key,
    )
    authored_bytes = dcbor(authored)
    author_event_preimage = domain_separated_preimage(
        TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes,
    )
    author_event_hash = hashlib.sha256(author_event_preimage).digest()

    event_payload = build_event_payload(
        sequence=sequence,
        prev_hash=prev_hash,
        author_event_hash=author_event_hash,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
        idempotency_key=idempotency_key,
    )
    event_payload_bytes = dcbor(event_payload)

    protected_map_bytes = dcbor(build_protected_header(kid))
    sig_structure = build_sig_structure(protected_map_bytes, event_payload_bytes)
    signature = ed25519_sign(seed, sig_structure)

    cose_sign1 = cbor2.CBORTag(
        18,
        [protected_map_bytes, {}, event_payload_bytes, signature],
    )
    signed_envelope_bytes = dcbor(cose_sign1)

    canonical_preimage = build_canonical_event_hash_preimage(event_payload)
    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1, dcbor(canonical_preimage),
    )

    append_head_bytes = dcbor(
        build_append_head(LEDGER_SCOPE, sequence, canonical_event_hash)
    )

    return (
        authored_bytes,
        author_event_hash,
        event_payload_bytes,
        sig_structure,
        signed_envelope_bytes,
        canonical_event_hash,
        append_head_bytes,
    )


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"generating vector at {OUT_DIR.relative_to(ROOT.parent.parent)}/")

    # 1. Load both signing keys + payload.
    seed_001, pubkey_001 = load_cose_key(KEY_ISSUER_001)
    seed_002, pubkey_002 = load_cose_key(KEY_ISSUER_002)
    kid_001 = derive_kid(SUITE_ID, pubkey_001)
    kid_002 = derive_kid(SUITE_ID, pubkey_002)
    payload_bytes = PAYLOAD_FILE.read_bytes()
    assert len(payload_bytes) == 64

    # 2. Build Event A (genesis, signed by issuer-001).
    (
        a_authored,
        a_author_hash,
        a_event_payload,
        a_sig_structure,
        a_signed_event,
        a_canonical_hash,
        a_append_head,
    ) = build_event_artifacts(
        seed=seed_001,
        kid=kid_001,
        sequence=EVENT_A_SEQUENCE,
        prev_hash=None,
        authored_at=EVENT_A_TIMESTAMP,
        idempotency_key=EVENT_A_IDEMPOTENCY_KEY,
        payload_bytes=payload_bytes,
    )

    # 3. Build Event B (sequence=1, signed by issuer-002, prev_hash from A).
    (
        b_authored,
        b_author_hash,
        b_event_payload,
        b_sig_structure,
        b_signed_event,
        b_canonical_hash,
        b_append_head,
    ) = build_event_artifacts(
        seed=seed_002,
        kid=kid_002,
        sequence=EVENT_B_SEQUENCE,
        prev_hash=a_canonical_hash,
        authored_at=EVENT_B_TIMESTAMP,
        idempotency_key=EVENT_B_IDEMPOTENCY_KEY,
        payload_bytes=payload_bytes,
    )

    # 4. Build the two registry snapshots in the new `KeyEntrySigning` shape.
    #    Pre-rotation: issuer-001 active, valid_to=null, supersedes=null.
    #    Post-rotation: issuer-001 retired with valid_to=ROTATION_TIMESTAMP;
    #                  issuer-002 active with supersedes=kid_001.
    entry_a_before = build_key_entry_signing(
        kid=kid_001,
        pubkey=pubkey_001,
        status=STATUS_ACTIVE,
        valid_from=EVENT_A_TIMESTAMP,
        valid_to=None,
        supersedes=None,
    )
    entry_a_after = build_key_entry_signing(
        kid=kid_001,
        pubkey=pubkey_001,
        status=STATUS_RETIRED,
        valid_from=EVENT_A_TIMESTAMP,
        valid_to=ROTATION_TIMESTAMP,
        supersedes=None,
    )
    entry_b_after = build_key_entry_signing(
        kid=kid_002,
        pubkey=pubkey_002,
        status=STATUS_ACTIVE,
        valid_from=ROTATION_TIMESTAMP,
        valid_to=None,
        supersedes=kid_001,
    )

    registry_before_bytes = dcbor([entry_a_before])
    registry_after_bytes = dcbor([entry_a_after, entry_b_after])

    # 5. Invariant #7 reproduction assertion (in-script). The registry-shape
    #    migration adds a `kind` field but leaves §9.5 inputs unchanged;
    #    Event A's `author_event_hash` is determined entirely by its
    #    AuthorEventHashPreimage bytes (sequence/prev_hash/content_hash/header/
    #    key_bag/idempotency_key/payload_ref). None of those fields touches the
    #    registry snapshot, so re-deriving Event A under the new registry shape
    #    yields the same author_event_hash bytes.
    (
        _a_authored_2,
        a_author_hash_2,
        *_rest,
    ) = build_event_artifacts(
        seed=seed_001,
        kid=kid_001,
        sequence=EVENT_A_SEQUENCE,
        prev_hash=None,
        authored_at=EVENT_A_TIMESTAMP,
        idempotency_key=EVENT_A_IDEMPOTENCY_KEY,
        payload_bytes=payload_bytes,
    )
    assert a_author_hash == a_author_hash_2

    # 6. Commit artifacts.
    write_bytes("input-pre-rotation-author-event-hash-preimage.cbor", a_authored)
    write_bytes("input-pre-rotation-author-event-hash.bin", a_author_hash)
    write_bytes("input-pre-rotation-event-payload.cbor", a_event_payload)
    write_bytes("input-pre-rotation-event.cbor", a_signed_event)
    write_bytes("input-pre-rotation-append-head.cbor", a_append_head)
    write_bytes("input-signing-key-registry-before.cbor", registry_before_bytes)
    write_bytes("input-signing-key-registry-after.cbor", registry_after_bytes)
    write_bytes("input-author-event-hash-preimage.cbor", b_authored)
    write_bytes("author-event-hash.bin", b_author_hash)
    write_bytes("expected-event-payload.cbor", b_event_payload)
    write_bytes("sig-structure.bin", b_sig_structure)
    write_bytes("expected-event.cbor", b_signed_event)
    write_bytes("expected-append-head.cbor", b_append_head)

    print()
    print(f"  kid(issuer-001)                    = {kid_001.hex()}")
    print(f"  kid(issuer-002)                    = {kid_002.hex()}")
    print(f"  author_event_hash(A)               = {a_author_hash.hex()}")
    print(f"  canonical_event_hash(A)            = {a_canonical_hash.hex()}")
    print(f"  author_event_hash(B)               = {b_author_hash.hex()}")
    print(f"  canonical_event_hash(B)            = {b_canonical_hash.hex()}")


if __name__ == "__main__":
    main()
