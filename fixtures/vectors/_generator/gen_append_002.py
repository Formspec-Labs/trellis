"""Generate byte-exact reference vector `append/002-rotation-signing-key`.

Authoring aid only. Every construction block carries an inline Core-§ citation
naming the normative paragraph that determines the bytes. This script is NOT
normative; `derivation.md` is the spec-prose reproduction evidence. If this
script and Core disagree, Core wins.

Determinism: two runs of this script produce byte-identical output. No
randomness, no wall-clock reads, no environment lookups beyond pinned inputs.

Scope decision: this vector exercises Phase 1 invariant #7 — "`key_bag` /
`author_event_hash` immutable under rotation" (Core §9.5 bottom of section;
TR-CORE-038). The construction is **rotation-without-re-wrap**: the KeyBag is
empty in both the pre-rotation and post-rotation events, so no LAK re-wrap
fires (§8.6's `LedgerServiceWrapEntry` path) and the immutability claim lands
entirely on the signing-key-registry side of §8. A later vector in the
`append/` series (`004-hpke-wrapped-inline` or a residue-batch vector) will
exercise `LedgerServiceWrapEntry` mechanics once real HPKE wraps exist.

Two events, own scope. The vector runs in its own `ledger_scope`
(`"test-rotation-ledger"`) so it is independent of `001` / `005`'s
`"test-response-ledger"` chain and does not collide with the `sequence == 1`
position already claimed by `005` there. The scope contains:

  * Event A — genesis, `sequence = 0`, signed by `issuer-001` (pre-rotation).
  * Event B — `sequence = 1`, chained from A via §10.2 `prev_hash`, signed by
    `issuer-002` (post-rotation).

Between A and B the signing-key registry rotates: `issuer-001` flips
`Active → Retired` (§8.4) and `issuer-002` is added as `Active` with
`supersedes = kid(issuer-001)` per §8.2. The registry-before and registry-after
snapshots are committed as pinned inputs so the stranger test can reproduce
the rotation diff and verify that Event A's bytes — including its
`author_event_hash` — do not change when `issuer-002` is appended to the
registry.

What this vector proves (byte-level):
  1. Event A's `author_event_hash` computed from its
     `AuthorEventHashPreimage` bytes is the same 32 bytes regardless of
     which registry snapshot a verifier consults. The preimage (§9.5 CDDL)
     carries no `kid` field; no registry field is in scope.
  2. Event A's signed envelope (`expected-pre-rotation-event.cbor`) verifies
     against the `issuer-001` entry that persists in the post-rotation
     registry snapshot (with `status = Retired`, `valid_to` pinned).
  3. Event B's signed envelope (`expected-event.cbor`) verifies against the
     `issuer-002` entry in the post-rotation registry snapshot.
  4. Event B's `prev_hash` equals Event A's `canonical_event_hash` per §10.2;
     the chain is intact across the rotation boundary.

Extraction decision: this script duplicates the dCBOR / domain-separation /
COSE-assembly helpers from `gen_append_001.py` and `gen_append_005.py` inline.
Rationale: by the brainstorm at `thoughts/specs/2026-04-18-trellis-g3-first-batch-brainstorm.md` §4,
`_generator/_lib/` extraction is a separate commit; until it lands each vector
is a self-contained reading of Core to preserve the G-5 stranger-test
discipline.
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

ROOT = Path(__file__).resolve().parent.parent           # fixtures/vectors/
KEY_ISSUER_001 = ROOT / "_keys" / "issuer-001.cose_key"
KEY_ISSUER_002 = ROOT / "_keys" / "issuer-002.cose_key"
PAYLOAD_FILE = ROOT / "_inputs" / "sample-payload-001.bin"
OUT_DIR = ROOT / "append" / "002-rotation-signing-key"

# Event-level pinned values. Own ledger_scope — see file docstring.
LEDGER_SCOPE = b"test-rotation-ledger"                  # bstr, §10.6

# Pre-rotation event A (genesis).
A_SEQUENCE = 0                                          # §10.2: sequence == 0
A_TIMESTAMP = ts(1745100000)                              # +100000s past 001/005; narrative-only
A_IDEMPOTENCY_KEY = b"idemp-append-002a"                # 17 bytes; §6.1 .size (1..64)

# Post-rotation event B (chained).
B_SEQUENCE = 1                                          # §10.2: sequence > 0 → prev_hash non-null
B_TIMESTAMP = ts(1745100120)                              # +120s after A; narrative-only
B_IDEMPOTENCY_KEY = b"idemp-append-002b"                # 17 bytes; distinct from A per §17.3

# Rotation event pinned timestamp — used as `valid_to` on issuer-001's entry in
# the post-rotation registry snapshot and as `valid_from` on issuer-002's. One
# second after A, one minute before B, so A is unambiguously pre-rotation and
# B is unambiguously post-rotation by wall-clock ordering. §10.2 ordering is
# by prev_hash not wall-clock; the timestamps are narrative only.
ROTATION_TIMESTAMP = ts(1745100060)

# Header fields inherited from 001/005. §14.6 reserved test prefix.
EVENT_TYPE = b"x-trellis-test/append-minimal"
CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0

# PayloadInline-specific pinned values. Inherited from 001 / 005 unchanged.
PAYLOAD_NONCE = b"\x00" * 12                            # §6.4 bstr .size 12

# Phase 1 signature suite, §7.1.
SUITE_ID = 1
ALG_EDDSA = -8                                          # COSE alg, §7.1
COSE_LABEL_ALG = 1                                      # §7.4, per RFC 9052 §3.1
COSE_LABEL_KID = 4                                      # §7.4, per RFC 9052 §3.1
COSE_LABEL_SUITE_ID = -65537                            # §7.4, Trellis-reserved
COSE_LABEL_ARTIFACT_TYPE = -65538
ARTIFACT_TYPE_EVENT = "event"
ARTIFACT_TYPE_CHECKPOINT = "checkpoint"
ARTIFACT_TYPE_MANIFEST = "manifest"

# Signing-key registry status codes (Core §8.2 SigningKeyStatus CDDL enum).
STATUS_ACTIVE = 0
STATUS_RETIRED = 2

# Domain-separation tags, §9.8 registry.
TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"               # §9.2
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1" # §9.5
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"           # §9.3


# ---------------------------------------------------------------------------
# dCBOR (RFC 8949 §4.2.2, Core §5.1). Identical discipline to 001 / 005.
# ---------------------------------------------------------------------------

def dcbor(value: object) -> bytes:
    return cbor2.dumps(value, canonical=True)


# ---------------------------------------------------------------------------
# §9.1 domain separation discipline.
# ---------------------------------------------------------------------------

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
# Key loaders. §8.2 SigningKeyEntry.pubkey is raw key bytes.
# ---------------------------------------------------------------------------

def load_cose_key(path: Path) -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(path.read_bytes())
    seed = cose_key[-4]         # COSE_Key label -4 = 'd' (private key / seed)
    pubkey = cose_key[-2]       # COSE_Key label -2 = 'x' (public key)
    assert len(seed) == 32 and len(pubkey) == 32
    return seed, pubkey


# ---------------------------------------------------------------------------
# §8.3 Derived kid construction (pinned).
# ---------------------------------------------------------------------------

def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    suite_id_dcbor = dcbor(suite_id)                    # §5.1: uint 1 → 0x01
    return hashlib.sha256(suite_id_dcbor + pubkey_raw).digest()[:16]


# ---------------------------------------------------------------------------
# CDDL struct builders — shared between Event A and Event B. Both events use
# the same header shape (§12.1), empty KeyBag (§9.4), and PayloadInline (§6.4)
# with the pinned 64-byte payload. Only `authored_at` differs in the header.
# ---------------------------------------------------------------------------

def build_event_header(timestamp: int) -> dict:
    # §12.1 EventHeader.
    return {
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


def build_payload_ref(ciphertext: bytes) -> dict:
    # §6.4 PayloadInline.
    return {
        "ref_type":   "inline",
        "ciphertext": ciphertext,
        "nonce":      PAYLOAD_NONCE,
    }


def build_key_bag() -> dict:
    # §9.4 KeyBag; empty across both events (no HPKE wrap; see file docstring).
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
    # §9.5 / Appendix A AuthorEventHashPreimage.
    return {
        "version":         1,
        "ledger_scope":    LEDGER_SCOPE,
        "sequence":        sequence,
        "prev_hash":       prev_hash,                   # null iff sequence==0
        "causal_deps":     None,                        # §10.3: null in Phase 1
        "content_hash":    content_hash,
        "header":          header,
        "commitments":     None,                        # §13.3
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
    # §6.1 EventPayload.
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
    # §9.2 / Appendix A CanonicalEventHashPreimage.
    return {
        "version":       1,
        "ledger_scope":  LEDGER_SCOPE,
        "event_payload": event_payload,
    }


# ---------------------------------------------------------------------------
# §7.4 Protected-header map and RFC 9052 §4.4 Sig_structure. Identical to 001.
# ---------------------------------------------------------------------------

def build_protected_header(kid: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> dict:
    return {
        COSE_LABEL_ALG:      ALG_EDDSA,
        COSE_LABEL_KID:      kid,
        COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
    }


def build_sig_structure(protected_bstr: bytes, payload_bstr: bytes) -> bytes:
    # RFC 9052 §4.4: ["Signature1", protected, external_aad, payload];
    # Core §6.6 pins external_aad = h'' (zero-length) for Phase 1.
    return dcbor(["Signature1", protected_bstr, b"", payload_bstr])


# ---------------------------------------------------------------------------
# §10.6 AppendHead builder.
# ---------------------------------------------------------------------------

def build_append_head(scope: bytes, sequence: int, canonical_event_hash: bytes) -> dict:
    return {
        "scope":                scope,
        "sequence":             sequence,
        "canonical_event_hash": canonical_event_hash,
    }


# ---------------------------------------------------------------------------
# §8.2 SigningKeyEntry builder. Registry snapshots are dCBOR arrays (§8.5;
# §19 pins file = `030-signing-key-registry.cbor` for exports — here the
# fixture commits before/after snapshots as pinned inputs to the rotation
# vector and narrates the relationship in derivation.md). Inline here so that
# the registry shape is visibly a §8.2-compliant map per entry.
# ---------------------------------------------------------------------------

def build_signing_key_entry(
    kid: bytes,
    pubkey: bytes,
    status: int,
    valid_from: int,
    valid_to: int | None,
    supersedes: bytes | None,
) -> dict:
    # §8.2 SigningKeyEntry.
    return {
        "kid":         kid,
        "pubkey":      pubkey,
        "suite_id":    SUITE_ID,
        "status":      status,
        "valid_from":  valid_from,
        "valid_to":    valid_to,
        "supersedes":  supersedes,
        "attestation": None,     # optional per §8.2
    }


# ---------------------------------------------------------------------------
# Ed25519 signing wrapper. §7.1.
# ---------------------------------------------------------------------------

def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(message)
    assert len(signature) == 64                         # RFC 8032 §5.1.6
    return signature


# ---------------------------------------------------------------------------
# Write + report helper.
# ---------------------------------------------------------------------------

def write_bytes(name: str, data: bytes) -> None:
    path = OUT_DIR / name
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"  {name:50s}  {len(data):>5d} bytes  sha256={digest}")


# ---------------------------------------------------------------------------
# Build one event end-to-end and return its artifacts. Shared between
# Event A (pre-rotation) and Event B (post-rotation).
# ---------------------------------------------------------------------------

def build_event(
    *,
    sequence: int,
    prev_hash: bytes | None,
    timestamp: int,
    idempotency_key: bytes,
    signing_seed: bytes,
    signing_kid: bytes,
    payload_bytes: bytes,
) -> dict:
    """Return a dict of all named intermediates for one event.

    Keys mirror the named sibling files of `001` / `005` — `authored_preimage`,
    `author_event_preimage`, `author_event_hash`, `event_payload`,
    `protected_header`, `sig_structure`, `signature`, `signed_envelope`,
    `canonical_event_hash`, `append_head`. The caller decides which of these
    it wants to commit on disk (Event A commits as `input-pre-rotation-*`;
    Event B commits as the primary `expected-*`).
    """
    header = build_event_header(timestamp)
    payload_ref = build_payload_ref(payload_bytes)
    key_bag = build_key_bag()

    # §9.3 + §9.1 content_hash over ciphertext bytes.
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_bytes)

    # §9.5 authored-form preimage.
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

    # §9.5 + §9.1 author_event_hash.
    author_event_preimage = domain_separated_preimage(
        TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes,
    )
    author_event_hash = hashlib.sha256(author_event_preimage).digest()
    assert len(author_event_hash) == 32

    # §6.1 canonical-form EventPayload.
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

    # §7.4 protected header + RFC 9052 §4.4 Sig_structure.
    protected_map_bytes = dcbor(build_protected_header(signing_kid))
    sig_structure = build_sig_structure(protected_map_bytes, event_payload_bytes)

    # §7.1 Ed25519 signature.
    signature = ed25519_sign(signing_seed, sig_structure)

    # §6.1 + §7.4 COSE_Sign1 tag-18 signed envelope.
    cose_sign1 = cbor2.CBORTag(
        18,
        [protected_map_bytes, {}, event_payload_bytes, signature],
    )
    signed_envelope_bytes = dcbor(cose_sign1)

    # §9.2 canonical_event_hash.
    canonical_preimage_struct = build_canonical_event_hash_preimage(event_payload)
    canonical_preimage_bytes = dcbor(canonical_preimage_struct)
    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1, canonical_preimage_bytes,
    )

    # §10.6 AppendHead.
    append_head_bytes = dcbor(
        build_append_head(LEDGER_SCOPE, sequence, canonical_event_hash)
    )

    return {
        "authored_bytes":            authored_bytes,
        "author_event_preimage":     author_event_preimage,
        "author_event_hash":         author_event_hash,
        "event_payload_bytes":       event_payload_bytes,
        "protected_map_bytes":       protected_map_bytes,
        "sig_structure":             sig_structure,
        "signature":                 signature,
        "signed_envelope_bytes":     signed_envelope_bytes,
        "canonical_event_hash":      canonical_event_hash,
        "append_head_bytes":         append_head_bytes,
    }


# ---------------------------------------------------------------------------
# Main pipeline.
# ---------------------------------------------------------------------------

def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"generating vector at {OUT_DIR.relative_to(ROOT.parent.parent)}/")

    # 1. Load both pinned signing keys.
    seed_001, pubkey_001 = load_cose_key(KEY_ISSUER_001)
    seed_002, pubkey_002 = load_cose_key(KEY_ISSUER_002)

    # 2. Derive kids per §8.3.
    kid_001 = derive_kid(SUITE_ID, pubkey_001)
    kid_002 = derive_kid(SUITE_ID, pubkey_002)
    assert kid_001 != kid_002

    # 3. Load pinned payload plaintext (reuses 001's 64-byte fixture payload).
    payload_bytes = PAYLOAD_FILE.read_bytes()
    assert len(payload_bytes) == 64

    # -----------------------------------------------------------------------
    # 4. Build Event A (pre-rotation, genesis signed by issuer-001).
    # -----------------------------------------------------------------------
    event_a = build_event(
        sequence=A_SEQUENCE,
        prev_hash=None,
        timestamp=A_TIMESTAMP,
        idempotency_key=A_IDEMPOTENCY_KEY,
        signing_seed=seed_001,
        signing_kid=kid_001,
        payload_bytes=payload_bytes,
    )

    # Commit Event A as the pre-rotation inputs.
    write_bytes(
        "input-pre-rotation-author-event-hash-preimage.cbor",
        event_a["authored_bytes"],
    )
    write_bytes(
        "input-pre-rotation-author-event-hash.bin",
        event_a["author_event_hash"],
    )
    write_bytes(
        "input-pre-rotation-event-payload.cbor",
        event_a["event_payload_bytes"],
    )
    write_bytes(
        "input-pre-rotation-event.cbor",
        event_a["signed_envelope_bytes"],
    )
    write_bytes(
        "input-pre-rotation-append-head.cbor",
        event_a["append_head_bytes"],
    )

    # -----------------------------------------------------------------------
    # 5. Build signing-key-registry snapshots per §8.2 / §8.5. `before` is the
    #    single-entry registry at the moment Event A is signed (issuer-001 is
    #    the sole Active key; valid_to is null). `after` reflects the
    #    post-rotation state: issuer-001 → Retired (§8.4) with valid_to pinned
    #    to ROTATION_TIMESTAMP, and issuer-002 appended as Active with
    #    `supersedes = kid(issuer-001)` per §8.2.
    #
    #    Snapshot shape: dCBOR array of SigningKeyEntry maps. §8.5 names the
    #    file `030-signing-key-registry.cbor` in an export package; we commit
    #    the same byte shape here under fixture-local names.
    # -----------------------------------------------------------------------
    entry_001_before = build_signing_key_entry(
        kid=kid_001,
        pubkey=pubkey_001,
        status=STATUS_ACTIVE,
        valid_from=A_TIMESTAMP,
        valid_to=None,
        supersedes=None,
    )
    entry_001_after = build_signing_key_entry(
        kid=kid_001,
        pubkey=pubkey_001,
        status=STATUS_RETIRED,
        valid_from=A_TIMESTAMP,
        valid_to=ROTATION_TIMESTAMP,        # pinned at rotation moment
        supersedes=None,
    )
    entry_002_after = build_signing_key_entry(
        kid=kid_002,
        pubkey=pubkey_002,
        status=STATUS_ACTIVE,
        valid_from=ROTATION_TIMESTAMP,
        valid_to=None,
        supersedes=kid_001,                 # §8.2 supersession pointer
    )

    registry_before = dcbor([entry_001_before])
    registry_after = dcbor([entry_001_after, entry_002_after])

    write_bytes("input-signing-key-registry-before.cbor", registry_before)
    write_bytes("input-signing-key-registry-after.cbor", registry_after)

    # -----------------------------------------------------------------------
    # 6. Invariant #7 reproduction assertion (in-script, not emitted to disk).
    #    Event A's author_event_hash is determined entirely by A's preimage
    #    bytes (§9.5 CDDL has no kid field); the rotation event does not
    #    mutate those bytes. Recomputing after the registry delta must yield
    #    the same 32 bytes. The committed
    #    `input-pre-rotation-author-event-hash.bin` is that hash — we assert
    #    here that building Event A's preimage a second time (after the
    #    registry snapshots have been produced) reproduces byte-identical
    #    output. This is the generator-side evidence for TR-CORE-038's
    #    immutability half; derivation.md reproduces the claim from Core prose.
    # -----------------------------------------------------------------------
    event_a_recomputed = build_event(
        sequence=A_SEQUENCE,
        prev_hash=None,
        timestamp=A_TIMESTAMP,
        idempotency_key=A_IDEMPOTENCY_KEY,
        signing_seed=seed_001,
        signing_kid=kid_001,
        payload_bytes=payload_bytes,
    )
    assert event_a_recomputed["author_event_hash"] == event_a["author_event_hash"], (
        "invariant #7 violated: Event A's author_event_hash changed on recompute"
    )
    assert event_a_recomputed["signed_envelope_bytes"] == event_a["signed_envelope_bytes"], (
        "Event A signed envelope changed on recompute"
    )

    # -----------------------------------------------------------------------
    # 7. Build Event B (post-rotation, sequence = 1 chained from A, signed by
    #    issuer-002). prev_hash = canonical_event_hash(A) per §10.2. The
    #    kid carried in B's COSE protected header is kid(issuer-002);
    #    verification of B MUST resolve that kid via the post-rotation
    #    registry snapshot.
    # -----------------------------------------------------------------------
    event_b = build_event(
        sequence=B_SEQUENCE,
        prev_hash=event_a["canonical_event_hash"],
        timestamp=B_TIMESTAMP,
        idempotency_key=B_IDEMPOTENCY_KEY,
        signing_seed=seed_002,
        signing_kid=kid_002,
        payload_bytes=payload_bytes,
    )

    # Commit Event B as the primary `expected-*` artifacts. These are the
    # bytes a conforming `append` implementation produces for the post-rotation
    # append call.
    write_bytes(
        "input-author-event-hash-preimage.cbor",
        event_b["authored_bytes"],
    )
    write_bytes("author-event-preimage.bin", event_b["author_event_preimage"])
    write_bytes("author-event-hash.bin", event_b["author_event_hash"])
    write_bytes("expected-event-payload.cbor", event_b["event_payload_bytes"])
    write_bytes("sig-structure.bin", event_b["sig_structure"])
    write_bytes("expected-event.cbor", event_b["signed_envelope_bytes"])
    write_bytes("expected-append-head.cbor", event_b["append_head_bytes"])

    # -----------------------------------------------------------------------
    # 8. Informational summary.
    # -----------------------------------------------------------------------
    print()
    print(f"  kid(issuer-001)                = {kid_001.hex()}")
    print(f"  kid(issuer-002)                = {kid_002.hex()}")
    print(f"  A.canonical_event_hash          = {event_a['canonical_event_hash'].hex()}")
    print(f"  A.author_event_hash             = {event_a['author_event_hash'].hex()}")
    print(f"  B.prev_hash (= A.canonical)     = {event_a['canonical_event_hash'].hex()}")
    print(f"  B.author_event_hash             = {event_b['author_event_hash'].hex()}")
    print(f"  B.canonical_event_hash          = {event_b['canonical_event_hash'].hex()}")
    print(f"  B.signature (Ed25519, 64 B)     = {event_b['signature'].hex()}")


if __name__ == "__main__":
    main()
