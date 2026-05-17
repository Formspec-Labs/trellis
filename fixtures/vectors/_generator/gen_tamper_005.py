"""Generate byte-exact reference vector `tamper/005-chain-truncation`.

Authoring aid only. Every construction block carries an inline Core-§ citation
naming the normative paragraph that determines the bytes. This script is NOT
normative; `derivation.md` is the spec-prose reproduction evidence. If this
script and Core disagree, Core wins.

Determinism: two runs produce byte-identical output. No randomness, no
wall-clock reads, no environment lookups beyond pinned inputs.

Scope decision: first vector in the expanded tamper suite (task #4) that
exercises the chain-integrity surface at Core §19 step 4.h — `prev_hash`
linkage. The construction uses the existing two-event chain already pinned
by fixtures:

  * `append/001-minimal-inline-payload` — genesis, `sequence = 0`,
    `prev_hash = null`, canonical_event_hash
    `ef2622f1470ba3d9c24b47c0566cab8902b6500fbb3d47bdd77aae068e724ddb`.
  * `append/005-prior-head-chain`       — non-genesis, `sequence = 1`,
    `prev_hash = ef2622…4ddb`                (= append/001's canonical hash),
    canonical_event_hash
    `3d3d5aeb5d4b8d972adbddfe0f339a94fffe01bf90ac1648be2eb98d4acc9f17`.

The tamper is **removal of the genesis event from the ledger**: the
tampered ledger is a one-element dCBOR array carrying only append/005's
byte-exact COSE_Sign1 envelope. No event bytes are mutated — every
remaining event is a valid, properly signed, byte-identical artifact.
Only the *set* of events is tampered with.

Core §19 step 4.h:

>  h. If payload.sequence == 0: check payload.prev_hash == null. Else check
>     payload.prev_hash == canonical_event_hash(events[payload.sequence - 1]).

A conforming verifier walking the tampered ledger:

  * Step 4.a (kid resolution)       — passes; the surviving event's kid
    is in the one-entry signing-key registry.
  * Step 4.b (signature verify)     — passes; the bytes are append/005's
    byte-exact valid signature.
  * Step 4.c (payload decode)       — passes; unchanged bytes.
  * Step 4.d (author_event_hash)    — passes; unchanged bytes.
  * Step 4.e (canonical_event_hash) — passes; unchanged bytes.
  * Step 4.f (ledger_scope match)   — not exercised; no manifest in this
    vector.
  * Step 4.h (prev_hash linkage)    — **fails.** `payload.sequence = 1`,
    so the verifier looks up `events[0]`. `events` has length 1 and
    `events[0]` IS the surviving event, whose `canonical_event_hash`
    (`3d3d5aeb…9f17`) does NOT equal `payload.prev_hash`
    (`ef2622f1…4ddb` = append/001's canonical hash, now dangling).
  * Step 4.k records a `VerificationFailure` in `event_failures`.
  * Step 9's `integrity_verified` AND-conjunction drops to false via
    "prev_hash links ... valid".

Per tamper/001's tamper-kind enum, row `event_truncation`:

>  `event_truncation` | A middle event of a chain is absent, and subsequent
>  events' prev_hash values do not link to their recomputed predecessors |
>  step 4.h | Distinguished from `prev_hash_break` by intent; structurally
>  detected the same way.

Dropping the *genesis* event is a special case of this enum row: the
"middle event" language generalizes to "any non-head event of the chain
is absent". The structural detection surface is identical — step 4.h
fails on the first surviving event whose predecessor is gone. The
`failing_event_id` is the surviving event's own canonical_event_hash
because that is the event at which step 4.h trips.

Scope decision: no ExportManifest, no checkpoint, no HPKE wrap. The
tamper surfaces at §19 step 4.h directly, reachable from just
(ledger, signing_key_registry). Same scope discipline as tamper/001.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cbor2  # noqa: E402

from _lib.byte_utils import ts  # noqa: E402

# ---------------------------------------------------------------------------
# Pinned inputs.
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent           # fixtures/vectors/
KEY_FILE = ROOT / "_keys" / "issuer-001.cose_key"
GENESIS_VECTOR_DIR = ROOT / "append" / "001-minimal-inline-payload"
SURVIVOR_VECTOR_DIR = ROOT / "append" / "005-prior-head-chain"
OUT_DIR = ROOT / "tamper" / "005-chain-truncation"

# Byte-exact inputs from the pinned append chain. The survivor's bytes are
# what the verifier hashes, decodes, and checks against its dangling prev_hash
# pointer.
GENESIS_EVENT_FILE = GENESIS_VECTOR_DIR / "expected-event.cbor"
SURVIVOR_EVENT_FILE = SURVIVOR_VECTOR_DIR / "expected-event.cbor"
GENESIS_APPEND_HEAD_FILE = GENESIS_VECTOR_DIR / "expected-append-head.cbor"
SURVIVOR_APPEND_HEAD_FILE = SURVIVOR_VECTOR_DIR / "expected-append-head.cbor"

EXPECTED_GENESIS_EVENT_SHA256 = (
    "deca82133a10729c570e277ee38a975b7f6b9e79374052f80069b3863bdd733d"
)
EXPECTED_SURVIVOR_EVENT_SHA256 = (
    "a22ff7aa140f5aacc429cab158688c34823af7e0ec5b88bcac7e63a0fcf27091"
)

# The two canonical event hashes pinned by the upstream append vectors. We
# re-read them from the corresponding AppendHead bytes below as a drift
# alarm; these constants are for documentation and for the final console
# summary.
GENESIS_CANONICAL_EVENT_HASH_HEX = (
    "bb2cdb1e0aa3bcae1d50cb72d68b26af45b92e088f820e901c3d6d1558694396"
)  # append/001 canonical_event_hash
SURVIVOR_CANONICAL_EVENT_HASH_HEX = (
    "7a8574461a5fb60b6ee60c552e414aaf45aefba3ca1b6cc71fa72d029537c020"
)  # append/005 canonical_event_hash — also the failing_event_id.

LEDGER_SCOPE = b"test-response-ledger"                  # §10.6

# §8.2 / §8.5 registry values — identical to tamper/001. The tampered
# survivor event is signed under issuer-001; §19 step 4.a MUST resolve its
# kid or abort before ever reaching step 4.h.
ISSUER_VALID_FROM = ts(1745000000)                          # §8.2
SIGNING_KEY_ACTIVE_STATUS = 0                           # §8.4 Active
SUITE_ID = 1                                            # §7.2
ALG_EDDSA = -8                                          # COSE alg, §7.1

# ---------------------------------------------------------------------------
# dCBOR (RFC 8949 §4.2.2, Core §5.1) — identical discipline to tamper/001.
# ---------------------------------------------------------------------------

def dcbor(value: object) -> bytes:
    return cbor2.dumps(value, canonical=True)


# ---------------------------------------------------------------------------
# §8.3 derived kid construction (pinned). Matches append/001/005 and
# tamper/001.
# ---------------------------------------------------------------------------

def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    suite_id_dcbor = dcbor(suite_id)                    # §5.1: uint 1 → 0x01
    return hashlib.sha256(suite_id_dcbor + pubkey_raw).digest()[:16]


def load_issuer_pubkey() -> bytes:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    pubkey = cose_key[-2]
    assert len(pubkey) == 32
    return pubkey


# ---------------------------------------------------------------------------
# §8.2 SigningKeyEntry builder — identical shape to tamper/001.
# ---------------------------------------------------------------------------

def build_signing_key_entry(kid: bytes, pubkey_raw: bytes) -> dict:
    return {
        "kid":         kid,                             # bstr .size 16
        "pubkey":      pubkey_raw,                      # §7.1
        "suite_id":    SUITE_ID,                        # §7.2
        "status":      SIGNING_KEY_ACTIVE_STATUS,       # §8.4 Active
        "valid_from":  ISSUER_VALID_FROM,               # §8.2
        "valid_to":    None,                            # §8.2 null = active
        "supersedes":  None,                            # §8.2
        "attestation": None,                            # §8.2
    }


# ---------------------------------------------------------------------------
# Write + report helper.
# ---------------------------------------------------------------------------

def write_bytes(name: str, data: bytes) -> None:
    path = OUT_DIR / name
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"  {name:45s}  {len(data):>5d} bytes  sha256={digest}")


# ---------------------------------------------------------------------------
# Main pipeline.
# ---------------------------------------------------------------------------

def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"generating vector at {OUT_DIR.relative_to(ROOT.parent.parent)}/")

    # 1. Verify upstream drift alarms before emitting any bytes. The tamper's
    #    failing_event_id and the "dangling" prev_hash value pinned in the
    #    derivation both depend on the exact bytes of the upstream append
    #    events; if either drifts, regenerate the upstream vector first.
    genesis_bytes = GENESIS_EVENT_FILE.read_bytes()
    survivor_bytes = SURVIVOR_EVENT_FILE.read_bytes()
    genesis_digest = hashlib.sha256(genesis_bytes).hexdigest()
    survivor_digest = hashlib.sha256(survivor_bytes).hexdigest()
    assert genesis_digest == EXPECTED_GENESIS_EVENT_SHA256, (
        "append/001 genesis event drifted; regenerate tamper/005 after "
        "updating EXPECTED_GENESIS_EVENT_SHA256"
    )
    assert survivor_digest == EXPECTED_SURVIVOR_EVENT_SHA256, (
        "append/005 survivor event drifted; regenerate tamper/005 after "
        "updating EXPECTED_SURVIVOR_EVENT_SHA256"
    )
    genesis_append_head = cbor2.loads(GENESIS_APPEND_HEAD_FILE.read_bytes())
    survivor_append_head = cbor2.loads(SURVIVOR_APPEND_HEAD_FILE.read_bytes())
    assert genesis_append_head["canonical_event_hash"].hex() == (
        GENESIS_CANONICAL_EVENT_HASH_HEX
    ), "append/001 canonical_event_hash drifted from tamper/005 dangling prev_hash pin"
    assert survivor_append_head["canonical_event_hash"].hex() == (
        SURVIVOR_CANONICAL_EVENT_HASH_HEX
    ), "append/005 canonical_event_hash drifted from tamper/005 failing_event_id pin"

    # 2. Decode the survivor's payload and sanity-check that the tamper
    #    signal is structurally present (its prev_hash points at the
    #    genesis event we are about to omit, and its sequence == 1).
    survivor_envelope = cbor2.loads(survivor_bytes)
    assert (
        isinstance(survivor_envelope, cbor2.CBORTag)
        and survivor_envelope.tag == 18
    ), "survivor event must be a COSE_Sign1 tag-18 envelope (§7.4)"
    survivor_payload = cbor2.loads(survivor_envelope.value[2])
    assert survivor_payload["sequence"] == 1, (
        "survivor event must be sequence == 1 for §19 step 4.h to expect "
        "events[0]"
    )
    assert survivor_payload["prev_hash"].hex() == GENESIS_CANONICAL_EVENT_HASH_HEX, (
        "survivor's prev_hash must reference the genesis event's "
        "canonical_event_hash for chain truncation to leave a dangling pointer"
    )
    assert survivor_payload["ledger_scope"] == LEDGER_SCOPE, (
        "survivor's ledger_scope must match the pinned scope"
    )
    print(
        f"  survivor (append/005)                         "
        f"{len(survivor_bytes):>5d} bytes  sha256={survivor_digest}"
    )
    print(
        f"  omitted genesis (append/001)                  "
        f"{len(genesis_bytes):>5d} bytes  sha256={genesis_digest}"
    )

    # 3. Commit the survivor's byte-exact COSE_Sign1 envelope as
    #    `input-tampered-event.cbor`. No byte is mutated — the tamper is
    #    that the *predecessor* is missing from the ledger, not that the
    #    survivor's bytes are wrong.
    write_bytes("input-tampered-event.cbor", survivor_bytes)

    # 4. Build the truncated ledger: a one-element dCBOR array carrying
    #    only the survivor. Core §18.4 pins `010-events.cbor` as "a dCBOR
    #    array of Event COSE_Sign1 records in canonical order, starting at
    #    sequence = 0 up to sequence = tree_size - 1". A one-element ledger
    #    whose sole entry is sequence = 1 violates the "starting at
    #    sequence = 0" clause — but §19 does NOT abort on that; instead
    #    step 4.h is the enumerated check that surfaces it. (A future
    #    vector in this suite could exercise an explicit "sequence=0 must
    #    be at index 0" step if §19 is tightened; for now step 4.h is the
    #    normative failure site.)
    ledger_bytes = dcbor([survivor_envelope])
    write_bytes("input-tampered-ledger.cbor", ledger_bytes)

    # 5. Build the minimum signing-key registry (§8.5). One SigningKeyEntry,
    #    the one whose kid is referenced by the survivor event's protected
    #    header. Byte-identical in intent to tamper/001's registry — same
    #    issuer key, same suite, same kid derivation. The registry's
    #    existence is what lets §19 step 4.a succeed; the tamper surfaces
    #    later, at step 4.h.
    pubkey_raw = load_issuer_pubkey()
    kid = derive_kid(SUITE_ID, pubkey_raw)
    registry = [build_signing_key_entry(kid, pubkey_raw)]
    registry_bytes = dcbor(registry)
    write_bytes("input-signing-key-registry.cbor", registry_bytes)

    # 6. Summary the derivation.md can quote verbatim.
    print()
    print(f"  ledger_scope                 = {LEDGER_SCOPE.decode()}")
    print(f"  omitted_event_id (dangling)  = {GENESIS_CANONICAL_EVENT_HASH_HEX}")
    print(f"  failing_event_id (survivor)  = {SURVIVOR_CANONICAL_EVENT_HASH_HEX}")
    print(f"  kid                          = {kid.hex()}")
    print(f"  tamper_kind                  = event_truncation")


if __name__ == "__main__":
    main()
