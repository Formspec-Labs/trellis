"""Generate byte-exact reference vector `tamper/006-event-reorder`.

Authoring aid only. Every construction block carries an inline Core-§ citation
naming the normative paragraph that determines the bytes. This script is NOT
normative; `derivation.md` is the spec-prose reproduction evidence. If this
script and Core disagree, Core wins.

Determinism: two runs produce byte-identical output. No randomness, no
wall-clock reads, no environment lookups beyond pinned inputs.

Scope — the second expanded-tamper case (task #12 per TODO.md). Exercises
§19 step 4.h `prev_hash` linkage, this time via **event reordering** (the
tamper-kind enum row pinned in `tamper/001`'s derivation):

>  `event_reorder` | Two adjacent events are swapped; the later event's
>  `prev_hash` no longer matches the now-earlier event's canonical hash |
>  step 4.h | Variant of `prev_hash_break` with the additional property
>  that `sequence` monotonicity is also broken.

Construction re-uses the byte-exact events already pinned by the append
corpus:

  * `append/001-minimal-inline-payload` — genesis, `sequence = 0`,
    `prev_hash = null`.
  * `append/005-prior-head-chain`       — non-genesis, `sequence = 1`,
    `prev_hash = <append/001 canonical hash>`.

The tamper is **swap the order** — the tampered ledger is a two-element
dCBOR array `[append/005 event, append/001 event]`. No event bytes are
mutated. Every event individually signs and decodes cleanly.

Core §19 step 4.h on the tampered ledger:

  * Index 0 (survivor = append/005, `sequence = 1`): step 4.h requires
    `prev_hash == canonical_event_hash(events[0])`. `events[0]` is the
    survivor itself; its canonical hash (`3d3d…9f17`) does NOT equal its
    recorded `prev_hash` (`ef2622…4ddb`, pointing at append/001 which is
    now at index 1, not index 0). **FAIL** — recorded in
    `event_failures`.
  * Index 1 (genesis = append/001, `sequence = 0`): step 4.h requires
    `prev_hash == null`; it is. PASS.

Step 9's `integrity_verified` AND-conjunction drops to `false` via
"prev_hash links … valid". `structure_verified = true` (both events decode
through step 4.c cleanly; they are byte-exact upstream-fixture bytes).
`readability_verified = true` (Phase 1 PayloadInline bytes are structural-
only; no decryption is attempted).

Distinguishes from `tamper/005-chain-truncation`:
  - tamper/005 = one event absent;   tamper_kind = event_truncation
  - tamper/006 = same events, order swapped; tamper_kind = event_reorder
The structural detection surface is the same (§19 step 4.h), but the
failure *set* differs — truncation surfaces a single failure on the
survivor, reorder surfaces a single failure on the now-first event. The
explicit enum pin keeps the two cases distinguishable in the conformance
report.

Scope decision: no ExportManifest, no checkpoint, no HPKE wrap. Same
scope discipline as tamper/001 and tamper/005.
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
FOLLOWER_VECTOR_DIR = ROOT / "append" / "005-prior-head-chain"
OUT_DIR = ROOT / "tamper" / "006-event-reorder"

# Byte-exact inputs from the pinned append chain.
GENESIS_EVENT_FILE = GENESIS_VECTOR_DIR / "expected-event.cbor"
FOLLOWER_EVENT_FILE = FOLLOWER_VECTOR_DIR / "expected-event.cbor"
GENESIS_APPEND_HEAD_FILE = GENESIS_VECTOR_DIR / "expected-append-head.cbor"
FOLLOWER_APPEND_HEAD_FILE = FOLLOWER_VECTOR_DIR / "expected-append-head.cbor"

# Drift-alarm SHA-256 digests — identical to tamper/005's constants. If these
# drift, regenerate the upstream vector first and update here.
EXPECTED_GENESIS_EVENT_SHA256 = (
    "deca82133a10729c570e277ee38a975b7f6b9e79374052f80069b3863bdd733d"
)
EXPECTED_FOLLOWER_EVENT_SHA256 = (
    "a22ff7aa140f5aacc429cab158688c34823af7e0ec5b88bcac7e63a0fcf27091"
)

GENESIS_CANONICAL_EVENT_HASH_HEX = (
    "bb2cdb1e0aa3bcae1d50cb72d68b26af45b92e088f820e901c3d6d1558694396"
)  # append/001 canonical_event_hash — the expected predecessor the reorder dislocates.
FOLLOWER_CANONICAL_EVENT_HASH_HEX = (
    "7a8574461a5fb60b6ee60c552e414aaf45aefba3ca1b6cc71fa72d029537c020"
)  # append/005 canonical_event_hash — the failing_event_id (now at index 0).

LEDGER_SCOPE = b"test-response-ledger"                  # §10.6

# §8.2 / §8.5 registry values — identical to tamper/001 / tamper/005.
ISSUER_VALID_FROM = ts(1745000000)
SIGNING_KEY_ACTIVE_STATUS = 0
SUITE_ID = 1
ALG_EDDSA = -8


# ---------------------------------------------------------------------------
# dCBOR (§5.1).
# ---------------------------------------------------------------------------

def dcbor(value: object) -> bytes:
    return cbor2.dumps(value, canonical=True)


# ---------------------------------------------------------------------------
# §8.3 derived kid construction (pinned).
# ---------------------------------------------------------------------------

def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    suite_id_dcbor = dcbor(suite_id)
    return hashlib.sha256(suite_id_dcbor + pubkey_raw).digest()[:16]


def load_issuer_pubkey() -> bytes:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    pubkey = cose_key[-2]
    assert len(pubkey) == 32
    return pubkey


# ---------------------------------------------------------------------------
# §8.2 SigningKeyEntry builder — identical shape to tamper/001 / tamper/005.
# ---------------------------------------------------------------------------

def build_signing_key_entry(kid: bytes, pubkey_raw: bytes) -> dict:
    return {
        "kid":         kid,
        "pubkey":      pubkey_raw,
        "suite_id":    SUITE_ID,
        "status":      SIGNING_KEY_ACTIVE_STATUS,
        "valid_from":  ISSUER_VALID_FROM,
        "valid_to":    None,
        "supersedes":  None,
        "attestation": None,
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

    # 1. Drift alarms — identical discipline to tamper/005.
    genesis_bytes = GENESIS_EVENT_FILE.read_bytes()
    follower_bytes = FOLLOWER_EVENT_FILE.read_bytes()
    genesis_digest = hashlib.sha256(genesis_bytes).hexdigest()
    follower_digest = hashlib.sha256(follower_bytes).hexdigest()
    assert genesis_digest == EXPECTED_GENESIS_EVENT_SHA256, (
        "append/001 genesis event drifted; regenerate tamper/006 after "
        "updating EXPECTED_GENESIS_EVENT_SHA256"
    )
    assert follower_digest == EXPECTED_FOLLOWER_EVENT_SHA256, (
        "append/005 follower event drifted; regenerate tamper/006 after "
        "updating EXPECTED_FOLLOWER_EVENT_SHA256"
    )
    genesis_append_head = cbor2.loads(GENESIS_APPEND_HEAD_FILE.read_bytes())
    follower_append_head = cbor2.loads(FOLLOWER_APPEND_HEAD_FILE.read_bytes())
    assert genesis_append_head["canonical_event_hash"].hex() == (
        GENESIS_CANONICAL_EVENT_HASH_HEX
    ), "append/001 canonical_event_hash drifted from tamper/006 prev_hash pin"
    assert follower_append_head["canonical_event_hash"].hex() == (
        FOLLOWER_CANONICAL_EVENT_HASH_HEX
    ), "append/005 canonical_event_hash drifted from tamper/006 failing_event_id pin"

    # 2. Decode both envelopes and cross-check the tamper signal: after swap,
    #    the follower (sequence=1) will sit at index 0, and events[0] will be
    #    itself — its canonical hash does not equal its recorded prev_hash.
    genesis_envelope = cbor2.loads(genesis_bytes)
    follower_envelope = cbor2.loads(follower_bytes)
    assert (
        isinstance(genesis_envelope, cbor2.CBORTag) and genesis_envelope.tag == 18
    ), "genesis event must be COSE_Sign1 tag-18 (§7.4)"
    assert (
        isinstance(follower_envelope, cbor2.CBORTag) and follower_envelope.tag == 18
    ), "follower event must be COSE_Sign1 tag-18 (§7.4)"

    follower_payload = cbor2.loads(follower_envelope.value[2])
    assert follower_payload["sequence"] == 1, (
        "follower event must be sequence == 1; step 4.h looks up events[0]"
    )
    assert follower_payload["prev_hash"].hex() == GENESIS_CANONICAL_EVENT_HASH_HEX, (
        "follower's prev_hash must reference genesis canonical hash"
    )
    assert follower_payload["ledger_scope"] == LEDGER_SCOPE, (
        "follower's ledger_scope must match pinned scope"
    )

    genesis_payload = cbor2.loads(genesis_envelope.value[2])
    assert genesis_payload["sequence"] == 0, "genesis event must be sequence == 0"
    assert genesis_payload["prev_hash"] is None, "genesis event prev_hash must be null"

    # 3. Commit each event's byte-exact envelope for runners that want to
    #    process individual events. No byte is mutated; the tamper is the
    #    *order* within the ledger array.
    write_bytes("input-tampered-event-at-index-0.cbor", follower_bytes)
    write_bytes("input-tampered-event-at-index-1.cbor", genesis_bytes)

    # 4. Build the reordered ledger: a two-element dCBOR array with the
    #    follower (sequence=1) at index 0 and the genesis (sequence=0) at
    #    index 1. Core §18.4 pins the canonical order — "starting at
    #    sequence = 0 up to sequence = tree_size - 1" — but §19 does not
    #    abort on that structurally; step 4.h is the enumerated check that
    #    surfaces the violation.
    ledger_bytes = dcbor([follower_envelope, genesis_envelope])
    write_bytes("input-tampered-ledger.cbor", ledger_bytes)

    # 5. Minimum signing-key registry (§8.5) — single issuer-001 entry,
    #    byte-identical in intent to tamper/001 / tamper/005.
    pubkey_raw = load_issuer_pubkey()
    kid = derive_kid(SUITE_ID, pubkey_raw)
    registry = [build_signing_key_entry(kid, pubkey_raw)]
    registry_bytes = dcbor(registry)
    write_bytes("input-signing-key-registry.cbor", registry_bytes)

    # 6. Summary.
    print()
    print(f"  ledger_scope                 = {LEDGER_SCOPE.decode()}")
    print(f"  failing_event_id (at idx 0)  = {FOLLOWER_CANONICAL_EVENT_HASH_HEX}")
    print(f"  dangling prev_hash pointer   = {GENESIS_CANONICAL_EVENT_HASH_HEX}")
    print(f"  kid                          = {kid.hex()}")
    print(f"  tamper_kind                  = event_reorder")


if __name__ == "__main__":
    main()
