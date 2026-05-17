"""Generate byte-exact reference vector `tamper/001-signature-flip`.

Authoring aid only. Every construction block carries an inline Core-§ citation
naming the normative paragraph that determines the bytes. This script is NOT
normative; `derivation.md` is the spec-prose reproduction evidence. If this
script and Core disagree, Core wins.

Determinism: two runs of this script produce byte-identical output. No
randomness, no wall-clock reads, no environment lookups beyond pinned inputs.

Scope decision: this is the **first** tamper vector. It pins the tamper-op
manifest shape (`[expected.report]` sub-table with `tamper_kind` +
`failing_event_id`) that every subsequent tamper vector inherits. The tamper
construction itself is the simplest possible: start from `append/005`'s
byte-exact COSE_Sign1 signed event, flip one byte in the 64-byte Ed25519
signature bstr, write the mutated bytes into `input-tampered-event.cbor`, and
wrap the single tampered event in a one-element dCBOR array committed as
`input-tampered-ledger.cbor`. The signing-key registry is a one-entry dCBOR
array carrying the issuer-001 public key so a verifier following Core §19
step 4.a can resolve the event's `kid`.

Export-manifest scope note. Core §19's verification algorithm step 1 opens a
signed ExportManifest and steps 2-3 check its bindings before the per-event
loop at step 4. Authoring a signed ExportManifest for this tamper vector
would require digests over seven sibling archive members (events,
checkpoints, inclusion-proofs, consistency-proofs, signing-key-registry, the
head checkpoint, and each domain-registry binding) plus a COSE_Sign1 wrap,
plus a `posture_declaration` with the full shape of Core §20. None of that
scaffolding carries signal for a signature-flip tamper — §19's per-event
signature check is at step 4.b, reachable from just a ledger + a registry
that resolves the event's `kid`. A later tamper vector will exercise the
manifest-binding path end-to-end; this vector defers that and declares the
deferral in `derivation.md`.

The `tamper_kind` enum pinned in `[expected.report]` is `signature_invalid`.
The full enum proposal (thirteen values) is committed into `derivation.md`
so later tamper authors have a single source of truth to cite. That enum is
also the core return item for orchestrator sync into the fixture-system
design doc.
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
SOURCE_VECTOR_DIR = ROOT / "append" / "005-prior-head-chain"
OUT_DIR = ROOT / "tamper" / "001-signature-flip"

# The source event — `append/005`'s byte-exact COSE_Sign1 artifact (737 bytes,
# sha256 a22ff7aa140f5aacc429cab158688c34823af7e0ec5b88bcac7e63a0fcf27091).
# This vector's only byte-level delta vs 005's `expected-event.cbor` is the
# one flipped signature byte.
SOURCE_EVENT_FILE = SOURCE_VECTOR_DIR / "expected-event.cbor"
SOURCE_APPEND_HEAD_FILE = SOURCE_VECTOR_DIR / "expected-append-head.cbor"
EXPECTED_SOURCE_EVENT_SHA256 = (
    "a22ff7aa140f5aacc429cab158688c34823af7e0ec5b88bcac7e63a0fcf27091"
)

# Ledger-scope and sequence values mirror 005 because the tampered event IS
# 005's event (pre-tamper). The canonical_event_hash of the pre-tamper event
# is what this vector pins as `failing_event_id` for the runner.
LEDGER_SCOPE = b"test-response-ledger"                  # §10.6
PRE_TAMPER_CANONICAL_EVENT_HASH_HEX = (
    "7a8574461a5fb60b6ee60c552e414aaf45aefba3ca1b6cc71fa72d029537c020"
)  # from 005's derivation.md Step 11.

# Signing-key registry entry values. `valid_from` / `valid_to` are narrative-
# only for this fixture — §19's per-event signature check does not read
# them. `attestation = null` is permitted under §8.2 (optional HSM/KMS
# attestation).
ISSUER_VALID_FROM = ts(1745000000)                          # §8.2
SIGNING_KEY_ACTIVE_STATUS = 0                           # §8.2; SigningKeyStatus.Active

# §7.4 / §7.1 pins for kid-derivation. Same values the append/001 / append/005
# generators use — we rederive the kid here so the registry entry carries
# exactly the kid that appears in the tampered event's protected header.
SUITE_ID = 1
ALG_EDDSA = -8                                          # COSE alg, §7.1

# ---------------------------------------------------------------------------
# dCBOR (RFC 8949 §4.2.2, Core §5.1) — identical discipline to append/001/005.
# ---------------------------------------------------------------------------

def dcbor(value: object) -> bytes:
    return cbor2.dumps(value, canonical=True)


# ---------------------------------------------------------------------------
# §8.3 derived kid construction (pinned). Matches append/001/005.
# ---------------------------------------------------------------------------

def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    suite_id_dcbor = dcbor(suite_id)                    # §5.1: uint 1 → 0x01
    return hashlib.sha256(suite_id_dcbor + pubkey_raw).digest()[:16]


# ---------------------------------------------------------------------------
# Load issuer key (same seed/pub append/001 and append/005 used; 005 signed
# the source event with this key, so this is the key a §19-compliant verifier
# MUST be able to resolve via the registry).
# ---------------------------------------------------------------------------

def load_issuer_key() -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    assert len(seed) == 32 and len(pubkey) == 32
    return seed, pubkey


# ---------------------------------------------------------------------------
# §8.2 SigningKeyEntry builder — minimal single-entry registry.
# ---------------------------------------------------------------------------

def build_signing_key_entry(kid: bytes, pubkey_raw: bytes) -> dict:
    return {
        "kid":         kid,                             # bstr .size 16
        "pubkey":      pubkey_raw,                      # 32-byte Ed25519 pub, §7.1
        "suite_id":    SUITE_ID,                        # §7.2
        "status":      SIGNING_KEY_ACTIVE_STATUS,       # §8.4 Active
        "valid_from":  ISSUER_VALID_FROM,               # §8.2
        "valid_to":    None,                            # §8.2: null = currently-active
        "supersedes":  None,                            # §8.2; no predecessor
        "attestation": None,                            # §8.2; optional
    }


# ---------------------------------------------------------------------------
# §7.4 COSE_Sign1 byte-layout parser. The tag-18 CBOR envelope is
# [protected, unprotected, payload, signature]; we parse it solely to locate
# the signature bstr offset within the outer bytes so the byte flip lands on
# the correct byte.
#
# We rely on cbor2's decoder to parse the envelope into Python objects, then
# compute the signature offset by re-serializing the *prefix* (everything up
# to and including the signature's bstr header) and subtracting from the
# total. This avoids hand-rolling CBOR length-prefix math for 1/2/4/8-byte
# bstr headers.
# ---------------------------------------------------------------------------

def locate_signature_last_byte_offset(cose_sign1_bytes: bytes) -> tuple[int, bytes]:
    """Return (offset_of_last_signature_byte, original_byte) for a Trellis
    COSE_Sign1 tag-18 envelope.

    The last byte of the 64-byte Ed25519 signature is also the last byte of
    the serialized envelope, because the signature is the final element of
    the 4-array and dCBOR emits no trailing bytes. Therefore the offset is
    simply `len(cose_sign1_bytes) - 1`. This implementation re-parses the
    envelope and asserts that the final 64 bytes match the signature bstr
    extracted by cbor2 — a belt-and-braces check that our index math is not
    drifting relative to the encoded form.
    """
    tag = cbor2.loads(cose_sign1_bytes)
    assert isinstance(tag, cbor2.CBORTag) and tag.tag == 18, \
        "source must be a COSE_Sign1 tag-18 envelope (§7.4)"
    array = tag.value
    assert isinstance(array, (list, tuple)) and len(array) == 4, \
        "COSE_Sign1 is a 4-array (RFC 9052 §4.2)"
    signature = array[3]
    assert isinstance(signature, bytes) and len(signature) == 64, \
        "Phase 1 Ed25519 signature is 64 bytes (§7.1)"
    # Sanity: envelope tail MUST be the signature bstr.
    assert cose_sign1_bytes.endswith(signature), (
        "signature bstr must appear at the tail of the dCBOR-encoded envelope; "
        "if this assert fires, the CBOR encoding path changed shape"
    )
    offset = len(cose_sign1_bytes) - 1
    return offset, cose_sign1_bytes[offset : offset + 1]


def flip_last_signature_byte(cose_sign1_bytes: bytes) -> tuple[bytes, int, int, int]:
    """Return (tampered_bytes, byte_offset, original_byte, mutated_byte).

    The mutation is `original XOR 0x01` — flipping the low bit is sufficient
    to invalidate Ed25519 under RFC 8032 with overwhelming probability.
    """
    offset, original = locate_signature_last_byte_offset(cose_sign1_bytes)
    assert len(original) == 1
    mutated = bytes([original[0] ^ 0x01])
    tampered = cose_sign1_bytes[:offset] + mutated + cose_sign1_bytes[offset + 1 :]
    assert len(tampered) == len(cose_sign1_bytes)
    return tampered, offset, original[0], mutated[0]


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

    # 1. Load the source event (append/005's signed, pre-tamper COSE_Sign1).
    source_bytes = SOURCE_EVENT_FILE.read_bytes()
    source_digest = hashlib.sha256(source_bytes).hexdigest()
    assert source_digest == EXPECTED_SOURCE_EVENT_SHA256, (
        "append/005 source event drifted; regenerate tamper/001 derivation "
        "and expected report pins before emitting new bytes"
    )
    source_append_head = cbor2.loads(SOURCE_APPEND_HEAD_FILE.read_bytes())
    assert source_append_head["canonical_event_hash"].hex() == (
        PRE_TAMPER_CANONICAL_EVENT_HASH_HEX
    ), "append/005 canonical_event_hash drifted from tamper/001 failing_event_id"
    print(f"  source (append/005)                          {len(source_bytes):>5d} bytes  sha256={source_digest}")

    # 2. Flip the last byte of the signature bstr.
    tampered_bytes, offset, original_byte, mutated_byte = flip_last_signature_byte(source_bytes)
    print(
        f"  tamper: offset={offset} (= len-1), original=0x{original_byte:02x}, "
        f"mutated=0x{mutated_byte:02x}"
    )

    # 3. Commit the tampered single-event bytes.
    write_bytes("input-tampered-event.cbor", tampered_bytes)

    # 4. Commit a one-element dCBOR array carrying the tampered event.
    #    Core §18.4 pins `010-events.cbor` as "a dCBOR array of Event COSE_Sign1
    #    records in canonical order". A one-event ledger is the smallest shape
    #    that round-trips through §19 step 4's "for each Event in 010-events.cbor"
    #    loop. cbor2 emits the array with the embedded CBOR tag preserved.
    ledger_bytes = dcbor([cbor2.loads(tampered_bytes)])
    write_bytes("input-tampered-ledger.cbor", ledger_bytes)

    # 5. Build a minimal signing-key registry (§8.5). One SigningKeyEntry, the
    #    one whose kid is referenced by the tampered event's protected header.
    #    §19 step 4.a MUST resolve this kid; the vector fails at step 4.b
    #    (signature verify) post-resolution, which is precisely the signal.
    _seed, pubkey_raw = load_issuer_key()
    kid = derive_kid(SUITE_ID, pubkey_raw)
    registry = [build_signing_key_entry(kid, pubkey_raw)]
    registry_bytes = dcbor(registry)
    write_bytes("input-signing-key-registry.cbor", registry_bytes)

    # 6. Emit a summary line the derivation.md can quote directly.
    print()
    print(f"  ledger_scope                 = {LEDGER_SCOPE.decode()}")
    print(f"  pre_tamper_failing_event_id  = {PRE_TAMPER_CANONICAL_EVENT_HASH_HEX}")
    print(f"  kid                          = {kid.hex()}")
    print(f"  tamper_kind                  = signature_invalid")


if __name__ == "__main__":
    main()
