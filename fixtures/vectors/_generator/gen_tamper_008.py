"""Generate byte-exact reference vector `tamper/008-malformed-cose`.

Authoring aid only. Every construction block carries an inline Core-§ citation
naming the normative paragraph that determines the bytes. This script is NOT
normative; `derivation.md` is the spec-prose reproduction evidence. If this
script and Core disagree, Core wins.

Determinism: two runs produce byte-identical output. No randomness, no
wall-clock reads, no environment lookups beyond pinned inputs.

Scope — fourth expanded-tamper case (task #12). Exercises Core §19's
structural-identification surface via the tamper-kind enum row
`malformed_cose` pinned in `tamper/001`'s derivation:

>  `malformed_cose` | COSE_Sign1 envelope is structurally invalid (wrong
>  array length, wrong tag, malformed bstr length prefix, absent or nil
>  payload) | step 4.c (and step 4.b if decode proceeds) | Fatal-
>  classification candidate; §19's "Failure classes" prose names decode
>  failures as aborts if they corrupt structure_verified globally.

The minimum-surface malformation is a one-byte outer-tag flip: byte 0 of
`append/001-minimal-inline-payload/expected-event.cbor` is `0xd2` (CBOR
tag 18 = COSE_Sign1 per RFC 9052 §4.2). Flipping to `0xd1` (CBOR tag 17 =
COSE_Mac0) means the item is no longer a COSE_Sign1 envelope; a §19
verifier expecting COSE_Sign1 at each position in `010-events.cbor` MUST
reject. Every other byte is byte-identical to `append/001`'s envelope.

Critical design discipline: the tag-flip does NOT touch the signed bytes.
The signature in RFC 9052 §4.4's `Sig_structure = ["Signature1",
protected, external_aad, payload]` is computed over protected+payload, not
over the outer tag. If a lenient verifier ignored the tag and proceeded
directly to §19 step 4.b signature verification, the signature would
still verify. The tamper is therefore isolated to step 4.c's (or earlier)
structural-identification surface — the verifier's obligation to reject
items whose CBOR tag is not 18. This isolation is what distinguishes
`malformed_cose` from `signature_invalid` (`tamper/001`) and from
`hash_mismatch` (`tamper/007`).

§19 verifier walk:
  * Outer CBOR decodes as tag-17 item. "Is this a COSE_Sign1 per
    RFC 9052 §4.2?" — NO; tag number ≠ 18. **FAIL** before step 4.a.
    `structure_verified = false`.
  * Every other check — signature, payload decode, hash recomputation,
    chain linkage — is not reached.

Distinguishes from prior tamper cases:
  - tamper/001 (`signature_invalid`)  — signature bytes flipped; step 4.b.
  - tamper/005 (`event_truncation`)   — ledger set tampered; step 4.h.
  - tamper/006 (`event_reorder`)      — ledger order tampered; step 4.h.
  - tamper/007 (`hash_mismatch`)      — stored hash field tampered; step 4.d.
  - tamper/008 (`malformed_cose`)     — outer CBOR tag tampered; structure
                                        fails before step 4.a.

Scope decision: single-event ledger, no manifest, no checkpoint, no HPKE
wrap. Same discipline as tamper/001/005/006/007.
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
BASELINE_VECTOR_DIR = ROOT / "append" / "001-minimal-inline-payload"
OUT_DIR = ROOT / "tamper" / "008-malformed-cose"

BASELINE_EVENT_FILE = BASELINE_VECTOR_DIR / "expected-event.cbor"
BASELINE_APPEND_HEAD_FILE = BASELINE_VECTOR_DIR / "expected-append-head.cbor"

# Drift-alarm SHA-256 — if append/001's envelope drifts, regenerate that
# vector first and update here.
EXPECTED_BASELINE_EVENT_SHA256 = (
    "deca82133a10729c570e277ee38a975b7f6b9e79374052f80069b3863bdd733d"
)
BASELINE_CANONICAL_EVENT_HASH_HEX = (
    "bb2cdb1e0aa3bcae1d50cb72d68b26af45b92e088f820e901c3d6d1558694396"
)

LEDGER_SCOPE = b"test-response-ledger"                  # §10.4

# CBOR tag pins per RFC 9052 §4.2.
CBOR_TAG_COSE_SIGN1 = 18                                # canonical
CBOR_TAG_COSE_MAC0 = 17                                 # wrong, but same 1-byte short form

# CBOR short-form tag byte layout (major type 6 = 0b110 = 0xc0 | tag_number
# for tag_number < 24). 0xc0 | 18 = 0xd2 (COSE_Sign1). 0xc0 | 17 = 0xd1
# (COSE_Mac0). Single-byte change.
BASELINE_TAG_BYTE = 0xd2
TAMPERED_TAG_BYTE = 0xd1

SUITE_ID = 1
ALG_EDDSA = -8
ISSUER_VALID_FROM = ts(1745000000)
SIGNING_KEY_ACTIVE_STATUS = 0


# ---------------------------------------------------------------------------
# dCBOR + §8.3 kid derivation.
# ---------------------------------------------------------------------------

def dcbor(value: object) -> bytes:
    return cbor2.dumps(value, canonical=True)


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def load_issuer_pubkey() -> bytes:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    pubkey = cose_key[-2]
    assert len(pubkey) == 32
    return pubkey


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

    # 1. Drift alarm.
    baseline_bytes = BASELINE_EVENT_FILE.read_bytes()
    baseline_digest = hashlib.sha256(baseline_bytes).hexdigest()
    assert baseline_digest == EXPECTED_BASELINE_EVENT_SHA256, (
        "append/001 envelope drifted; regenerate tamper/008 after updating "
        "EXPECTED_BASELINE_EVENT_SHA256"
    )
    assert baseline_bytes[0] == BASELINE_TAG_BYTE, (
        f"append/001 envelope byte 0 is {baseline_bytes[0]:#x}, expected "
        f"{BASELINE_TAG_BYTE:#x} (CBOR tag 18 short form)"
    )
    # Drift alarm on the upstream canonical_event_hash — the tampered
    # envelope's would-be canonical_event_hash (if the verifier ignored
    # the tag) equals this value, because the signed bytes are unchanged.
    baseline_append_head = cbor2.loads(BASELINE_APPEND_HEAD_FILE.read_bytes())
    assert baseline_append_head["canonical_event_hash"].hex() == (
        BASELINE_CANONICAL_EVENT_HASH_HEX
    ), "append/001 canonical_event_hash drifted from tamper/008 pin"

    # 2. Build the tampered envelope: byte 0 flipped from 0xd2 → 0xd1. Every
    #    other byte byte-identical to append/001's envelope, including the
    #    signed-bytes surface (protected header + payload).
    tampered_bytes = bytes([TAMPERED_TAG_BYTE]) + baseline_bytes[1:]
    assert len(tampered_bytes) == len(baseline_bytes)
    assert tampered_bytes[1:] == baseline_bytes[1:]
    assert tampered_bytes != baseline_bytes
    assert tampered_bytes[0] == TAMPERED_TAG_BYTE

    # 3. Structural sanity: the tampered bytes ARE parseable as generic
    #    CBOR (tag 17 + the same 4-element array; cbor2 returns a CBORTag
    #    with .tag == 17). But they are NOT a COSE_Sign1 per RFC 9052 §4.2
    #    (which pins tag 18). A conforming §19 verifier that identifies
    #    the item by tag number MUST reject it.
    decoded = cbor2.loads(tampered_bytes)
    assert isinstance(decoded, cbor2.CBORTag), (
        "tampered bytes must still decode as a CBOR tag item (the "
        "malformation is semantic, not CBOR-structural)"
    )
    assert decoded.tag == CBOR_TAG_COSE_MAC0 == TAMPERED_TAG_BYTE ^ 0xc0, (
        f"tampered tag number must be COSE_Mac0 ({CBOR_TAG_COSE_MAC0}), "
        f"got {decoded.tag}"
    )
    assert isinstance(decoded.value, (list, tuple)) and len(decoded.value) == 4, (
        "even with the wrong tag, the contents remain a 4-element array "
        "(that's precisely what makes the tamper subtle — lenient "
        "verifiers might proceed)"
    )

    write_bytes("input-tampered-event.cbor", tampered_bytes)

    # 4. Single-element dCBOR array wrapping the tampered envelope.
    ledger_bytes = dcbor([decoded])
    write_bytes("input-tampered-ledger.cbor", ledger_bytes)

    # 5. Minimum signing-key registry (§8.5) — same issuer-001 entry as
    #    tamper/001/005/006/007. The registry's existence is academic for
    #    this vector: the tamper surfaces at structural identification
    #    before §19 step 4.a's kid-resolve.
    pubkey_raw = load_issuer_pubkey()
    kid = derive_kid(SUITE_ID, pubkey_raw)
    registry = [build_signing_key_entry(kid, pubkey_raw)]
    registry_bytes = dcbor(registry)
    write_bytes("input-signing-key-registry.cbor", registry_bytes)

    # 6. Reviewer-facing summary.
    print()
    print(f"  ledger_scope                     = {LEDGER_SCOPE.decode()}")
    print(f"  baseline tag byte (0xd2 = tag 18) = {BASELINE_TAG_BYTE:#x}")
    print(f"  tampered tag byte (0xd1 = tag 17) = {TAMPERED_TAG_BYTE:#x}")
    print(f"  baseline envelope sha256          = {baseline_digest}")
    print(f"  tampered envelope sha256          = {hashlib.sha256(tampered_bytes).hexdigest()}")
    print(f"  kid                               = {kid.hex()}")
    print(f"  tamper_kind                       = malformed_cose")


if __name__ == "__main__":
    main()
