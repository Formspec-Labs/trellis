"""Generate byte-exact reference vector `tamper/007-hash-mismatch`.

Authoring aid only. Every construction block carries an inline Core-§ citation
naming the normative paragraph that determines the bytes. This script is NOT
normative; `derivation.md` is the spec-prose reproduction evidence. If this
script and Core disagree, Core wins.

Determinism: two runs produce byte-identical output. No randomness, no
wall-clock reads, no environment lookups beyond pinned inputs.

Scope — third expanded-tamper case (task #12). Exercises Core §19 step 4.d —
`author_event_hash` recomputation disagreement with the payload's recorded
value. Per the tamper-kind enum pinned in `tamper/001`'s derivation:

>  `hash_mismatch` | `author_event_hash` or `canonical_event_hash`
>  recomputation disagrees with the payload's recorded value | step
>  4.d / 4.e | Payload-field tamper that the author forgot to re-sign;
>  §19's recomputation of the hash catches it.

The enum text says "that the author forgot to re-sign" — but that is the
detection surface's intent, not the construction discipline. To isolate
`hash_mismatch` from `signature_invalid`, this vector DOES re-sign: the
signature is legitimately valid under `issuer-001`, so §19 step 4.b passes.
Step 4.d then recomputes `author_event_hash` from the unmodified preimage
(`header`, `payload_ref`, `key_bag`, `idempotency_key`, `extensions`, etc.)
and compares against the payload's stored value. The stored value is a
one-byte flip of the upstream `append/001` hash; the recomputation matches
the upstream-pinned hash. **Mismatch → step 9 `integrity_verified = false`**.

Construction:
  1. Load `append/001`'s byte-exact `EventPayload` (from
     `expected-event-payload.cbor`) and the issuer-001 key seed.
  2. Flip bit 0 of byte 0 of `author_event_hash` inside the payload.
  3. Re-encode the payload as dCBOR; re-build the RFC 9052 §4.4
     `Sig_structure`; re-sign under `issuer-001`'s seed.
  4. Assemble a tag-18 `COSE_Sign1` envelope; commit.

§19 verifier walk:
  * Step 4.a — kid resolves in registry. PASS.
  * Step 4.b — COSE_Sign1 signature verifies under issuer-001 (we signed
    it with the real seed). PASS.
  * Step 4.c — payload decodes as EventPayload. PASS.
  * Step 4.d — recompute author_event_hash per §9.5 from the decoded
    payload's {header, payload_ref, key_bag, idempotency_key, extensions,
    content_hash, sequence, prev_hash, causal_deps, ledger_scope, version}
    inputs. Those inputs are byte-identical to `append/001`'s preimage.
    Recomputed hash = upstream-pinned value. Stored hash = flipped
    upstream value. **FAIL** — recorded in event_failures.
  * Step 4.e — canonical_event_hash recomputation depends on
    author_event_hash (via the payload carrying it as a field). The
    recomputation over the stored (tampered) payload bytes produces a
    different canonical_event_hash than the upstream-pinned value; but
    §19 step 4.e compares against `AppendHead.canonical_event_hash` only
    when an AppendHead is present. This vector does not commit an
    AppendHead as expected input (the tamper surfaces at step 4.d
    already; AppendHead comparison is supplementary).
  * Step 9 — `integrity_verified` drops to `false` via "hash
    recomputations … match".

`structure_verified = true` (payload decodes cleanly through step 4.c).
`readability_verified = true` (Phase 1 PayloadInline opaque bytes).

Distinguishes from prior tamper cases:
  - tamper/001 = signature byte flipped; signature invalid at step 4.b.
  - tamper/005 = chain truncation; step 4.h fails.
  - tamper/006 = event reorder; step 4.h fails.
  - tamper/007 = THIS vector; stored hash ≠ recomputed hash at step 4.d;
    signature re-signed under real key so step 4.b passes.

Scope decision: single-event ledger, same discipline as tamper/001 / 005 /
006. No manifest, no checkpoint, no HPKE wrap.
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
KEY_FILE = ROOT / "_keys" / "issuer-001.cose_key"
BASELINE_VECTOR_DIR = ROOT / "append" / "001-minimal-inline-payload"
OUT_DIR = ROOT / "tamper" / "007-hash-mismatch"

BASELINE_EVENT_PAYLOAD_FILE = BASELINE_VECTOR_DIR / "expected-event-payload.cbor"
BASELINE_EVENT_FILE = BASELINE_VECTOR_DIR / "expected-event.cbor"
BASELINE_AUTHOR_EVENT_HASH_FILE = BASELINE_VECTOR_DIR / "author-event-hash.bin"
BASELINE_AUTHORED_PREIMAGE_FILE = BASELINE_VECTOR_DIR / "input-author-event-hash-preimage.cbor"

# Drift-alarm SHA-256 digests on upstream append/001 artifacts. If these drift,
# regenerate `append/001` first and update here.
EXPECTED_BASELINE_EVENT_SHA256 = (
    "deca82133a10729c570e277ee38a975b7f6b9e79374052f80069b3863bdd733d"
)
EXPECTED_BASELINE_PAYLOAD_SHA256 = (
    # SHA-256(fixtures/vectors/append/001-minimal-inline-payload/
    #        expected-event-payload.cbor). Computed at vector-authoring time.
    None  # auto-read from file; left None so drift is only checked against
          # the envelope digest above
)

LEDGER_SCOPE = b"test-response-ledger"                  # §10.4, matches append/001

# §7.1 signature suite + §7.4 COSE header labels.
SUITE_ID = 1
ALG_EDDSA = -8
COSE_LABEL_ALG = 1
COSE_LABEL_KID = 4
COSE_LABEL_SUITE_ID = -65537
COSE_LABEL_ARTIFACT_TYPE = -65538
ARTIFACT_TYPE_EVENT = "event"
ARTIFACT_TYPE_CHECKPOINT = "checkpoint"
ARTIFACT_TYPE_MANIFEST = "manifest"

# §8.2 / §8.5 registry values — identical to tamper/001 / tamper/005 / 006.
ISSUER_VALID_FROM = ts(1745000000)
SIGNING_KEY_ACTIVE_STATUS = 0

# §9.5 domain-separation tag.
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"


# ---------------------------------------------------------------------------
# dCBOR (§5.1).
# ---------------------------------------------------------------------------

def dcbor(value: object) -> bytes:
    return cbor2.dumps(value, canonical=True)


# ---------------------------------------------------------------------------
# §9.1 domain separation.
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
# §8.3 derived kid construction (pinned).
# ---------------------------------------------------------------------------

def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    suite_id_dcbor = dcbor(suite_id)
    return hashlib.sha256(suite_id_dcbor + pubkey_raw).digest()[:16]


def load_issuer_key() -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(KEY_FILE.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    assert len(seed) == 32 and len(pubkey) == 32
    return seed, pubkey


# ---------------------------------------------------------------------------
# §7.4 protected-header + RFC 9052 §4.4 Sig_structure.
# ---------------------------------------------------------------------------

def build_protected_header(kid: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> dict:
    return {
        COSE_LABEL_ALG:      ALG_EDDSA,
        COSE_LABEL_KID:      kid,
        COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
    }


def build_sig_structure(protected_bstr: bytes, payload_bstr: bytes) -> bytes:
    # RFC 9052 §4.4; Core §6.6 pins external_aad = h''.
    return dcbor(["Signature1", protected_bstr, b"", payload_bstr])


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(message)
    assert len(signature) == 64                         # RFC 8032 §5.1.6
    return signature


# ---------------------------------------------------------------------------
# §8.2 SigningKeyEntry — byte-identical to tamper/001 / 005 / 006 registry.
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
# Output helper.
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

    # 1. Drift alarms on upstream append/001.
    baseline_event_bytes = BASELINE_EVENT_FILE.read_bytes()
    baseline_event_digest = hashlib.sha256(baseline_event_bytes).hexdigest()
    assert baseline_event_digest == EXPECTED_BASELINE_EVENT_SHA256, (
        "append/001 envelope drifted; regenerate tamper/007 after updating "
        "EXPECTED_BASELINE_EVENT_SHA256"
    )

    # 2. Decode the baseline EventPayload and verify structural assumptions
    #    the tamper depends on.
    payload_bytes = BASELINE_EVENT_PAYLOAD_FILE.read_bytes()
    payload = cbor2.loads(payload_bytes)
    assert payload["ledger_scope"] == LEDGER_SCOPE
    assert payload["sequence"] == 0
    baseline_author_event_hash = payload["author_event_hash"]
    assert len(baseline_author_event_hash) == 32
    assert BASELINE_AUTHOR_EVENT_HASH_FILE.read_bytes() == baseline_author_event_hash, (
        "append/001's expected-event-payload.cbor author_event_hash does not "
        "match author-event-hash.bin"
    )

    # 3. Independently verify the baseline author_event_hash to prove the
    #    preimage inputs are clean. §9.5: author_event_hash = domain-sep
    #    SHA-256 over the AuthorEventHashPreimage bytes under tag
    #    "trellis-author-event-v1".
    authored_preimage_bytes = BASELINE_AUTHORED_PREIMAGE_FILE.read_bytes()
    recomputed_author_event_hash = domain_separated_sha256(
        TAG_TRELLIS_AUTHOR_EVENT_V1, authored_preimage_bytes,
    )
    assert recomputed_author_event_hash == baseline_author_event_hash, (
        "baseline author_event_hash drift: expected recompute-from-preimage to "
        "equal the stored hash — upstream vector is inconsistent"
    )

    # 4. Build the tampered payload. Mutate byte 0 of author_event_hash with
    #    XOR 0x01 (flip the LSB); this is the minimum-surface mutation
    #    (parallel to tamper/001's single-byte signature flip). The rest of
    #    the payload — header, payload_ref, key_bag, idempotency_key,
    #    extensions, content_hash, prev_hash, causal_deps, sequence,
    #    ledger_scope, version — is unchanged, so step 4.d's recomputation
    #    over that preimage produces the UPSTREAM hash, not the stored
    #    (tampered) one. Mismatch is surfaced at step 4.d.
    tampered_author_event_hash = (
        bytes([baseline_author_event_hash[0] ^ 0x01])
        + baseline_author_event_hash[1:]
    )
    assert tampered_author_event_hash != baseline_author_event_hash

    tampered_payload = dict(payload)
    tampered_payload["author_event_hash"] = tampered_author_event_hash
    tampered_payload_bytes = dcbor(tampered_payload)

    # 5. Build protected header + re-sign with issuer-001's real seed. The
    #    signature covers the TAMPERED payload bytes, so step 4.b verifies
    #    cleanly; the tamper surfaces only at step 4.d's hash recomputation.
    seed, pubkey_raw = load_issuer_key()
    kid = derive_kid(SUITE_ID, pubkey_raw)
    protected_map_bytes = dcbor(build_protected_header(kid))
    sig_structure = build_sig_structure(protected_map_bytes, tampered_payload_bytes)
    signature = ed25519_sign(seed, sig_structure)

    # 6. Assemble tag-18 COSE_Sign1 envelope.
    cose_sign1 = cbor2.CBORTag(
        18,
        [protected_map_bytes, {}, tampered_payload_bytes, signature],
    )
    tampered_envelope_bytes = dcbor(cose_sign1)

    # 7. Commit the tampered artifacts.
    write_bytes("input-tampered-event.cbor", tampered_envelope_bytes)
    write_bytes("input-tampered-event-payload.cbor", tampered_payload_bytes)
    write_bytes("sig-structure.bin", sig_structure)

    # 8. Build the ledger as a one-element dCBOR array.
    ledger_bytes = dcbor([cose_sign1])
    write_bytes("input-tampered-ledger.cbor", ledger_bytes)

    # 9. Minimum signing-key registry, byte-identical in intent to
    #    tamper/001 / 005 / 006.
    registry = [build_signing_key_entry(kid, pubkey_raw)]
    registry_bytes = dcbor(registry)
    write_bytes("input-signing-key-registry.cbor", registry_bytes)

    # 10. Reviewer-facing summary. The stored (tampered) hash byte-differs
    #     from the recomputed hash at byte 0 by bit 0; all other bytes
    #     identical.
    print()
    print(f"  ledger_scope                        = {LEDGER_SCOPE.decode()}")
    print(f"  upstream author_event_hash (recomp) = {baseline_author_event_hash.hex()}")
    print(f"  stored author_event_hash (tampered) = {tampered_author_event_hash.hex()}")
    print(f"  kid                                 = {kid.hex()}")
    print(f"  signature (Ed25519, 64 B)            = {signature.hex()}")
    print(f"  tamper_kind                         = hash_mismatch")


if __name__ == "__main__":
    main()
