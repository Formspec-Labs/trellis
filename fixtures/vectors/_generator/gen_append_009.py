"""Generate byte-exact reference vector `append/009-signing-key-revocation`.

Authoring aid only. Every construction block carries an inline Core-§ citation
naming the normative paragraph that determines the bytes. This script is NOT
normative; `derivation.md` is the spec-prose reproduction evidence. If this
script and Core disagree, Core wins.

Determinism: two runs of this script produce byte-identical output. No
randomness, no wall-clock reads, no environment lookups beyond pinned inputs.

Scope — the `append/` residue batch closure. This vector discharges the last
two entries of `fixtures/vectors/_pending-invariants.toml` by exercising both
invariants byte-exactly inside a single append-context fixture:

  * **Invariant #3 — signing-key registry Active/Revoked lifecycle
    (TR-CORE-037).**  The `append/002-rotation-signing-key` vector already
    landed the Active→Retired half of §8.4's lifecycle. This vector lands the
    Active→Revoked half: a single genesis event signed by `issuer-002`, then a
    registry transition that flips `issuer-002` `Active → Revoked` with
    `valid_to` pinned at the compromise-detection timestamp. Per §8.4 "Revoked
    is terminal" and per §8.5 the entry MUST persist so historical events
    signed before `valid_to` remain verifiable — the registry-after snapshot
    therefore still resolves `kid(issuer-002)` to the same public-key bytes,
    only with `status = Revoked (3)`.

  * **Invariant #6 — registry-snapshot binding in manifest (TR-CORE-070).**
    Commits a minimal §14.2-conformant `domain-registry.cbor` and a matching
    §14.3 `RegistryBinding` whose `registry_digest = SHA-256(domain-registry
    .cbor)`. The binding's `bound_at_sequence = 0` per §14.3 "first binding
    MUST cover sequence = 0" and `registry_format = 1` (dCBOR). The domain
    registry declares the single `x-trellis-test/append-minimal` `event_type`
    and `x-trellis-test/unclassified` classification used by the fixture
    corpus under §14.6's reserved test-identifier prefix.

Scope choice — own ledger. `test-revocation-ledger` is deliberately distinct
from every other fixture scope (no collision at `sequence = 0` with
`test-response-ledger` / `test-rotation-ledger` / `test-external-ledger` /
`test-hpke-ledger` / `test-posture-ledger`).

What this vector does NOT cover. LAK rotation (§8.6 LedgerServiceWrapEntry);
that path lives with the HPKE-wrap vectors. Registry migration discipline
(§14.5 — a second RegistryBinding in the same scope bound at a later
sequence); deferred to the export/ suite that Task #5 will build.

Extraction decision — duplicates the dCBOR / domain-separation / COSE-assembly
helpers from `gen_append_002.py` inline. Same rationale as 002: `_generator/
_lib/` extraction is a separate commit; until it lands each vector is a
self-contained reading of Core to preserve the G-5 stranger-test discipline.
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
KEY_ISSUER_002 = ROOT / "_keys" / "issuer-002.cose_key"
PAYLOAD_FILE = ROOT / "_inputs" / "sample-payload-001.bin"
OUT_DIR = ROOT / "append" / "009-signing-key-revocation"

# Event-level pinned values. Own ledger_scope — see file docstring.
LEDGER_SCOPE = b"test-revocation-ledger"                # bstr, §10.4

# Single genesis event (sequence = 0). The Revoked-side lifecycle claim
# attaches to the registry-after snapshot independent of event count.
EVENT_SEQUENCE = 0                                      # §10.2 genesis
EVENT_TIMESTAMP = ts(1745110000)                            # +10000s past 002; narrative-only
EVENT_IDEMPOTENCY_KEY = b"idemp-append-009"             # 16 bytes; §6.1 .size (1..64)

# Compromise-detection timestamp — pinned as `valid_to` on issuer-002's
# post-compromise registry entry. Chosen > EVENT_TIMESTAMP so the event is
# unambiguously pre-compromise by wall-clock narrative; §10.2 ordering is
# by prev_hash not wall-clock but the timestamps carry narrative intent.
COMPROMISE_TIMESTAMP = ts(1745110120)                       # +120s after event

# Header fields inherited from 001/002/005. §14.6 reserved test prefix.
EVENT_TYPE = b"x-trellis-test/append-minimal"
CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0

# PayloadInline-specific pinned values. Inherited unchanged.
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
STATUS_REVOKED = 3                                      # §8.4 — terminal; hard-reject new

# Domain-separation tags, §9.8 registry.
TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"               # §9.2
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1" # §9.5
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"           # §9.3

# §14.3 RegistryBinding pinned values.
REGISTRY_FORMAT_DCBOR = 1                               # §14.3 "1 = dCBOR"
REGISTRY_VERSION = "x-trellis-test/registry-009-v1"     # §14.3 human-readable
REGISTRY_BOUND_AT_SEQUENCE = 0                          # §14.3 first binding MUST cover seq 0


# ---------------------------------------------------------------------------
# dCBOR (RFC 8949 §4.2.2, Core §5.1).
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
# CDDL struct builders — §12.1, §9.4, §6.4, §9.5, §6.1, §9.2, §10.6.
# ---------------------------------------------------------------------------

def build_event_header() -> dict:
    # §12.1 EventHeader.
    return {
        "event_type":             EVENT_TYPE,
        "authored_at":            EVENT_TIMESTAMP,
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
    # §9.4 KeyBag — empty (no HPKE wrap in this vector).
    return {"entries": []}


def build_author_event_hash_preimage(
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
) -> dict:
    # §9.5 / Appendix A AuthorEventHashPreimage.
    return {
        "version":         1,
        "ledger_scope":    LEDGER_SCOPE,
        "sequence":        EVENT_SEQUENCE,
        "prev_hash":       None,                         # sequence==0 → null
        "causal_deps":     None,                         # §10.3: null in Phase 1
        "content_hash":    content_hash,
        "header":          header,
        "commitments":     None,                         # §13.3
        "payload_ref":     payload_ref,
        "key_bag":         key_bag,
        "idempotency_key": EVENT_IDEMPOTENCY_KEY,
        "extensions":      None,
    }


def build_event_payload(
    author_event_hash: bytes,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
) -> dict:
    # §6.1 EventPayload.
    return {
        "version":           1,
        "ledger_scope":      LEDGER_SCOPE,
        "sequence":          EVENT_SEQUENCE,
        "prev_hash":         None,
        "causal_deps":       None,
        "author_event_hash": author_event_hash,
        "content_hash":      content_hash,
        "header":            header,
        "commitments":       None,
        "payload_ref":       payload_ref,
        "key_bag":           key_bag,
        "idempotency_key":   EVENT_IDEMPOTENCY_KEY,
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
# §7.4 Protected-header map and RFC 9052 §4.4 Sig_structure.
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
# §8.2 SigningKeyEntry builder.
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
# §14.2 minimal domain-registry builder. A §14.2-conformant registry covers at
# minimum: event-type taxonomy, role vocabulary, governance rules, and
# classification vocabulary. The minimal shape below declares one entry per
# category using §14.6's reserved `x-trellis-test/*` prefix so the registry is
# self-contained and does not depend on any external registry.
#
# The registry is a dCBOR map with stable, lowercase keys. Per §14.3 the
# binding only cares about the registry's SHA-256 digest over its canonical
# bytes — the internal shape below is a reasonable minimal choice, not a
# normative layout.
# ---------------------------------------------------------------------------

def build_domain_registry() -> dict:
    # §14.2 bound-registry content (minimal Phase 1 fixture shape).
    return {
        "event_types": {
            # §14.6 reserved test prefix; commitment schema and privacy class
            # are declared alongside the name per §14.2.
            "x-trellis-test/append-minimal": {
                "commitment_schema": "x-trellis-test/commitment-schema-v1",
                "privacy_class":     "public",
            },
        },
        "role_vocabulary": [
            # Minimal single role; §14.2 "role vocabulary."
            "x-trellis-test/role-author",
        ],
        "governance": {
            # §14.2 "governance rules: the WOS governance ruleset identifier
            # and its digest." Pinned test-namespace identifier.
            "ruleset_id":     "x-trellis-test/governance-ruleset-v1",
            "ruleset_digest": hashlib.sha256(b"x-trellis-test/governance-ruleset-v1").digest(),
        },
        "classifications": [
            # §14.6 reserved test prefix.
            "x-trellis-test/unclassified",
        ],
    }


# ---------------------------------------------------------------------------
# §14.3 RegistryBinding builder.
# ---------------------------------------------------------------------------

def build_registry_binding(registry_digest: bytes) -> dict:
    return {
        "registry_digest":   registry_digest,
        "registry_format":   REGISTRY_FORMAT_DCBOR,       # 1 = dCBOR per §14.3
        "registry_version":  REGISTRY_VERSION,
        "bound_at_sequence": REGISTRY_BOUND_AT_SEQUENCE,  # §14.3: first binding MUST cover seq 0
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
# Main pipeline.
# ---------------------------------------------------------------------------

def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"generating vector at {OUT_DIR.relative_to(ROOT.parent.parent)}/")

    # 1. Load the pinned signing key and payload.
    seed_002, pubkey_002 = load_cose_key(KEY_ISSUER_002)
    kid_002 = derive_kid(SUITE_ID, pubkey_002)
    payload_bytes = PAYLOAD_FILE.read_bytes()
    assert len(payload_bytes) == 64

    # -----------------------------------------------------------------------
    # 2. Build the §14.2 minimal domain registry and its SHA-256 digest; build
    #    the §14.3 RegistryBinding. Committed as pinned inputs — the binding's
    #    `registry_digest` byte-exactly equals SHA-256 of the committed
    #    `input-domain-registry.cbor`. This is the byte-testable surface of
    #    invariant #6 / TR-CORE-070.
    # -----------------------------------------------------------------------
    domain_registry_bytes = dcbor(build_domain_registry())
    registry_digest = hashlib.sha256(domain_registry_bytes).digest()
    registry_binding_bytes = dcbor(build_registry_binding(registry_digest))

    # -----------------------------------------------------------------------
    # 3. Build the signing-key-registry snapshots per §8.2 / §8.5.
    #
    #    `registry-before` — issuer-002 Active, valid_from = event timestamp,
    #    valid_to = null (no successor, no compromise yet).
    #
    #    `registry-after`  — issuer-002 transitions Active → Revoked per §8.4
    #    with `valid_to = COMPROMISE_TIMESTAMP`. Per §8.4 "Revoked is terminal"
    #    — and per §8.5 the entry MUST persist so historical material remains
    #    verifiable. The kid does not rotate: this is the Revoked side of the
    #    lifecycle (distinct from 002's Active→Retired side), which together
    #    span §8.4's SigningKeyStatus enum coverage. Invariant #3 / TR-CORE-037.
    # -----------------------------------------------------------------------
    entry_before = build_signing_key_entry(
        kid=kid_002,
        pubkey=pubkey_002,
        status=STATUS_ACTIVE,
        valid_from=EVENT_TIMESTAMP,
        valid_to=None,
        supersedes=None,
    )
    entry_after = build_signing_key_entry(
        kid=kid_002,
        pubkey=pubkey_002,
        status=STATUS_REVOKED,
        valid_from=EVENT_TIMESTAMP,
        valid_to=COMPROMISE_TIMESTAMP,    # pinned at compromise-detection moment
        supersedes=None,
    )

    registry_before_bytes = dcbor([entry_before])
    registry_after_bytes = dcbor([entry_after])

    # -----------------------------------------------------------------------
    # 4. Build the event bytes. §9.3 content_hash → §9.5 authored preimage →
    #    §9.5 + §9.1 author_event_hash → §6.1 EventPayload → §7.4 protected
    #    header + RFC 9052 Sig_structure → §7.1 Ed25519 signature → tag-18
    #    COSE_Sign1 → §9.2 canonical_event_hash → §10.6 AppendHead.
    # -----------------------------------------------------------------------
    header = build_event_header()
    payload_ref = build_payload_ref(payload_bytes)
    key_bag = build_key_bag()

    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_bytes)

    authored = build_author_event_hash_preimage(
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
    )
    authored_bytes = dcbor(authored)

    author_event_preimage = domain_separated_preimage(
        TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes,
    )
    author_event_hash = hashlib.sha256(author_event_preimage).digest()
    assert len(author_event_hash) == 32

    event_payload = build_event_payload(
        author_event_hash=author_event_hash,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
    )
    event_payload_bytes = dcbor(event_payload)

    protected_map_bytes = dcbor(build_protected_header(kid_002))
    sig_structure = build_sig_structure(protected_map_bytes, event_payload_bytes)
    signature = ed25519_sign(seed_002, sig_structure)

    cose_sign1 = cbor2.CBORTag(
        18,
        [protected_map_bytes, {}, event_payload_bytes, signature],
    )
    signed_envelope_bytes = dcbor(cose_sign1)

    canonical_preimage = build_canonical_event_hash_preimage(event_payload)
    canonical_preimage_bytes = dcbor(canonical_preimage)
    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1, canonical_preimage_bytes,
    )

    append_head_bytes = dcbor(
        build_append_head(LEDGER_SCOPE, EVENT_SEQUENCE, canonical_event_hash)
    )

    # -----------------------------------------------------------------------
    # 5. Invariant #3 verification-under-revocation assertion (in-script). The
    #    event's protected-header `kid` equals `kid_002`; the post-compromise
    #    registry snapshot MUST still resolve that kid to the same pubkey
    #    bytes, with status `Revoked` and `valid_to = COMPROMISE_TIMESTAMP`.
    #    Per §8.4 "Retired is terminal for signature issuance but not for
    #    verification of historical records"; the same rule applies to Revoked
    #    by construction of §8.5 ("entry MUST remain in the registry to
    #    preserve historical verifiability").
    # -----------------------------------------------------------------------
    assert entry_after["kid"] == kid_002
    assert entry_after["pubkey"] == pubkey_002
    assert entry_after["status"] == STATUS_REVOKED
    assert entry_after["valid_to"] == COMPROMISE_TIMESTAMP

    # -----------------------------------------------------------------------
    # 6. Invariant #6 registry-digest reproduction assertion (in-script).
    #    SHA-256 of the committed domain-registry bytes reproduces the digest
    #    carried inside the RegistryBinding.
    # -----------------------------------------------------------------------
    assert hashlib.sha256(domain_registry_bytes).digest() == registry_digest

    # -----------------------------------------------------------------------
    # 7. Commit artifacts.
    # -----------------------------------------------------------------------
    write_bytes("input-domain-registry.cbor", domain_registry_bytes)
    write_bytes("input-registry-binding.cbor", registry_binding_bytes)
    write_bytes("input-signing-key-registry-before.cbor", registry_before_bytes)
    write_bytes("input-signing-key-registry-after.cbor", registry_after_bytes)
    write_bytes("input-author-event-hash-preimage.cbor", authored_bytes)
    write_bytes("author-event-preimage.bin", author_event_preimage)
    write_bytes("author-event-hash.bin", author_event_hash)
    write_bytes("expected-event-payload.cbor", event_payload_bytes)
    write_bytes("sig-structure.bin", sig_structure)
    write_bytes("expected-event.cbor", signed_envelope_bytes)
    write_bytes("expected-append-head.cbor", append_head_bytes)

    # -----------------------------------------------------------------------
    # 8. Informational summary.
    # -----------------------------------------------------------------------
    print()
    print(f"  kid(issuer-002)                 = {kid_002.hex()}")
    print(f"  registry_digest (SHA-256)        = {registry_digest.hex()}")
    print(f"  content_hash                     = {content_hash.hex()}")
    print(f"  author_event_hash                = {author_event_hash.hex()}")
    print(f"  canonical_event_hash             = {canonical_event_hash.hex()}")
    print(f"  signature (Ed25519, 64 B)        = {signature.hex()}")


if __name__ == "__main__":
    main()
