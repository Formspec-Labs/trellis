"""Generate byte-exact reference vectors `append/032..035` — Phase-1 reservation
positives for the four reserved non-signing `KeyEntry` classes (ADR 0006).

Each of the four vectors carries:
  * One genesis event in its own ledger scope (`test-key-entry-N-ledger`),
    signed by `issuer-001` with the legacy flat `SigningKeyEntry` shape so
    the event itself is verification-equivalent to `append/001`.
  * A two-entry registry snapshot:
      - row 0 = `issuer-001` as the resolvable signer (legacy shape, no
        `kind` field — Core §8.7's mixed-shape acceptance rule).
      - row 1 = a `KeyEntryNonSigning` entry whose `kind` is the per-vector
        reserved class (`subject` / `tenant-root` / `scope` / `recovery`)
        with a minimal but CDDL-conformant `attributes` map.
  * Verifier expectations: structure_verified + integrity_verified +
    readability_verified all true; the verifier dispatches the row-0 entry
    via the legacy path (kind absent) and the row-1 entry via the
    `KeyEntry` non-signing path (kind present, attributes-map shape gate
    enforced). Phase-1 lint emits a warning for the non-signing row;
    verification does NOT fail per Core §8.7.3 step 3 + TR-CORE-047.

Pinned non-signing pubkeys are deterministic 32-byte byte strings derived
by SHA-256 over a per-class fixture-only seed string; this keeps fixtures
byte-stable without occupying a `_keys/` slot for material that does not
sign anything in Phase 1.

Determinism: two runs produce byte-identical output. Dispatched from a
single script so the four vectors share one definition of correctness;
each vector still emits its own `manifest.toml` + `derivation.md` for
G-3 lint compliance.
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
# Pinned inputs.
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
    suite_id_dcbor = dcbor(suite_id)
    return hashlib.sha256(suite_id_dcbor + pubkey_raw).digest()[:16]


# ---------------------------------------------------------------------------
# Fixture-only deterministic non-signing pubkeys. NOT real keypairs — just
# byte strings that fill the `attributes.pubkey` slot. The 32-byte length
# matches §8.7.2's `bstr .size 32` constraint for each reserved class.
#
# These bytes do NOT sign anything (Phase-1 lint warns on non-signing
# entries; runtime never asks for the corresponding private key); pinning
# them here as `SHA-256(<fixture-marker>)` keeps the byte path reproducible
# without occupying a `_keys/` slot.
# ---------------------------------------------------------------------------

def fixture_pubkey(marker: str) -> bytes:
    return hashlib.sha256(f"trellis-fixture-non-signing-pubkey-{marker}".encode()).digest()


# ---------------------------------------------------------------------------
# Per-class attribute builders. Each returns a dict with the minimal CDDL-
# conformant fields per Core §8.7.2; dCBOR canonical map ordering applies
# at encode time. Phase-1 verifier only enforces the structural-shape gate
# (attributes-is-a-map per §8.7.1); per-field validation is Phase-2+ per
# ADR 0006 §"Verifier obligations" step 4. The fields below are pinned at
# CDDL-spec-level minima so the verifier is exercised at the boundary
# Phase-1 actually enforces.
# ---------------------------------------------------------------------------

def build_subject_attrs() -> dict:
    return {
        "pubkey":           fixture_pubkey("subject"),
        "subject_ref":      "urn:agency.gov:subject:fixture-032",
        "authorized_for":   [b"x-trellis-test/wrap-cap-1"],
        "effective_from":   ts(1745130000),
        "valid_to":         None,
        "supersedes":       None,
    }


def build_tenant_root_attrs() -> dict:
    return {
        "pubkey":         fixture_pubkey("tenant-root"),
        "tenant_ref":     "urn:agency.gov:tenant:fixture-033",
        "effective_from": ts(1745130000),
        "supersedes":     None,
    }


def build_scope_attrs() -> dict:
    return {
        "pubkey":            fixture_pubkey("scope"),
        "scope_ref":         b"test-key-entry-scope-fixture-034",
        "parent_tenant_ref": "urn:agency.gov:tenant:fixture-034",
        "effective_from":    ts(1745130000),
        "supersedes":        None,
    }


def build_recovery_attrs(authorized_kid: bytes) -> dict:
    # `authorizes_recovery_for` references kids of signing-class keys per §8.7.2;
    # the fixture binds the recovery-class entry to issuer-001's kid so the
    # cross-class reference is reproducible.
    return {
        "pubkey":                  fixture_pubkey("recovery"),
        "authorizes_recovery_for": [authorized_kid],
        "activation_quorum":       1,
        "activation_quorum_set":   None,
        "effective_from":          ts(1745130000),
        "supersedes":              None,
    }


# ---------------------------------------------------------------------------
# Per-vector configuration.
# ---------------------------------------------------------------------------

@dataclass
class VectorSpec:
    number: str                 # "032" / "033" / "034" / "035"
    name: str                   # full directory name
    ledger_scope: bytes
    timestamp: int
    idempotency_key: bytes
    class_kind: str
    description: str
    coverage_extra: list[str]   # additional TR-CORE rows beyond TR-CORE-039 + 047

    @property
    def out_dir(self) -> Path:
        return ROOT / "append" / self.name


VECTOR_SPECS: list[VectorSpec] = [
    VectorSpec(
        number="032",
        name="032-key-entry-subject-reservation",
        ledger_scope=b"test-key-entry-subject-ledger",
        timestamp=ts(1745130200),
        idempotency_key=b"idemp-append-032",
        class_kind="subject",
        description=(
            "Phase-1 reservation positive for `kind = \"subject\"`. The registry "
            "carries `issuer-001` (legacy shape, signing) + one non-signing "
            "`KeyEntry` of kind `subject` with the minimal `SubjectKeyAttributes` "
            "map per Core §8.7.2. Verifier accepts; lint warns per Core §8.7.4."
        ),
        coverage_extra=[],
    ),
    VectorSpec(
        number="033",
        name="033-key-entry-tenant-root-reservation",
        ledger_scope=b"test-key-entry-tenant-root-ledger",
        timestamp=ts(1745130400),
        idempotency_key=b"idemp-append-033",
        class_kind="tenant-root",
        description=(
            "Phase-1 reservation positive for `kind = \"tenant-root\"`. Registry "
            "carries one signing entry + one non-signing `TenantRootKeyAttributes` "
            "entry per Core §8.7.2. Verifier accepts; lint warns."
        ),
        coverage_extra=[],
    ),
    VectorSpec(
        number="034",
        name="034-key-entry-scope-reservation",
        ledger_scope=b"test-key-entry-scope-ledger",
        timestamp=ts(1745130600),
        idempotency_key=b"idemp-append-034",
        class_kind="scope",
        description=(
            "Phase-1 reservation positive for `kind = \"scope\"`. Registry carries "
            "one signing entry + one non-signing `ScopeKeyAttributes` entry per "
            "Core §8.7.2. Verifier accepts; lint warns."
        ),
        coverage_extra=[],
    ),
    VectorSpec(
        number="035",
        name="035-key-entry-recovery-reservation",
        ledger_scope=b"test-key-entry-recovery-ledger",
        timestamp=ts(1745130800),
        idempotency_key=b"idemp-append-035",
        class_kind="recovery",
        description=(
            "Phase-1 reservation positive for `kind = \"recovery\"`. Registry "
            "carries one signing entry + one non-signing `RecoveryKeyAttributes` "
            "entry per Core §8.7.2 whose `authorizes_recovery_for` lists "
            "`kid(issuer-001)` (cross-class reference; signing kids only per ADR "
            "0006). Verifier accepts; lint warns."
        ),
        coverage_extra=[],
    ),
]


# ---------------------------------------------------------------------------
# Common event-builder pipeline. Same shape as `append/001` but parameterized
# per vector for ledger_scope / timestamp / idempotency_key.
# ---------------------------------------------------------------------------

def build_event(spec: VectorSpec, seed: bytes, pubkey: bytes, kid: bytes,
                payload_bytes: bytes) -> tuple[bytes, bytes, bytes, bytes, bytes, bytes, bytes]:
    """Returns (authored_bytes, author_event_hash, event_payload_bytes,
    sig_structure, signed_envelope_bytes, canonical_event_hash,
    append_head_bytes)."""

    header = {
        "event_type":             EVENT_TYPE,
        "authored_at":            spec.timestamp,
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
        "ledger_scope":    spec.ledger_scope,
        "sequence":        0,
        "prev_hash":       None,
        "causal_deps":     None,
        "content_hash":    content_hash,
        "header":          header,
        "commitments":     None,
        "payload_ref":     payload_ref,
        "key_bag":         key_bag,
        "idempotency_key": spec.idempotency_key,
        "extensions":      None,
    }
    authored_bytes = dcbor(authored)
    author_event_preimage = domain_separated_preimage(
        TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes,
    )
    author_event_hash = hashlib.sha256(author_event_preimage).digest()

    event_payload = {
        "version":           1,
        "ledger_scope":      spec.ledger_scope,
        "sequence":          0,
        "prev_hash":         None,
        "causal_deps":       None,
        "author_event_hash": author_event_hash,
        "content_hash":      content_hash,
        "header":            header,
        "commitments":       None,
        "payload_ref":       payload_ref,
        "key_bag":           key_bag,
        "idempotency_key":   spec.idempotency_key,
        "extensions":        None,
    }
    event_payload_bytes = dcbor(event_payload)

    protected_map_bytes = dcbor({
        COSE_LABEL_ALG:      ALG_EDDSA,
        COSE_LABEL_KID:      kid,
        COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: ARTIFACT_TYPE_EVENT,
    })
    sig_structure = dcbor(["Signature1", protected_map_bytes, b"", event_payload_bytes])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    assert len(signature) == 64

    cose_sign1 = cbor2.CBORTag(
        18,
        [protected_map_bytes, {}, event_payload_bytes, signature],
    )
    signed_envelope_bytes = dcbor(cose_sign1)

    canonical_preimage = {
        "version":       1,
        "ledger_scope":  spec.ledger_scope,
        "event_payload": event_payload,
    }
    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1, dcbor(canonical_preimage),
    )

    append_head = {
        "scope":                spec.ledger_scope,
        "sequence":             0,
        "canonical_event_hash": canonical_event_hash,
    }
    append_head_bytes = dcbor(append_head)

    return (
        authored_bytes,
        author_event_hash,
        event_payload_bytes,
        sig_structure,
        signed_envelope_bytes,
        canonical_event_hash,
        append_head_bytes,
    )


def build_signing_entry_legacy(kid: bytes, pubkey: bytes, valid_from: int) -> dict:
    # Legacy `SigningKeyEntry` (no `kind` field) — Core §8.2. The verifier
    # dispatches on absence of `kind` per §8.7.3 step 1.
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
    # `KeyEntryNonSigning` per Core §8.7.1: `kind` + `kid` + `suite_id` +
    # `attributes` + `extensions`. The kid is derived from the attributes'
    # `pubkey` field per §8.3 (class-agnostic derivation).
    pubkey = attrs["pubkey"]
    kid = derive_kid(SUITE_ID, pubkey)
    return {
        "kind":       kind,
        "kid":        kid,
        "suite_id":   SUITE_ID,
        "attributes": attrs,
        "extensions": None,
    }


def write_bytes(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"  {path.name:50s}  {len(data):>5d} bytes  sha256={digest}")


def emit_vector(spec: VectorSpec, seed_001: bytes, pubkey_001: bytes, kid_001: bytes,
                payload_bytes: bytes) -> None:
    spec.out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {spec.out_dir.relative_to(ROOT.parent.parent)}/")

    # 1. Build the genesis event signed by issuer-001.
    (
        authored_bytes,
        author_event_hash,
        event_payload_bytes,
        sig_structure,
        signed_envelope_bytes,
        canonical_event_hash,
        append_head_bytes,
    ) = build_event(spec, seed_001, pubkey_001, kid_001, payload_bytes)

    # 2. Build the registry snapshot. Row 0 = legacy signing entry for
    #    issuer-001; row 1 = the per-class non-signing reservation.
    signing_row = build_signing_entry_legacy(kid_001, pubkey_001, spec.timestamp)

    if spec.class_kind == "subject":
        non_signing_row = build_non_signing_entry("subject", build_subject_attrs())
    elif spec.class_kind == "tenant-root":
        non_signing_row = build_non_signing_entry("tenant-root", build_tenant_root_attrs())
    elif spec.class_kind == "scope":
        non_signing_row = build_non_signing_entry("scope", build_scope_attrs())
    elif spec.class_kind == "recovery":
        non_signing_row = build_non_signing_entry(
            "recovery", build_recovery_attrs(authorized_kid=kid_001),
        )
    else:
        raise SystemExit(f"unhandled class_kind: {spec.class_kind}")

    registry_bytes = dcbor([signing_row, non_signing_row])

    # 3. Commit artifacts.
    write_bytes(spec.out_dir / "input-author-event-hash-preimage.cbor", authored_bytes)
    write_bytes(spec.out_dir / "author-event-hash.bin", author_event_hash)
    write_bytes(spec.out_dir / "expected-event-payload.cbor", event_payload_bytes)
    write_bytes(spec.out_dir / "sig-structure.bin", sig_structure)
    write_bytes(spec.out_dir / "expected-event.cbor", signed_envelope_bytes)
    write_bytes(spec.out_dir / "expected-append-head.cbor", append_head_bytes)
    write_bytes(spec.out_dir / "input-signing-key-registry.cbor", registry_bytes)

    print(f"  kid(issuer-001)        = {kid_001.hex()}")
    print(f"  kid({spec.class_kind:11s})= {non_signing_row['kid'].hex()}")
    print(f"  canonical_event_hash   = {canonical_event_hash.hex()}")


def main() -> None:
    seed_001, pubkey_001 = load_cose_key(KEY_ISSUER_001)
    kid_001 = derive_kid(SUITE_ID, pubkey_001)
    payload_bytes = PAYLOAD_FILE.read_bytes()
    assert len(payload_bytes) == 64

    for spec in VECTOR_SPECS:
        emit_vector(spec, seed_001, pubkey_001, kid_001, payload_bytes)


if __name__ == "__main__":
    main()
