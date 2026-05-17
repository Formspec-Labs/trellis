"""Generate byte-exact reference vectors `append/036..039` — ADR 0010
user-content-attestation positive corpus.

Authoring aid only. Each vector's `derivation.md` is the spec-prose
reproduction evidence. Determinism: two runs produce byte-identical output.

Vector matrix (ADR 0010 §"Fixture plan"):

  | dir                                                     | identity_ref | attestor scheme                  | extra                          |
  |---------------------------------------------------------|--------------|----------------------------------|--------------------------------|
  | 036-user-content-attestation-minimal                    | non-null     | urn:trellis:principal:applicant  | single attestation, well-formed |
  | 037-user-content-attestation-multi-attestor             | non-null     | urn:trellis:principal:applicant  | applicant attestation; vector 037-bis-style sibling rides 037 with `signing_intent` distinguishing the role |
  | 038-user-content-attestation-without-identity           | null         | urn:trellis:principal:applicant  | Posture admits unverified      |
  | 039-user-content-attestation-stand-alone                | non-null     | urn:trellis:principal:notary     | notarial intent; bare attestation |

Per ADR 0010 §"Wire shape", every vector's COSE_Sign1 envelope payload
is the canonical EventPayload; the inner Ed25519 signature on the
`UserContentAttestationPayload.signature` field is computed under
domain tag `trellis-user-content-attestation-v1` (Core §9.8) over
`dCBOR([attestation_id, attested_event_hash, attested_event_position,
attestor, identity_attestation_ref, signing_intent, attested_at])`.

The Phase-1 reference verifier admits the byte shape unconditionally at
decode time (steps 1 + 2 partial). Chain-position / identity resolution
(steps 3 / 4) and signature verification against the registry (step 5)
require a multi-event ledger context — those exercise via the
`tamper/028..034` corpus, the rotation boundary in `tamper/043`, and
the (deferred) export-bundle vector.

All four vectors:

* Are independent genesis appends on distinct `ledger_scope` values
  (sequence = 0, prev_hash = null). The `attested_event_hash` and
  `identity_attestation_ref` digests are stable deterministic values
  pinned per vector — they do not resolve in this single-event slice;
  the resolution path is exercised by the multi-event tamper corpus.
* Sign the COSE_Sign1 envelope with `_keys/issuer-001.cose_key`.
* Carry the `trellis.user-content-attestation.v1` payload under
  `EventPayload.extensions` (Core §6.7).
* Sign the inner `UserContentAttestationPayload.signature` field with
  the same `_keys/issuer-001.cose_key` (the `signing_kid` field then
  contains issuer-001's 16-byte derived kid). Real deployments separate
  the envelope-signing key from the user-content-attestation signing
  key; the fixture corpus reuses one key for byte-exact reproducibility
  without sacrificing the test surface.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cbor2  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from _lib.byte_utils import (  # noqa: E402
    ALG_EDDSA,
    COSE_LABEL_ALG,
    COSE_LABEL_KID,
    COSE_LABEL_SUITE_ID,
    ARTIFACT_TYPE_CHECKPOINT,
    ARTIFACT_TYPE_EVENT,
    ARTIFACT_TYPE_MANIFEST,
    COSE_LABEL_ARTIFACT_TYPE,
    SUITE_ID_PHASE_1,
    dcbor,
    domain_separated_sha256,
    ts,
)


# ---------------------------------------------------------------------------
# Pinned paths.
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent  # fixtures/vectors/
KEY_ISSUER = ROOT / "_keys" / "issuer-001.cose_key"


# ---------------------------------------------------------------------------
# Pinned constants shared across all four vectors.
# ---------------------------------------------------------------------------

CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0
EVENT_TYPE = b"trellis.user-content-attestation.v1"
PAYLOAD_NONCE = b"\x00" * 12

# Every vector signs at the same authored_at; per-vector ledger_scope
# guarantees genesis sequence = 0 on each. ADR 0010 §"Field semantics"
# `attested_at` clause: `attested_at` MUST exactly equal `authored_at`.
HOST_AUTHORED_AT = ts(1_776_900_000)

SUITE_ID = SUITE_ID_PHASE_1

TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"
TAG_USER_CONTENT_ATTESTATION_V1 = "trellis-user-content-attestation-v1"


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def domain_separated_preimage(tag: str, component: bytes) -> bytes:
    tag_bytes = tag.encode("utf-8")
    return (
        len(tag_bytes).to_bytes(4, "big")
        + tag_bytes
        + len(component).to_bytes(4, "big")
        + component
    )


def load_cose_key(path: Path) -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(path.read_bytes())
    seed = cose_key[-4]
    pubkey = cose_key[-2]
    assert len(seed) == 32 and len(pubkey) == 32
    return seed, pubkey


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def write_bytes(out_dir: Path, name: str, data: bytes) -> str:
    path = out_dir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"  {name:55s}  {len(data):>5d} bytes  sha256={digest}")
    return digest


def write_text(out_dir: Path, name: str, text: str) -> None:
    path = out_dir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


# ---------------------------------------------------------------------------
# UserContentAttestationPayload signature preimage.
# ---------------------------------------------------------------------------


def build_user_content_attestation_preimage(
    *,
    attestation_id: str,
    attested_event_hash: bytes,
    attested_event_position: int,
    attestor: str,
    identity_attestation_ref: bytes | None,
    signing_intent: str,
    attested_at: int,
) -> bytes:
    """Per ADR 0010 §"Wire shape": `dCBOR([attestation_id,
    attested_event_hash, attested_event_position, attestor,
    identity_attestation_ref, signing_intent, attested_at])`.

    Mirrors `compute_user_content_attestation_preimage` in
    `integrity-verify::trellis` byte-for-byte.
    """
    return dcbor([
        attestation_id,
        attested_event_hash,
        attested_event_position,
        attestor,
        identity_attestation_ref,        # `null` (None) admitted under permissive posture
        signing_intent,
        attested_at,
    ])


def sign_user_content_attestation(
    *,
    signing_seed: bytes,
    preimage: bytes,
) -> bytes:
    """Per ADR 0010 §"Verifier obligations" step 5: detached Ed25519 over
    `domain_separated_sha256(trellis-user-content-attestation-v1, preimage)`.

    Mirrors `verify_user_content_attestation_signature` in
    `integrity-verify::trellis` byte-for-byte (signing side).
    """
    digest = domain_separated_sha256(TAG_USER_CONTENT_ATTESTATION_V1, preimage)
    sk = Ed25519PrivateKey.from_private_bytes(signing_seed)
    signature = sk.sign(digest)
    assert len(signature) == 64
    return signature


# ---------------------------------------------------------------------------
# UserContentAttestationPayload + envelope builders.
# ---------------------------------------------------------------------------


def build_user_content_attestation_payload(
    *,
    attestation_id: str,
    attested_event_hash: bytes,
    attested_event_position: int,
    attestor: str,
    identity_attestation_ref: bytes | None,
    signing_intent: str,
    attested_at: int,
    signature: bytes,
    signing_kid: bytes,
) -> dict:
    """Build the `UserContentAttestationPayload` map per Core §28 CDDL /
    ADR 0010 §"Wire shape". `signing_kid` is a 16-byte bstr per the
    Rust-byte-authority reconciliation noted in Core §28."""
    return {
        "attestation_id":           attestation_id,
        "attested_event_hash":      attested_event_hash,
        "attested_event_position":  attested_event_position,
        "attestor":                 attestor,
        "identity_attestation_ref": identity_attestation_ref,
        "signing_intent":           signing_intent,
        "attested_at":              attested_at,
        "signature":                signature,
        "signing_kid":              signing_kid,
        "extensions":               None,
    }


def build_event_header() -> dict:
    return {
        "event_type":             EVENT_TYPE,
        "authored_at":             HOST_AUTHORED_AT,
        "retention_tier":          RETENTION_TIER,
        "classification":          CLASSIFICATION,
        "outcome_commitment":      None,
        "subject_ref_commitment":  None,
        "tag_commitment":          None,
        "witness_ref":             None,
        "extensions":              None,
    }


def build_payload_ref(payload_marker: bytes) -> dict:
    return {
        "ref_type":   "inline",
        "ciphertext": payload_marker,
        "nonce":      PAYLOAD_NONCE,
    }


def build_key_bag() -> dict:
    return {"entries": []}


def build_author_event_hash_preimage(
    *,
    ledger_scope: bytes,
    sequence: int,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
    extensions: dict,
    idempotency_key: bytes,
) -> dict:
    return {
        "version":         1,
        "ledger_scope":    ledger_scope,
        "sequence":        sequence,
        "prev_hash":       None,
        "causal_deps":     None,
        "content_hash":    content_hash,
        "header":          header,
        "commitments":     None,
        "payload_ref":     payload_ref,
        "key_bag":         key_bag,
        "idempotency_key": idempotency_key,
        "extensions":      extensions,
    }


def build_event_payload(
    *,
    ledger_scope: bytes,
    sequence: int,
    author_event_hash: bytes,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
    extensions: dict,
    idempotency_key: bytes,
) -> dict:
    return {
        "version":           1,
        "ledger_scope":      ledger_scope,
        "sequence":          sequence,
        "prev_hash":         None,
        "causal_deps":       None,
        "author_event_hash": author_event_hash,
        "content_hash":      content_hash,
        "header":            header,
        "commitments":       None,
        "payload_ref":       payload_ref,
        "key_bag":           key_bag,
        "idempotency_key":   idempotency_key,
        "extensions":        extensions,
    }


def build_canonical_event_hash_preimage(
    ledger_scope: bytes, event_payload: dict
) -> dict:
    return {
        "version":       1,
        "ledger_scope":  ledger_scope,
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


# ---------------------------------------------------------------------------
# Per-vector specs.
# ---------------------------------------------------------------------------


def vector_specs() -> list[dict]:
    """Pinned spec for each of append/036..039. The `attested_event_hash`
    and `identity_attestation_ref` digests are deterministic test markers:
    SHA-256(b"trellis-fixture-host-event:<vector>") for the host event,
    SHA-256(b"trellis-fixture-identity-event:<vector>") for the identity
    event. They do not resolve in this single-event slice (positive vector
    contract is "this one event signs cleanly"); the multi-event resolution
    path lives in the tamper corpus.

    Vector 037 — "multi-attestor" — collapses two distinct attestation
    events into one positive vector by parameterizing two distinct
    `attestation_id` values per role; each attestation event signs
    separately. The fixture lays out vector 037's primary applicant
    attestation; the operator workflow precedent is the same shape for
    the witness attestation a downstream vector would emit.
    """
    def host_digest(label: str) -> bytes:
        return hashlib.sha256(f"trellis-fixture-host-event:{label}".encode("utf-8")).digest()

    def identity_digest(label: str) -> bytes:
        return hashlib.sha256(f"trellis-fixture-identity-event:{label}".encode("utf-8")).digest()

    return [
        {
            "dir":                       "append/036-user-content-attestation-minimal",
            "ledger_scope":              b"trellis-uca:test:036-minimal",
            "vector_id":                 "036",
            "attestation_id":            "urn:trellis:user-content-attestation:test:036",
            "attested_event_hash":       host_digest("036"),
            "attested_event_position":   0,
            "attestor":                  "urn:trellis:principal:applicant-036",
            "identity_attestation_ref":  identity_digest("036"),
            "signing_intent":            "urn:wos:signature-intent:applicant-affirmation",
            "idempotency_key":           b"idemp-uca-036",
        },
        {
            "dir":                       "append/037-user-content-attestation-multi-attestor",
            "ledger_scope":              b"trellis-uca:test:037-multi",
            "vector_id":                 "037",
            "attestation_id":            "urn:trellis:user-content-attestation:test:037-applicant",
            "attested_event_hash":       host_digest("037"),
            "attested_event_position":   0,
            "attestor":                  "urn:trellis:principal:applicant-037",
            "identity_attestation_ref":  identity_digest("037-applicant"),
            "signing_intent":            "urn:wos:signature-intent:applicant-affirmation",
            "idempotency_key":           b"idemp-uca-037-applicant",
        },
        {
            "dir":                       "append/038-user-content-attestation-without-identity",
            "ledger_scope":              b"trellis-uca:test:038-noident",
            "vector_id":                 "038",
            "attestation_id":            "urn:trellis:user-content-attestation:test:038",
            "attested_event_hash":       host_digest("038"),
            "attested_event_position":   0,
            "attestor":                  "urn:trellis:principal:applicant-038",
            "identity_attestation_ref":  None,                   # ← null per ADR 0010 §"Field semantics"
            "signing_intent":            "urn:wos:signature-intent:public-comment",
            "idempotency_key":           b"idemp-uca-038",
        },
        {
            "dir":                       "append/039-user-content-attestation-stand-alone",
            "ledger_scope":              b"trellis-uca:test:039-notary",
            "vector_id":                 "039",
            "attestation_id":            "urn:trellis:user-content-attestation:test:039",
            "attested_event_hash":       host_digest("039"),
            "attested_event_position":   0,
            "attestor":                  "urn:trellis:principal:notary-039",
            "identity_attestation_ref":  identity_digest("039"),
            "signing_intent":            "urn:wos:signature-intent:notarial-attestation",
            "idempotency_key":           b"idemp-uca-039",
        },
    ]


# ---------------------------------------------------------------------------
# Per-vector main.
# ---------------------------------------------------------------------------


def generate_vector(
    spec: dict,
    *,
    issuer_seed: bytes,
    issuer_pub: bytes,
    kid: bytes,
) -> bytes:
    """Returns canonical_event_hash for this vector."""
    out_dir = ROOT / spec["dir"]
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating vector at {out_dir.relative_to(ROOT.parent.parent)}/")

    # 1. Build the user-content-attestation signature preimage and sign it.
    preimage = build_user_content_attestation_preimage(
        attestation_id=spec["attestation_id"],
        attested_event_hash=spec["attested_event_hash"],
        attested_event_position=spec["attested_event_position"],
        attestor=spec["attestor"],
        identity_attestation_ref=spec["identity_attestation_ref"],
        signing_intent=spec["signing_intent"],
        attested_at=HOST_AUTHORED_AT,
    )
    write_bytes(out_dir, "input-uca-signature-preimage.cbor", preimage)
    signature = sign_user_content_attestation(
        signing_seed=issuer_seed, preimage=preimage,
    )
    write_bytes(out_dir, "input-uca-signature.bin", signature)

    # 2. Build the UserContentAttestationPayload + envelope extensions.
    uca_payload = build_user_content_attestation_payload(
        attestation_id=spec["attestation_id"],
        attested_event_hash=spec["attested_event_hash"],
        attested_event_position=spec["attested_event_position"],
        attestor=spec["attestor"],
        identity_attestation_ref=spec["identity_attestation_ref"],
        signing_intent=spec["signing_intent"],
        attested_at=HOST_AUTHORED_AT,
        signature=signature,
        signing_kid=kid,
    )
    write_bytes(out_dir, "input-uca-payload.cbor", dcbor(uca_payload))
    extensions = {EVENT_TYPE.decode("utf-8"): uca_payload}

    # 3. PayloadInline marker (the user-content-attestation IS the extension;
    # the inline payload is an opaque per-vector marker so content_hash
    # differs across vectors and the test ledgers are independent).
    payload_marker = (
        f"user-content-attestation-marker-{spec['vector_id']}".encode("utf-8")
    )
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_marker)

    header = build_event_header()
    payload_ref = build_payload_ref(payload_marker)
    key_bag = build_key_bag()

    # 4. AuthorEventHashPreimage → author_event_hash (Core §9.5, §9.1).
    authored_map = build_author_event_hash_preimage(
        ledger_scope=spec["ledger_scope"],
        sequence=0,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
        extensions=extensions,
        idempotency_key=spec["idempotency_key"],
    )
    authored_bytes = dcbor(authored_map)
    write_bytes(out_dir, "input-author-event-hash-preimage.cbor", authored_bytes)

    author_event_hash = hashlib.sha256(
        domain_separated_preimage(TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes)
    ).digest()
    write_bytes(out_dir, "author-event-hash.bin", author_event_hash)

    # 5. EventPayload (Core §6.1).
    event_payload = build_event_payload(
        ledger_scope=spec["ledger_scope"],
        sequence=0,
        author_event_hash=author_event_hash,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
        extensions=extensions,
        idempotency_key=spec["idempotency_key"],
    )
    event_payload_bytes = dcbor(event_payload)
    write_bytes(out_dir, "expected-event-payload.cbor", event_payload_bytes)

    # 6. Protected header + Sig_structure + Ed25519 signature.
    protected_map = build_protected_header(kid)
    protected_map_bytes = dcbor(protected_map)
    sig_structure = build_sig_structure(protected_map_bytes, event_payload_bytes)
    write_bytes(out_dir, "sig-structure.bin", sig_structure)

    sk = Ed25519PrivateKey.from_private_bytes(issuer_seed)
    cose_signature = sk.sign(sig_structure)
    assert len(cose_signature) == 64

    cose_sign1 = cbor2.CBORTag(
        18, [protected_map_bytes, {}, event_payload_bytes, cose_signature],
    )
    cose_sign1_bytes = dcbor(cose_sign1)
    write_bytes(out_dir, "expected-event.cbor", cose_sign1_bytes)

    # 7. canonical_event_hash + AppendHead.
    canonical_preimage = dcbor(
        build_canonical_event_hash_preimage(spec["ledger_scope"], event_payload)
    )
    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1, canonical_preimage
    )
    append_head = build_append_head(
        spec["ledger_scope"], 0, canonical_event_hash
    )
    write_bytes(out_dir, "expected-append-head.cbor", dcbor(append_head))

    print()
    print(f"  ledger_scope         = {spec['ledger_scope']!r}")
    print(f"  kid                  = {kid.hex()}")
    print(f"  attestation_id       = {spec['attestation_id']}")
    print(f"  attestor             = {spec['attestor']}")
    print(f"  signing_intent       = {spec['signing_intent']}")
    print(f"  uca signature        = {signature.hex()[:32]}...")
    print(f"  content_hash         = {content_hash.hex()}")
    print(f"  author_event_hash    = {author_event_hash.hex()}")
    print(f"  canonical_event_hash = {canonical_event_hash.hex()}")

    write_manifest(spec, out_dir)
    write_derivation(spec, out_dir, canonical_event_hash, author_event_hash, signature)
    return canonical_event_hash


# ---------------------------------------------------------------------------
# manifest.toml + derivation.md per vector.
# ---------------------------------------------------------------------------


def manifest_for(spec: dict) -> str:
    # Per-vector tr_core baseline: every user-content-attestation vector
    # exercises canonical-append discipline + ADR 0010 wire-shape pin.
    # 038 additionally exercises the null-admission posture (TR-CORE-154).
    base_tr_core = [
        "TR-CORE-001",
        "TR-CORE-018",
        "TR-CORE-021",
        "TR-CORE-030",
        "TR-CORE-031",
        "TR-CORE-035",
        "TR-CORE-050",
        "TR-CORE-051",
        "TR-CORE-080",
        "TR-CORE-152",
    ]
    extra_tr_core: list[str] = []
    if spec["vector_id"] == "038":
        extra_tr_core.append("TR-CORE-154")
    if spec["identity_attestation_ref"] is not None:
        # Vectors with non-null identity_attestation_ref pin TR-CORE-153
        # (chain-position binding) only as wire-shape; full chain-position
        # resolution rides the tamper corpus where the chain context
        # carries the resolvable host event.
        pass

    tr_core = base_tr_core + extra_tr_core
    tr_core_lines = ",\n    ".join(f'"{x}"' for x in tr_core)

    description = {
        "036": (
            "ADR 0010 §\"Wire shape\" minimal positive vector. Single "
            "user-content-attestation event (`trellis.user-content-attestation.v1`) "
            "with `identity_attestation_ref` non-null, `signing_intent` "
            "well-formed (`urn:wos:signature-intent:applicant-affirmation`), "
            "`attestor` non-operator URI. Genesis sequence on its own "
            "ledger_scope; per-event verifier path (steps 1 + 2 partial) "
            "decodes cleanly. Chain-position / identity resolution (steps "
            "3 / 4) and signature verification against the registry (step 5) "
            "exercise via the multi-event tamper corpus."
        ),
        "037": (
            "ADR 0010 §\"Fixture plan\" multi-attestor positive vector. "
            "Distinct `attestation_id` (per-role), distinct `signing_intent` "
            "(applicant role), non-null `identity_attestation_ref`. The "
            "ADR's two-attestor scenario maps to two byte-distinct events "
            "with disjoint `attestation_id` values; this fixture pins the "
            "primary applicant attestation. Witness / co-signer attestations "
            "follow the same shape with `attestor` + `attestation_id` + "
            "`signing_intent` distinguishing the role."
        ),
        "038": (
            "ADR 0010 §\"Field semantics\" `identity_attestation_ref` "
            "null-admission positive vector. `identity_attestation_ref = "
            "null`; the deployment's Posture Declaration MUST declare "
            "`admit_unverified_user_attestations: true` for the verifier "
            "to admit (TR-CORE-154). Public-comment intake is the canonical "
            "use-case (`urn:wos:signature-intent:public-comment`)."
        ),
        "039": (
            "ADR 0010 §\"Composition with existing primitives\" stand-alone "
            "positive vector. Bare attestation event with `signing_intent = "
            "urn:wos:signature-intent:notarial-attestation` — no "
            "`SignatureAffirmation` host, no certificate-of-completion. The "
            "verifier path is identical to 036; verification independence "
            "(Core §16) holds."
        ),
    }[spec["vector_id"]]

    return f'''id          = "{spec["dir"]}"
op          = "append"
status      = "active"
description = """{description}"""

[coverage]
tr_core = [
    {tr_core_lines},
]

[inputs]
signing_key                  = "../../_keys/issuer-001.cose_key"
authored_event               = "input-author-event-hash-preimage.cbor"
user_content_attestation_payload = "input-uca-payload.cbor"
user_content_attestation_signature_preimage = "input-uca-signature-preimage.cbor"
user_content_attestation_signature = "input-uca-signature.bin"

[expected]
author_event_hash = "author-event-hash.bin"
canonical_event   = "expected-event-payload.cbor"
signed_event      = "expected-event.cbor"
append_head       = "expected-append-head.cbor"

[derivation]
document = "derivation.md"
'''


def write_manifest(spec: dict, out_dir: Path) -> None:
    write_text(out_dir, "manifest.toml", manifest_for(spec))


def derivation_for(
    spec: dict,
    canonical_event_hash: bytes,
    author_event_hash: bytes,
    uca_signature: bytes,
) -> str:
    identity_repr = (
        f"`{spec['identity_attestation_ref'].hex()}` (32 bytes)"
        if spec["identity_attestation_ref"] is not None
        else "`null` (Posture Declaration MUST admit unverified attestors)"
    )
    return f"""# Derivation — `{spec["dir"]}`

ADR 0010 §\"Wire shape\" positive vector for `trellis.user-content-attestation.v1`.

## Inputs

- Issuer key: `_keys/issuer-001.cose_key` (Ed25519 / suite-id 1).
- `attestation_id` = `{spec['attestation_id']}`
- `attested_event_hash` = `{spec['attested_event_hash'].hex()}` (deterministic
  fixture marker: `SHA-256("trellis-fixture-host-event:{spec['vector_id']}")`).
- `attested_event_position` = `{spec['attested_event_position']}`
- `attestor` = `{spec['attestor']}`
- `identity_attestation_ref` = {identity_repr}
- `signing_intent` = `{spec['signing_intent']}` (RFC 3986 syntactically valid;
  semantics owned by WOS Signature Profile per ADR 0010 §"Field semantics").
- `attested_at` = `{HOST_AUTHORED_AT}` (= envelope `authored_at`; ADR 0010
  §"Verifier obligations" step 2 exact-equality rule).

## Construction

1. **UserContentAttestationPayload signature preimage** (ADR 0010 §"Wire shape"):
   `dCBOR([attestation_id, attested_event_hash, attested_event_position,
   attestor, identity_attestation_ref, signing_intent, attested_at])`. See
   `input-uca-signature-preimage.cbor`.

2. **UserContentAttestationPayload.signature.** Sign the SHA-256 of the
   preimage under domain tag `trellis-user-content-attestation-v1` (Core §9.8)
   using `_keys/issuer-001.cose_key`. Detached Ed25519, 64 bytes. See
   `input-uca-signature.bin`. First 16 bytes: `{uca_signature.hex()[:32]}`.

3. **UserContentAttestationPayload** (Core §28 / ADR 0010 §"Wire shape"):
   the 11-field map carrying all signed fields plus `signing_kid` (issuer-001's
   16-byte derived kid, the `signing` key class). See `input-uca-payload.cbor`.

4. **EventPayload.extensions** carries the user-content-attestation payload
   under key `trellis.user-content-attestation.v1` (Core §6.7 registration row).

5. **Envelope.** Genesis sequence = 0, `prev_hash = null`, `ledger_scope =
   {spec['ledger_scope']!r}`. Standard Trellis Core §6 envelope; signed under
   `_keys/issuer-001.cose_key` (Ed25519, suite-id 1).

6. **Hashes.** Author/canonical hashes follow Core §9.5 / §9.1 framing.
   - `author_event_hash` = `{author_event_hash.hex()}`
   - `canonical_event_hash` = `{canonical_event_hash.hex()}`

## Phase-1 verifier posture

Per `decode_user_content_attestation_payload` in
`integrity-verify::trellis`: this vector exercises step 1 (CDDL decode)
and step 2 partial (`attested_at == authored_at`; `signing_intent` RFC 3986
well-formedness) at the per-event path. Cross-event steps 3 / 4 / 5 / 6 / 7 / 8
require multi-event chain context and exercise via `tamper/028..034`.

Generator: `fixtures/vectors/_generator/gen_append_036_to_039.py`.
"""


def write_derivation(
    spec: dict,
    out_dir: Path,
    canonical_event_hash: bytes,
    author_event_hash: bytes,
    uca_signature: bytes,
) -> None:
    write_text(
        out_dir,
        "derivation.md",
        derivation_for(spec, canonical_event_hash, author_event_hash, uca_signature),
    )


# ---------------------------------------------------------------------------
# Top-level main: runs all four.
# ---------------------------------------------------------------------------


def main() -> None:
    issuer_seed, issuer_pub = load_cose_key(KEY_ISSUER)
    kid = derive_kid(SUITE_ID, issuer_pub)
    for spec in vector_specs():
        generate_vector(
            spec,
            issuer_seed=issuer_seed,
            issuer_pub=issuer_pub,
            kid=kid,
        )


if __name__ == "__main__":
    main()
