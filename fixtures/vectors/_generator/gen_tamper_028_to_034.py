"""Generate ADR 0010 user-content-attestation tamper vectors:

  tamper/028 — uca-signature-invalid (signature under wrong domain tag)
  tamper/029 — uca-chain-position-mismatch
  tamper/030 — uca-identity-unresolved
  tamper/031 — uca-identity-subject-mismatch
  tamper/032 — uca-identity-temporal-inversion
  tamper/033 — uca-intent-malformed (signing_intent not RFC 3986)
  tamper/034 — uca-key-not-active (signing_kid lifecycle = Retired)

Each tamper runs through `verify_tampered_ledger`. The ledger shape per
vector is documented inline; the common pattern is a 2-or-3-event chain
with a chain-resolvable host event, an optional chain-resolvable
identity-attestation event, and the user-content-attestation event whose
inner state triggers the verifier failure.

Per ADR 0010 §"Verifier obligations" steps 1–9, the failure surfaces
land as the matching `tamper_kind` per Core §19.1:

  | vector  | step | tamper_kind                                          |
  |---------|------|------------------------------------------------------|
  | 028     | 5    | user_content_attestation_signature_invalid           |
  | 029     | 3    | user_content_attestation_chain_position_mismatch     |
  | 030     | 4    | user_content_attestation_identity_unresolved         |
  | 031     | 4    | user_content_attestation_identity_subject_mismatch   |
  | 032     | 4    | user_content_attestation_identity_temporal_inversion |
  | 033     | 2    | user_content_attestation_intent_malformed            |
  | 034     | 6    | user_content_attestation_key_not_active              |

Phase-1 reference verifier exercises SigningKeyStatus at the
user-content-attestation step 6 surface. Vectors 028..033 register
the `signing_kid` with `status=0` (Active); tamper/034 specifically
registers `status=2` (Retired) to flip step 6. The `Rotating` overlap
boundary lands separately in tamper/043.
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


ROOT = Path(__file__).resolve().parent.parent
KEY_ISSUER = ROOT / "_keys" / "issuer-001.cose_key"

CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0
PAYLOAD_NONCE = b"\x00" * 12
SUITE_ID = SUITE_ID_PHASE_1

EVENT_TYPE_HOST = b"trellis.test.host-event.v1"
EVENT_TYPE_IDENTITY = b"x-trellis-test/identity-attestation/v1"
EVENT_TYPE_UCA = b"trellis.user-content-attestation.v1"

TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"
TAG_USER_CONTENT_ATTESTATION_V1 = "trellis-user-content-attestation-v1"
TAG_TRELLIS_TRANSITION_ATTESTATION_V1 = "trellis-transition-attestation-v1"

HOST_AUTHORED_AT = ts(1_776_900_000)


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
    return cose_key[-4], cose_key[-2]


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


def cose_sign1(seed: bytes, kid: bytes, payload_bytes: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> bytes:
    protected = dcbor(
        {
            COSE_LABEL_ALG: ALG_EDDSA,
            COSE_LABEL_KID: kid,
            COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
        }
    )
    sig_structure = dcbor(["Signature1", protected, b"", payload_bytes])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    return dcbor(cbor2.CBORTag(18, [protected, {}, payload_bytes, signature]))


def build_signing_key_registry(kid: bytes, pubkey: bytes, *, status: int = 0) -> bytes:
    """Phase-1 flat signing-key registry (Core §8.2 legacy shape).

    `status = 0` is Active per Core §28 `SigningKeyStatus`; ADR 0010
    user-content-attestation step 6 admits Active only. tamper/034
    registers status = 2 (Retired) to flip step 6.
    """
    return dcbor(
        [
            {
                "kid":      kid,
                "pubkey":   pubkey,
                "status":   status,
                "valid_to": None,
            }
        ]
    )


def build_event_header(event_type: bytes, authored_at: int) -> dict:
    return {
        "event_type":             event_type,
        "authored_at":             authored_at,
        "retention_tier":          RETENTION_TIER,
        "classification":          CLASSIFICATION,
        "outcome_commitment":      None,
        "subject_ref_commitment":  None,
        "tag_commitment":          None,
        "witness_ref":             None,
        "extensions":              None,
    }


def build_event(
    *,
    ledger_scope: bytes,
    sequence: int,
    prev_hash: bytes | None,
    authored_at: int,
    event_type: bytes,
    extensions: dict | None,
    payload_marker: bytes,
    idempotency_key: bytes,
) -> tuple[dict, bytes, bytes, bytes]:
    """Build one event end-to-end. Returns (event_payload, payload_bytes,
    author_event_hash, canonical_event_hash)."""
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, payload_marker)
    header = build_event_header(event_type, authored_at)
    payload_ref = {
        "ref_type":   "inline",
        "ciphertext": payload_marker,
        "nonce":      PAYLOAD_NONCE,
    }
    key_bag = {"entries": []}
    authored_map = {
        "version":         1,
        "ledger_scope":    ledger_scope,
        "sequence":        sequence,
        "prev_hash":       prev_hash,
        "causal_deps":     None,
        "content_hash":    content_hash,
        "header":          header,
        "commitments":     None,
        "payload_ref":     payload_ref,
        "key_bag":         key_bag,
        "idempotency_key": idempotency_key,
        "extensions":      extensions,
    }
    authored_bytes = dcbor(authored_map)
    author_event_hash = hashlib.sha256(
        domain_separated_preimage(TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes)
    ).digest()
    event_payload = {
        "version":           1,
        "ledger_scope":      ledger_scope,
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
        "extensions":        extensions,
    }
    event_payload_bytes = dcbor(event_payload)
    canonical_preimage = dcbor(
        {
            "version":       1,
            "ledger_scope":  ledger_scope,
            "event_payload": event_payload,
        }
    )
    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1, canonical_preimage
    )
    return event_payload, event_payload_bytes, author_event_hash, canonical_event_hash


def build_uca_signature(
    *,
    signing_seed: bytes,
    attestation_id: str,
    attested_event_hash: bytes,
    attested_event_position: int,
    attestor: str,
    identity_attestation_ref: bytes | None,
    signing_intent: str,
    attested_at: int,
    domain_tag: str = TAG_USER_CONTENT_ATTESTATION_V1,
) -> bytes:
    """Sign the UCA signature preimage. `domain_tag` is parameterized so
    tamper/028 can compute the signature under the wrong tag
    (`trellis-transition-attestation-v1`) and exercise step 5."""
    preimage = dcbor([
        attestation_id,
        attested_event_hash,
        attested_event_position,
        attestor,
        identity_attestation_ref,
        signing_intent,
        attested_at,
    ])
    digest = domain_separated_sha256(domain_tag, preimage)
    sk = Ed25519PrivateKey.from_private_bytes(signing_seed)
    return sk.sign(digest)


def build_uca_payload(
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


def build_identity_extension(subject: str) -> dict:
    """Phase-1 deployment-local identity-attestation payload shape.
    Mirrors `parse_identity_attestation_subject` in the Trellis verifier."""
    return {
        EVENT_TYPE_IDENTITY.decode("utf-8"): {
            "subject": subject,
        }
    }


# ---------------------------------------------------------------------------
# Common: build a host event + identity event for the chain context.
# ---------------------------------------------------------------------------


def build_host_event(
    *,
    seed: bytes,
    kid: bytes,
    ledger_scope: bytes,
    sequence: int,
    prev_hash: bytes | None,
    authored_at: int,
    payload_marker: bytes,
    idempotency_key: bytes,
) -> tuple[bytes, bytes, bytes]:
    """Returns (signed_cose_bytes, canonical_event_hash, payload_bytes)."""
    _, payload_bytes, _, canonical_hash = build_event(
        ledger_scope=ledger_scope,
        sequence=sequence,
        prev_hash=prev_hash,
        authored_at=authored_at,
        event_type=EVENT_TYPE_HOST,
        extensions=None,
        payload_marker=payload_marker,
        idempotency_key=idempotency_key,
    )
    signed = cose_sign1(seed, kid, payload_bytes)
    return signed, canonical_hash, payload_bytes


def build_identity_event(
    *,
    seed: bytes,
    kid: bytes,
    ledger_scope: bytes,
    sequence: int,
    prev_hash: bytes | None,
    authored_at: int,
    subject: str,
    payload_marker: bytes,
    idempotency_key: bytes,
) -> tuple[bytes, bytes, bytes]:
    """Returns (signed_cose_bytes, canonical_event_hash, payload_bytes)."""
    extensions = build_identity_extension(subject)
    _, payload_bytes, _, canonical_hash = build_event(
        ledger_scope=ledger_scope,
        sequence=sequence,
        prev_hash=prev_hash,
        authored_at=authored_at,
        event_type=EVENT_TYPE_IDENTITY,
        extensions=extensions,
        payload_marker=payload_marker,
        idempotency_key=idempotency_key,
    )
    signed = cose_sign1(seed, kid, payload_bytes)
    return signed, canonical_hash, payload_bytes


def build_uca_event(
    *,
    seed: bytes,
    kid: bytes,
    ledger_scope: bytes,
    sequence: int,
    prev_hash: bytes | None,
    authored_at: int,
    uca_payload: dict,
    payload_marker: bytes,
    idempotency_key: bytes,
) -> tuple[bytes, bytes, bytes]:
    """Returns (signed_cose_bytes, canonical_event_hash, payload_bytes)."""
    extensions = {EVENT_TYPE_UCA.decode("utf-8"): uca_payload}
    _, payload_bytes, _, canonical_hash = build_event(
        ledger_scope=ledger_scope,
        sequence=sequence,
        prev_hash=prev_hash,
        authored_at=authored_at,
        event_type=EVENT_TYPE_UCA,
        extensions=extensions,
        payload_marker=payload_marker,
        idempotency_key=idempotency_key,
    )
    signed = cose_sign1(seed, kid, payload_bytes)
    return signed, canonical_hash, payload_bytes


def write_manifest(
    out_dir: Path,
    *,
    vector_id: str,
    description: str,
    tamper_kind: str,
    tr_core: list[str],
    failing_event_id: str,
    structure_verified: bool = True,
    integrity_verified: bool = False,
    readability_verified: bool = True,
) -> None:
    tr_core_lines = ",\n    ".join(f'"{x}"' for x in tr_core)
    text = f'''id          = "tamper/{vector_id}"
op          = "tamper"
status      = "active"
description = """{description}"""

[coverage]
tr_core = [
    {tr_core_lines},
]

[inputs]
ledger               = "input-tampered-ledger.cbor"
tampered_event       = "input-tampered-event.cbor"
signing_key_registry = "input-signing-key-registry.cbor"

[expected.report]
structure_verified   = {str(structure_verified).lower()}
integrity_verified   = {str(integrity_verified).lower()}
readability_verified = {str(readability_verified).lower()}
tamper_kind          = "{tamper_kind}"
failing_event_id     = "{failing_event_id}"

[derivation]
document = "derivation.md"
'''
    write_text(out_dir, "manifest.toml", text)


# ---------------------------------------------------------------------------
# tamper/028 — signature under wrong domain tag.
# ---------------------------------------------------------------------------


def gen_tamper_028(*, seed: bytes, pub: bytes, kid: bytes) -> bytes:
    out_dir = ROOT / "tamper" / "028-uca-signature-invalid"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {out_dir.relative_to(ROOT.parent.parent)}/")

    scope = b"trellis-uca-tamper:028-sig-invalid"
    attestor = "urn:trellis:principal:applicant-028"
    attestation_id = "urn:trellis:user-content-attestation:tamper:028"
    signing_intent = "urn:wos:signature-intent:applicant-affirmation"

    # Chain layout: [identity(0), host(1), uca(2)].
    # Per ADR 0010 §"Verifier obligations" step 4 temporal precedence:
    # identity.sequence < attested_event_position (host's sequence).
    # 0 < 1 → step 4 passes. Identity FIRST, host SECOND, attestation LAST.
    identity_signed, identity_hash, _ = build_identity_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=0, prev_hash=None,
        authored_at=HOST_AUTHORED_AT, subject=attestor,
        payload_marker=b"identity-event-028",
        idempotency_key=b"idemp-028-identity",
    )
    host_signed, host_hash, _ = build_host_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=1, prev_hash=identity_hash,
        authored_at=HOST_AUTHORED_AT,
        payload_marker=b"host-event-028", idempotency_key=b"idemp-028-host",
    )

    # Event 2: user-content-attestation. Signature computed under the
    # WRONG domain tag (`trellis-transition-attestation-v1`) so step 5
    # signature verification fails. Steps 3 / 4 / 6 pass: chain-position
    # resolves (host at seq 1), identity resolves (identity at seq 0,
    # subject matches, sequence 0 < attested_event_position 1), signing
    # key is Active in registry.
    bad_signature = build_uca_signature(
        signing_seed=seed, attestation_id=attestation_id,
        attested_event_hash=host_hash, attested_event_position=1,
        attestor=attestor, identity_attestation_ref=identity_hash,
        signing_intent=signing_intent, attested_at=HOST_AUTHORED_AT,
        domain_tag=TAG_TRELLIS_TRANSITION_ATTESTATION_V1,  # ← WRONG TAG
    )
    uca_payload = build_uca_payload(
        attestation_id=attestation_id, attested_event_hash=host_hash,
        attested_event_position=1, attestor=attestor,
        identity_attestation_ref=identity_hash,
        signing_intent=signing_intent, attested_at=HOST_AUTHORED_AT,
        signature=bad_signature, signing_kid=kid,
    )
    uca_signed, uca_hash, _ = build_uca_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=2,
        prev_hash=host_hash, authored_at=HOST_AUTHORED_AT,
        uca_payload=uca_payload, payload_marker=b"uca-event-028",
        idempotency_key=b"idemp-028-uca",
    )

    ledger = dcbor([cbor2.loads(identity_signed), cbor2.loads(host_signed), cbor2.loads(uca_signed)])
    write_bytes(out_dir, "input-tampered-ledger.cbor", ledger)
    write_bytes(out_dir, "input-signing-key-registry.cbor",
                build_signing_key_registry(kid, pub, status=0))
    write_bytes(out_dir, "input-tampered-event.cbor", uca_signed)

    write_manifest(
        out_dir, vector_id="028-uca-signature-invalid",
        description=(
            "ADR 0010 §\"Verifier obligations\" step 5 violation: "
            "`UserContentAttestationPayload.signature` computed under "
            "`trellis-transition-attestation-v1` (the operator-actor "
            "posture-transition tag) instead of "
            "`trellis-user-content-attestation-v1`. The cross-family "
            "domain-separation rule rejects the signature; verifier "
            "emits `user_content_attestation_signature_invalid`. "
            "3-event chain: [host(seq 0), identity(seq 1), uca(seq 2)]; "
            "steps 3 / 4 / 6 pass, step 5 fails."
        ),
        tamper_kind="user_content_attestation_signature_invalid",
        tr_core=["TR-CORE-018", "TR-CORE-030", "TR-CORE-035",
                 "TR-CORE-152", "TR-CORE-155"],
        failing_event_id=uca_hash.hex(),
    )
    write_text(out_dir, "derivation.md", f"""# Derivation — `tamper/028-uca-signature-invalid`

3-event chain on `ledger_scope = {scope!r}`:

* seq 0: identity-attestation event whose payload `extensions.\"{EVENT_TYPE_IDENTITY.decode()}\".subject` equals `\"{attestor}\"`
* seq 1: host event (event_type `trellis.test.host-event.v1`)
* seq 2: user-content-attestation event whose `attested_event_hash`
  resolves to seq 1 (the host), `identity_attestation_ref` resolves to
  seq 0 (the identity event). Step 4 temporal precedence: identity
  sequence 0 < attested_event_position 1 — passes.

Per ADR 0010 §\"Verifier obligations\" step 5, the signature on
`UserContentAttestationPayload.signature` MUST be computed under domain
tag `trellis-user-content-attestation-v1` (Core §9.8). This vector
computes the signature under `trellis-transition-attestation-v1`
(Companion §A.5's operator-actor posture-transition tag). The Phase-1
verifier flips `signature_verified = false` and emits
`user_content_attestation_signature_invalid` with `failing_event_id`
= `{uca_hash.hex()}`.

Adversary intent: cross-family signature confusion — present an A.5
Attestation byte slug as a user-content attestation, hoping the verifier
admits the byte shape. The domain-separation tag is what blocks this.

Generator: `_generator/gen_tamper_028_to_034.py`.
""")
    return uca_hash


# ---------------------------------------------------------------------------
# tamper/029 — chain-position mismatch.
# ---------------------------------------------------------------------------


def gen_tamper_029(*, seed: bytes, pub: bytes, kid: bytes) -> bytes:
    out_dir = ROOT / "tamper" / "029-uca-chain-position-mismatch"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {out_dir.relative_to(ROOT.parent.parent)}/")

    scope = b"trellis-uca-tamper:029-chain-pos"
    attestor = "urn:trellis:principal:applicant-029"
    attestation_id = "urn:trellis:user-content-attestation:tamper:029"
    signing_intent = "urn:wos:signature-intent:applicant-affirmation"

    # Chain layout: [identity(0), host(1), uca(2)] per ADR 0010 step 4
    # temporal precedence (identity seq < attested_event_position).
    identity_signed, identity_hash, _ = build_identity_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=0, prev_hash=None,
        authored_at=HOST_AUTHORED_AT, subject=attestor,
        payload_marker=b"identity-event-029",
        idempotency_key=b"idemp-029-identity",
    )
    host_signed, host_hash, _ = build_host_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=1, prev_hash=identity_hash,
        authored_at=HOST_AUTHORED_AT,
        payload_marker=b"host-event-029", idempotency_key=b"idemp-029-host",
    )

    # Mutation: `attested_event_hash` is a wrong digest (not the host's
    # canonical hash). `attested_event_position = 1` resolves to the host
    # event, but the hash disagreement triggers
    # `user_content_attestation_chain_position_mismatch`.
    wrong_hash = hashlib.sha256(b"wrong-host-event-hash-029").digest()
    sig = build_uca_signature(
        signing_seed=seed, attestation_id=attestation_id,
        attested_event_hash=wrong_hash, attested_event_position=1,
        attestor=attestor, identity_attestation_ref=identity_hash,
        signing_intent=signing_intent, attested_at=HOST_AUTHORED_AT,
    )
    uca_payload = build_uca_payload(
        attestation_id=attestation_id, attested_event_hash=wrong_hash,
        attested_event_position=1, attestor=attestor,
        identity_attestation_ref=identity_hash,
        signing_intent=signing_intent, attested_at=HOST_AUTHORED_AT,
        signature=sig, signing_kid=kid,
    )
    uca_signed, uca_hash, _ = build_uca_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=2,
        prev_hash=host_hash, authored_at=HOST_AUTHORED_AT,
        uca_payload=uca_payload, payload_marker=b"uca-event-029",
        idempotency_key=b"idemp-029-uca",
    )

    ledger = dcbor([cbor2.loads(identity_signed), cbor2.loads(host_signed), cbor2.loads(uca_signed)])
    write_bytes(out_dir, "input-tampered-ledger.cbor", ledger)
    write_bytes(out_dir, "input-signing-key-registry.cbor",
                build_signing_key_registry(kid, pub, status=0))
    write_bytes(out_dir, "input-tampered-event.cbor", uca_signed)

    write_manifest(
        out_dir, vector_id="029-uca-chain-position-mismatch",
        description=(
            "ADR 0010 §\"Verifier obligations\" step 3 violation: "
            "`attested_event_position = 0` resolves to a chain-present "
            "event whose `canonical_event_hash` does not equal the "
            "attestation's `attested_event_hash` field. The verifier "
            "flips `chain_position_resolved = false` and emits "
            "`user_content_attestation_chain_position_mismatch`. Adversary "
            "intent: sign a hash without committing to its sequence "
            "(ADR 0010 §\"Adversary model\" wrong-position case)."
        ),
        tamper_kind="user_content_attestation_chain_position_mismatch",
        tr_core=["TR-CORE-018", "TR-CORE-030", "TR-CORE-035",
                 "TR-CORE-152", "TR-CORE-153"],
        failing_event_id=uca_hash.hex(),
    )
    write_text(out_dir, "derivation.md", f"""# Derivation — `tamper/029-uca-chain-position-mismatch`

3-event chain on `ledger_scope = {scope!r}`:

* seq 0: identity-attestation event resolving `\"{attestor}\"`
* seq 1: host event with `canonical_event_hash` = `{host_hash.hex()}`
* seq 2: user-content-attestation event with `attested_event_position = 1`
  but `attested_event_hash` set to `{wrong_hash.hex()}` (≠ host's actual hash).

Per ADR 0010 §\"Verifier obligations\" step 3, the verifier MUST resolve
`attested_event_position` to a chain-present event in scope and confirm
its `canonical_event_hash` equals `attested_event_hash`. This vector's
disagreement flips `chain_position_resolved = false` and emits
`user_content_attestation_chain_position_mismatch` with `failing_event_id`
= `{uca_hash.hex()}`.

Generator: `_generator/gen_tamper_028_to_034.py`.
""")
    return uca_hash


# ---------------------------------------------------------------------------
# tamper/030 — identity unresolved.
# ---------------------------------------------------------------------------


def gen_tamper_030(*, seed: bytes, pub: bytes, kid: bytes) -> bytes:
    out_dir = ROOT / "tamper" / "030-uca-identity-unresolved"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {out_dir.relative_to(ROOT.parent.parent)}/")

    scope = b"trellis-uca-tamper:030-no-identity"
    attestor = "urn:trellis:principal:applicant-030"
    attestation_id = "urn:trellis:user-content-attestation:tamper:030"
    signing_intent = "urn:wos:signature-intent:applicant-affirmation"

    host_signed, host_hash, _ = build_host_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=0, prev_hash=None,
        authored_at=HOST_AUTHORED_AT,
        payload_marker=b"host-event-030", idempotency_key=b"idemp-030-host",
    )

    # Mutation: `identity_attestation_ref` is a digest that does NOT
    # resolve to any chain-present event. No identity event in chain.
    phantom_identity = hashlib.sha256(b"phantom-identity-030").digest()

    sig = build_uca_signature(
        signing_seed=seed, attestation_id=attestation_id,
        attested_event_hash=host_hash, attested_event_position=0,
        attestor=attestor, identity_attestation_ref=phantom_identity,
        signing_intent=signing_intent, attested_at=HOST_AUTHORED_AT,
    )
    uca_payload = build_uca_payload(
        attestation_id=attestation_id, attested_event_hash=host_hash,
        attested_event_position=0, attestor=attestor,
        identity_attestation_ref=phantom_identity,
        signing_intent=signing_intent, attested_at=HOST_AUTHORED_AT,
        signature=sig, signing_kid=kid,
    )
    uca_signed, uca_hash, _ = build_uca_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=1,
        prev_hash=host_hash, authored_at=HOST_AUTHORED_AT,
        uca_payload=uca_payload, payload_marker=b"uca-event-030",
        idempotency_key=b"idemp-030-uca",
    )

    ledger = dcbor([cbor2.loads(host_signed), cbor2.loads(uca_signed)])
    write_bytes(out_dir, "input-tampered-ledger.cbor", ledger)
    write_bytes(out_dir, "input-signing-key-registry.cbor",
                build_signing_key_registry(kid, pub, status=0))
    write_bytes(out_dir, "input-tampered-event.cbor", uca_signed)

    write_manifest(
        out_dir, vector_id="030-uca-identity-unresolved",
        description=(
            "ADR 0010 §\"Verifier obligations\" step 4 violation: "
            "`identity_attestation_ref` digest does not resolve to any "
            "chain-present event. No identity-attestation event present "
            "in the chain. Verifier flips `identity_resolved = false` "
            "and emits `user_content_attestation_identity_unresolved`. "
            "Adversary intent: claim identity proof without the proof "
            "actually being on-chain (the ADR §\"Adversary model\" "
            "detached identity claim case)."
        ),
        tamper_kind="user_content_attestation_identity_unresolved",
        tr_core=["TR-CORE-018", "TR-CORE-030", "TR-CORE-035",
                 "TR-CORE-152", "TR-CORE-154"],
        failing_event_id=uca_hash.hex(),
    )
    write_text(out_dir, "derivation.md", f"""# Derivation — `tamper/030-uca-identity-unresolved`

2-event chain on `ledger_scope = {scope!r}`:

* seq 0: host event
* seq 1: user-content-attestation event with `identity_attestation_ref` =
  `{phantom_identity.hex()}` (a digest that does NOT resolve to any
  chain-present event).

Per ADR 0010 §\"Verifier obligations\" step 4, when `identity_attestation_ref`
is non-null the verifier MUST resolve it to a chain-present event of a
registered identity-attestation event type. Failure to resolve flips
`identity_resolved = false` and emits
`user_content_attestation_identity_unresolved` with `failing_event_id` =
the **identity_attestation_ref** digest (the unresolvable target), per
verifier convention for the location-of-failure field.

The default-required posture is in force (no Posture Declaration shipped
with this tamper, so `admit_unverified_user_attestations` defaults to
`false`).

Generator: `_generator/gen_tamper_028_to_034.py`.
""")
    # Note: the `failing_event_id` field in the manifest references the
    # identity digest (where the verifier's location-of-failure points)
    # rather than the UCA event's canonical hash. Adjust the manifest
    # accordingly.
    write_manifest(
        out_dir, vector_id="030-uca-identity-unresolved",
        description=(
            "ADR 0010 §\"Verifier obligations\" step 4 violation: "
            "`identity_attestation_ref` digest does not resolve to any "
            "chain-present event. No identity-attestation event present "
            "in the chain. Verifier flips `identity_resolved = false` "
            "and emits `user_content_attestation_identity_unresolved` "
            "with location pointing at the unresolvable digest. Adversary "
            "intent: claim identity proof without the proof actually "
            "being on-chain (ADR 0010 §\"Adversary model\" detached "
            "identity claim case)."
        ),
        tamper_kind="user_content_attestation_identity_unresolved",
        tr_core=["TR-CORE-018", "TR-CORE-030", "TR-CORE-035",
                 "TR-CORE-152", "TR-CORE-154"],
        failing_event_id=phantom_identity.hex(),
    )
    return uca_hash


# ---------------------------------------------------------------------------
# tamper/031 — identity subject mismatch.
# ---------------------------------------------------------------------------


def gen_tamper_031(*, seed: bytes, pub: bytes, kid: bytes) -> bytes:
    out_dir = ROOT / "tamper" / "031-uca-identity-subject-mismatch"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {out_dir.relative_to(ROOT.parent.parent)}/")

    scope = b"trellis-uca-tamper:031-subj-mismatch"
    attestor = "urn:trellis:principal:applicant-031"
    other_subject = "urn:trellis:principal:somebody-else-031"
    attestation_id = "urn:trellis:user-content-attestation:tamper:031"
    signing_intent = "urn:wos:signature-intent:applicant-affirmation"

    # Chain layout: [identity(0), host(1), uca(2)] per ADR 0010 step 4
    # temporal precedence. Identity event is present, but its subject is
    # OTHER than the attestation's `attestor`.
    identity_signed, identity_hash, _ = build_identity_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=0, prev_hash=None,
        authored_at=HOST_AUTHORED_AT, subject=other_subject,  # ← MISMATCH
        payload_marker=b"identity-event-031",
        idempotency_key=b"idemp-031-identity",
    )
    host_signed, host_hash, _ = build_host_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=1, prev_hash=identity_hash,
        authored_at=HOST_AUTHORED_AT,
        payload_marker=b"host-event-031", idempotency_key=b"idemp-031-host",
    )
    sig = build_uca_signature(
        signing_seed=seed, attestation_id=attestation_id,
        attested_event_hash=host_hash, attested_event_position=1,
        attestor=attestor, identity_attestation_ref=identity_hash,
        signing_intent=signing_intent, attested_at=HOST_AUTHORED_AT,
    )
    uca_payload = build_uca_payload(
        attestation_id=attestation_id, attested_event_hash=host_hash,
        attested_event_position=1, attestor=attestor,
        identity_attestation_ref=identity_hash,
        signing_intent=signing_intent, attested_at=HOST_AUTHORED_AT,
        signature=sig, signing_kid=kid,
    )
    uca_signed, uca_hash, _ = build_uca_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=2,
        prev_hash=host_hash, authored_at=HOST_AUTHORED_AT,
        uca_payload=uca_payload, payload_marker=b"uca-event-031",
        idempotency_key=b"idemp-031-uca",
    )

    ledger = dcbor([cbor2.loads(identity_signed), cbor2.loads(host_signed), cbor2.loads(uca_signed)])
    write_bytes(out_dir, "input-tampered-ledger.cbor", ledger)
    write_bytes(out_dir, "input-signing-key-registry.cbor",
                build_signing_key_registry(kid, pub, status=0))
    write_bytes(out_dir, "input-tampered-event.cbor", uca_signed)

    write_manifest(
        out_dir, vector_id="031-uca-identity-subject-mismatch",
        description=(
            "ADR 0010 §\"Verifier obligations\" step 4 violation: "
            "resolved identity-attestation event's payload subject "
            f"(`{other_subject}`) does not equal the attestation's "
            f"`attestor` (`{attestor}`). Verifier flips "
            "`identity_resolved = false` and emits "
            "`user_content_attestation_identity_subject_mismatch`."
        ),
        tamper_kind="user_content_attestation_identity_subject_mismatch",
        tr_core=["TR-CORE-018", "TR-CORE-030", "TR-CORE-035",
                 "TR-CORE-152", "TR-CORE-154"],
        failing_event_id=identity_hash.hex(),  # location is the resolved-but-wrong-subject digest
    )
    write_text(out_dir, "derivation.md", f"""# Derivation — `tamper/031-uca-identity-subject-mismatch`

3-event chain on `ledger_scope = {scope!r}`:

* seq 0: identity-attestation event with `subject` = `\"{other_subject}\"`
* seq 1: host event
* seq 2: user-content-attestation event with `attestor` = `\"{attestor}\"`,
  `identity_attestation_ref` = seq 0's `canonical_event_hash`
  (`{identity_hash.hex()}`).

Per ADR 0010 §\"Verifier obligations\" step 4, the resolved identity-
attestation event's payload subject MUST equal `attestor`. This vector's
mismatch flips `identity_resolved = false` and emits
`user_content_attestation_identity_subject_mismatch` with location
pointing at the resolved-but-wrong-subject identity event hash.

Generator: `_generator/gen_tamper_028_to_034.py`.
""")
    return uca_hash


# ---------------------------------------------------------------------------
# tamper/032 — identity temporal inversion.
# ---------------------------------------------------------------------------


def gen_tamper_032(*, seed: bytes, pub: bytes, kid: bytes) -> bytes:
    out_dir = ROOT / "tamper" / "032-uca-identity-temporal-inversion"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {out_dir.relative_to(ROOT.parent.parent)}/")

    scope = b"trellis-uca-tamper:032-temporal"
    attestor = "urn:trellis:principal:applicant-032"
    attestation_id = "urn:trellis:user-content-attestation:tamper:032"
    signing_intent = "urn:wos:signature-intent:applicant-affirmation"

    # Chain layout: [host(seq 0), uca(seq 1), identity(seq 2)]. The
    # attestation references identity at seq 2, but identity sequence
    # (2) MUST be strictly less than `attested_event_position` (0). Since
    # 2 >= 0, step 4 flags `temporal_inversion`.
    host_signed, host_hash, _ = build_host_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=0, prev_hash=None,
        authored_at=HOST_AUTHORED_AT,
        payload_marker=b"host-event-032", idempotency_key=b"idemp-032-host",
    )

    # Pre-compute identity event's canonical hash so the attestation can
    # carry it. Identity event is at sequence 2 with a known prev_hash
    # (the attestation's canonical hash). To keep the chain linear,
    # we'll compute the attestation FIRST with a placeholder identity_ref,
    # then build the identity event referencing the attestation's hash.
    # That requires a two-pass build: build the UCA payload + canonical
    # hash without knowing identity yet (or with a deterministic
    # identity_ref the identity event will materialize), then verify
    # consistency. Cleanest approach: use the FUTURE identity event's
    # canonical hash by construction — predict it from a deterministic
    # identity-event author hash. Since the identity event's hash depends
    # on prev_hash (the UCA event's hash) and that depends on identity_ref
    # in extensions, this is a fixpoint problem.
    #
    # Resolution: pre-compute the identity event using the UCA's
    # eventually-canonical hash via a deterministic placeholder, then
    # author the UCA event with the identity hash, then re-author the
    # identity event with the actual UCA hash. The chain that lands has
    # the SAME identity_attestation_ref as the second identity event —
    # which means the first build is just a hash-prediction round.
    #
    # Simpler: relax `prev_hash` linkage by accepting that the verifier's
    # step 4 fires BEFORE chain integrity (step 4.h prev_hash check),
    # so we can break linkage on the identity event without confusing
    # the test's failure target. But step 4.h would surface as
    # `prev_hash_break` which would mask `temporal_inversion`.
    #
    # CORRECT resolution: build the identity event's hash by FIXED
    # IDENTITY (independent of UCA event prev). Use a fresh ledger-scope-
    # AND-sequence-2 identity with `prev_hash` = (TBD UCA hash).
    # We achieve this with iteration: predict, build, re-predict, until
    # stable. Since `build_event` is pure, two iterations suffice.

    # First pass: build UCA with a placeholder identity_ref (zeros).
    placeholder_identity_ref = b"\x00" * 32

    def build_uca(identity_ref: bytes, prev_hash: bytes) -> tuple[bytes, bytes]:
        sig = build_uca_signature(
            signing_seed=seed, attestation_id=attestation_id,
            attested_event_hash=host_hash, attested_event_position=0,
            attestor=attestor, identity_attestation_ref=identity_ref,
            signing_intent=signing_intent, attested_at=HOST_AUTHORED_AT,
        )
        uca_payload = build_uca_payload(
            attestation_id=attestation_id, attested_event_hash=host_hash,
            attested_event_position=0, attestor=attestor,
            identity_attestation_ref=identity_ref,
            signing_intent=signing_intent, attested_at=HOST_AUTHORED_AT,
            signature=sig, signing_kid=kid,
        )
        signed, h, _ = build_uca_event(
            seed=seed, kid=kid, ledger_scope=scope, sequence=1,
            prev_hash=prev_hash, authored_at=HOST_AUTHORED_AT,
            uca_payload=uca_payload, payload_marker=b"uca-event-032",
            idempotency_key=b"idemp-032-uca",
        )
        return signed, h

    def build_identity(prev_hash: bytes) -> tuple[bytes, bytes]:
        signed, h, _ = build_identity_event(
            seed=seed, kid=kid, ledger_scope=scope, sequence=2,
            prev_hash=prev_hash, authored_at=HOST_AUTHORED_AT,
            subject=attestor, payload_marker=b"identity-event-032",
            idempotency_key=b"idemp-032-identity",
        )
        return signed, h

    # Pass 1: predict identity hash by building it with a placeholder
    # prev. Then build UCA with that predicted identity hash. Then
    # rebuild identity with the real prev = UCA hash. Then rebuild UCA
    # with the rebuilt identity hash. Iterate until both hashes are
    # consistent. Practical fix: build identity FIRST with a stable
    # prev_hash (host_hash; we'll relax sequence — actually no, the
    # chain order is fixed: identity at sequence 2 means its prev MUST
    # be UCA at sequence 1).
    #
    # Pragmatic compromise: this fixpoint converges in one iteration if
    # we use a stable predicted identity hash. The trick: compute the
    # identity event with a CONSTANT sentinel prev_hash, get its
    # canonical_event_hash; use that as identity_ref in the UCA; build
    # the UCA with prev=host_hash; the UCA's canonical hash is X; rebuild
    # the identity with prev=X; the identity's canonical hash is Y.
    # In the wire-bytes ledger, identity event reflects prev=X (correct
    # chain linkage) but its canonical hash is Y, NOT the predicted
    # value the UCA references. The UCA references the predicted value,
    # which doesn't exist on the chain → `identity_unresolved` not
    # `temporal_inversion`.
    #
    # Resolution: we need the chain to contain the EXACT identity event
    # whose hash the UCA references. Approach: use a CONSTANT prev_hash
    # value (like host_hash) for the identity event, accept that the
    # chain has a `prev_hash_break` AT seq 2 (identity's prev disagrees
    # with the actual seq-1 UCA hash), and rely on the verifier's step
    # ordering: prev_hash_break vs temporal_inversion run in different
    # passes (chain integrity step 4.h vs ADR 0010 step 4). Since
    # event_failures aggregate, multiple kinds will appear; the
    # `tamper_kind` is the FIRST failure, which depends on event order.
    #
    # CLEANER APPROACH: ABANDON strict chain linkage for tamper/032 and
    # accept that the resulting `tamper_kind` will be the dominant
    # failure picked by `_first_failure`. We structure the chain so
    # the per-event UCA decode + step 4 finalize fire BEFORE the chain
    # integrity step. Since `verify_event_set_with_classes` walks events
    # in order, runs decode + collects user-content-attestation payloads,
    # then runs the cross-event finalize loop, then merges event_failures,
    # the first event to fail dominates `_first_failure`. The UCA event
    # is at seq 1; the chain check on the identity at seq 2 fires AFTER.
    # So as long as the UCA-related failure (temporal_inversion) lands
    # BEFORE the identity event's prev_hash_break at seq 2, we're fine.
    #
    # The verifier's loop appends event_failures in event-iteration
    # order. UCA failures are emitted by the FINALIZE pass (post-loop),
    # while prev_hash failures are emitted in-loop. So in-loop failures
    # come first; the prev_hash_break would dominate.
    #
    # FINAL SIMPLE FIX: skip the identity event entirely from the
    # tampered ledger. Instead, manufacture a fake identity hash that
    # collides with a chain-present event whose `event_type` IS the
    # identity-attestation type AND whose sequence ≥ attested_event_position.
    # We can place the identity event at seq 2 and the UCA at seq 1
    # AS LONG AS we drop chain linkage. Or we order them as
    # [identity(seq 0), uca(seq 1), host(seq 2)] — host is at seq 2 so
    # `attested_event_position = 2`, identity is at seq 0, identity
    # sequence (0) IS strictly less than 2 ... wait that PASSES the
    # temporal precedence check. We need the OPPOSITE: identity sequence
    # >= attested_event_position. So `attested_event_position` must be
    # SMALLER than the identity's sequence.
    #
    # PROPER LAYOUT: [identity(seq 0), uca(seq 1)] but
    # `attested_event_position = 0` referencing... wait, what does the
    # UCA attest? It must attest to a chain-present event. If the only
    # chain events are identity(seq 0) and uca(seq 1), then
    # `attested_event_position = 0` resolves to the identity event
    # (which is wrong — the attestation should reference a host event,
    # not an identity event). The verifier wouldn't reject that
    # specifically because step 3 only checks position+hash agreement,
    # not host event_type — so identity-as-host is admitted at step 3.
    # Then step 4 needs the identity_ref (a separate digest) to resolve
    # to the SAME identity event at seq 0, with sequence (0) ≥
    # attested_event_position (0). 0 >= 0 trips `temporal_inversion`!
    #
    # That's the working construction. Layout: [identity(seq 0),
    # uca(seq 1)]. UCA attests to identity-as-host (position 0,
    # canonical_event_hash = identity_hash) AND identity_attestation_ref
    # = identity_hash. Step 3 passes (position 0 resolves to identity,
    # hash matches). Step 4 fails (identity sequence 0 NOT < attested_
    # event_position 0).
    #
    # This works. Let me implement.
    pass

    # Layout: [identity(seq 0), uca(seq 1)]. UCA references identity AS
    # the host event (attested_event_hash = identity's canonical hash;
    # attested_event_position = 0) AND as the identity reference. Step
    # 3 passes (hash + position consistent). Step 4 fails because
    # identity sequence (0) is NOT strictly less than
    # attested_event_position (0).
    identity_signed, identity_hash, _ = build_identity_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=0, prev_hash=None,
        authored_at=HOST_AUTHORED_AT, subject=attestor,
        payload_marker=b"identity-event-032",
        idempotency_key=b"idemp-032-identity",
    )
    sig = build_uca_signature(
        signing_seed=seed, attestation_id=attestation_id,
        attested_event_hash=identity_hash, attested_event_position=0,
        attestor=attestor, identity_attestation_ref=identity_hash,
        signing_intent=signing_intent, attested_at=HOST_AUTHORED_AT,
    )
    uca_payload = build_uca_payload(
        attestation_id=attestation_id, attested_event_hash=identity_hash,
        attested_event_position=0, attestor=attestor,
        identity_attestation_ref=identity_hash,
        signing_intent=signing_intent, attested_at=HOST_AUTHORED_AT,
        signature=sig, signing_kid=kid,
    )
    uca_signed, uca_hash, _ = build_uca_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=1,
        prev_hash=identity_hash, authored_at=HOST_AUTHORED_AT,
        uca_payload=uca_payload, payload_marker=b"uca-event-032",
        idempotency_key=b"idemp-032-uca",
    )

    ledger = dcbor([cbor2.loads(identity_signed), cbor2.loads(uca_signed)])
    write_bytes(out_dir, "input-tampered-ledger.cbor", ledger)
    write_bytes(out_dir, "input-signing-key-registry.cbor",
                build_signing_key_registry(kid, pub, status=0))
    write_bytes(out_dir, "input-tampered-event.cbor", uca_signed)

    write_manifest(
        out_dir, vector_id="032-uca-identity-temporal-inversion",
        description=(
            "ADR 0010 §\"Verifier obligations\" step 4 violation: "
            "resolved identity-attestation event's `sequence` is not "
            "strictly less than `attested_event_position`. Identity at "
            "seq 0; attested_event_position = 0; 0 ≥ 0. Verifier flips "
            "`identity_resolved = false` and emits "
            "`user_content_attestation_identity_temporal_inversion`. "
            "Adversary intent: establish identity AFTER the attestation "
            "the identity allegedly justifies."
        ),
        tamper_kind="user_content_attestation_identity_temporal_inversion",
        tr_core=["TR-CORE-018", "TR-CORE-030", "TR-CORE-035",
                 "TR-CORE-152", "TR-CORE-154"],
        failing_event_id=identity_hash.hex(),  # location is the temporal-inverted identity event
    )
    write_text(out_dir, "derivation.md", f"""# Derivation — `tamper/032-uca-identity-temporal-inversion`

2-event chain on `ledger_scope = {scope!r}`:

* seq 0: identity-attestation event with `subject` = `\"{attestor}\"`,
  `canonical_event_hash` = `{identity_hash.hex()}`.
* seq 1: user-content-attestation event with
  `attested_event_position = 0`, `attested_event_hash` = identity event's
  canonical hash, `identity_attestation_ref` = same digest.

Per ADR 0010 §\"Verifier obligations\" step 4, the resolved identity-
attestation event's `sequence` MUST be strictly less than
`attested_event_position` (identity proof temporally precedes the
attestation). Here both are 0, so the inequality `0 < 0` fails. Verifier
flips `identity_resolved = false` and emits
`user_content_attestation_identity_temporal_inversion`.

The construction collapses the host event and identity event into one
event for compactness — the attestation references identity-as-host at
position 0 AND as identity_ref. Step 3 (position+hash agreement) passes;
step 4 (temporal precedence) fails. Real deployments would have a
separate host event; the temporal-inversion class still applies whenever
identity event sequence ≥ attested_event_position.

Generator: `_generator/gen_tamper_028_to_034.py`.
""")
    return uca_hash


# ---------------------------------------------------------------------------
# tamper/033 — intent malformed.
# ---------------------------------------------------------------------------


def gen_tamper_033(*, seed: bytes, pub: bytes, kid: bytes) -> bytes:
    out_dir = ROOT / "tamper" / "033-uca-intent-malformed"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {out_dir.relative_to(ROOT.parent.parent)}/")

    scope = b"trellis-uca-tamper:033-bad-intent"
    attestor = "urn:trellis:principal:applicant-033"
    attestation_id = "urn:trellis:user-content-attestation:tamper:033"
    bad_signing_intent = "not-a-uri-just-some-string"

    # Chain layout: [identity(0), host(1), uca(2)].
    identity_signed, identity_hash, _ = build_identity_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=0, prev_hash=None,
        authored_at=HOST_AUTHORED_AT, subject=attestor,
        payload_marker=b"identity-event-033",
        idempotency_key=b"idemp-033-identity",
    )
    host_signed, host_hash, _ = build_host_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=1, prev_hash=identity_hash,
        authored_at=HOST_AUTHORED_AT,
        payload_marker=b"host-event-033", idempotency_key=b"idemp-033-host",
    )
    sig = build_uca_signature(
        signing_seed=seed, attestation_id=attestation_id,
        attested_event_hash=host_hash, attested_event_position=1,
        attestor=attestor, identity_attestation_ref=identity_hash,
        signing_intent=bad_signing_intent, attested_at=HOST_AUTHORED_AT,
    )
    uca_payload = build_uca_payload(
        attestation_id=attestation_id, attested_event_hash=host_hash,
        attested_event_position=1, attestor=attestor,
        identity_attestation_ref=identity_hash,
        signing_intent=bad_signing_intent, attested_at=HOST_AUTHORED_AT,
        signature=sig, signing_kid=kid,
    )
    uca_signed, uca_hash, _ = build_uca_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=2,
        prev_hash=host_hash, authored_at=HOST_AUTHORED_AT,
        uca_payload=uca_payload, payload_marker=b"uca-event-033",
        idempotency_key=b"idemp-033-uca",
    )

    ledger = dcbor([cbor2.loads(identity_signed), cbor2.loads(host_signed), cbor2.loads(uca_signed)])
    write_bytes(out_dir, "input-tampered-ledger.cbor", ledger)
    write_bytes(out_dir, "input-signing-key-registry.cbor",
                build_signing_key_registry(kid, pub, status=0))
    write_bytes(out_dir, "input-tampered-event.cbor", uca_signed)

    write_manifest(
        out_dir, vector_id="033-uca-intent-malformed",
        description=(
            f"ADR 0010 §\"Verifier obligations\" step 2 violation: "
            f"`signing_intent` (`{bad_signing_intent}`) is not a "
            "syntactically valid URI per RFC 3986 (no scheme separator). "
            "Step 2 is an intra-payload-invariant check (post-CDDL-decode); "
            "flips `integrity_verified = false` only — `structure_verified` "
            "and `readability_verified` stay true. Verifier emits "
            "`user_content_attestation_intent_malformed`. Adversary "
            "intent: smuggle a non-URI intent label into a slot a "
            "downstream WOS verifier might rely on for legal-effect "
            "classification."
        ),
        tamper_kind="user_content_attestation_intent_malformed",
        tr_core=["TR-CORE-018", "TR-CORE-030", "TR-CORE-035",
                 "TR-CORE-152", "TR-CORE-153"],
        failing_event_id=uca_hash.hex(),
    )
    write_text(out_dir, "derivation.md", f"""# Derivation — `tamper/033-uca-intent-malformed`

3-event chain on `ledger_scope = {scope!r}`:

* seq 0: identity-attestation event
* seq 1: host event
* seq 2: user-content-attestation event with `signing_intent` =
  `\"{bad_signing_intent}\"` (not a URI — no scheme separator).

Per ADR 0010 §\"Verifier obligations\" step 2, `signing_intent` MUST be
a syntactically valid URI per RFC 3986. The reference verifier's
`is_syntactically_valid_uri` rejects this string. Step 2 is an
intra-payload-invariant check (post-CDDL-decode), so the failure flips
`integrity_verified = false` only — `structure_verified` and
`readability_verified` stay `true`. The decoder records a deferred
`step_2_failure` marker on `UserContentAttestationDetails`;
`finalize_user_content_attestations` raises it as an `event_failure`
with kind `user_content_attestation_intent_malformed` and skips
remaining per-event checks for this attestation.

`failing_event_id` = `{uca_hash.hex()}` (the offending UCA event).

Generator: `_generator/gen_tamper_028_to_034.py`.
""")
    return uca_hash


# ---------------------------------------------------------------------------
# tamper/034 — key not Active.
# ---------------------------------------------------------------------------


def gen_tamper_034(*, seed: bytes, pub: bytes, kid: bytes) -> bytes:
    out_dir = ROOT / "tamper" / "034-uca-key-not-active"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\ngenerating {out_dir.relative_to(ROOT.parent.parent)}/")

    scope = b"trellis-uca-tamper:034-key-retired"
    attestor = "urn:trellis:principal:applicant-034"
    attestation_id = "urn:trellis:user-content-attestation:tamper:034"
    signing_intent = "urn:wos:signature-intent:applicant-affirmation"

    # Chain layout: [identity(0), host(1), uca(2)].
    identity_signed, identity_hash, _ = build_identity_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=0, prev_hash=None,
        authored_at=HOST_AUTHORED_AT, subject=attestor,
        payload_marker=b"identity-event-034",
        idempotency_key=b"idemp-034-identity",
    )
    host_signed, host_hash, _ = build_host_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=1, prev_hash=identity_hash,
        authored_at=HOST_AUTHORED_AT,
        payload_marker=b"host-event-034", idempotency_key=b"idemp-034-host",
    )
    sig = build_uca_signature(
        signing_seed=seed, attestation_id=attestation_id,
        attested_event_hash=host_hash, attested_event_position=1,
        attestor=attestor, identity_attestation_ref=identity_hash,
        signing_intent=signing_intent, attested_at=HOST_AUTHORED_AT,
    )
    uca_payload = build_uca_payload(
        attestation_id=attestation_id, attested_event_hash=host_hash,
        attested_event_position=1, attestor=attestor,
        identity_attestation_ref=identity_hash,
        signing_intent=signing_intent, attested_at=HOST_AUTHORED_AT,
        signature=sig, signing_kid=kid,
    )
    uca_signed, uca_hash, _ = build_uca_event(
        seed=seed, kid=kid, ledger_scope=scope, sequence=2,
        prev_hash=host_hash, authored_at=HOST_AUTHORED_AT,
        uca_payload=uca_payload, payload_marker=b"uca-event-034",
        idempotency_key=b"idemp-034-uca",
    )

    ledger = dcbor([cbor2.loads(identity_signed), cbor2.loads(host_signed), cbor2.loads(uca_signed)])
    write_bytes(out_dir, "input-tampered-ledger.cbor", ledger)

    # KEY MUTATION: register the kid with status=2 (Retired). Per ADR 0010
    # §"Verifier obligations" step 6, UCA admits `Active` and bounded
    # `Rotating` overlap only; `Retired` remains excluded from new
    # attestations.
    # NOTE: the ENVELOPE-signing path checks status==3 (Revoked) for the
    # COSE_Sign1 envelope; status=2 (Retired) is admitted at the envelope
    # layer (historical signature). The user-content-attestation step 6
    # is a STRICTER check that requires status==0. So the COSE envelope
    # verifies, but step 6 flags `key_not_active`.
    write_bytes(out_dir, "input-signing-key-registry.cbor",
                build_signing_key_registry(kid, pub, status=2))
    write_bytes(out_dir, "input-tampered-event.cbor", uca_signed)

    write_manifest(
        out_dir, vector_id="034-uca-key-not-active",
        description=(
            "ADR 0010 §\"Verifier obligations\" step 6 violation: "
            "`signing_kid` resolves to a registry entry with "
            "`status = 2` (Retired). User-content attestations admit "
            "`Active` keys and `Rotating` keys only inside the declared "
            "rotation-grace overlap; `Retired` remains excluded from new "
            "attestations. The COSE envelope verifies (envelope path admits "
            "Retired for historical signatures), but the step-6 user-"
            "content-attestation key-state check flips "
            "`key_active = false` and emits "
            "`user_content_attestation_key_not_active`. Adversary intent: "
            "issue an attestation under a Retired kid (key-state evasion)."
        ),
        tamper_kind="user_content_attestation_key_not_active",
        tr_core=["TR-CORE-018", "TR-CORE-030", "TR-CORE-035",
                 "TR-CORE-152", "TR-CORE-156"],
        failing_event_id=uca_hash.hex(),
    )
    write_text(out_dir, "derivation.md", f"""# Derivation — `tamper/034-uca-key-not-active`

3-event chain on `ledger_scope = {scope!r}`:

* seq 0: identity-attestation event
* seq 1: host event
* seq 2: user-content-attestation event signed under kid
  `{kid.hex()}` (registered with `status = 2` Retired per Core §28
  `SigningKeyStatus`).

Per ADR 0010 §\"Verifier obligations\" step 6, user-content attestations admit
`Active` keys and `Rotating` keys only inside the declared rotation-grace
overlap. `Retired` remains excluded from new attestations. The verifier flips
`key_active = false` and emits
`user_content_attestation_key_not_active` with `failing_event_id` =
`{uca_hash.hex()}`.

This is the first fixture corpus to exercise the SigningKeyStatus
distinction at the user-content-attestation step 6 surface — prior
fixtures use the COSE-envelope-only key-state path which only gates on
Revoked (status = 3).

Generator: `_generator/gen_tamper_028_to_034.py`.
""")
    return uca_hash


# ---------------------------------------------------------------------------
# Top-level main.
# ---------------------------------------------------------------------------


def main() -> None:
    seed, pub = load_cose_key(KEY_ISSUER)
    kid = derive_kid(SUITE_ID, pub)

    gen_tamper_028(seed=seed, pub=pub, kid=kid)
    gen_tamper_029(seed=seed, pub=pub, kid=kid)
    gen_tamper_030(seed=seed, pub=pub, kid=kid)
    gen_tamper_031(seed=seed, pub=pub, kid=kid)
    gen_tamper_032(seed=seed, pub=pub, kid=kid)
    gen_tamper_033(seed=seed, pub=pub, kid=kid)
    gen_tamper_034(seed=seed, pub=pub, kid=kid)


if __name__ == "__main__":
    main()
