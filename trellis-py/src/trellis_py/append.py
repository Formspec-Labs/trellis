"""Canonical append pipeline (append vectors, Core §6–§10, §17)."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trellis_py.codec import (
    domain_separated_sha256,
    encode_bstr,
    encode_cbor_negative_int,
    encode_cose_suite_id_label,
    encode_tstr,
    encode_uint,
    sig_structure_bytes,
)
from trellis_py.constants import (
    ARTIFACT_TYPE_EVENT,
    AUTHORED_LEDGER_EVENT_MAP_PREFIX,
    AUTHOR_EVENT_DOMAIN,
    CANONICAL_LEDGER_EVENT_MAP_PREFIX,
    COSE_LABEL_ALG,
    COSE_LABEL_ARTIFACT_TYPE,
    COSE_LABEL_KID,
    EVENT_DOMAIN,
    SUITE_ID_PHASE_1,
)


@dataclass(frozen=True)
class AppendArtifacts:
    author_event_hash: bytes
    canonical_event_hash: bytes
    protected_header: bytes
    sig_structure: bytes
    canonical_event: bytes
    signed_event: bytes
    append_head: bytes


class AppendError(Exception):
    pass


def _parse_ed25519_cose_key(raw: bytes) -> tuple[bytes, bytes]:
    import cbor2

    key = cbor2.loads(raw)
    if not isinstance(key, dict):
        raise AppendError("COSE_Key root is not a map")
    pub = key.get(-2)
    seed = key.get(-4)
    if not isinstance(pub, bytes) or len(pub) != 32:
        raise AppendError("invalid public key (-2)")
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise AppendError("invalid private seed (-4)")
    return pub, seed


def _parse_authored_event(raw: bytes) -> tuple[bytes, int]:
    import cbor2

    ev = cbor2.loads(raw)
    if not isinstance(ev, dict):
        raise AppendError("authored event root is not a map")
    scope = ev.get("ledger_scope")
    seq = ev.get("sequence")
    if not isinstance(scope, bytes):
        raise AppendError("missing ledger_scope")
    if not isinstance(seq, int) or seq < 0:
        raise AppendError("missing sequence")
    return scope, seq


def _derive_kid(suite_id: int, public_key: bytes) -> bytes:
    import hashlib

    h = hashlib.sha256()
    h.update(encode_uint(suite_id))
    h.update(public_key)
    return h.digest()[:16]


def protected_header_bytes(kid: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> bytes:
    b = bytearray()
    b.append(0xA4)
    b.extend(encode_uint(COSE_LABEL_ALG))
    b.extend(encode_cbor_negative_int(7))  # -8 EdDSA
    b.extend(encode_uint(COSE_LABEL_KID))
    b.extend(encode_bstr(kid))
    b.extend(encode_cose_suite_id_label())
    b.extend(encode_uint(SUITE_ID_PHASE_1))
    b.extend(encode_cbor_negative_int(-1 - COSE_LABEL_ARTIFACT_TYPE))
    b.extend(encode_tstr(artifact_type))
    return bytes(b)


def canonical_event_from_authored(authored_event: bytes, author_event_hash: bytes) -> bytes:
    if authored_event[0:1] != bytes([AUTHORED_LEDGER_EVENT_MAP_PREFIX]):
        raise AppendError("authored event does not start with expected 12-entry map prefix")
    out = bytearray()
    out.append(CANONICAL_LEDGER_EVENT_MAP_PREFIX)
    out.extend(authored_event[1:])
    out.extend(encode_tstr("author_event_hash"))
    out.extend(encode_bstr(author_event_hash))
    return bytes(out)


def canonical_event_hash_preimage(scope: bytes, canonical_event: bytes) -> bytes:
    b = bytearray()
    b.append(0xA3)
    b.extend(encode_tstr("version"))
    b.extend(encode_uint(1))
    b.extend(encode_tstr("ledger_scope"))
    b.extend(encode_bstr(scope))
    b.extend(encode_tstr("event_payload"))
    b.extend(canonical_event)
    return bytes(b)


def append_head_bytes(scope: bytes, sequence: int, canonical_event_hash: bytes) -> bytes:
    b = bytearray()
    b.append(0xA3)
    b.extend(encode_tstr("scope"))
    b.extend(encode_bstr(scope))
    b.extend(encode_tstr("sequence"))
    b.extend(encode_uint(sequence))
    b.extend(encode_tstr("canonical_event_hash"))
    b.extend(encode_bstr(canonical_event_hash))
    return bytes(b)


def sign1_bytes(protected_header: bytes, payload: bytes, signature: bytes) -> bytes:
    b = bytearray()
    b.append(0xD2)
    b.append(0x84)
    b.extend(encode_bstr(protected_header))
    b.append(0xA0)
    b.extend(encode_bstr(payload))
    b.extend(encode_bstr(signature))
    return bytes(b)


def append_event(signing_key_cose: bytes, authored_event: bytes) -> AppendArtifacts:
    scope, sequence = _parse_authored_event(authored_event)
    pub, seed = _parse_ed25519_cose_key(signing_key_cose)
    author_event_hash = domain_separated_sha256(AUTHOR_EVENT_DOMAIN, authored_event)
    canonical_event = canonical_event_from_authored(authored_event, author_event_hash)
    kid = _derive_kid(SUITE_ID_PHASE_1, pub)
    protected = protected_header_bytes(kid)
    sig_struct = sig_structure_bytes(protected, canonical_event)
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    signature = sk.sign(sig_struct)
    signed = sign1_bytes(protected, canonical_event, signature)
    preimage = canonical_event_hash_preimage(scope, canonical_event)
    canonical_event_hash = domain_separated_sha256(EVENT_DOMAIN, preimage)
    ahead = append_head_bytes(scope, sequence, canonical_event_hash)
    return AppendArtifacts(
        author_event_hash=author_event_hash,
        canonical_event_hash=canonical_event_hash,
        protected_header=protected,
        sig_structure=sig_struct,
        canonical_event=canonical_event,
        signed_event=signed,
        append_head=ahead,
    )
