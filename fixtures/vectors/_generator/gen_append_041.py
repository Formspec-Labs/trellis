"""Generate byte-exact reference vector `append/041-aead-retry-determinism`.

Authoring aid only. Core prose and committed vector bytes are normative.
This vector proves deterministic AEAD nonce derivation per Core §9.4:
  nonce = HKDF-SHA256(
      salt = dCBOR(idempotency_key),
      ikm  = SHA-256(plaintext_payload),
      info = "trellis-payload-nonce-v1",
      length = 12
  )
so a retry with the same idempotency_key and identical authored bytes
produces byte-identical ciphertext, content_hash, author_event_hash, and
canonical_event_hash. The payload is encrypted with ChaCha20-Poly1305
under a real 32-byte DEK; the DEK is wrapped via HPKE suite 1.
"""
from __future__ import annotations

import hashlib
import hmac
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cbor2  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import x25519  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from _lib.byte_utils import ts  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SIGNING_KEY_FILE = ROOT / "_keys" / "issuer-001.cose_key"
RECIPIENT_KEY_FILE = ROOT / "_keys" / "recipient-004-ledger-service.cose_key"
EPHEMERAL_KEY_FILE = ROOT / "_keys" / "ephemeral-041-recipient-001.cose_key"
PAYLOAD_FILE = ROOT / "_inputs" / "sample-payload-001.bin"
OUT_DIR = ROOT / "append" / "041-aead-retry-determinism"

LEDGER_SCOPE = b"test-response-ledger"
SEQUENCE = 0
TIMESTAMP = ts(1745000041)
EVENT_TYPE = b"x-trellis-test/aead-retry-determinism"
CLASSIFICATION = b"x-trellis-test/unclassified"
RETENTION_TIER = 0
IDEMPOTENCY_KEY = b"idemp-append-041"

PAYLOAD_DEK = bytes(range(32))
RECIPIENT_ID = b"ledger-service"
RECIPIENT_X25519_SEED = bytes.fromhex(
    "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
)
EPHEMERAL_X25519_SEED = bytes.fromhex(
    "7895fb033fbb83a8bdddf51bbfdd05591e4199598018b21800faa6a9ea793334"
)

SUITE_ID = 1
ALG_EDDSA = -8
COSE_LABEL_ALG = 1
COSE_LABEL_KID = 4
COSE_LABEL_SUITE_ID = -65537
COSE_LABEL_ARTIFACT_TYPE = -65538
ARTIFACT_TYPE_EVENT = "event"
ARTIFACT_TYPE_CHECKPOINT = "checkpoint"
ARTIFACT_TYPE_MANIFEST = "manifest"

TAG_TRELLIS_EVENT_V1 = "trellis-event-v1"
TAG_TRELLIS_AUTHOR_EVENT_V1 = "trellis-author-event-v1"
TAG_TRELLIS_CONTENT_V1 = "trellis-content-v1"

# deterministic nonce derivation constants (Core §9.4)
PAYLOAD_NONCE_INFO = b"trellis-payload-nonce-v1"
PAYLOAD_NONCE_LEN = 12

HPKE_VERSION_LABEL = b"HPKE-v1"
HPKE_KEM_ID_X25519_HKDF_SHA256 = (0x0020).to_bytes(2, "big")
HPKE_KDF_ID_HKDF_SHA256 = (0x0001).to_bytes(2, "big")
HPKE_AEAD_ID_CHACHA20POLY1305 = (0x0003).to_bytes(2, "big")
HPKE_KEM_SUITE_ID = b"KEM" + HPKE_KEM_ID_X25519_HKDF_SHA256
HPKE_SUITE_ID = (
    b"HPKE"
    + HPKE_KEM_ID_X25519_HKDF_SHA256
    + HPKE_KDF_ID_HKDF_SHA256
    + HPKE_AEAD_ID_CHACHA20POLY1305
)


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


def hkdf_extract(salt: bytes | None, ikm: bytes) -> bytes:
    if salt is None:
        salt = b"\x00" * hashlib.sha256().digest_size
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            prk,
            previous + info + bytes([counter]),
            hashlib.sha256,
        ).digest()
        output += previous
        counter += 1
    return output[:length]


def labeled_extract(suite_id: bytes, salt: bytes | None, label: bytes, ikm: bytes) -> bytes:
    return hkdf_extract(salt, HPKE_VERSION_LABEL + suite_id + label + ikm)


def labeled_expand(suite_id: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    labeled_info = length.to_bytes(2, "big") + HPKE_VERSION_LABEL + suite_id + label + info
    return hkdf_expand(prk, labeled_info, length)


def public_bytes(key: x25519.X25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def hpke_seal_base_x25519(
    recipient_pubkey: bytes,
    ephemeral_seed: bytes,
    plaintext: bytes,
) -> tuple[bytes, bytes]:
    """RFC 9180 Base mode for suite 1 with info=h'' and aad=h''."""
    ephemeral_private = x25519.X25519PrivateKey.from_private_bytes(ephemeral_seed)
    ephemeral_public = public_bytes(ephemeral_private.public_key())
    recipient_public = x25519.X25519PublicKey.from_public_bytes(recipient_pubkey)
    dh = ephemeral_private.exchange(recipient_public)

    kem_context = ephemeral_public + recipient_pubkey
    eae_prk = labeled_extract(HPKE_KEM_SUITE_ID, None, b"eae_prk", dh)
    shared_secret = labeled_expand(
        HPKE_KEM_SUITE_ID, eae_prk, b"shared_secret", kem_context, 32
    )

    psk_id_hash = labeled_extract(HPKE_SUITE_ID, None, b"psk_id_hash", b"")
    info_hash = labeled_extract(HPKE_SUITE_ID, None, b"info_hash", b"")
    key_schedule_context = b"\x00" + psk_id_hash + info_hash
    secret = labeled_extract(HPKE_SUITE_ID, shared_secret, b"secret", b"")
    key = labeled_expand(HPKE_SUITE_ID, secret, b"key", key_schedule_context, 32)
    base_nonce = labeled_expand(
        HPKE_SUITE_ID, secret, b"base_nonce", key_schedule_context, 12
    )
    ciphertext = ChaCha20Poly1305(key).encrypt(base_nonce, plaintext, b"")
    return ephemeral_public, ciphertext


def derive_payload_nonce(idempotency_key: bytes, plaintext_payload: bytes) -> bytes:
    """Core §9.4 deterministic nonce derivation.
    salt = dCBOR(idempotency_key)
    ikm  = SHA-256(plaintext_payload)
    info = "trellis-payload-nonce-v1"
    """
    salt = dcbor(idempotency_key)
    ikm = hashlib.sha256(plaintext_payload).digest()
    okm = hkdf_expand(
        hkdf_extract(salt, ikm),
        PAYLOAD_NONCE_INFO,
        PAYLOAD_NONCE_LEN,
    )
    return okm


def load_signing_key() -> tuple[bytes, bytes]:
    cose_key = cbor2.loads(SIGNING_KEY_FILE.read_bytes())
    return cose_key[-4], cose_key[-2]


def write_x25519_cose_key(path: Path, seed: bytes) -> bytes:
    private = x25519.X25519PrivateKey.from_private_bytes(seed)
    pubkey = public_bytes(private.public_key())
    cose_key = {
        1: 1,      # kty: OKP
        -1: 4,    # crv: X25519
        -2: pubkey,
        -4: seed,
    }
    path.write_bytes(dcbor(cose_key))
    return pubkey


def derive_kid(suite_id: int, pubkey_raw: bytes) -> bytes:
    return hashlib.sha256(dcbor(suite_id) + pubkey_raw).digest()[:16]


def build_event_header() -> dict:
    return {
        "event_type": EVENT_TYPE,
        "authored_at": TIMESTAMP,
        "retention_tier": RETENTION_TIER,
        "classification": CLASSIFICATION,
        "outcome_commitment": None,
        "subject_ref_commitment": None,
        "tag_commitment": None,
        "witness_ref": None,
        "extensions": None,
    }


def build_payload_ref(ciphertext: bytes, nonce: bytes) -> dict:
    return {
        "ref_type": "inline",
        "ciphertext": ciphertext,
        "nonce": nonce,
    }


def build_key_bag(ephemeral_pubkey: bytes, wrapped_dek: bytes) -> dict:
    return {
        "entries": [
            {
                "recipient": RECIPIENT_ID,
                "suite": 1,
                "ephemeral_pubkey": ephemeral_pubkey,
                "wrapped_dek": wrapped_dek,
            }
        ]
    }


def build_author_event_hash_preimage(
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
) -> dict:
    return {
        "version": 1,
        "ledger_scope": LEDGER_SCOPE,
        "sequence": SEQUENCE,
        "prev_hash": None,
        "causal_deps": None,
        "content_hash": content_hash,
        "header": header,
        "commitments": None,
        "payload_ref": payload_ref,
        "key_bag": key_bag,
        "idempotency_key": IDEMPOTENCY_KEY,
        "extensions": None,
    }


def build_event_payload(
    author_event_hash: bytes,
    content_hash: bytes,
    header: dict,
    payload_ref: dict,
    key_bag: dict,
) -> dict:
    return {
        "version": 1,
        "ledger_scope": LEDGER_SCOPE,
        "sequence": SEQUENCE,
        "prev_hash": None,
        "causal_deps": None,
        "author_event_hash": author_event_hash,
        "content_hash": content_hash,
        "header": header,
        "commitments": None,
        "payload_ref": payload_ref,
        "key_bag": key_bag,
        "idempotency_key": IDEMPOTENCY_KEY,
        "extensions": None,
    }


def build_canonical_event_hash_preimage(event_payload: dict) -> dict:
    return {
        "version": 1,
        "ledger_scope": LEDGER_SCOPE,
        "event_payload": event_payload,
    }


def build_protected_header(kid: bytes, artifact_type: str = ARTIFACT_TYPE_EVENT) -> dict:
    return {
        COSE_LABEL_ALG: ALG_EDDSA,
        COSE_LABEL_KID: kid,
        COSE_LABEL_SUITE_ID: SUITE_ID, COSE_LABEL_ARTIFACT_TYPE: artifact_type,
    }


def build_sig_structure(protected_bstr: bytes, payload_bstr: bytes) -> bytes:
    return dcbor(["Signature1", protected_bstr, b"", payload_bstr])


def build_append_head(scope: bytes, sequence: int, canonical_event_hash: bytes) -> dict:
    return {
        "scope": scope,
        "sequence": sequence,
        "canonical_event_hash": canonical_event_hash,
    }


def write_bytes(name: str, data: bytes) -> None:
    path = OUT_DIR / name
    path.write_bytes(data)
    print(f"  {name:45s}  {len(data):>5d} bytes  sha256={hashlib.sha256(data).hexdigest()}")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"generating vector at {OUT_DIR.relative_to(ROOT.parent.parent)}/")

    seed, signing_pubkey = load_signing_key()
    kid = derive_kid(SUITE_ID, signing_pubkey)

    recipient_pubkey = write_x25519_cose_key(
        RECIPIENT_KEY_FILE, RECIPIENT_X25519_SEED
    )
    ephemeral_pubkey = write_x25519_cose_key(
        EPHEMERAL_KEY_FILE, EPHEMERAL_X25519_SEED
    )
    hpke_ephemeral_pubkey, wrapped_dek = hpke_seal_base_x25519(
        recipient_pubkey, EPHEMERAL_X25519_SEED, PAYLOAD_DEK
    )
    assert hpke_ephemeral_pubkey == ephemeral_pubkey

    plaintext = PAYLOAD_FILE.read_bytes()

    # Step 1: derive deterministic nonce from plaintext + idempotency_key
    payload_nonce = derive_payload_nonce(IDEMPOTENCY_KEY, plaintext)

    # Step 2: encrypt payload with deterministic nonce
    ciphertext = ChaCha20Poly1305(PAYLOAD_DEK).encrypt(payload_nonce, plaintext, b"")

    # Step 3: build authored map with real ciphertext and real nonce
    content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, ciphertext)
    header = build_event_header()
    payload_ref = build_payload_ref(ciphertext, payload_nonce)
    key_bag = build_key_bag(ephemeral_pubkey, wrapped_dek)
    authored_map = build_author_event_hash_preimage(
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
    )
    authored_bytes = dcbor(authored_map)
    write_bytes("input-author-event-hash-preimage.cbor", authored_bytes)

    author_event_preimage = domain_separated_preimage(
        TAG_TRELLIS_AUTHOR_EVENT_V1, authored_bytes,
    )
    write_bytes("author-event-preimage.bin", author_event_preimage)
    author_event_hash = hashlib.sha256(author_event_preimage).digest()
    write_bytes("author-event-hash.bin", author_event_hash)

    event_payload = build_event_payload(
        author_event_hash=author_event_hash,
        content_hash=content_hash,
        header=header,
        payload_ref=payload_ref,
        key_bag=key_bag,
    )
    event_payload_bytes = dcbor(event_payload)
    write_bytes("expected-event-payload.cbor", event_payload_bytes)

    protected_map_bytes = dcbor(build_protected_header(kid))
    sig_structure = build_sig_structure(protected_map_bytes, event_payload_bytes)
    write_bytes("sig-structure.bin", sig_structure)

    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    cose_sign1 = cbor2.CBORTag(18, [protected_map_bytes, {}, event_payload_bytes, signature])
    write_bytes("expected-event.cbor", dcbor(cose_sign1))

    canonical_preimage = dcbor(build_canonical_event_hash_preimage(event_payload))
    canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1, canonical_preimage
    )
    write_bytes(
        "expected-append-head.cbor",
        dcbor(build_append_head(LEDGER_SCOPE, SEQUENCE, canonical_event_hash)),
    )

    # Retry determinism proof: rebuild from same inputs and assert byte identity
    retry_nonce = derive_payload_nonce(IDEMPOTENCY_KEY, plaintext)
    assert retry_nonce == payload_nonce, "retry nonce must match"
    retry_ciphertext = ChaCha20Poly1305(PAYLOAD_DEK).encrypt(retry_nonce, plaintext, b"")
    assert retry_ciphertext == ciphertext, "retry ciphertext must match"
    retry_content_hash = domain_separated_sha256(TAG_TRELLIS_CONTENT_V1, retry_ciphertext)
    assert retry_content_hash == content_hash, "retry content_hash must match"

    retry_authored_map = build_author_event_hash_preimage(
        content_hash=retry_content_hash,
        header=build_event_header(),
        payload_ref=build_payload_ref(retry_ciphertext, retry_nonce),
        key_bag=build_key_bag(ephemeral_pubkey, wrapped_dek),
    )
    retry_authored_bytes = dcbor(retry_authored_map)
    assert retry_authored_bytes == authored_bytes, "retry authored bytes must match"
    retry_author_event_hash = hashlib.sha256(
        domain_separated_preimage(TAG_TRELLIS_AUTHOR_EVENT_V1, retry_authored_bytes)
    ).digest()
    assert retry_author_event_hash == author_event_hash, "retry author_event_hash must match"
    retry_event_payload = build_event_payload(
        author_event_hash=retry_author_event_hash,
        content_hash=retry_content_hash,
        header=build_event_header(),
        payload_ref=build_payload_ref(retry_ciphertext, retry_nonce),
        key_bag=build_key_bag(ephemeral_pubkey, wrapped_dek),
    )
    retry_event_payload_bytes = dcbor(retry_event_payload)
    assert retry_event_payload_bytes == event_payload_bytes, "retry event payload must match"
    retry_canonical_event_hash = domain_separated_sha256(
        TAG_TRELLIS_EVENT_V1,
        dcbor(build_canonical_event_hash_preimage(retry_event_payload)),
    )
    assert retry_canonical_event_hash == canonical_event_hash, "retry canonical_event_hash must match"

    print()
    print(f"  kid                          = {kid.hex()}")
    print(f"  payload_nonce                = {payload_nonce.hex()}")
    print(f"  content_hash                 = {content_hash.hex()}")
    print(f"  author_event_hash            = {author_event_hash.hex()}")
    print(f"  canonical_event_hash         = {canonical_event_hash.hex()}")
    print("  RETRY DETERMINISM: all intermediates byte-identical ✓")


if __name__ == "__main__":
    main()
