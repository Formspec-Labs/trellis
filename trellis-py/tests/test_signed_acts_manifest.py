"""Tests for the v1 signed-acts manifest deriver and canonical encoder.

Mirror of Rust tests in `trellis/crates/trellis-verify-wos/src/signed_acts.rs`
(see `signed_acts_manifest_*`). Test #6 (the byte-identity pin) is the
load-bearing parity gate proving cross-runtime byte conformance for the
preimage shape.
"""

from __future__ import annotations

import trellis_py
from trellis_py import verify as core
from trellis_py import verify_wos


def _event(
    event_type: str,
    canonical_event_hash: bytes,
) -> core.EventDetails:
    return core.EventDetails(
        scope=b"scope",
        sequence=1,
        authored_at=core.TrellisTimestamp(1, 0),
        event_type=event_type,
        classification="x-test",
        prev_hash=None,
        author_event_hash=b"\x00" * 32,
        content_hash=b"\x01" * 32,
        canonical_event_hash=canonical_event_hash,
        idempotency_key=b"idem",
        payload_ref_inline=None,
        payload_ref_external=False,
        transition=None,
    )


def _affirmation(canonical_event_hash: bytes) -> core.EventDetails:
    return _event(
        verify_wos.WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE, canonical_event_hash
    )


def _admission_failed(canonical_event_hash: bytes) -> core.EventDetails:
    return _event(
        verify_wos.WOS_SIGNATURE_ADMISSION_FAILED_EVENT_TYPE,
        canonical_event_hash,
    )


def test_signed_acts_manifest_empty_events_yields_empty_array() -> None:
    manifest = verify_wos.derive_signed_acts_manifest_v1([])
    assert manifest == []
    encoded = verify_wos.encode_signed_acts_manifest_v1(manifest)
    # CBOR array(0) is a single byte 0x80.
    assert encoded == b"\x80"


def test_signed_acts_manifest_single_signature_affirmation_is_included() -> None:
    event = _affirmation(b"\x22" * 32)

    manifest = verify_wos.derive_signed_acts_manifest_v1([event])

    assert len(manifest) == 1
    assert manifest[0] == (
        b"\x22" * 32,
        verify_wos.WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE,
    )


def test_signed_acts_manifest_single_signature_admission_failed_is_included() -> None:
    event = _admission_failed(b"\x33" * 32)

    manifest = verify_wos.derive_signed_acts_manifest_v1([event])

    assert len(manifest) == 1
    assert manifest[0] == (
        b"\x33" * 32,
        verify_wos.WOS_SIGNATURE_ADMISSION_FAILED_EVENT_TYPE,
    )


def test_signed_acts_manifest_mixed_events_sort_by_hash_then_event_type() -> None:
    # Hash 0x11 < 0x22, so the admission-failed event (hash 0x11) sorts first
    # even though its event_type literal sorts after the affirmation literal —
    # exactly the discriminator the Rust test 4 pins.
    affirmation = _affirmation(b"\x22" * 32)
    admission_failed = _admission_failed(b"\x11" * 32)

    manifest = verify_wos.derive_signed_acts_manifest_v1(
        [affirmation, admission_failed]
    )

    assert len(manifest) == 2
    assert manifest[0] == (
        b"\x11" * 32,
        verify_wos.WOS_SIGNATURE_ADMISSION_FAILED_EVENT_TYPE,
    )
    assert manifest[1] == (
        b"\x22" * 32,
        verify_wos.WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE,
    )

    # Shuffling input order must not affect output order (permutation
    # invariance — covered again at the encoded-bytes layer below).
    reshuffled = verify_wos.derive_signed_acts_manifest_v1(
        [admission_failed, affirmation]
    )
    assert reshuffled == manifest


def test_signed_acts_manifest_same_hash_sorts_by_event_type() -> None:
    # Both events share canonical_event_hash 0x44; tie breaks on event_type ASC.
    # "wos.kernel.signature_admission_failed" < "wos.kernel.signature_affirmation"
    # lexicographically (`_` 0x5f < `f` 0x66 at the diverging byte).
    affirmation = _affirmation(b"\x44" * 32)
    admission_failed = _admission_failed(b"\x44" * 32)

    manifest = verify_wos.derive_signed_acts_manifest_v1(
        [affirmation, admission_failed]
    )

    assert len(manifest) == 2
    assert manifest[0][1] == verify_wos.WOS_SIGNATURE_ADMISSION_FAILED_EVENT_TYPE
    assert manifest[1][1] == verify_wos.WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE


def test_signed_acts_manifest_excludes_unrelated_event_types() -> None:
    unrelated = _event("wos.kernel.case_created", b"\x55" * 32)
    manifest = verify_wos.derive_signed_acts_manifest_v1([unrelated])
    assert manifest == []


def test_signed_acts_manifest_encoding_is_input_order_invariant() -> None:
    events = [
        _affirmation(b"\x22" * 32),
        _admission_failed(b"\x11" * 32),
        _affirmation(b"\x33" * 32),
    ]
    permuted = [events[2], events[0], events[1]]

    canonical = verify_wos.encode_signed_acts_manifest_v1(
        verify_wos.derive_signed_acts_manifest_v1(events)
    )
    from_permuted = verify_wos.encode_signed_acts_manifest_v1(
        verify_wos.derive_signed_acts_manifest_v1(permuted)
    )

    assert canonical == from_permuted


def test_signed_acts_manifest_encoding_matches_canonical_cbor_layout() -> None:
    # Byte-identity pin against Rust
    # `signed_acts_manifest_encoding_matches_canonical_cbor_layout`
    # (signed_acts.rs:1612). Manually compute the canonical bytes for a
    # one-event manifest:
    #   hash       = [0x00; 32]
    #   event_type = wos.kernel.signature_affirmation (32 ASCII bytes)
    #
    # Encoding:
    #   0x81                              -- array(1)
    #   0x82                              -- array(2)
    #   0x58 0x20 <32 zero bytes>         -- bstr(32) of zeros
    #   0x78 0x20 <"wos.kernel.signature_affirmation">
    #                                     -- tstr(32) one-byte-length form
    event_type = verify_wos.WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE
    assert len(event_type) == 32, "event_type literal length pin"

    expected = (
        b"\x81"  # array(1)
        b"\x82"  # array(2)
        b"\x58\x20"  # bstr(32)
        + b"\x00" * 32
        + b"\x78\x20"  # tstr(32)
        + event_type.encode("ascii")
    )
    assert len(expected) == 70

    event = _event(event_type, b"\x00" * 32)
    encoded = verify_wos.encode_signed_acts_manifest_v1(
        verify_wos.derive_signed_acts_manifest_v1([event])
    )

    assert encoded == expected


def test_signed_acts_manifest_reexported_from_package() -> None:
    """A9 parity gate will import these via `from trellis_py import ...`;
    pin the re-export so the wire surface does not regress silently."""
    assert (
        trellis_py.derive_signed_acts_manifest_v1
        is verify_wos.derive_signed_acts_manifest_v1
    )
    assert (
        trellis_py.encode_signed_acts_manifest_v1
        is verify_wos.encode_signed_acts_manifest_v1
    )
