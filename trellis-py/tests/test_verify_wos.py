from __future__ import annotations

from pathlib import Path

import pytest

from trellis_py import verify as core
from trellis_py import verify_wos

TRELLIS_ROOT = Path(__file__).resolve().parents[2]


def test_map_lookup_str_alias_returns_preferred_when_string() -> None:
    out = core._map_lookup_str_alias(  # noqa: SLF001
        {"preferred": "PREF", "legacy": "LEG"}, "preferred", "legacy"
    )
    assert out == "PREF"


def test_map_lookup_str_alias_falls_back_when_preferred_absent() -> None:
    out = core._map_lookup_str_alias(  # noqa: SLF001
        {"legacy": "LEG"}, "preferred", "legacy"
    )
    assert out == "LEG"


def test_map_lookup_str_alias_rejects_present_but_non_string_preferred() -> None:
    """Phase O narrowing (review F3): a present-but-malformed preferred key
    MUST NOT silently fall through to the legacy alias. Surface a parse
    error instead so the caller emits a localized failure rather than
    silently accepting the legacy value."""
    with pytest.raises(core.VerifyError):
        core._map_lookup_str_alias(  # noqa: SLF001
            {"preferred": 42, "legacy": "LEG"}, "preferred", "legacy"
        )


def test_signature_export_extension_parse_error_becomes_wos_finding() -> None:
    findings = verify_wos._validate_export(  # noqa: SLF001
        archive={},
        events=[],
        payload_blobs={},
        manifest_map={
            "extensions": {
                verify_wos.SIGNATURE_EXPORT_EXTENSION: b"not-a-cbor-map",
            }
        },
        generated_at=core.TrellisTimestamp(1, 0),
    )

    assert len(findings) == 1
    assert findings[0].kind == "signature_catalog_invalid"
    assert findings[0].severity == "failure"
    assert "signature export extension is invalid" in findings[0].detail


def test_intake_export_extension_parse_error_becomes_wos_finding() -> None:
    findings = verify_wos._validate_export(  # noqa: SLF001
        archive={},
        events=[],
        payload_blobs={},
        manifest_map={
            "extensions": {
                verify_wos.INTAKE_EXPORT_EXTENSION: b"not-a-cbor-map",
            }
        },
        generated_at=core.TrellisTimestamp(1, 0),
    )

    assert len(findings) == 1
    assert findings[0].kind == "intake_handoff_catalog_invalid"
    assert findings[0].severity == "failure"
    assert "intake export extension is invalid" in findings[0].detail


def test_signed_acts_projection_mismatch_blocks_relying_party_verdict() -> None:
    export_zip = (
        TRELLIS_ROOT
        / "fixtures/vectors/verify/019-export-006-signed-acts-projection-mismatch/input-export.zip"
    ).read_bytes()

    report = verify_wos.verify_export_zip(export_zip)

    assert report.substrate.structure_verified is True
    assert report.substrate.integrity_verified is True
    assert report.verdict.cryptographic_integrity == "pass"
    assert report.verdict.projection_integrity == "fail"
    assert report.verdict.domain_admissibility == "pass"
    assert report.verdict.relying_party_result == "invalid"
    assert report.verdict.blocking_reasons == ["projection_mismatch"]
    assert report.integrity_verified is False


def test_clock_event_type_constants_match_f13_literals() -> None:
    assert (
        verify_wos.WOS_GOVERNANCE_CLOCK_STARTED_EVENT_TYPE
        == "wos.governance.clock_started"
    )
    assert (
        verify_wos.WOS_GOVERNANCE_CLOCK_RESOLVED_EVENT_TYPE
        == "wos.governance.clock_resolved"
    )


def test_validate_clock_segments_skips_clock_shaped_payload_on_non_clock_event_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Spec contract (`trellis/specs/wos-trellis-verification.md` §3):
    clock semantics gate on `event_type`, not on payload shape. A non-clock
    event whose payload happens to deserialize as a clock record MUST NOT
    participate in segment validation."""

    class _FakeDetails:
        def __init__(self, event_type: str) -> None:
            self.event_type = event_type
            self.canonical_event_hash = b"\x01" * 32

    # Two events with payload-clock-shape but a non-clock event_type. If the
    # gating regresses, the parser would be invoked and (paired with a later
    # real clock-started) could synthesize a `clock_calendar_mismatch`.
    fake_events = [object(), object()]
    fake_details_by_event = {
        id(fake_events[0]): _FakeDetails("wos.kernel.case_created"),
        id(fake_events[1]): _FakeDetails("wos.kernel.case_created"),
    }
    parse_calls: list[bytes] = []

    monkeypatch.setattr(
        core,
        "_decode_event_details",
        lambda event: fake_details_by_event[id(event)],
    )
    monkeypatch.setattr(
        core,
        "_readable_payload_bytes",
        lambda details, payload_blobs: b"\xa0",  # any non-None bytes
    )
    original_parse = verify_wos._parse_clock_record  # noqa: SLF001

    def _spy_parse(payload_bytes: bytes):
        parse_calls.append(payload_bytes)
        return original_parse(payload_bytes)

    monkeypatch.setattr(verify_wos, "_parse_clock_record", _spy_parse)

    findings = verify_wos._validate_clock_segments(fake_events, {})  # noqa: SLF001

    assert findings == []
    assert parse_calls == [], (
        "non-clock event_type must short-circuit before _parse_clock_record"
    )
