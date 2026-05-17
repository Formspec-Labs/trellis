from __future__ import annotations

from pathlib import Path

import cbor2
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


def test_signed_acts_nested_map_oracle_matches_rust_canonical_bytes() -> None:
    value = {"consent": {"z": "last", "a": "first"}}

    assert cbor2.dumps(value, canonical=True) == bytes.fromhex(
        "a167636f6e73656e74a26161656669727374617a646c617374"
    )


def test_signed_acts_v1_derivation_rule_is_registry_backed() -> None:
    rules = verify_wos._signed_acts_derivation_rules()  # noqa: SLF001

    assert verify_wos.SIGNED_ACTS_DERIVATION_RULE in rules


def test_signed_acts_unknown_derivation_rule_is_failure_without_v1_fallback() -> None:
    catalog_bytes = cbor2.dumps(
        {
            "projection_schema_version": 1,
            "derivation_rule_id": verify_wos.SIGNED_ACTS_DERIVATION_RULE,
            "acts": [],
        },
        canonical=True,
    )
    extension = {
        "catalog_ref": verify_wos.SIGNED_ACTS_MEMBER,
        "catalog_digest": core._sha256(catalog_bytes),  # noqa: SLF001
        "derivation_rule": "signed-act-projection-wos-formspec-v2",
    }

    findings = verify_wos._validate_signed_acts_projection(  # noqa: SLF001
        archive={verify_wos.SIGNED_ACTS_MEMBER: catalog_bytes},
        events=[],
        payload_blobs={},
        manifest_map={
            "extensions": {verify_wos.SIGNED_ACTS_EXPORT_EXTENSION: extension}
        },
    )

    assert any(
        finding.kind == "signed_acts_catalog_invalid"
        and "unsupported signed acts derivation_rule" in finding.detail
        for finding in findings
    )
    assert all(
        finding.kind != "signed_acts_projection_mismatch" for finding in findings
    )


def test_signed_acts_act_correlation_merges_compatible_source_refs() -> None:
    acts = verify_wos._correlate_projected_acts(  # noqa: SLF001
        [
            _projected_act("act-1", "signer-1", b"\x22" * 32),
            _projected_act("act-1", "signer-1", b"\x11" * 32),
        ]
    )

    assert len(acts) == 1
    assert len(acts[0]["source_refs"]) == 2
    assert acts[0]["source_refs"][0]["ref"] == b"\x11" * 32
    assert acts[0]["source_refs"][1]["ref"] == b"\x22" * 32


def test_signed_acts_act_correlation_rejects_incompatible_duplicate_id() -> None:
    with pytest.raises(core.VerifyError, match="act_correlation_conflict"):
        verify_wos._correlate_projected_acts(  # noqa: SLF001
            [
                _projected_act("act-1", "signer-1", b"\x11" * 32),
                _projected_act("act-1", "signer-2", b"\x22" * 32),
            ]
        )


def test_signed_acts_act_correlation_rejects_duplicate_source_ref_across_ids() -> None:
    with pytest.raises(core.VerifyError, match="repeats a source_ref"):
        verify_wos._correlate_projected_acts(  # noqa: SLF001
            [
                _projected_act("act-1", "signer-1", b"\x11" * 32),
                _projected_act("act-2", "signer-1", b"\x11" * 32),
            ]
        )


def _projected_act(act_id: str, signer: str, source_ref: bytes) -> dict[str, object]:
    return {
        "act_id": act_id,
        "signer": signer,
        "signed_at": "2026-05-17T00:00:00Z",
        "source_refs": [
            {
                "layer": "wos",
                "kind": "signature-affirmation",
                "ref": source_ref,
            }
        ],
    }


def test_signed_acts_unknown_derivation_rule_blocks_public_verdict() -> None:
    export_zip = (
        TRELLIS_ROOT
        / "fixtures/vectors/verify/020-export-006-signed-acts-unsupported-rule/input-export.zip"
    ).read_bytes()

    report = verify_wos.verify_export_zip(export_zip)

    assert report.substrate.structure_verified is True
    assert report.substrate.integrity_verified is True
    assert report.verdict.cryptographic_integrity == "pass"
    assert report.verdict.projection_integrity == "fail"
    assert report.verdict.domain_admissibility == "pass"
    assert report.verdict.relying_party_result == "invalid"
    assert report.verdict.blocking_reasons == ["projection_integrity"]
    assert [
        finding.kind
        for finding in report.wos_findings
        if finding.severity == "failure"
    ] == ["signed_acts_catalog_invalid"]


def test_signature_catalog_signing_act_mismatch_fails_domain_validation() -> None:
    export_zip = (
        TRELLIS_ROOT
        / "fixtures/vectors/verify/014-export-006-signature-row-mismatch/input-export.zip"
    ).read_bytes()

    report = verify_wos.verify_export_zip(export_zip)

    assert report.substrate.structure_verified is True
    assert report.substrate.integrity_verified is True
    assert any(
        finding.kind == "signature_catalog_mismatch"
        for finding in report.wos_findings
    )
    assert report.verdict.cryptographic_integrity == "pass"
    assert report.verdict.domain_admissibility == "fail"
    assert report.verdict.relying_party_result == "invalid"


def test_policy_closure_digest_mismatch_blocks_domain_verdict() -> None:
    export_zip = (
        TRELLIS_ROOT
        / "fixtures/vectors/tamper/056-policy-closure-digest-mismatch/input-export.zip"
    ).read_bytes()

    report = verify_wos.verify_export_zip(export_zip)

    assert report.substrate.structure_verified is True
    assert report.substrate.integrity_verified is True
    assert any(
        finding.kind == "policy_closure_digest_mismatch"
        for finding in report.wos_findings
    )
    assert report.verdict.cryptographic_integrity == "pass"
    assert report.verdict.projection_integrity == "pass"
    assert report.verdict.domain_admissibility == "fail"
    assert report.verdict.relying_party_result == "invalid"
    assert report.verdict.blocking_reasons == ["domain_admissibility"]
    assert report.integrity_verified is False


def test_wos_resolver_reads_response_digest_without_full_signed_act_shape() -> None:
    payload = cbor2.dumps(
        {
            "event": verify_wos.WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE,
            "data": {
                "signerId": "applicant",
                "signedPayloadDigestAlgorithm": "sha-256",
                "signedPayloadDigest": "12" * 32,
            },
        }
    )

    resolver = verify_wos.WosFormspecResolver()
    proof = resolver.resolve(payload)

    assert proof is not None
    assert proof.response_hash == bytes.fromhex("12" * 32)
    assert resolver.resolve_principal_ref(payload) == "applicant"


def test_wos_resolver_malformed_response_digest_fails_closed() -> None:
    payload = cbor2.dumps(
        {
            "event": verify_wos.WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE,
            "data": {
                "signedPayloadDigestAlgorithm": "sha-256",
                "signedPayloadDigest": "ZZ" * 32,
            },
        }
    )

    with pytest.raises(core.MalformedResponseDigestError):
        verify_wos.WosFormspecResolver().resolve(payload)


def test_certificate_response_ref_mismatch_fixture_fails_substrate_verification() -> None:
    export_zip = (
        TRELLIS_ROOT
        / "fixtures/vectors/tamper/024-cert-response-ref-mismatch/input-export.zip"
    ).read_bytes()

    report = verify_wos.verify_export_zip(export_zip)

    assert report.substrate.structure_verified is True
    assert report.substrate.integrity_verified is False
    assert any(
        failure.kind == "response_ref_mismatch"
        for failure in report.substrate.event_failures
    )
    assert any(
        "response_ref_mismatch" in outcome.failures
        for outcome in report.substrate.certificates_of_completion
    )


def test_certificate_malformed_response_digest_fixture_fails_substrate_verification() -> None:
    export_zip = (
        TRELLIS_ROOT
        / "fixtures/vectors/tamper/052-cert-response-ref-malformed-digest/input-export.zip"
    ).read_bytes()

    report = verify_wos.verify_export_zip(export_zip)

    assert report.substrate.structure_verified is True
    assert report.substrate.integrity_verified is False
    assert any(
        failure.kind == "malformed_response_digest"
        for failure in report.substrate.event_failures
    )
    assert any(
        "malformed_response_digest" in outcome.failures
        for outcome in report.substrate.certificates_of_completion
    )


def test_signature_admission_failed_export_projects_rejected_signed_act() -> None:
    export_dir = (
        TRELLIS_ROOT
        / "fixtures/vectors/export/007-signature-admission-failed-inline"
    )
    report = verify_wos.verify_export_zip((export_dir / "expected-export.zip").read_bytes())

    assert report.substrate.structure_verified is True
    assert report.substrate.integrity_verified is True
    assert report.wos_findings == []
    assert report.verdict.relying_party_result == "valid"

    catalog = cbor2.loads((export_dir / "066-signed-acts.cbor").read_bytes())
    act = catalog["acts"][0]
    assert act["act_id"] == "sig-2026-0001"
    assert act["admission"]["outcome"] == "rejected"
    assert act["admission"]["failure_reason"] == "method_unregistered"
    assert act["consent"] is None
    assert act["source_refs"][0]["kind"] == "signature-admission-failed"


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
