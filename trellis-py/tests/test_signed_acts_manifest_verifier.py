"""Tests for the Python `_validate_signed_acts_manifest_extension` verifier.

Mirrors Rust `validate_signed_acts_manifest_extension` at
`trellis/crates/trellis-verify-wos/src/signed_acts.rs:82-185` (Task A7).

Covers the four-way present/absent extension/member dispatch and the bound
validation path (digest mismatch and end-to-end happy path via the fixture
corpus). The cross-runtime byte-identity assertion lives in
`trellis/scripts/check_cross_runtime_parity.py` (signed-acts-projection gate;
formerly `check_signed_acts_projection_parity.py`, renamed in preflight Task A2).
"""

from __future__ import annotations

from pathlib import Path

import cbor2

from trellis_py import verify as core
from trellis_py import verify_wos

TRELLIS_ROOT = Path(__file__).resolve().parents[2]


def _manifest_extension(
    catalog_ref: str = verify_wos.SIGNED_ACTS_MANIFEST_MEMBER,
    derivation_rule: str = verify_wos.SIGNED_ACTS_MANIFEST_DERIVATION_RULE_V1,
    manifest_digest: bytes | None = None,
) -> dict:
    if manifest_digest is None:
        manifest_digest = b"\x00" * 32
    return {
        "catalog_ref": catalog_ref,
        "manifest_digest": manifest_digest,
        "derivation_rule": derivation_rule,
    }


def test_manifest_absent_extension_and_member_yields_no_findings() -> None:
    findings = verify_wos._validate_signed_acts_manifest_extension(  # noqa: SLF001
        archive={}, events=[], manifest_map={}
    )
    assert findings == []


def test_manifest_member_present_without_extension_is_unbound_failure() -> None:
    member_bytes = b"\x80"  # canonical CBOR array(0)
    findings = verify_wos._validate_signed_acts_manifest_extension(  # noqa: SLF001
        archive={verify_wos.SIGNED_ACTS_MANIFEST_MEMBER: member_bytes},
        events=[],
        manifest_map={},
    )
    assert len(findings) == 1
    assert findings[0].kind == "signed_acts_manifest_member_unbound"
    assert findings[0].severity == "failure"


def test_manifest_extension_declared_without_member_is_missing_failure() -> None:
    extension = _manifest_extension()
    findings = verify_wos._validate_signed_acts_manifest_extension(  # noqa: SLF001
        archive={},
        events=[],
        manifest_map={
            "extensions": {
                verify_wos.SIGNED_ACTS_MANIFEST_EXPORT_EXTENSION: extension
            }
        },
    )
    assert len(findings) == 1
    assert findings[0].kind == "signed_acts_manifest_missing_member"
    assert findings[0].severity == "failure"


def test_manifest_extension_digest_mismatch_is_blocking_failure() -> None:
    # Empty manifest is the canonical CBOR array(0) = b"\x80".
    correct_bytes = verify_wos.encode_signed_acts_manifest_v1([])
    assert correct_bytes == b"\x80"
    wrong_digest = b"\xde" * 32
    extension = _manifest_extension(manifest_digest=wrong_digest)
    findings = verify_wos._validate_signed_acts_manifest_extension(  # noqa: SLF001
        archive={verify_wos.SIGNED_ACTS_MANIFEST_MEMBER: correct_bytes},
        events=[],
        manifest_map={
            "extensions": {
                verify_wos.SIGNED_ACTS_MANIFEST_EXPORT_EXTENSION: extension
            }
        },
    )
    assert len(findings) == 1
    assert findings[0].kind == "signed_acts_manifest_extension_digest_mismatch"
    assert findings[0].severity == "failure"


def test_manifest_extension_wrong_catalog_ref_is_invalid_failure() -> None:
    correct_bytes = verify_wos.encode_signed_acts_manifest_v1([])
    extension = _manifest_extension(
        catalog_ref="wrong-member.cbor", manifest_digest=core._sha256(correct_bytes)
    )
    findings = verify_wos._validate_signed_acts_manifest_extension(  # noqa: SLF001
        archive={verify_wos.SIGNED_ACTS_MANIFEST_MEMBER: correct_bytes},
        events=[],
        manifest_map={
            "extensions": {
                verify_wos.SIGNED_ACTS_MANIFEST_EXPORT_EXTENSION: extension
            }
        },
    )
    assert any(
        finding.kind == "signed_acts_manifest_extension_invalid"
        for finding in findings
    )


def test_manifest_extension_unparseable_yields_invalid_failure() -> None:
    # Extension key bound to raw bytes instead of a map — same path as the
    # signature_catalog/intake_catalog parse-error tests above.
    findings = verify_wos._validate_signed_acts_manifest_extension(  # noqa: SLF001
        archive={},
        events=[],
        manifest_map={
            "extensions": {
                verify_wos.SIGNED_ACTS_MANIFEST_EXPORT_EXTENSION: b"not-a-cbor-map",
            }
        },
    )
    assert len(findings) == 1
    assert findings[0].kind == "signed_acts_manifest_extension_invalid"
    assert findings[0].severity == "failure"


def test_manifest_verifier_accepts_fixture_006_happy_path() -> None:
    """End-to-end happy path via the export/006 fixture (068 member present
    and matches its extension binding + re-derivation). Verdict must stay
    valid with no blocking reasons."""
    export_zip = (
        TRELLIS_ROOT
        / "fixtures/vectors/export/006-signature-affirmations-inline/expected-export.zip"
    ).read_bytes()

    report = verify_wos.verify_export_zip(export_zip)

    failures = [
        finding.kind
        for finding in report.wos_findings
        if finding.severity == "failure"
    ]
    assert failures == []
    assert report.verdict.relying_party_result == "valid"


def test_manifest_verifier_rejects_fixture_021_tamper() -> None:
    """Cross-runtime parity: Python verdict for verify/021 (068 byte tamper
    after manifest signing) MUST match the Rust verdict — blocking failure
    with kind `signed_acts_manifest_extension_digest_mismatch`."""
    export_zip = (
        TRELLIS_ROOT
        / "fixtures/vectors/verify/021-signed-acts-manifest-tamper/input-export.zip"
    ).read_bytes()

    report = verify_wos.verify_export_zip(export_zip)

    failures = {
        finding.kind
        for finding in report.wos_findings
        if finding.severity == "failure"
    }
    assert failures == {"signed_acts_manifest_extension_digest_mismatch"}
    assert report.verdict.cryptographic_integrity == "pass"
    # `signed_acts_manifest_*` kinds are NOT projection findings (they signal
    # substrate damage / declaration violation of the substrate-anchored
    # signed-acts proof) — they surface under `domain_admissibility` to mirror
    # Rust `is_projection_finding` at
    # `integrity-stack/crates/integrity-verify/src/trellis/validator.rs:288-297`.
    assert report.verdict.projection_integrity == "pass"
    assert report.verdict.domain_admissibility == "fail"
    assert report.verdict.relying_party_result == "invalid"
    assert report.verdict.blocking_reasons == ["domain_admissibility"]


def test_manifest_verifier_passes_fixture_022_render_drift_only() -> None:
    """The 022 fixture tampers 066 but leaves 068 untouched. The 068 verifier
    MUST NOT contribute any blocking failure — render drift on 066 is advisory
    and the substrate-anchored manifest still proves which events landed."""
    export_zip = (
        TRELLIS_ROOT
        / "fixtures/vectors/verify/022-066-render-drift-tampered-only/input-export.zip"
    ).read_bytes()

    report = verify_wos.verify_export_zip(export_zip)

    manifest_findings = [
        finding
        for finding in report.wos_findings
        if finding.kind.startswith("signed_acts_manifest_")
    ]
    assert manifest_findings == []
    assert report.verdict.relying_party_result == "valid"


def test_manifest_verifier_skipped_unrelated_events_do_not_break_derivation() -> None:
    """Smoke-cover the in-place re-derivation path: an export with no
    signature_affirmation / signature_admission_failed events yields the
    canonical empty manifest (`b"\\x80"`), which a corresponding extension
    must bind to. Verifier accepts this."""
    empty_manifest = verify_wos.encode_signed_acts_manifest_v1(
        verify_wos.derive_signed_acts_manifest_v1([])
    )
    assert empty_manifest == b"\x80"
    extension = _manifest_extension(
        manifest_digest=core._sha256(empty_manifest)  # noqa: SLF001
    )
    # cbor2 round-trip mirrors the on-disk dict the verifier sees after
    # `parse_export_zip`.
    cbor_extension = cbor2.loads(cbor2.dumps(extension))
    findings = verify_wos._validate_signed_acts_manifest_extension(  # noqa: SLF001
        archive={verify_wos.SIGNED_ACTS_MANIFEST_MEMBER: empty_manifest},
        events=[],
        manifest_map={
            "extensions": {
                verify_wos.SIGNED_ACTS_MANIFEST_EXPORT_EXTENSION: cbor_extension
            }
        },
    )
    assert findings == []
