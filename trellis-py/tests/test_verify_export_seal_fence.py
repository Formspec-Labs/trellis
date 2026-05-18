"""Tests for the Python `verify_seal_fence_extension` verifier.

Mirror of Rust `verify_seal_fence_extension` at
`integrity-stack/crates/integrity-verify/src/trellis/export.rs:996` (Task C2).

The Rust verifier emits a single `Err(String)` that the dispatching
`verify_export_zip` wraps as `VerificationReport::fatal(ManifestPayloadInvalid)`.
The Python verifier emits per-tamper typed `WosFinding` kinds so direct
callers get precise diagnostics; the wiring point in
`trellis_py.verify.verify_export_zip` translates the first finding to
`VerificationReport.fatal("manifest_payload_invalid", ...)` for parity at
the report level.

Tests construct a synthetic seal-fence extension on top of fixture 006's
unmodified archive members (the fixture corpus does not yet ship a
seal-fence extension), then mutate one field per tamper case. This avoids
re-signing the COSE_Sign1 manifest while still exercising every recompute
path the verifier walks.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import cbor2

from trellis_py import verify as core
from trellis_py.verify_export import (
    EXPORT_ATTEMPT_DOMAIN,
    SEAL_FENCE_EXPORT_EXTENSION,
    SEAL_FENCE_IDENTITY_RULE,
    export_attempt_id,
    verify_seal_fence_extension,
)


FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "vectors"
SOURCE_EXPORT = (
    FIXTURES / "export" / "006-signature-affirmations-inline" / "expected-export.zip"
)


def _load_archive_and_manifest_map() -> tuple[dict[str, bytes], dict[str, Any]]:
    archive = core.parse_export_zip(SOURCE_EXPORT.read_bytes())
    manifest_sign1 = core._parse_sign1_bytes(archive["000-manifest.cbor"])
    manifest_map = cbor2.loads(manifest_sign1.payload)
    assert isinstance(manifest_map, dict)
    return archive, manifest_map


def _build_seal_fence(
    archive: dict[str, bytes], manifest_map: dict
) -> dict[str, Any]:
    """Construct a happy-path seal-fence extension dict from archive members."""
    events = core._parse_sign1_array(archive["010-events.cbor"])
    assert events, "fixture 006 must have events"
    hw = core._decode_event_details(events[-1])
    scope = bytes(core._map_lookup_bytes(manifest_map, "scope"))
    events_digest = core._map_lookup_fixed_bytes(manifest_map, "events_digest", 32)
    head_ck_digest = core._map_lookup_fixed_bytes(
        manifest_map, "head_checkpoint_digest", 32
    )
    closure_bytes = archive.get("067-policy-closure.cbor")
    closure_digest = core._sha256(closure_bytes) if closure_bytes is not None else None
    event_count = len(events)
    # Rust fixture sealed-export-package uses seal_version = event_count.
    seal_version = event_count
    attempt = export_attempt_id(
        scope, seal_version, hw.sequence, hw.canonical_event_hash
    )
    return {
        "identity_rule": SEAL_FENCE_IDENTITY_RULE,
        "bundle_scope": scope,
        "export_attempt_id": attempt,
        "seal_version": seal_version,
        "event_count": event_count,
        "high_water_sequence": hw.sequence,
        "high_water_event_hash": hw.canonical_event_hash,
        "head_checkpoint_digest": head_ck_digest,
        "events_digest": events_digest,
        "policy_closure_digest": closure_digest,
    }


def _manifest_with_seal_fence(seal_fence_override: Any = None) -> tuple[
    dict[str, bytes], dict[str, Any]
]:
    archive, manifest_map = _load_archive_and_manifest_map()
    seal_fence = _build_seal_fence(archive, manifest_map)
    if seal_fence_override is not None:
        seal_fence_override(seal_fence)
    extensions = manifest_map.setdefault("extensions", {})
    if not isinstance(extensions, dict):
        extensions = {}
        manifest_map["extensions"] = extensions
    # Replace any existing seal-fence binding from prior test mutation.
    extensions = copy.deepcopy(extensions)
    extensions[SEAL_FENCE_EXPORT_EXTENSION] = seal_fence
    manifest_map["extensions"] = extensions
    return archive, manifest_map


# --- Happy path ------------------------------------------------------------


def test_seal_fence_happy_path_emits_no_findings() -> None:
    """End-to-end happy path: synthetic seal-fence built from fixture 006's
    unmodified archive members verifies cleanly."""
    archive, manifest_map = _manifest_with_seal_fence()
    findings = verify_seal_fence_extension(archive, manifest_map)
    assert findings == []


def test_seal_fence_absent_emits_no_findings() -> None:
    """When the extension is absent (the default fixture state), the
    verifier short-circuits with an empty finding list — matches Rust's
    `Ok(())` early-return at `export.rs:1004`."""
    archive, manifest_map = _load_archive_and_manifest_map()
    # Fixture 006 ships no seal-fence extension by default.
    extensions = manifest_map.get("extensions", {})
    assert SEAL_FENCE_EXPORT_EXTENSION not in extensions
    findings = verify_seal_fence_extension(archive, manifest_map)
    assert findings == []


# --- Tamper coverage (one per Rust SealFenceTamper variant) ----------------


def _mutate_identity_rule(sf: dict[str, Any]) -> None:
    sf["identity_rule"] = "trellis-export-seal-fence-test"


def _mutate_export_attempt_id(sf: dict[str, Any]) -> None:
    sf["export_attempt_id"] = "sha256:wrong"


def _mutate_events_digest(sf: dict[str, Any]) -> None:
    sf["events_digest"] = b"\xaa" * 32


def _mutate_head_checkpoint_digest(sf: dict[str, Any]) -> None:
    sf["head_checkpoint_digest"] = b"\xbb" * 32


def _mutate_policy_closure_digest(sf: dict[str, Any]) -> None:
    sf["policy_closure_digest"] = b"\xcc" * 32


def test_seal_fence_identity_rule_tamper() -> None:
    """Mirror of Rust `SealFenceTamper::IdentityRule` at `export.rs:1274`.
    The parser rejects any non-`trellis-export-seal-fence-v1` identity rule."""
    archive, manifest_map = _manifest_with_seal_fence(_mutate_identity_rule)
    findings = verify_seal_fence_extension(archive, manifest_map)
    kinds = [f.kind for f in findings]
    assert "seal_fence_identity_rule_mismatch" in kinds


def test_seal_fence_export_attempt_id_tamper() -> None:
    """Mirror of Rust `SealFenceTamper::ExportAttemptId` at `export.rs:1278`.
    The stored `export_attempt_id` must equal the deterministic
    `domain_separated_sha256(EXPORT_ATTEMPT_DOMAIN, canonical_cbor(material))`
    recompute over `{bundle_scope, seal_version, high_water_sequence,
    high_water_event_hash}`."""
    archive, manifest_map = _manifest_with_seal_fence(_mutate_export_attempt_id)
    findings = verify_seal_fence_extension(archive, manifest_map)
    kinds = [f.kind for f in findings]
    assert "seal_fence_export_attempt_id_mismatch" in kinds


def test_seal_fence_events_digest_tamper() -> None:
    """Mirror of Rust `SealFenceTamper::EventsDigest` at `export.rs:1282`.
    The stored `events_digest` must match both the manifest field and
    SHA-256 of the 010-events.cbor member."""
    archive, manifest_map = _manifest_with_seal_fence(_mutate_events_digest)
    findings = verify_seal_fence_extension(archive, manifest_map)
    kinds = [f.kind for f in findings]
    assert "seal_fence_events_digest_recompute_mismatch" in kinds


def test_seal_fence_head_checkpoint_digest_tamper() -> None:
    """Mirror of Rust `SealFenceTamper::HeadCheckpointDigest` at
    `export.rs:1285`. The stored `head_checkpoint_digest` must equal the
    manifest's `head_checkpoint_digest` field."""
    archive, manifest_map = _manifest_with_seal_fence(_mutate_head_checkpoint_digest)
    findings = verify_seal_fence_extension(archive, manifest_map)
    kinds = [f.kind for f in findings]
    assert "seal_fence_head_checkpoint_digest_recompute_mismatch" in kinds


def test_seal_fence_policy_closure_digest_tamper() -> None:
    """Mirror of Rust `SealFenceTamper::PolicyClosureDigest` at
    `export.rs:1288`. The stored `policy_closure_digest` must equal
    SHA-256(`067-policy-closure.cbor`) when the member ships, or be null
    when it does not."""
    archive, manifest_map = _manifest_with_seal_fence(_mutate_policy_closure_digest)
    findings = verify_seal_fence_extension(archive, manifest_map)
    kinds = [f.kind for f in findings]
    assert "seal_fence_policy_closure_digest_recompute_mismatch" in kinds


# --- Domain-separation byte oracle -----------------------------------------


def test_export_attempt_id_format_is_sha256_hex() -> None:
    """The recompute returns the `"sha256:" + hex(digest)` form pinned by
    Rust `export_attempt_id` at `export.rs:1129`."""
    digest_id = export_attempt_id(b"scope-bytes", 7, 3, b"\x11" * 32)
    assert digest_id.startswith("sha256:")
    hex_part = digest_id.removeprefix("sha256:")
    assert len(hex_part) == 64
    assert all(c in "0123456789abcdef" for c in hex_part)


def test_export_attempt_id_domain_tag_matches_rust_constant() -> None:
    """The `EXPORT_ATTEMPT_DOMAIN` constant must match the Rust constant
    at `integrity-stack/crates/integrity-verify/src/trellis/mod.rs:155`."""
    assert EXPORT_ATTEMPT_DOMAIN == "trellis-export-attempt-v1"


def test_seal_fence_identity_rule_constant_matches_rust() -> None:
    """The `SEAL_FENCE_IDENTITY_RULE` constant must match the Rust literal
    at `integrity-stack/crates/integrity-verify/src/trellis/parse.rs:1033`."""
    assert SEAL_FENCE_IDENTITY_RULE == "trellis-export-seal-fence-v1"
