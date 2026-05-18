"""Trellis export-bundle manifest extension verifiers (core, non-WOS).

This module hosts core (non-domain) manifest-extension validators that ride
inside `verify_export_zip`. Today it covers the
`trellis.export.seal-fence.v1` extension (Core §18.3e / §28 CDDL) — the
substrate-anchored, deterministic identity rule that proves an export bundle
is the unique sealed snapshot of `(scope, high_water_event)`.

Mirror of Rust `verify_seal_fence_extension` at
`integrity-stack/crates/integrity-verify/src/trellis/export.rs:996`. The
finding kinds emitted here are per-tamper typed names
(`seal_fence_identity_rule_mismatch` etc.) so direct callers get precise
diagnostics; the wiring point in :func:`trellis_py.verify.verify_export_zip`
translates the first finding (if any) into a
``VerificationReport.fatal("manifest_payload_invalid", ...)`` to mirror
Rust's `VerificationReport::fatal(ManifestPayloadInvalid, message)` behavior
for cross-runtime parity at the report level.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from trellis_py import verify as core
from trellis_py._cbor_canonical import (
    CanonicalCborError,
    domain_separated_sha256,
    encode_canonical_cbor_value,
)
from trellis_py.verify_wos import WosFinding


# --- Constants -------------------------------------------------------------

# Manifest-extension key (Core §28 CDDL extension namespace).
SEAL_FENCE_EXPORT_EXTENSION = "trellis.export.seal-fence.v1"

# Identity-rule literal pinned by Core §18.3e and matched by Rust
# `parse_seal_fence_export_extension` at
# `integrity-stack/crates/integrity-verify/src/trellis/parse.rs:1033`.
SEAL_FENCE_IDENTITY_RULE = "trellis-export-seal-fence-v1"

# Domain-separation tag for `export_attempt_id` preimage. Mirrors Rust
# `EXPORT_ATTEMPT_DOMAIN` at
# `integrity-stack/crates/integrity-verify/src/trellis/mod.rs:155`.
EXPORT_ATTEMPT_DOMAIN = "trellis-export-attempt-v1"

EVENTS_MEMBER = "010-events.cbor"
POLICY_CLOSURE_MEMBER = "067-policy-closure.cbor"


# --- Parsed-extension dataclass --------------------------------------------


@dataclass
class SealFenceExtension:
    """Parsed `trellis.export.seal-fence.v1` extension fields. Mirror of Rust
    `SealFenceExportExtension` at
    `integrity-stack/crates/integrity-verify/src/trellis/types.rs:837`."""

    bundle_scope: bytes
    export_attempt_id: str
    seal_version: int
    event_count: int
    high_water_sequence: int
    head_checkpoint_digest: bytes
    events_digest: bytes
    policy_closure_digest: Optional[bytes]


# --- Parser ----------------------------------------------------------------


def _parse_seal_fence_export_extension(
    manifest_map: dict,
) -> Optional[SealFenceExtension]:
    """Parse the `trellis.export.seal-fence.v1` manifest extension.

    Mirror of Rust `parse_seal_fence_export_extension` at
    `integrity-stack/crates/integrity-verify/src/trellis/parse.rs:1019`.

    Returns ``None`` when the extension is absent. Raises
    :class:`core.VerifyError` when the extension is present but malformed
    (unsupported identity-rule, missing required fields, wrong widths).
    """
    exts = core._map_lookup_optional_extensions(manifest_map)
    if exts is None:
        return None
    ext = exts.get(SEAL_FENCE_EXPORT_EXTENSION)
    if ext is None:
        return None
    if not isinstance(ext, dict):
        raise core.VerifyError("seal fence export extension is not a map")

    identity_rule = core._map_lookup_str(ext, "identity_rule")
    if not isinstance(identity_rule, str):
        raise core.VerifyError("seal fence export extension identity_rule is not text")
    if identity_rule != SEAL_FENCE_IDENTITY_RULE:
        raise core.VerifyError(
            "seal fence export extension identity_rule is unsupported"
        )

    # `policy_closure_digest` is required (per Rust parser) but accepts null
    # for exports without a 067 closure member.
    if "policy_closure_digest" not in ext:
        raise core.VerifyError(
            "seal fence export extension policy_closure_digest is required"
        )
    raw_closure = ext["policy_closure_digest"]
    if raw_closure is None:
        policy_closure_digest: Optional[bytes] = None
    elif isinstance(raw_closure, (bytes, bytearray)) and len(raw_closure) == 32:
        policy_closure_digest = bytes(raw_closure)
    else:
        raise core.VerifyError(
            "seal fence export extension policy_closure_digest must be null or bstr .size 32"
        )

    export_attempt_id = core._map_lookup_str(ext, "export_attempt_id")
    if not isinstance(export_attempt_id, str):
        raise core.VerifyError(
            "seal fence export extension export_attempt_id is not text"
        )

    return SealFenceExtension(
        bundle_scope=bytes(core._map_lookup_bytes(ext, "bundle_scope")),
        export_attempt_id=export_attempt_id,
        seal_version=int(core._map_lookup_u64(ext, "seal_version")),
        event_count=int(core._map_lookup_u64(ext, "event_count")),
        high_water_sequence=int(core._map_lookup_u64(ext, "high_water_sequence")),
        head_checkpoint_digest=core._map_lookup_fixed_bytes(
            ext, "head_checkpoint_digest", 32
        ),
        events_digest=core._map_lookup_fixed_bytes(ext, "events_digest", 32),
        policy_closure_digest=policy_closure_digest,
    )


# --- Identity-rule recompute ------------------------------------------------


def export_attempt_id(
    bundle_scope: bytes,
    seal_version: int,
    high_water_sequence: int,
    high_water_event_hash: bytes,
) -> str:
    """Recompute the deterministic `export_attempt_id` per Core §18.3e.

    Mirror of Rust `export_attempt_id` at
    `integrity-stack/crates/integrity-verify/src/trellis/export.rs:1103`.

    Builds the canonical-CBOR preimage map
    ``{bundle_scope, seal_version, high_water_sequence, high_water_event_hash}``
    (key order is irrelevant — the §4.2.2 encoder sorts by encoded key bytes),
    runs the §4.2 domain-separated SHA-256 over the encoded bytes, and
    formats as ``"sha256:" + hex(digest)``. Byte-identical to Rust.
    """
    if not isinstance(bundle_scope, (bytes, bytearray)):
        raise core.VerifyError("bundle_scope must be bytes")
    if not isinstance(high_water_event_hash, (bytes, bytearray)) or len(
        high_water_event_hash
    ) != 32:
        raise core.VerifyError("high_water_event_hash must be 32-byte digest")
    material = {
        "bundle_scope": bytes(bundle_scope),
        "seal_version": int(seal_version),
        "high_water_sequence": int(high_water_sequence),
        "high_water_event_hash": bytes(high_water_event_hash),
    }
    try:
        encoded = encode_canonical_cbor_value(material)
    except CanonicalCborError as exc:
        raise core.VerifyError(f"failed to encode export-attempt preimage: {exc}") from exc
    digest = domain_separated_sha256(EXPORT_ATTEMPT_DOMAIN, encoded)
    return "sha256:" + digest.hex()


# --- Public verifier --------------------------------------------------------


def verify_seal_fence_extension(
    archive: dict, manifest_map: dict
) -> list[WosFinding]:
    """Verify the `trellis.export.seal-fence.v1` manifest extension.

    Re-derives every fence-bound value from archive members
    (`010-events.cbor`, `067-policy-closure.cbor`, manifest
    `head_checkpoint_digest` / `events_digest` / `scope` / `tree_size`)
    and asserts the seal-fence extension's stored values match.

    Mirror of Rust `verify_seal_fence_extension` at
    `integrity-stack/crates/integrity-verify/src/trellis/export.rs:996`.

    Returns ``[]`` when the extension is absent or every fence-bound check
    passes. Emits blocking findings on mismatch:

      - ``seal_fence_identity_rule_mismatch`` — extension shape rejected by
        the parser (unsupported identity_rule, missing required field, wrong
        widths). Mirrors Rust's "seal fence export extension is invalid: ..."
        envelope wrapping `parse_seal_fence_export_extension` errors.
      - ``seal_fence_export_attempt_id_mismatch`` — stored
        `export_attempt_id` does not match the deterministic recompute
        from `{bundle_scope, seal_version, high_water_sequence,
        high_water_event_hash}`.
      - ``seal_fence_events_digest_recompute_mismatch`` — stored
        `events_digest` does not match the manifest `events_digest`, or
        does not match SHA-256(`010-events.cbor` bytes).
      - ``seal_fence_head_checkpoint_digest_recompute_mismatch`` — stored
        `head_checkpoint_digest` does not match the manifest
        `head_checkpoint_digest`.
      - ``seal_fence_policy_closure_digest_recompute_mismatch`` — stored
        `policy_closure_digest` does not match SHA-256(`067-policy-closure.cbor`
        bytes), or claims a digest when no closure member is present, or
        claims null when a closure member ships.

    Callers MAY treat any returned finding as fatal — the wiring point in
    :func:`trellis_py.verify.verify_export_zip` does, mirroring Rust's
    `VerificationReport::fatal(ManifestPayloadInvalid, message)` semantics.
    """
    try:
        extension = _parse_seal_fence_export_extension(manifest_map)
    except core.VerifyError as exc:
        return [
            WosFinding(
                "seal_fence_identity_rule_mismatch",
                b"",
                "failure",
                f"seal fence export extension is invalid: {exc}",
            )
        ]
    if extension is None:
        return []

    findings: list[WosFinding] = []

    # --- Scope / seal-version / event-count alignment ---
    try:
        scope = bytes(core._map_lookup_bytes(manifest_map, "scope"))
    except core.VerifyError as exc:
        return [
            WosFinding(
                "seal_fence_identity_rule_mismatch",
                b"",
                "failure",
                f"manifest scope is invalid: {exc}",
            )
        ]
    if extension.bundle_scope != scope:
        findings.append(
            WosFinding(
                "seal_fence_identity_rule_mismatch",
                b"",
                "failure",
                "seal fence export extension bundle_scope does not match manifest scope",
            )
        )

    if extension.seal_version == 0:
        findings.append(
            WosFinding(
                "seal_fence_identity_rule_mismatch",
                b"",
                "failure",
                "seal fence export extension seal_version must be positive",
            )
        )

    try:
        manifest_tree_size = int(core._map_lookup_u64(manifest_map, "tree_size"))
    except core.VerifyError as exc:
        return findings + [
            WosFinding(
                "seal_fence_identity_rule_mismatch",
                b"",
                "failure",
                f"manifest tree_size is invalid: {exc}",
            )
        ]
    if extension.event_count != manifest_tree_size:
        findings.append(
            WosFinding(
                "seal_fence_identity_rule_mismatch",
                b"",
                "failure",
                f"seal fence export extension event_count {extension.event_count} "
                f"does not match manifest tree_size {manifest_tree_size}",
            )
        )

    # --- Events member structural binding ---
    events_bytes = archive.get(EVENTS_MEMBER)
    if events_bytes is None:
        findings.append(
            WosFinding(
                "seal_fence_events_digest_recompute_mismatch",
                b"",
                "failure",
                "seal fence export extension cannot resolve events member",
            )
        )
    else:
        try:
            events = core._parse_sign1_array(events_bytes)
        except core.VerifyError as exc:
            return findings + [
                WosFinding(
                    "seal_fence_events_digest_recompute_mismatch",
                    b"",
                    "failure",
                    f"failed to decode {EVENTS_MEMBER}: {exc}",
                )
            ]
        event_count = len(events)
        if extension.event_count != event_count:
            findings.append(
                WosFinding(
                    "seal_fence_identity_rule_mismatch",
                    b"",
                    "failure",
                    f"seal fence export extension event_count {extension.event_count} "
                    f"does not match events member count {event_count}",
                )
            )
        if not events:
            findings.append(
                WosFinding(
                    "seal_fence_identity_rule_mismatch",
                    b"",
                    "failure",
                    "seal fence export extension requires at least one event",
                )
            )
        else:
            try:
                high_water_details = core._decode_event_details(events[-1])
            except core.VerifyError as exc:
                return findings + [
                    WosFinding(
                        "seal_fence_export_attempt_id_mismatch",
                        b"",
                        "failure",
                        f"cannot decode high-water event for seal-fence recompute: {exc}",
                    )
                ]
            if extension.high_water_sequence != high_water_details.sequence:
                findings.append(
                    WosFinding(
                        "seal_fence_identity_rule_mismatch",
                        b"",
                        "failure",
                        f"seal fence export extension high_water_sequence "
                        f"{extension.high_water_sequence} does not match final event "
                        f"sequence {high_water_details.sequence}",
                    )
                )
            expected_count = high_water_details.sequence + 1
            if extension.event_count != expected_count:
                findings.append(
                    WosFinding(
                        "seal_fence_identity_rule_mismatch",
                        b"",
                        "failure",
                        f"seal fence export extension event_count {extension.event_count} "
                        f"does not match high-water sequence {extension.high_water_sequence}",
                    )
                )
            expected_attempt = export_attempt_id(
                extension.bundle_scope,
                extension.seal_version,
                extension.high_water_sequence,
                high_water_details.canonical_event_hash,
            )
            if extension.export_attempt_id != expected_attempt:
                findings.append(
                    WosFinding(
                        "seal_fence_export_attempt_id_mismatch",
                        b"",
                        "failure",
                        f"seal fence export extension export_attempt_id "
                        f"{extension.export_attempt_id} does not match deterministic "
                        f"identity {expected_attempt}",
                    )
                )

    # --- Head-checkpoint digest binding ---
    try:
        manifest_head_checkpoint_digest = core._map_lookup_fixed_bytes(
            manifest_map, "head_checkpoint_digest", 32
        )
    except core.VerifyError as exc:
        findings.append(
            WosFinding(
                "seal_fence_head_checkpoint_digest_recompute_mismatch",
                b"",
                "failure",
                f"manifest head_checkpoint_digest is invalid: {exc}",
            )
        )
    else:
        if extension.head_checkpoint_digest != manifest_head_checkpoint_digest:
            findings.append(
                WosFinding(
                    "seal_fence_head_checkpoint_digest_recompute_mismatch",
                    b"",
                    "failure",
                    "seal fence export extension head_checkpoint_digest does not match manifest",
                )
            )

    # --- Events digest binding (manifest binding + member recompute) ---
    try:
        manifest_events_digest = core._map_lookup_fixed_bytes(
            manifest_map, "events_digest", 32
        )
    except core.VerifyError as exc:
        findings.append(
            WosFinding(
                "seal_fence_events_digest_recompute_mismatch",
                b"",
                "failure",
                f"manifest events_digest is invalid: {exc}",
            )
        )
    else:
        if extension.events_digest != manifest_events_digest:
            findings.append(
                WosFinding(
                    "seal_fence_events_digest_recompute_mismatch",
                    b"",
                    "failure",
                    "seal fence export extension events_digest does not match manifest",
                )
            )
        if events_bytes is not None:
            actual_events_digest = core._sha256(events_bytes)
            if extension.events_digest != actual_events_digest:
                findings.append(
                    WosFinding(
                        "seal_fence_events_digest_recompute_mismatch",
                        b"",
                        "failure",
                        "seal fence export extension events_digest does not match events member",
                    )
                )

    # --- Policy-closure digest binding ---
    closure_bytes = archive.get(POLICY_CLOSURE_MEMBER)
    actual_closure_digest = (
        core._sha256(closure_bytes) if closure_bytes is not None else None
    )
    if extension.policy_closure_digest != actual_closure_digest:
        findings.append(
            WosFinding(
                "seal_fence_policy_closure_digest_recompute_mismatch",
                b"",
                "failure",
                "seal fence export extension policy_closure_digest does not match closure member",
            )
        )

    return findings
