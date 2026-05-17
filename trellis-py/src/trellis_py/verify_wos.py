"""WOS-domain verification composed with Trellis Core verification.

`trellis_py.verify` is the byte-integrity verifier. This module owns WOS
record semantics that depend on WOS event names, WOS record shapes, or
WOS-specific catalog interpretation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import cbor2

from trellis_py import verify as core


SIGNATURE_EXPORT_EXTENSION = "trellis.export.signature-affirmations.v1"
INTAKE_EXPORT_EXTENSION = "trellis.export.intake-handoffs.v1"
OPEN_CLOCKS_EXPORT_EXTENSION = "trellis.export.open-clocks.v1"
OPEN_CLOCKS_MEMBER = "open-clocks.json"
SIGNED_ACTS_EXPORT_EXTENSION = "trellis.export.signed-acts.v1"
SIGNED_ACTS_MEMBER = "066-signed-acts.cbor"
SIGNED_ACTS_DERIVATION_RULE = "signed-act-projection-wos-formspec-v1"
POLICY_CLOSURE_EXPORT_EXTENSION = "trellis.export.policy-closure.v1"
POLICY_CLOSURE_MEMBER = "067-policy-closure.cbor"
POLICY_CLOSURE_SCHEMA_VERSION = 1
REQUIRED_POLICY_CLOSURE_ARTIFACT_KINDS = {
    "formspec.signing-intent-registry.v1",
    "formspec.signature-method-registry.v1",
    "wos.signature-posture-floors.v1",
    "wos.signer-authority-shape.v1",
    "wos.identity-proofing-primitives.v1",
    "wos.signature-defaults.v1",
    "wos.signature-deny-rules.v1",
    "wos.signature-tombstones.v1",
}
WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE = "wos.kernel.signature_affirmation"
WOS_SIGNATURE_ADMISSION_FAILED_EVENT_TYPE = "wos.kernel.signature_admission_failed"
WOS_INTAKE_ACCEPTED_EVENT_TYPE = "wos.kernel.intake_accepted"
WOS_CASE_CREATED_EVENT_TYPE = "wos.kernel.case_created"
WOS_IDENTITY_ATTESTATION_EVENT_TYPE = "wos.assurance.identity_attestation"
WOS_OPERATOR_URI_PREFIX = "urn:wos:operator:"
WOS_GOVERNANCE_DETERMINATION_PREFIX = "wos.governance.determination"
WOS_GOVERNANCE_DETERMINATION_RESCINDED_EVENT_TYPE = (
    "wos.governance.determination_rescinded"
)
WOS_GOVERNANCE_REINSTATED_EVENT_TYPE = "wos.governance.reinstated"
WOS_GOVERNANCE_CLOCK_STARTED_EVENT_TYPE = "wos.governance.clock_started"
WOS_GOVERNANCE_CLOCK_RESOLVED_EVENT_TYPE = "wos.governance.clock_resolved"
CLOCK_RESOLUTION_PAUSED = "paused"


@dataclass
class WosFinding:
    kind: str
    event_hash: Optional[bytes]
    severity: str
    detail: str


@dataclass
class RelyingPartyVerdict:
    cryptographic_integrity: str
    projection_integrity: str
    domain_admissibility: str
    relying_party_result: str
    blocking_reasons: list[str] = field(default_factory=list)


@dataclass
class DomainReport:
    findings: list[WosFinding] = field(default_factory=list)


@dataclass
class LayeredVerificationReport:
    verdict: RelyingPartyVerdict
    substrate: core.VerificationReport
    domain: DomainReport


@dataclass
class WosVerificationReport:
    trellis: core.VerificationReport
    wos_findings: list[WosFinding] = field(default_factory=list)

    @property
    def substrate(self) -> core.VerificationReport:
        return self.trellis

    @property
    def domain(self) -> DomainReport:
        return DomainReport(list(self.wos_findings))

    @property
    def verdict(self) -> RelyingPartyVerdict:
        return _verdict_from_parts(self.trellis, self.wos_findings)

    @property
    def layered_report(self) -> LayeredVerificationReport:
        return LayeredVerificationReport(self.verdict, self.trellis, self.domain)

    @property
    def integrity_verified(self) -> bool:
        return self.verdict.relying_party_result == "valid"


def _verdict_from_parts(
    substrate: core.VerificationReport, findings: list[WosFinding]
) -> RelyingPartyVerdict:
    cryptographic_integrity = (
        "pass"
        if substrate.structure_verified and substrate.integrity_verified
        else "fail"
    )
    substrate_ok = cryptographic_integrity == "pass"
    projection_integrity = (
        "indeterminate"
        if not substrate_ok
        else "fail"
        if any(
            finding.severity == "failure" and _is_projection_finding(finding)
            for finding in findings
        )
        else "pass"
    )
    domain_admissibility = (
        "indeterminate"
        if not substrate_ok
        else "fail"
        if any(
            finding.severity == "failure" and not _is_projection_finding(finding)
            for finding in findings
        )
        else "pass"
    )
    blocking_reasons: list[str] = []
    if cryptographic_integrity == "fail":
        blocking_reasons.append("substrate_integrity")
    if projection_integrity == "fail":
        reason = (
            "projection_mismatch"
            if any(
                finding.kind == "signed_acts_projection_mismatch"
                for finding in findings
            )
            else "projection_integrity"
        )
        blocking_reasons.append(reason)
    if domain_admissibility == "fail":
        blocking_reasons.append("domain_admissibility")
    if (
        not blocking_reasons
        and cryptographic_integrity == "pass"
        and projection_integrity == "pass"
        and domain_admissibility == "pass"
    ):
        relying_party_result = "valid"
    elif blocking_reasons:
        relying_party_result = "invalid"
    else:
        relying_party_result = "indeterminate"
    return RelyingPartyVerdict(
        cryptographic_integrity,
        projection_integrity,
        domain_admissibility,
        relying_party_result,
        blocking_reasons,
    )


def _is_projection_finding(finding: WosFinding) -> bool:
    return finding.kind in {
        "missing_signed_acts_catalog",
        "signed_acts_catalog_digest_mismatch",
        "signed_acts_catalog_invalid",
        "signed_acts_catalog_unbound",
        "signed_acts_projection_mismatch",
    }


def verify_export_zip(export_zip: bytes) -> WosVerificationReport:
    trellis = core.verify_export_zip(
        export_zip,
        identity_event_type_admitted=_is_wos_identity_attestation_event_type,
        operator_uri_admitted=_is_wos_operator_uri,
        resolver=WosFormspecResolver(),
    )
    if not trellis.structure_verified:
        return WosVerificationReport(trellis)
    try:
        archive, events, payload_blobs, manifest_map, generated_at = _domain_export(
            export_zip
        )
    except core.VerifyError:
        return WosVerificationReport(trellis)

    findings = _validate_events(events, payload_blobs)
    findings.extend(
        _validate_export(archive, events, payload_blobs, manifest_map, generated_at)
    )
    return WosVerificationReport(trellis, findings)


def verify_tampered_ledger(
    signing_key_registry: bytes,
    ledger: bytes,
    initial_posture_declaration: Optional[bytes] = None,
    posture_declaration: Optional[bytes] = None,
) -> WosVerificationReport:
    trellis = core.verify_tampered_ledger(
        signing_key_registry,
        ledger,
        initial_posture_declaration,
        posture_declaration,
        identity_event_type_admitted=_is_wos_identity_attestation_event_type,
        operator_uri_admitted=_is_wos_operator_uri,
        resolver=WosFormspecResolver(),
    )
    if not trellis.structure_verified:
        return WosVerificationReport(trellis)
    try:
        events = core._parse_sign1_array(ledger)
    except Exception:  # noqa: BLE001
        events = []
    findings = _validate_events(events, {})
    return WosVerificationReport(trellis, findings)


def _domain_export(
    export_zip: bytes,
) -> tuple[
    dict[str, bytes],
    list[core.ParsedSign1],
    dict[bytes, bytes],
    dict,
    core.TrellisTimestamp,
]:
    archive = core.parse_export_zip(export_zip)
    manifest = core._parse_sign1_bytes(archive["000-manifest.cbor"])
    if manifest.payload is None:
        raise core.VerifyError("manifest payload is detached")
    manifest_payload = core._decode_value(manifest.payload)
    if not isinstance(manifest_payload, dict):
        raise core.VerifyError("manifest payload root is not a map")
    events = core._parse_sign1_array(archive["010-events.cbor"])
    payload_blobs: dict[bytes, bytes] = {}
    for name, blob in archive.items():
        if not name.startswith("060-payloads/") or not name.endswith(".bin"):
            continue
        digest_hex = name[len("060-payloads/") : -len(".bin")]
        try:
            digest = core._hex_decode(digest_hex)
        except core.VerifyError:
            continue
        if len(digest) == 32:
            payload_blobs[digest] = blob
    generated_at = core._map_lookup_timestamp(manifest_payload, "generated_at")
    return archive, events, payload_blobs, manifest_payload, generated_at


def _validate_events(
    events: list[core.ParsedSign1], payload_blobs: dict[bytes, bytes]
) -> list[WosFinding]:
    findings: list[WosFinding] = []
    findings.extend(_validate_rescission_terminality(events))
    findings.extend(_validate_clock_segments(events, payload_blobs))
    return findings


def _is_wos_identity_attestation_event_type(event_type: str) -> bool:
    return event_type == WOS_IDENTITY_ATTESTATION_EVENT_TYPE


def _is_wos_operator_uri(value: str) -> bool:
    return value.startswith(WOS_OPERATOR_URI_PREFIX)


def _validate_export(
    archive: dict[str, bytes],
    events: list[core.ParsedSign1],
    payload_blobs: dict[bytes, bytes],
    manifest_map: dict,
    generated_at: core.TrellisTimestamp,
) -> list[WosFinding]:
    findings: list[WosFinding] = []
    event_by_hash, duplicate_failures = core._index_events_by_canonical_hash(events)
    for failure in duplicate_failures:
        findings.append(_failure(failure.kind, None, failure.location))

    try:
        signature_catalog_digest = _parse_signature_export_extension(manifest_map)
    except core.VerifyError as exc:
        findings.append(
            _failure(
                "signature_catalog_invalid",
                None,
                f"signature export extension is invalid: {exc}",
            )
        )
        signature_catalog_digest = None
    if signature_catalog_digest is not None:
        findings.extend(
            _validate_signature_catalog(
                archive, payload_blobs, signature_catalog_digest, event_by_hash
            )
        )
    try:
        intake_catalog_digest = _parse_intake_export_extension(manifest_map)
    except core.VerifyError as exc:
        findings.append(
            _failure(
                "intake_handoff_catalog_invalid",
                None,
                f"intake export extension is invalid: {exc}",
            )
        )
        intake_catalog_digest = None
    if intake_catalog_digest is not None:
        findings.extend(
            _validate_intake_catalog(
                archive, payload_blobs, intake_catalog_digest, event_by_hash
            )
        )
    findings.extend(_validate_open_clock_export(archive, manifest_map, generated_at))
    findings.extend(_validate_signed_acts_projection(archive, events, payload_blobs, manifest_map))
    findings.extend(_validate_policy_closure(archive, manifest_map))
    return findings


def _failure(kind: str, event_hash: Optional[bytes], detail: str) -> WosFinding:
    return WosFinding(kind, event_hash, "failure", detail)


def _advisory(kind: str, event_hash: Optional[bytes], detail: str) -> WosFinding:
    return WosFinding(kind, event_hash, "advisory", detail)


def _event_details(event: core.ParsedSign1) -> Optional[core.EventDetails]:
    try:
        return core._decode_event_details(event)
    except core.VerifyError:
        return None


def _validate_rescission_terminality(events: list[core.ParsedSign1]) -> list[WosFinding]:
    findings: list[WosFinding] = []
    rescission_terminal = False
    for event in events:
        details = _event_details(event)
        if details is None:
            continue
        if details.event_type == WOS_GOVERNANCE_DETERMINATION_RESCINDED_EVENT_TYPE:
            rescission_terminal = True
        elif details.event_type == WOS_GOVERNANCE_REINSTATED_EVENT_TYPE:
            rescission_terminal = False
        elif rescission_terminal and details.event_type.startswith(
            WOS_GOVERNANCE_DETERMINATION_PREFIX
        ):
            findings.append(
                _failure(
                    "rescission_terminality_violation",
                    details.canonical_event_hash,
                    "determination event follows rescission without reinstatement",
                )
            )
    return findings


def _parse_signature_export_extension(manifest_map: dict) -> Optional[bytes]:
    exts = core._map_lookup_optional_extensions(manifest_map)
    if exts is None:
        return None
    ext = exts.get(SIGNATURE_EXPORT_EXTENSION)
    if ext is None:
        return None
    if not isinstance(ext, dict):
        raise core.VerifyError("signature export extension is not a map")
    return core._map_lookup_fixed_bytes(ext, "signature_catalog_digest", 32)


def _parse_intake_export_extension(manifest_map: dict) -> Optional[bytes]:
    exts = core._map_lookup_optional_extensions(manifest_map)
    if exts is None:
        return None
    ext = exts.get(INTAKE_EXPORT_EXTENSION)
    if ext is None:
        return None
    if not isinstance(ext, dict):
        raise core.VerifyError("intake export extension is not a map")
    return core._map_lookup_fixed_bytes(ext, "intake_catalog_digest", 32)


def _parse_signed_acts_export_extension(manifest_map: dict) -> Optional[dict[str, Any]]:
    exts = core._map_lookup_optional_extensions(manifest_map)
    if exts is None:
        return None
    ext = exts.get(SIGNED_ACTS_EXPORT_EXTENSION)
    if ext is None:
        return None
    if not isinstance(ext, dict):
        raise core.VerifyError("signed acts export extension is not a map")
    catalog_ref = core._map_lookup_str(ext, "catalog_ref")
    derivation_rule = core._map_lookup_str(ext, "derivation_rule")
    if not isinstance(catalog_ref, str):
        raise core.VerifyError("signed acts catalog_ref is not text")
    if not isinstance(derivation_rule, str):
        raise core.VerifyError("signed acts derivation_rule is not text")
    return {
        "catalog_ref": catalog_ref,
        "catalog_digest": core._map_lookup_fixed_bytes(ext, "catalog_digest", 32),
        "derivation_rule": derivation_rule,
    }


def _parse_policy_closure_export_extension(manifest_map: dict) -> Optional[dict[str, Any]]:
    exts = core._map_lookup_optional_extensions(manifest_map)
    if exts is None:
        return None
    ext = exts.get(POLICY_CLOSURE_EXPORT_EXTENSION)
    if ext is None:
        return None
    if not isinstance(ext, dict):
        raise core.VerifyError("policy closure export extension is not a map")
    closure_ref = core._map_lookup_str(ext, "closure_ref")
    closure_version = core._map_lookup_str(ext, "closure_version")
    if not isinstance(closure_ref, str):
        raise core.VerifyError("policy closure closure_ref is not text")
    if not isinstance(closure_version, str):
        raise core.VerifyError("policy closure closure_version is not text")
    return {
        "closure_ref": closure_ref,
        "closure_digest": core._map_lookup_fixed_bytes(ext, "closure_digest", 32),
        "closure_version": closure_version,
    }


def _validate_policy_closure(
    archive: dict[str, bytes],
    manifest_map: dict,
) -> list[WosFinding]:
    has_member = POLICY_CLOSURE_MEMBER in archive
    try:
        extension = _parse_policy_closure_export_extension(manifest_map)
    except core.VerifyError as exc:
        return [
            _failure(
                "policy_closure_invalid",
                None,
                f"policy closure export extension is invalid: {exc}",
            )
        ]
    if extension is None and not has_member:
        return []
    if extension is None:
        return [
            _failure(
                "policy_closure_unbound",
                None,
                "067-policy-closure.cbor is present without trellis.export.policy-closure.v1",
            )
        ]
    if not has_member:
        return [
            _failure(
                "missing_policy_closure",
                None,
                "export is missing 067-policy-closure.cbor",
            )
        ]

    findings: list[WosFinding] = []
    closure_bytes = archive[POLICY_CLOSURE_MEMBER]
    if extension["closure_ref"] != POLICY_CLOSURE_MEMBER:
        findings.append(
            _failure(
                "policy_closure_invalid",
                None,
                f"policy closure_ref must be {POLICY_CLOSURE_MEMBER}, got {extension['closure_ref']}",
            )
        )
    if core._sha256(closure_bytes) != extension["closure_digest"]:
        findings.append(
            _failure(
                "policy_closure_digest_mismatch",
                None,
                "policy closure digest does not match manifest extension",
            )
        )
    try:
        _validate_policy_closure_member(closure_bytes, extension["closure_version"])
    except Exception as exc:  # noqa: BLE001
        findings.append(
            _failure(
                "policy_closure_invalid",
                None,
                f"067-policy-closure.cbor is invalid: {exc}",
            )
        )
    return findings


def _validate_policy_closure_member(
    closure_bytes: bytes, expected_version: str
) -> None:
    closure = cbor2.loads(closure_bytes)
    if not isinstance(closure, dict):
        raise core.VerifyError("policy closure is not a map")
    schema_version = core._map_lookup_u64(closure, "closure_schema_version")
    if schema_version != POLICY_CLOSURE_SCHEMA_VERSION:
        raise core.VerifyError(
            f"closure_schema_version must be {POLICY_CLOSURE_SCHEMA_VERSION}, got {schema_version}"
        )
    closure_version = core._map_lookup_str(closure, "closure_version")
    if closure_version != expected_version:
        raise core.VerifyError(
            f"closure_version {closure_version} does not match manifest extension {expected_version}"
        )
    verifier_boundary = core._map_lookup_map(closure, "verifier_boundary")
    _require_bool(verifier_boundary, "bundle_admission_policy_evidence", True)
    _require_bool(verifier_boundary, "bundle_trust_roots_authoritative", False)
    _require_bool(verifier_boundary, "verifier_supplied_trust_roots_required", True)
    _require_bool(
        verifier_boundary, "verifier_supplied_adapter_allowlists_required", True
    )
    _require_bool(verifier_boundary, "server_operational_config_included", False)

    artifacts = core._map_lookup_array(closure, "artifacts")
    if not artifacts:
        raise core.VerifyError("artifacts must not be empty")
    seen: set[str] = set()
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            raise core.VerifyError(f"artifacts[{index}] is not a map")
        kind = _validate_policy_closure_artifact(artifact, index)
        seen.add(kind)
    missing = sorted(REQUIRED_POLICY_CLOSURE_ARTIFACT_KINDS - seen)
    if missing:
        raise core.VerifyError(f"artifacts missing required kind {missing[0]}")


def _validate_policy_closure_artifact(artifact: dict, index: int) -> str:
    for field in ("owner", "kind", "version", "ref", "valid_from"):
        value = core._map_lookup_str(artifact, field)
        if value.strip() == "":
            raise core.VerifyError(f"artifacts[{index}].{field} must not be empty")
    algorithm = core._map_lookup_str(artifact, "digest_algorithm")
    if algorithm != "sha-256":
        raise core.VerifyError(f"artifacts[{index}].digest_algorithm must be sha-256")
    core._map_lookup_fixed_bytes(artifact, "digest", 32)
    valid_to = artifact.get("valid_to")
    if valid_to is not None and not isinstance(valid_to, str):
        raise core.VerifyError(f"artifacts[{index}].valid_to must be text or null")
    return core._map_lookup_str(artifact, "kind")


def _require_bool(m: dict, key: str, expected: bool) -> None:
    actual = core._map_lookup_bool(m, key)
    if actual != expected:
        raise core.VerifyError(f"{key} must be {expected}")


def _validate_signed_acts_projection(
    archive: dict[str, bytes],
    events: list[core.ParsedSign1],
    payload_blobs: dict[bytes, bytes],
    manifest_map: dict,
) -> list[WosFinding]:
    has_member = SIGNED_ACTS_MEMBER in archive
    try:
        extension = _parse_signed_acts_export_extension(manifest_map)
    except core.VerifyError as exc:
        return [
            _failure(
                "signed_acts_catalog_invalid",
                None,
                f"signed acts export extension is invalid: {exc}",
            )
        ]
    if extension is None and not has_member:
        return []
    if extension is None:
        return [
            _failure(
                "signed_acts_catalog_unbound",
                None,
                "066-signed-acts.cbor is present without trellis.export.signed-acts.v1",
            )
        ]
    if not has_member:
        return [
            _failure(
                "missing_signed_acts_catalog",
                None,
                "export is missing 066-signed-acts.cbor",
            )
        ]

    findings: list[WosFinding] = []
    catalog_bytes = archive[SIGNED_ACTS_MEMBER]
    if extension["catalog_ref"] != SIGNED_ACTS_MEMBER:
        findings.append(
            _failure(
                "signed_acts_catalog_invalid",
                None,
                f"signed acts catalog_ref must be {SIGNED_ACTS_MEMBER}, got {extension['catalog_ref']}",
            )
        )
    if extension["derivation_rule"] != SIGNED_ACTS_DERIVATION_RULE:
        findings.append(
            _failure(
                "signed_acts_catalog_invalid",
                None,
                f"signed acts derivation_rule must be {SIGNED_ACTS_DERIVATION_RULE}, got {extension['derivation_rule']}",
            )
        )
    if core._sha256(catalog_bytes) != extension["catalog_digest"]:
        findings.append(
            _failure(
                "signed_acts_catalog_digest_mismatch",
                None,
                "signed acts catalog digest does not match manifest extension",
            )
        )
    try:
        cbor2.loads(catalog_bytes)
    except Exception as exc:
        findings.append(
            _failure(
                "signed_acts_catalog_invalid",
                None,
                f"066-signed-acts.cbor is invalid CBOR: {exc}",
            )
        )
        return findings
    try:
        derived = _derive_signed_acts_catalog(events, payload_blobs)
    except core.VerifyError as exc:
        findings.append(_failure("signed_acts_catalog_invalid", None, str(exc)))
        return findings
    if derived != catalog_bytes:
        findings.append(
            _failure(
                "signed_acts_projection_mismatch",
                None,
                "signed acts catalog does not match deterministic WOS/Formspec derivation",
            )
        )
    return findings


def _derive_signed_acts_catalog(
    events: list[core.ParsedSign1], payload_blobs: dict[bytes, bytes]
) -> bytes:
    acts: list[dict[str, Any]] = []
    seen_source_refs: set[bytes] = set()
    for event in events:
        details = _event_details(event)
        if details is None:
            continue
        if details.event_type == WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE:
            payload = core._readable_payload_bytes(details, payload_blobs)
            if payload is None:
                raise core.VerifyError(
                    f"signature affirmation payload unreadable for {details.canonical_event_hash.hex()}"
                )
            record = _parse_signature_affirmation_record(
                payload, WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE
            )
            acts.append(_project_admitted_act(details, record))
        elif details.event_type == WOS_SIGNATURE_ADMISSION_FAILED_EVENT_TYPE:
            payload = core._readable_payload_bytes(details, payload_blobs)
            if payload is None:
                raise core.VerifyError(
                    f"signature admission-failed payload unreadable for {details.canonical_event_hash.hex()}"
                )
            record = _parse_signature_admission_failed_record(
                payload, WOS_SIGNATURE_ADMISSION_FAILED_EVENT_TYPE
            )
            acts.append(_project_rejected_act(details, record))

    acts.sort(
        key=lambda act: (
            str(act["act_id"]),
            str(act["signed_at"]),
            cbor2.dumps(act["source_refs"][0], canonical=True),
        )
    )
    for act in acts:
        for source_ref in act["source_refs"]:
            source_ref_bytes = cbor2.dumps(source_ref, canonical=True)
            if source_ref_bytes in seen_source_refs:
                raise core.VerifyError("signed acts projection repeats a source_ref")
            seen_source_refs.add(source_ref_bytes)
    return cbor2.dumps(
        {
            "projection_schema_version": 1,
            "derivation_rule_id": SIGNED_ACTS_DERIVATION_RULE,
            "acts": acts,
        },
        canonical=True,
    )


def _project_admitted_act(
    details: core.EventDetails, record: dict[str, Any]
) -> dict[str, Any]:
    intent = record.get("signing_intent")
    if not isinstance(intent, str):
        raise core.VerifyError("signature affirmation missing signingIntent")
    return {
        "act_id": record["signing_act_id"],
        "signer": {
            "id": record["signer_id"],
            "role": record["role"],
            "role_ref": record["role_id"],
            "identity_evidence_refs": [],
        },
        "bound": {
            "subject_kind": "formspec-response",
            "subject_hash": record.get("signed_payload_digest"),
            "subject_hash_algorithm": record.get("signed_payload_digest_algorithm"),
            "presentation_hash": record["presentation_hash"],
            "document_id": record["document_id"],
            "document_ref": record.get("document_ref"),
            "content_hash": record["document_hash"],
            "content_hash_algorithm": record["document_hash_algorithm"],
        },
        "intent": intent,
        "consent": record["consent_reference"],
        "admission": {
            "outcome": "admitted",
            "source_response_ref": record["source_response_ref"],
            "source_signature_system": record.get("source_signature_system"),
            "source_signature_id": record.get("source_signature_id"),
            "signature_provider": record["signature_provider"],
            "ceremony_id": record["ceremony_id"],
            "profile_ref": record.get("profile_ref"),
            "profile_key": record.get("profile_key"),
            "signed_payload_digest": record.get("signed_payload_digest"),
            "signed_payload_digest_algorithm": record.get(
                "signed_payload_digest_algorithm"
            ),
            "primitive_verification": record.get("primitive_verification"),
            "failure_reason": None,
        },
        "witness_of": record.get("witnessed_signature_ref"),
        "signed_at": record["signed_at"],
        "source_refs": _sorted_source_refs(
            [_source_ref(details, "signature-affirmation")]
        ),
    }


def _project_rejected_act(
    details: core.EventDetails, record: dict[str, Any]
) -> dict[str, Any]:
    return {
        "act_id": record["signature_id"],
        "signer": {
            "id": record.get("signer_id"),
            "role": None,
            "role_ref": None,
            "identity_evidence_refs": [],
        },
        "bound": {
            "subject_kind": "formspec-response",
            "subject_hash": record["signed_payload_digest"],
            "subject_hash_algorithm": None,
            "presentation_hash": None,
            "document_id": None,
            "document_ref": None,
            "content_hash": record["signed_payload_digest"],
            "content_hash_algorithm": None,
        },
        "intent": record["signing_intent"],
        "consent": None,
        "admission": {
            "outcome": "rejected",
            "source_response_ref": record["response_id"],
            "source_signature_system": None,
            "source_signature_id": record["signature_id"],
            "signature_provider": None,
            "ceremony_id": None,
            "profile_ref": None,
            "profile_key": None,
            "signed_payload_digest": record["signed_payload_digest"],
            "signed_payload_digest_algorithm": None,
            "primitive_verification": None,
            "failure_reason": record["reason"],
        },
        "witness_of": None,
        "signed_at": record["emitted_at"],
        "source_refs": _sorted_source_refs(
            [_source_ref(details, "signature-admission-failed")]
        ),
    }


def _source_ref(details: core.EventDetails, kind: str) -> dict[str, Any]:
    return {
        "layer": "wos",
        "kind": kind,
        "ref": details.canonical_event_hash,
    }


def _sorted_source_refs(source_refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        source_refs,
        key=lambda ref: (
            str(ref["layer"]),
            str(ref["kind"]),
            cbor2.dumps(ref["ref"], canonical=True),
        ),
    )


def _validate_signature_catalog(
    archive: dict[str, bytes],
    payload_blobs: dict[bytes, bytes],
    catalog_digest: bytes,
    event_by_hash: dict[bytes, core.EventDetails],
) -> list[WosFinding]:
    findings: list[WosFinding] = []
    cat_bytes = archive.get("062-signature-affirmations.cbor")
    if cat_bytes is None:
        return [
            _failure(
                "missing_signature_catalog",
                None,
                "export is missing 062-signature-affirmations.cbor",
            )
        ]
    if core._sha256(cat_bytes) != catalog_digest:
        findings.append(
            _failure(
                "signature_catalog_digest_mismatch",
                None,
                "signature catalog digest does not match manifest extension",
            )
        )
    try:
        entries = core._parse_signature_catalog_entries(cat_bytes)
    except core.VerifyError as exc:
        return [
            _failure(
                "signature_catalog_invalid",
                None,
                f"signature catalog is invalid: {exc}",
            )
        ]
    seen_row: set[bytes] = set()
    for row in entries:
        h = row["canonical_event_hash"]
        if h in seen_row:
            findings.append(
                _failure(
                    "signature_catalog_duplicate_event",
                    h,
                    "signature catalog repeats an event hash",
                )
            )
        seen_row.add(h)
    for row in entries:
        h = row["canonical_event_hash"]
        det = event_by_hash.get(h)
        if det is None:
            findings.append(
                _failure(
                    "signature_catalog_event_unresolved",
                    h,
                    "signature catalog references an event absent from the export",
                )
            )
            continue
        if det.event_type != WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE:
            findings.append(
                _failure(
                    "signature_catalog_event_type_mismatch",
                    h,
                    "signature catalog event is not a WOS signature affirmation",
                )
            )
            continue
        payload = core._readable_payload_bytes(det, payload_blobs)
        if payload is None:
            findings.append(
                _failure(
                    "signature_affirmation_payload_unreadable",
                    h,
                    "signature affirmation payload is not readable",
                )
            )
            continue
        try:
            record = _parse_signature_affirmation_record(
                payload, WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE
            )
        except core.VerifyError as exc:
            findings.append(
                _failure(
                    "signature_affirmation_payload_invalid",
                    h,
                    f"signature affirmation payload is invalid: {exc}",
                )
            )
            continue
        if not core._signature_entry_matches_record(row, record):
            findings.append(
                _failure(
                    "signature_catalog_mismatch",
                    h,
                    "signature catalog fields do not match the signed record",
                )
            )
    return findings


def _validate_intake_catalog(
    archive: dict[str, bytes],
    payload_blobs: dict[bytes, bytes],
    catalog_digest: bytes,
    event_by_hash: dict[bytes, core.EventDetails],
) -> list[WosFinding]:
    findings: list[WosFinding] = []
    cat_bytes = archive.get("063-intake-handoffs.cbor")
    if cat_bytes is None:
        return [
            _failure(
                "missing_intake_handoff_catalog",
                None,
                "export is missing 063-intake-handoffs.cbor",
            )
        ]
    if core._sha256(cat_bytes) != catalog_digest:
        findings.append(
            _failure(
                "intake_handoff_catalog_digest_mismatch",
                None,
                "intake handoff catalog digest does not match manifest extension",
            )
        )
    try:
        entries = core._parse_intake_manifest_entries(cat_bytes)
    except core.VerifyError as exc:
        return [
            _failure(
                "intake_handoff_catalog_invalid",
                None,
                f"intake handoff catalog is invalid: {exc}",
            )
        ]
    seen_row: set[bytes] = set()
    for entry in entries:
        h = entry["intake_event_hash"]
        if h in seen_row:
            findings.append(
                _failure(
                    "intake_handoff_catalog_duplicate_event",
                    h,
                    "intake handoff catalog repeats an intake event hash",
                )
            )
        seen_row.add(h)
    for entry in entries:
        findings.extend(_validate_intake_entry(entry, payload_blobs, event_by_hash))
    return findings


def _validate_intake_entry(
    entry: dict[str, Any],
    payload_blobs: dict[bytes, bytes],
    event_by_hash: dict[bytes, core.EventDetails],
) -> list[WosFinding]:
    findings: list[WosFinding] = []
    intake_h = entry["intake_event_hash"]
    det = event_by_hash.get(intake_h)
    if det is None:
        return [
            _failure(
                "intake_event_unresolved",
                intake_h,
                "intake catalog references an event absent from the export",
            )
        ]
    if det.event_type != WOS_INTAKE_ACCEPTED_EVENT_TYPE:
        return [
            _failure(
                "intake_event_type_mismatch",
                intake_h,
                "intake catalog event is not a WOS intakeAccepted event",
            )
        ]
    payload = core._readable_payload_bytes(det, payload_blobs)
    if payload is None:
        return [
            _failure(
                "intake_payload_unreadable",
                intake_h,
                "intakeAccepted payload is not readable",
            )
        ]
    try:
        intake_record = _parse_intake_accepted_record(
            payload, WOS_INTAKE_ACCEPTED_EVENT_TYPE
        )
    except core.VerifyError as exc:
        return [
            _failure(
                "intake_payload_invalid",
                intake_h,
                f"intakeAccepted payload is invalid: {exc}",
            )
        ]
    if not core._intake_entry_matches_record(entry, intake_record):
        findings.append(
            _failure(
                "intake_handoff_mismatch",
                intake_h,
                "intake handoff fields do not match the intakeAccepted record",
            )
        )
    ok, err_detail = core._response_hash_matches(
        entry["handoff"]["response_hash"], entry["response_bytes"]
    )
    if err_detail is not None:
        findings.append(
            _failure(
                "intake_handoff_catalog_invalid",
                intake_h,
                f"intake handoff response hash is invalid: {err_detail}",
            )
        )
    elif not ok:
        findings.append(
            _failure(
                "intake_response_hash_mismatch",
                intake_h,
                "intake handoff response hash does not match response bytes",
            )
        )

    handoff = entry["handoff"]
    mode = handoff["initiation_mode"]
    case_created_hash = entry["case_created_event_hash"]
    if mode == "workflowInitiated":
        if case_created_hash is not None:
            findings.append(
                _failure(
                    "case_created_handoff_mismatch",
                    intake_h,
                    "workflowInitiated handoff must not carry caseCreated event hash",
                )
            )
        return findings
    if mode != "publicIntake":
        findings.append(
            _failure(
                "intake_handoff_catalog_invalid",
                intake_h,
                "intake handoff initiationMode is unsupported",
            )
        )
        return findings
    if case_created_hash is None:
        findings.append(
            _failure(
                "case_created_handoff_mismatch",
                intake_h,
                "publicIntake handoff must carry caseCreated event hash",
            )
        )
        return findings
    case_details = event_by_hash.get(case_created_hash)
    if case_details is None:
        findings.append(
            _failure(
                "case_created_event_unresolved",
                case_created_hash,
                "caseCreated event hash is absent from the export",
            )
        )
        return findings
    if case_details.event_type != WOS_CASE_CREATED_EVENT_TYPE:
        findings.append(
            _failure(
                "case_created_event_type_mismatch",
                case_created_hash,
                "caseCreated hash does not reference a WOS caseCreated event",
            )
        )
        return findings
    case_payload = core._readable_payload_bytes(case_details, payload_blobs)
    if case_payload is None:
        findings.append(
            _failure(
                "case_created_payload_unreadable",
                case_created_hash,
                "caseCreated payload is not readable",
            )
        )
        return findings
    try:
        case_record = _parse_case_created_record(
            case_payload, WOS_CASE_CREATED_EVENT_TYPE
        )
    except core.VerifyError as exc:
        findings.append(
            _failure(
                "case_created_payload_invalid",
                case_created_hash,
                f"caseCreated payload is invalid: {exc}",
            )
        )
        return findings
    if not core._case_created_record_matches_handoff(entry, intake_record, case_record):
        findings.append(
            _failure(
                "case_created_handoff_mismatch",
                case_created_hash,
                "caseCreated fields do not match the intake handoff",
            )
        )
    return findings


def _validate_open_clock_export(
    archive: dict[str, bytes],
    manifest_map: dict,
    generated_at: core.TrellisTimestamp,
) -> list[WosFinding]:
    exts = core._map_lookup_optional_extensions(manifest_map)
    if exts is None or OPEN_CLOCKS_EXPORT_EXTENSION not in exts:
        return []
    catalog_bytes = archive.get(OPEN_CLOCKS_MEMBER)
    if catalog_bytes is None:
        return []
    try:
        catalog = core._parse_open_clocks_catalog(catalog_bytes)
    except core.VerifyError:
        return []
    if catalog["sealed_at"] != generated_at:
        return []
    return [
        _advisory(
            "open_clock_overdue:" + row["clock_id"] + ":" + core._hex(row["origin_event_hash"]),
            row["origin_event_hash"],
            "open statutory clock deadline is before export sealed_at",
        )
        for row in catalog["open_clocks"]
        if row["computed_deadline"] < catalog["sealed_at"]
    ]


def _parse_clock_record(payload_bytes: bytes, event_type: str) -> Optional[dict[str, Any]]:
    value = core._decode_value(payload_bytes)
    if not isinstance(value, dict):
        raise core.VerifyError("clock record root is not a map")
    payload_event = str(core._map_lookup_str(value, "event"))
    if payload_event != event_type:
        raise core.VerifyError("clock payload event does not match envelope event")
    data_value = value.get("data")
    if not isinstance(data_value, dict):
        raise core.VerifyError("clock record data is not a map")
    if event_type == WOS_GOVERNANCE_CLOCK_STARTED_EVENT_TYPE:
        calendar_ref = data_value.get("calendarRef")
        if calendar_ref is not None and not isinstance(calendar_ref, str):
            raise core.VerifyError("calendarRef must be a string or null")
        return {
            "clockId": str(core._map_lookup_str(data_value, "clockId")),
            "clockKind": str(core._map_lookup_str(data_value, "clockKind")),
            "calendarRef": calendar_ref,
        }
    if event_type != WOS_GOVERNANCE_CLOCK_RESOLVED_EVENT_TYPE:
        return None
    return {
        "clockId": str(core._map_lookup_str(data_value, "clockId")),
        "resolution": str(core._map_lookup_str(data_value, "resolution")),
    }


def _validate_clock_segments(
    events: list[core.ParsedSign1],
    payload_blobs: dict[bytes, bytes],
) -> list[WosFinding]:
    active: dict[str, dict[str, Any]] = {}
    paused: dict[str, dict[str, Any]] = {}
    findings: list[WosFinding] = []
    for event in events:
        try:
            details = core._decode_event_details(event)
        except core.VerifyError:
            continue
        # Spec contract (`trellis/specs/wos-trellis-verification.md` §3):
        # clock semantics gate on `event_type`, not on payload shape. A
        # non-clock event whose payload happens to deserialize as a clock
        # record MUST NOT participate in segment validation.
        if details.event_type not in (
            WOS_GOVERNANCE_CLOCK_STARTED_EVENT_TYPE,
            WOS_GOVERNANCE_CLOCK_RESOLVED_EVENT_TYPE,
        ):
            continue
        try:
            payload_bytes = core._readable_payload_bytes(details, payload_blobs)
            if payload_bytes is None:
                continue
            clock_record = _parse_clock_record(payload_bytes, details.event_type)
        except core.VerifyError:
            continue
        if clock_record is None:
            continue
        clock_id = clock_record["clockId"]
        if details.event_type == WOS_GOVERNANCE_CLOCK_STARTED_EVENT_TYPE:
            paused_segment = paused.pop(clock_id, None)
            if paused_segment is not None and (
                paused_segment["clockKind"] != clock_record["clockKind"]
                or paused_segment["calendarRef"] != clock_record["calendarRef"]
            ):
                findings.append(
                    _failure(
                        "clock_calendar_mismatch",
                        details.canonical_event_hash,
                        "resumed clock does not match paused clock kind or calendar reference",
                    )
                )
            active[clock_id] = {
                "clockKind": clock_record["clockKind"],
                "calendarRef": clock_record["calendarRef"],
            }
        elif clock_record["resolution"] == CLOCK_RESOLUTION_PAUSED:
            segment = active.pop(clock_id, None)
            if segment is not None:
                paused[clock_id] = segment
        else:
            active.pop(clock_id, None)
            paused.pop(clock_id, None)
    return findings


# ---------------------------------------------------------------
# WOS/Formspec implementation of the Trellis Core
# `ResponseProofResolver` Protocol. Reads consumer-domain field
# names (`data.signedPayloadDigest`, `data.signedPayloadDigestAlgorithm`,
# legacy `data.formspecResponseRef`, `data.signerId`) out of opaque
# payload bytes and returns a neutral `CertificateResponseProof` (or
# principal-ref string) to Trellis Core, or `None` if the payload is
# not a signing-event payload this resolver knows how to interpret.
#
# Mirror of Rust `trellis_verify_wos::WosFormspecResolver`. Phase N flips
# the malformed-digest branch from silent-skip to fail-closed
# `MalformedResponseDigestError`.
# ---------------------------------------------------------------


class WosFormspecResolver:
    """WOS/Formspec consumer-domain implementation of the Core
    `ResponseProofResolver` Protocol. Stateless; instantiate per-call.
    """

    def resolve(
        self, payload_bytes: bytes
    ) -> Optional[core.CertificateResponseProof]:
        try:
            value = core._decode_value(payload_bytes)
            if not isinstance(value, dict):
                return None
            data = core._map_lookup_map(value, "data")
        except core.VerifyError:
            return None

        # Keep this resolver intentionally narrower than the full
        # SignatureAffirmation parser: certificate response-proof checks only
        # need the response digest fields, and older ADR 0007 fixtures predate
        # later signed-act fields such as `signingActId`.
        if data.get("signedPayloadDigestAlgorithm") == "sha-256":
            digest_text = data.get("signedPayloadDigest")
            if isinstance(digest_text, str):
                try:
                    digest = core._parse_sha256_hex(digest_text)
                except (core.VerifyError, ValueError) as exc:
                    raise core.MalformedResponseDigestError(
                        f"signedPayloadDigest {digest_text!r} does not match "
                        f"sha-256 hex format (expected 64 hex chars)"
                    ) from exc
                return core.CertificateResponseProof(response_hash=digest)

        response_ref = data.get("formspecResponseRef")
        if not isinstance(response_ref, str):
            return None
        try:
            digest = core._parse_sha256_prefix_text(response_ref)
        except (core.VerifyError, ValueError):
            return None
        return core.CertificateResponseProof(response_hash=digest)

    def resolve_principal_ref(self, payload_bytes: bytes) -> Optional[str]:
        try:
            value = core._decode_value(payload_bytes)
            if not isinstance(value, dict):
                return None
            data = core._map_lookup_map(value, "data")
        except core.VerifyError:
            return None
        signer_id = data.get("signerId")
        if isinstance(signer_id, str):
            return signer_id
        return None


def _optional_str(value: Any) -> Optional[str]:
    """Return the string value or None if absent/null."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return None


def _parse_signature_affirmation_record(
    payload_bytes: bytes, expected_event: str
) -> dict[str, Any]:
    """Reads WOS-domain SignatureAffirmation record fields from an
    opaque payload. Moved here from `verify.py` per the Trellis Core
    dependency-inversion boundary: Core MUST NOT inspect WOS field
    names directly (ADR 0004).
    """
    v = core._decode_value(payload_bytes)
    if not isinstance(v, dict):
        raise core.VerifyError("signature affirmation payload root is not a map")
    _require_event(v, expected_event, "signature affirmation")
    data = core._map_lookup_map(v, "data")
    pr = data.get("profileRef")
    pk = data.get("profileKey")
    ib = core._map_lookup_map(data, "identityBinding")
    cr = core._map_lookup_map(data, "consentReference")
    return {
        "signer_id": str(core._map_lookup_str(data, "signerId")),
        "role_id": str(core._map_lookup_str(data, "roleId")),
        "role": str(core._map_lookup_str(data, "role")),
        "document_id": str(core._map_lookup_str(data, "documentId")),
        "document_ref": data.get("documentRef"),
        "document_hash": str(core._map_lookup_str(data, "documentHash")),
        "document_hash_algorithm": str(
            core._map_lookup_str(data, "documentHashAlgorithm")
        ),
        "signed_at": str(core._map_lookup_str(data, "signedAt")),
        "identity_binding": ib,
        "consent_reference": cr,
        "signature_provider": str(core._map_lookup_str(data, "signatureProvider")),
        "ceremony_id": str(core._map_lookup_str(data, "ceremonyId")),
        "source_signature_system": _optional_str(
            data.get("sourceSignatureSystem")
        ),
        "source_signature_id": _optional_str(
            data.get("sourceSignatureId")
        ),
        "signed_payload_digest": _optional_str(
            data.get("signedPayloadDigest")
        ),
        "signed_payload_digest_algorithm": _optional_str(
            data.get("signedPayloadDigestAlgorithm")
        ),
        "signing_intent": _optional_str(
            data.get("signingIntent")
        ),
        "profile_ref": str(pr) if isinstance(pr, str) else None,
        "profile_key": str(pk) if isinstance(pk, str) else None,
        "source_response_ref": core._map_lookup_str_alias(
            data, "sourceResponseRef", "formspecResponseRef"
        ),
        "signing_act_id": str(core._map_lookup_str(data, "signingActId")),
        "presentation_hash": str(core._map_lookup_str(data, "presentationHash")),
        "primitive_verification": data.get("primitiveVerification"),
        "witnessed_signature_ref": _optional_str(data.get("witnessedSignatureRef")),
    }


def _parse_signature_admission_failed_record(
    payload_bytes: bytes, expected_event: str
) -> dict[str, Any]:
    v = core._decode_value(payload_bytes)
    if not isinstance(v, dict):
        raise core.VerifyError("signature admission-failed payload root is not a map")
    _require_event(v, expected_event, "signature admission failed")
    data = core._map_lookup_map(v, "data")
    evidence = core._map_lookup_map(data, "evidenceBindings")
    return {
        "reason": str(core._map_lookup_str(data, "reason")),
        "response_id": str(core._map_lookup_str(evidence, "responseId")),
        "signed_payload_digest": str(
            core._map_lookup_str(evidence, "signedPayloadDigest")
        ),
        "signature_id": str(core._map_lookup_str(evidence, "signatureId")),
        "signing_intent": str(core._map_lookup_str(evidence, "signingIntent")),
        "signer_id": _optional_str(data.get("signerId")),
        "emitted_at": str(core._map_lookup_str(data, "emittedAt")),
    }


def _signature_affirmation_response_digest(record: dict[str, Any]) -> bytes:
    """Returns the response digest bytes referenced by a
    SignatureAffirmation record. Reads `signedPayloadDigest` (preferred)
    or legacy `formspecResponseRef`/`sourceResponseRef`."""
    if record.get("signed_payload_digest_algorithm") == "sha-256":
        return core._parse_sha256_hex(str(record["signed_payload_digest"]))
    legacy = record.get("source_response_ref")
    if isinstance(legacy, str):
        return core._parse_sha256_prefix_text(legacy)
    raise core.VerifyError("signature affirmation has no sha-256 response digest")


def _parse_intake_accepted_record(
    payload_bytes: bytes, expected_event: str
) -> dict[str, Any]:
    """Reads WOS-domain intakeAccepted fields from an opaque payload."""
    v = core._decode_value(payload_bytes)
    if not isinstance(v, dict):
        raise core.VerifyError("intake accepted payload root is not a map")
    _require_event(v, expected_event, "intake accepted")
    data = core._map_lookup_map(v, "data")
    case_ref = str(core._map_lookup_str(data, "caseRef"))
    outputs = core._map_lookup_array(v, "outputs")
    output_case_ref = core._first_array_text(outputs)
    if output_case_ref is None:
        raise core.VerifyError("intake accepted outputs array is missing or empty")
    if output_case_ref != case_ref:
        raise core.VerifyError("intake accepted outputs[0] does not match data.caseRef")
    return {
        "intake_id": str(core._map_lookup_str(data, "intakeId")),
        "case_intent": str(core._map_lookup_str(data, "caseIntent")),
        "case_disposition": str(core._map_lookup_str(data, "caseDisposition")),
        "case_ref": case_ref,
        "definition_url": core._map_lookup_optional_text(data, "definitionUrl"),
        "definition_version": core._map_lookup_optional_text(data, "definitionVersion"),
    }


def _parse_case_created_record(
    payload_bytes: bytes, expected_event: str
) -> dict[str, Any]:
    """Reads WOS-domain caseCreated record fields from an opaque
    payload. Moved here from `verify.py` per the Trellis Core
    dependency-inversion boundary (ADR 0004): Core MUST NOT inspect
    WOS field names directly."""
    v = core._decode_value(payload_bytes)
    if not isinstance(v, dict):
        raise core.VerifyError("case created payload root is not a map")
    _require_event(v, expected_event, "case created")
    data = core._map_lookup_map(v, "data")
    case_ref = str(core._map_lookup_str(data, "caseRef"))
    outputs = core._map_lookup_array(v, "outputs")
    output_case_ref = core._first_array_text(outputs)
    if output_case_ref is None:
        raise core.VerifyError("case created outputs array is missing or empty")
    if output_case_ref != case_ref:
        raise core.VerifyError("case created outputs[0] does not match data.caseRef")
    return {
        "case_ref": case_ref,
        "intake_handoff_ref": str(core._map_lookup_str(data, "intakeHandoffRef")),
        "formspec_response_ref": str(core._map_lookup_str(data, "formspecResponseRef")),
        "validation_report_ref": str(core._map_lookup_str(data, "validationReportRef")),
        "ledger_head_ref": str(core._map_lookup_str(data, "ledgerHeadRef")),
        "initiation_mode": str(core._map_lookup_str(data, "initiationMode")),
    }


def _require_event(value: dict[str, Any], expected: str, label: str) -> None:
    if "event" not in value:
        raise core.VerifyError("missing `event` value")
    event_value = value["event"]
    if not isinstance(event_value, str):
        raise core.VerifyError("`event` is not a text string")
    event = event_value
    if event != expected:
        raise core.VerifyError(f"{label} payload event is not {expected}")
