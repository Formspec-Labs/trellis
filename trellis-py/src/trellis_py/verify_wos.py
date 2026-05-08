"""WOS-domain verification composed with Trellis Core verification.

`trellis_py.verify` is the byte-integrity verifier. This module owns WOS
record semantics that depend on WOS event names, WOS record shapes, or
WOS-specific catalog interpretation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from trellis_py import verify as core


SIGNATURE_EXPORT_EXTENSION = "trellis.export.signature-affirmations.v1"
INTAKE_EXPORT_EXTENSION = "trellis.export.intake-handoffs.v1"
OPEN_CLOCKS_EXPORT_EXTENSION = "trellis.export.open-clocks.v1"
OPEN_CLOCKS_MEMBER = "open-clocks.json"
WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE = "wos.kernel.signatureAffirmation"
WOS_INTAKE_ACCEPTED_EVENT_TYPE = "wos.kernel.intakeAccepted"
WOS_CASE_CREATED_EVENT_TYPE = "wos.kernel.caseCreated"
WOS_IDENTITY_ATTESTATION_EVENT_TYPE = "wos.identity.identityAttestation"
WOS_GOVERNANCE_DETERMINATION_PREFIX = "wos.governance.determination"
WOS_GOVERNANCE_DETERMINATION_RESCINDED_EVENT_TYPE = (
    "wos.governance.determinationRescinded"
)
WOS_GOVERNANCE_REINSTATED_EVENT_TYPE = "wos.governance.reinstated"
CLOCK_STARTED_RECORD_KIND = "clockStarted"
CLOCK_RESOLVED_RECORD_KIND = "clockResolved"
CLOCK_RESOLUTION_PAUSED = "paused"


@dataclass
class WosFinding:
    kind: str
    event_hash: Optional[bytes]
    severity: str
    detail: str


@dataclass
class WosVerificationReport:
    trellis: core.VerificationReport
    wos_findings: list[WosFinding] = field(default_factory=list)

    @property
    def integrity_verified(self) -> bool:
        return self.trellis.integrity_verified and not any(
            finding.severity == "failure" for finding in self.wos_findings
        )


def verify_export_zip(export_zip: bytes) -> WosVerificationReport:
    trellis = core.verify_export_zip(
        export_zip,
        identity_event_type_admitted=_is_wos_identity_attestation_event_type,
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


def _validate_signature_catalog(
    archive: dict[str, bytes],
    payload_blobs: dict[bytes, bytes],
    catalog_digest: bytes,
    event_by_hash: dict[bytes, core.EventDetails],
) -> list[WosFinding]:
    findings: list[WosFinding] = []
    cat_bytes = archive.get("062-signature-affirmations.cbor")
    if cat_bytes is None:
        return [_failure("missing_signature_catalog", None, "062-signature-affirmations.cbor")]
    if core._sha256(cat_bytes) != catalog_digest:
        findings.append(
            _failure(
                "signature_catalog_digest_mismatch",
                None,
                "062-signature-affirmations.cbor",
            )
        )
    try:
        entries = core._parse_signature_catalog_entries(cat_bytes)
    except core.VerifyError as exc:
        return [
            _failure(
                "signature_catalog_invalid",
                None,
                f"062-signature-affirmations.cbor/{exc}",
            )
        ]
    seen_row: set[bytes] = set()
    for row in entries:
        h = row["canonical_event_hash"]
        if h in seen_row:
            findings.append(_failure("signature_catalog_duplicate_event", h, core._hex(h)))
        seen_row.add(h)
    for row in entries:
        h = row["canonical_event_hash"]
        det = event_by_hash.get(h)
        if det is None:
            findings.append(_failure("signature_catalog_event_unresolved", h, core._hex(h)))
            continue
        if det.event_type != WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE:
            findings.append(
                _failure("signature_catalog_event_type_mismatch", h, core._hex(h))
            )
            continue
        payload = core._readable_payload_bytes(det, payload_blobs)
        if payload is None:
            findings.append(
                _failure("signature_affirmation_payload_unreadable", h, core._hex(h))
            )
            continue
        try:
            record = _parse_signature_affirmation_record(payload)
        except core.VerifyError as exc:
            findings.append(
                _failure("signature_affirmation_payload_invalid", h, f"{core._hex(h)}/{exc}")
            )
            continue
        if not core._signature_entry_matches_record(row, record):
            findings.append(_failure("signature_catalog_mismatch", h, core._hex(h)))
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
        return [_failure("missing_intake_handoff_catalog", None, "063-intake-handoffs.cbor")]
    if core._sha256(cat_bytes) != catalog_digest:
        findings.append(
            _failure(
                "intake_handoff_catalog_digest_mismatch",
                None,
                "063-intake-handoffs.cbor",
            )
        )
    try:
        entries = core._parse_intake_manifest_entries(cat_bytes)
    except core.VerifyError as exc:
        return [
            _failure(
                "intake_handoff_catalog_invalid",
                None,
                f"063-intake-handoffs.cbor/{exc}",
            )
        ]
    seen_row: set[bytes] = set()
    for entry in entries:
        h = entry["intake_event_hash"]
        if h in seen_row:
            findings.append(_failure("intake_handoff_catalog_duplicate_event", h, core._hex(h)))
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
        return [_failure("intake_event_unresolved", intake_h, core._hex(intake_h))]
    if det.event_type != WOS_INTAKE_ACCEPTED_EVENT_TYPE:
        return [_failure("intake_event_type_mismatch", intake_h, core._hex(intake_h))]
    payload = core._readable_payload_bytes(det, payload_blobs)
    if payload is None:
        return [_failure("intake_payload_unreadable", intake_h, core._hex(intake_h))]
    try:
        intake_record = core._parse_intake_accepted_record(payload)
    except core.VerifyError as exc:
        return [_failure("intake_payload_invalid", intake_h, f"{core._hex(intake_h)}/{exc}")]
    if not core._intake_entry_matches_record(entry, intake_record):
        findings.append(_failure("intake_handoff_mismatch", intake_h, core._hex(intake_h)))
    ok, err_detail = core._response_hash_matches(
        entry["handoff"]["response_hash"], entry["response_bytes"]
    )
    if err_detail is not None:
        findings.append(
            _failure("intake_handoff_catalog_invalid", intake_h, f"{core._hex(intake_h)}/{err_detail}")
        )
    elif not ok:
        findings.append(_failure("intake_response_hash_mismatch", intake_h, core._hex(intake_h)))

    handoff = entry["handoff"]
    mode = handoff["initiation_mode"]
    case_created_hash = entry["case_created_event_hash"]
    if mode == "workflowInitiated":
        if case_created_hash is not None:
            findings.append(_failure("case_created_handoff_mismatch", intake_h, core._hex(intake_h)))
        return findings
    if mode != "publicIntake":
        return findings
    if case_created_hash is None:
        findings.append(_failure("case_created_handoff_mismatch", intake_h, core._hex(intake_h)))
        return findings
    case_details = event_by_hash.get(case_created_hash)
    if case_details is None:
        findings.append(_failure("case_created_event_unresolved", case_created_hash, core._hex(case_created_hash)))
        return findings
    if case_details.event_type != WOS_CASE_CREATED_EVENT_TYPE:
        findings.append(_failure("case_created_event_type_mismatch", case_created_hash, core._hex(case_created_hash)))
        return findings
    case_payload = core._readable_payload_bytes(case_details, payload_blobs)
    if case_payload is None:
        findings.append(_failure("case_created_payload_unreadable", case_created_hash, core._hex(case_created_hash)))
        return findings
    try:
        case_record = _parse_case_created_record(case_payload)
    except core.VerifyError as exc:
        findings.append(_failure("case_created_payload_invalid", case_created_hash, f"{core._hex(case_created_hash)}/{exc}"))
        return findings
    if not core._case_created_record_matches_handoff(entry, intake_record, case_record):
        findings.append(_failure("case_created_handoff_mismatch", case_created_hash, core._hex(case_created_hash)))
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


def _parse_clock_record(payload_bytes: bytes) -> Optional[dict[str, Any]]:
    value = core._decode_value(payload_bytes)
    if not isinstance(value, dict):
        raise core.VerifyError("clock record root is not a map")
    record_kind = str(core._map_lookup_str(value, "recordKind"))
    if record_kind not in (CLOCK_STARTED_RECORD_KIND, CLOCK_RESOLVED_RECORD_KIND):
        return None
    data_value = value.get("data")
    if not isinstance(data_value, dict):
        raise core.VerifyError("clock record data is not a map")
    if record_kind == CLOCK_STARTED_RECORD_KIND:
        calendar_ref = data_value.get("calendarRef")
        if calendar_ref is not None and not isinstance(calendar_ref, str):
            raise core.VerifyError("calendarRef must be a string or null")
        return {
            "recordKind": record_kind,
            "clockId": str(core._map_lookup_str(data_value, "clockId")),
            "clockKind": str(core._map_lookup_str(data_value, "clockKind")),
            "calendarRef": calendar_ref,
        }
    return {
        "recordKind": record_kind,
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
            payload_bytes = core._readable_payload_bytes(details, payload_blobs)
            if payload_bytes is None:
                continue
            clock_record = _parse_clock_record(payload_bytes)
        except core.VerifyError:
            continue
        if clock_record is None:
            continue
        clock_id = clock_record["clockId"]
        if clock_record["recordKind"] == CLOCK_STARTED_RECORD_KIND:
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
# Mirror of Rust `trellis_verify_wos::WosFormspecResolver`. Phase M
# leaves malformed-digest as silent-skip; Phase N flips it to
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
            record = _parse_signature_affirmation_record(payload_bytes)
        except core.VerifyError:
            return None
        try:
            digest = _signature_affirmation_response_digest(record)
        except core.VerifyError:
            # Phase M posture: source SignatureAffirmation carries no
            # sha-256 signed payload digest or legacy response digest;
            # silent-skip so Phase-1 admits signing-only shapes.
            # Phase N replaces this with
            # `raise core.MalformedResponseDigestError(...)`.
            return None
        return core.CertificateResponseProof(response_hash=digest)

    def resolve_principal_ref(self, payload_bytes: bytes) -> Optional[str]:
        try:
            record = _parse_signature_affirmation_record(payload_bytes)
        except core.VerifyError:
            return None
        signer_id = record.get("signer_id")
        if isinstance(signer_id, str):
            return signer_id
        return None


def _parse_signature_affirmation_record(payload_bytes: bytes) -> dict[str, Any]:
    """Reads WOS-domain SignatureAffirmation record fields from an
    opaque payload. Moved here from `verify.py` per the Trellis Core
    dependency-inversion boundary: Core MUST NOT inspect WOS field
    names directly (ADR 0004).
    """
    v = core._decode_value(payload_bytes)
    if not isinstance(v, dict):
        raise core.VerifyError("signature affirmation payload root is not a map")
    rk = str(core._map_lookup_str(v, "recordKind"))
    if rk != "signatureAffirmation":
        raise core.VerifyError("recordKind is not signatureAffirmation")
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
        "document_hash": str(core._map_lookup_str(data, "documentHash")),
        "document_hash_algorithm": str(
            core._map_lookup_str(data, "documentHashAlgorithm")
        ),
        "signed_at": str(core._map_lookup_str(data, "signedAt")),
        "identity_binding": ib,
        "consent_reference": cr,
        "signature_provider": str(core._map_lookup_str(data, "signatureProvider")),
        "ceremony_id": str(core._map_lookup_str(data, "ceremonyId")),
        "source_signature_system": str(
            core._map_lookup_str(data, "sourceSignatureSystem")
        ),
        "source_signature_id": str(core._map_lookup_str(data, "sourceSignatureId")),
        "signed_payload_digest": str(core._map_lookup_str(data, "signedPayloadDigest")),
        "signed_payload_digest_algorithm": str(
            core._map_lookup_str(data, "signedPayloadDigestAlgorithm")
        ),
        "signing_intent": str(core._map_lookup_str(data, "signingIntent")),
        "profile_ref": str(pr) if isinstance(pr, str) else None,
        "profile_key": str(pk) if isinstance(pk, str) else None,
        "source_response_ref": core._map_lookup_str_alias(
            data, "sourceResponseRef", "formspecResponseRef"
        ),
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


def _parse_case_created_record(payload_bytes: bytes) -> dict[str, Any]:
    """Reads WOS-domain caseCreated record fields from an opaque
    payload. Moved here from `verify.py` per the Trellis Core
    dependency-inversion boundary (ADR 0004): Core MUST NOT inspect
    WOS field names directly."""
    v = core._decode_value(payload_bytes)
    if not isinstance(v, dict):
        raise core.VerifyError("case created payload root is not a map")
    record_kind = str(core._map_lookup_str(v, "recordKind"))
    if record_kind != "caseCreated":
        raise core.VerifyError("case created payload recordKind is not caseCreated")
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
