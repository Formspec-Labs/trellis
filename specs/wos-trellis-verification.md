# WOS-Trellis Verification

**Status:** Normative for WOS deployments that compose Trellis export
verification with WOS record semantics.

**Scope:** This document defines the WOS-domain validator that runs beside
Trellis Core verification. Trellis Core remains authoritative for byte
structure, COSE signatures, hash links, checkpoint roots, inclusion proofs,
consistency proofs, and registered export-member digest binding.

## 1. Boundary

A WOS verifier MUST first run Trellis Core verification. If Core verification
cannot decode the export or event set, WOS validation MUST NOT reinterpret the
failure as a WOS finding.

WOS validation receives only Core-derived evidence:

- event type strings,
- canonical event hashes,
- chain order,
- authored timestamps,
- readable payload bytes when included,
- registered export extension payload bytes,
- registered export member bytes.

WOS validation MUST NOT depend on live WOS runtime state, task queues, service
databases, caches, or mutable APIs. It MAY use WOS schemas and record parsers
compiled into the verifier.

## 2. Event Types

The WOS validator owns the following event-type literals:

| Literal | Meaning |
|---|---|
| `wos.kernel.signature_affirmation` | Signature provenance event. |
| `wos.kernel.intake_accepted` | Intake-acceptance provenance event. |
| `wos.kernel.case_created` | Governed-case creation provenance event. |
| `wos.governance.determination_rescinded` | Rescission closes the current determination chain. |
| `wos.governance.reinstated` | Reinstatement reopens the current determination chain. |
| `wos.governance.determination*` | Determination-family event prefix for rescission terminality. |
| `wos.governance.clock_started` | Statutory-clock start/resume provenance event. |
| `wos.governance.clock_resolved` | Statutory-clock resolution provenance event. |

These literals MUST NOT be required by a Trellis Core verifier.

## 3. Requirements

| ID | Requirement |
|---|---|
| WOS-TV-001 | The WOS validator MUST report its findings separately from the Core `VerificationReport` or mark composed findings so callers can distinguish WOS-domain failures from Core integrity failures. |
| WOS-TV-002 | After a chain carries `wos.governance.determination_rescinded`, the WOS validator MUST report `rescission_terminality_violation` for any later same-chain `wos.governance.determination*` event unless an intervening `wos.governance.reinstated` event reopens the chain. |
| WOS-TV-003 | When a `wos.governance.clock_resolved` event carries a `clockResolved` record with `resolution = "paused"`, the next resumed `wos.governance.clock_started` segment for the same `clockId` MUST carry the same `calendarRef` as the paused segment. A mismatch is `clock_calendar_mismatch`. |
| WOS-TV-004 | If `trellis.export.signature-affirmations.v1` is present, `062-signature-affirmations.cbor` MUST be present and its SHA-256 digest MUST equal `signature_catalog_digest`. |
| WOS-TV-005 | Each signature catalog row MUST resolve `canonical_event_hash` to exactly one exported `wos.kernel.signature_affirmation` event and MUST field-match the decoded WOS `SignatureAffirmation` record for every catalogued field. Nested CBOR maps such as identity binding and consent reference compare semantically under RFC 8949 canonical map ordering, not by source map-entry order. |
| WOS-TV-006 | Signature catalog rows MUST NOT duplicate `canonical_event_hash`. |
| WOS-TV-007 | If `trellis.export.intake-handoffs.v1` is present, `063-intake-handoffs.cbor` MUST be present and its SHA-256 digest MUST equal `intake_catalog_digest`. |
| WOS-TV-008 | Each intake catalog row MUST resolve `intake_event_hash` to exactly one exported `wos.kernel.intake_accepted` event and MUST field-match the decoded WOS `IntakeAccepted` record against the included Formspec `IntakeHandoff`. |
| WOS-TV-009 | The WOS validator MUST recompute `handoff.responseHash` over the catalogued canonical Response bytes. A mismatch is an intake-handoff finding. |
| WOS-TV-010 | If `case_created_event_hash` is present, it MUST resolve to exactly one exported `wos.kernel.case_created` event and MUST field-match the decoded WOS `CaseCreated` record against the handoff evidence refs and created case ref. |
| WOS-TV-011 | If `handoff.initiationMode = "workflowInitiated"`, `case_created_event_hash` MUST be absent. If `handoff.initiationMode = "publicIntake"`, `case_created_event_hash` MUST be present. |
| WOS-TV-012 | Intake catalog rows MUST NOT duplicate `intake_event_hash`. |
| WOS-TV-013 | If `trellis.export.open-clocks.v1` is present, each `open-clocks.json` row whose `computed_deadline` is before catalog `sealed_at` MUST be reported as an advisory WOS finding. This advisory MUST NOT by itself fail composed integrity. |

## 4. WOS Tamper Kinds

WOS composed reports may use these `tamper_kind` values in fixture manifests and
human-facing diagnostics:

| `tamper_kind` | Requirement |
|---|---|
| `rescission_terminality_violation` | WOS-TV-002 |
| `clock_calendar_mismatch` | WOS-TV-003 |
| `signature_catalog_digest_mismatch` | WOS-TV-004 |
| `intake_handoff_catalog_digest_mismatch` | WOS-TV-007 |

Additional localizable WOS finding kinds MAY be emitted by implementations for
missing catalogs, malformed catalogs, duplicate rows, unresolved event hashes,
wrong event types, and field mismatches. Fixture `tamper_kind` values remain the
stable compatibility vocabulary; implementation-specific subcodes should be
reported as WOS findings, not added to the Core enum.

## 5. Implementation Mapping

The Rust implementation lives in `crates/trellis-verify-wos`. It depends on
`trellis-verify` and composes through the Core domain-validator seam. It MUST
not introduce a dependency from `trellis-verify` back to WOS runtime crates.
