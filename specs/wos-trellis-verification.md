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

The composed WOS report has three surfaces:

- `substrate`: the unchanged Trellis Core `VerificationReport`.
- `domain`: WOS findings and domain projections derived only from Core-derived
  evidence.
- `verdict`: a relying-party summary with `cryptographic_integrity`,
  `projection_integrity`, `domain_admissibility`, `relying_party_result`, and
  `blocking_reasons`.

`cryptographic_integrity` is derived only from the substrate report.
`projection_integrity` fails for SignedAct projection/catalog failures.
`domain_admissibility` fails for non-projection WOS failures. The final
`relying_party_result` is `valid` only when all blocking tiers pass.

## 2. Event Types

The WOS validator owns the following event-type literals:

| Literal | Meaning |
|---|---|
| `wos.kernel.signature_affirmation` | Signature provenance event. |
| `wos.kernel.signature_admission_failed` | Failed signature-admission provenance event. |
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
| WOS-TV-001 | The WOS validator MUST report its findings separately from the Core `VerificationReport` and MUST expose a relying-party verdict that distinguishes substrate cryptographic integrity, projection integrity, and domain admissibility. |
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
| WOS-TV-014 | If `trellis.export.signed-acts.v1` is present, `066-signed-acts.cbor` MUST be present. If `066-signed-acts.cbor` is present without the extension, the WOS validator MUST report `signed_acts_catalog_unbound`. |
| WOS-TV-014a | `068-signed-acts-manifest.cbor` is a byte-deterministic canonical CBOR array of 2-element arrays `[bstr(canonical_event_hash), tstr(event_type)]`, one entry per covered source event, sorted in ascending order by `(canonical_event_hash bytes ASC, event_type ASC)`. The event scope is `wos.kernel.signature_affirmation` AND `wos.kernel.signature_admission_failed` — the same event scope as the 066 signed-acts catalog. Both Rust (`trellis-verify-wos::derive_signed_acts_manifest_v1`) and conformant runtime derivations MUST produce byte-identical output for identical input event sets. Encoding follows the §4.2.2 Canonical CBOR profile in `specs/canonical-cbor-profile.md`. |
| WOS-TV-015 | The `trellis.export.signed-acts.v1` extension MUST be a CBOR map carrying `catalog_digest`, `catalog_ref = "066-signed-acts.cbor"`, and `derivation_rule`. The `derivation_rule` value MUST resolve to a verifier-registered derivation rule; today's registry contains `signed-act-projection-wos-formspec-v1` and `signed-act-projection-wos-formspec-v2`. Invalid extension shape, an unsupported derivation rule, or an invalid catalog member is `signed_acts_catalog_invalid`; absent member is `missing_signed_acts_catalog`. |
| WOS-TV-015a | The `derivation_rule = "signed-acts-manifest-v1"` value in `trellis.export.signed-acts.manifest.v1` is a stable identifier. Any change to the manifest derivation logic MUST introduce a new `derivation_rule` value (`"signed-acts-manifest-v2"`, etc.) AND a new extension key (`trellis.export.signed-acts.manifest.v2`, etc.). Verifiers MUST treat an unknown `derivation_rule` as a structural failure per Core §6.7 reject-if-unknown-at-version. The rule identifier is not versioned independently of the extension key; they advance together. |
| WOS-TV-016 | The SHA-256 digest of `066-signed-acts.cbor` MUST equal `catalog_digest`. A mismatch is `signed_acts_catalog_digest_mismatch`. |
| WOS-TV-017 | The WOS validator MUST deterministically rederive the SignedAct catalog from every readable exported `wos.kernel.signature_affirmation` and `wos.kernel.signature_admission_failed` event and compare it byte-for-byte to the committed `066-signed-acts.cbor` member. A mismatch is advisory `signed_acts_render_drift`: the 066 catalog is a render-time projection whose bytes may legitimately drift across renderers, and the substrate-anchored `068-signed-acts-manifest.cbor` member (Task A1 §6.7) is the load-bearing proof of which signed-act source events landed. Render drift on the 066 surface alone MUST NOT block the relying-party verdict. Substrate-shape failures on the 066 surface — missing catalog, digest mismatch, catalog unbound, invalid CBOR, unsupported derivation rule — remain blocking under WOS-TV-014 through WOS-TV-016 and WOS-TV-018. |
| WOS-TV-018 | The SignedAct catalog root MUST be canonical CBOR with `projection_schema_version = 1`, `derivation_rule_id` equal to the manifest-extension `derivation_rule`, and `acts`. Projected rows that share an `act_id` MUST be correlated before row sorting: rows with identical projected fields except `source_refs` merge their `source_refs`, while rows with divergent projected fields make the catalog invalid with `act_correlation_conflict` detail. Rows MUST be sorted by `(act_id, signed_at, first source_ref canonical bytes)`, and every `source_refs` entry MUST be unique across the catalog. |
| WOS-TV-018a | The `066-signed-acts.cbor` catalog mismatch finding (`signed_acts_render_drift`) is **advisory** severity. The `068-signed-acts-manifest.cbor` member, bound via `trellis.export.signed-acts.manifest.v1`, is the substrate-anchored verdict-bound proof of which signed-act source events landed in the chain. The 066 catalog is a render-time projection carrying act-level fields and source references; its bytes may legitimately differ across renderers or across re-renders of the same event set under non-structural schema evolution without invalidating the bundle's cryptographic integrity. A `signed_acts_render_drift` finding MUST NOT by itself cause `relying_party_result = invalid`. Structural failures on the 066 surface (`signed_acts_catalog_invalid`, `signed_acts_catalog_digest_mismatch`, `signed_acts_catalog_unbound`, `missing_signed_acts_catalog`) remain blocking. |
| WOS-TV-019 | A SignedAct row derived from `wos.kernel.signature_affirmation` MUST project signer, bound subject, intent, consent, admission, witness, timestamp, and source-reference fields from the signed WOS record only. Under `signed-act-projection-wos-formspec-v1`, `act_id` MUST come from `data.signingActId`. Under `signed-act-projection-wos-formspec-v2`, `act_id` MUST use `data.signingActId` when present and otherwise derive as `signed-act-projection-act-id-v1:<lowercase_hex(sha256(preimage))>` where `preimage` is the encoding of the sorted `source_refs` array under the §4.2.2 Canonical CBOR profile in `specs/canonical-cbor-profile.md` (recursive map-key sort, duplicate-key rejection, finite-float-only, definite-length only). The rule identifier itself serves as the domain namespace; no additional separation tag is applied. Missing `signingIntent` is a closed failure, not an advisory. |
| WOS-TV-020 | A SignedAct row derived from `wos.kernel.signature_admission_failed` MUST set `admission.outcome = "rejected"` and carry the failure reason and evidence-binding values from the signed WOS record. |
| WOS-TV-021 | `066-signed-acts.cbor` is a verifier/reporting projection only. A WOS validator MUST NOT accept a signature, failure, signer, response reference, or bound-subject claim solely because it appears in the projection; the signed source event remains the authority. |
| WOS-TV-022 | If `trellis.export.policy-closure.v1` is present, `067-policy-closure.cbor` MUST be present. If `067-policy-closure.cbor` is present without the extension, the WOS validator MUST report `policy_closure_unbound`. |
| WOS-TV-023 | The `trellis.export.policy-closure.v1` extension MUST be a CBOR map carrying `closure_digest`, `closure_ref = "067-policy-closure.cbor"`, and `closure_version`. Invalid extension shape or an invalid closure member is `policy_closure_invalid`; absent member is `missing_policy_closure`. |
| WOS-TV-024 | The SHA-256 digest of `067-policy-closure.cbor` MUST equal `closure_digest`. A mismatch is `policy_closure_digest_mismatch`. |
| WOS-TV-025 | `067-policy-closure.cbor` MUST be canonical CBOR with `closure_schema_version = 1`, a `closure_version` that matches the manifest extension, a `verifier_boundary` map, and a non-empty `artifacts` array. |
| WOS-TV-026 | The `verifier_boundary` MUST state that the bundle supplies admission-policy evidence, not authoritative trust roots, verifier adapter allowlists, or server operational configuration. The `artifacts` array MUST cover effective intent URI, method URI, posture-floor, signer-authority-shape, identity-proofing-primitive, default, deny-rule, tombstone, and validity-window inputs that could change whether a signature act was admitted. |
| WOS-TV-027 | If an export contains one or more `wos.kernel.signature_affirmation` events and has neither `trellis.export.policy-closure.v1` nor `067-policy-closure.cbor`, the WOS validator MUST report advisory `policy_closure_missing_for_signed_scope`. This advisory MUST NOT by itself fail composed integrity and MUST NOT be emitted for exports with no signature-affirmation events. **Rationale:** the advisory fires only on signed-scope evidence, not on admission-failed-only exports. A `signature_admission_failed` event records a rejection along with the reason taxonomy and is its own self-describing failure record; it does not produce signed-scope evidence whose admission claim needs policy-closure protection. An export containing only admission-failed events has no signed scope to obscure; the advisory's purpose — flagging ambiguous admission-policy state for legitimately signed acts — does not apply. |

## 4. SignedAct Projection

`066-signed-acts.cbor` is the verifier-facing signing projection for
WOS/Formspec exports. It exists to give auditors one compact signing ledger
surface without making a presentation artifact, PDF, or projection row the
source of truth.

The catalog root is canonical CBOR:

```text
{
  "projection_schema_version": 1,
  "derivation_rule_id": "<manifest derivation_rule>",
  "acts": [...]
}
```

`derivation_rule_id` matches the manifest-extension `derivation_rule`. The
registered WOS/Formspec rules are:

- `signed-act-projection-wos-formspec-v1`: strict shared-id projection.
- `signed-act-projection-wos-formspec-v2`: shared-id projection with fallback
  `act_id` derivation for source rows that do not carry `data.signingActId`.

For `wos.kernel.signature_affirmation`, each act row has:

- `act_id` from `data.signingActId` under v1; under v2, from
  `data.signingActId` when present, otherwise from
  `signed-act-projection-act-id-v1:<hex_sha256>` over the canonical CBOR bytes
  of the sorted `source_refs` array.
- `signer` with `id`, `role`, `role_ref`, and `identity_evidence_refs`.
- `bound` with `subject_kind = "formspec-response"`, the signed response digest, presentation hash, document id/ref, document content hash, and hash algorithms.
- `intent` from `data.signingIntent`.
- `consent` from `data.consentReference`.
- `admission` with `outcome = "admitted"` and the source response, signature, provider, signing policy, and primitive-verification fields.
- `witness_of`, `signed_at`, and `source_refs`.

For `wos.kernel.signature_admission_failed`, each act row has
`admission.outcome = "rejected"` and carries `failure_reason` plus the
evidence-binding values needed to identify the rejected response/signature.

`source_refs` entries are maps `{ layer, kind, ref }` with `layer = "wos"`,
`kind = "signature-affirmation"` or `"signature-admission-failed"`, and
`ref = canonical_event_hash`. Source refs are sorted by `(layer, kind, ref)`
using canonical CBOR bytes for `ref`; catalog rows are sorted by
`(act_id, signed_at, first source_ref canonical bytes)`.

Before row sorting, derived acts are correlated by `act_id`. If two source rows
produce the same `act_id` and the same projected fields except `source_refs`,
the catalog carries one row with the sorted union of source refs. If the same
`act_id` has divergent projected fields, the catalog is invalid as
`signed_acts_catalog_invalid` with `act_correlation_conflict` diagnostic
detail. Exact duplicate `source_refs` remain invalid across the catalog.

Nulls are explicit. A missing optional WOS source field projects as `null`.
Malformed required fields fail the projection. No relying party may treat the
projection as independent evidence; every claim in it must be recoverable from
the signed WOS source event.

## 5. Effective Policy Closure

`067-policy-closure.cbor` is bundle-resident admission-policy evidence for
WOS/Formspec exports. It is intentionally narrower than "configuration": it
travels with the bundle only when it could change whether a signed act was
admitted. Verifier trust roots, verifier adapter allowlists, and server runtime
environment variables remain verifier- or operator-supplied configuration and
MUST NOT be treated as authoritative because they appear in this member.

The closure root is canonical CBOR:

```text
{
  "closure_schema_version": 1,
  "closure_version": tstr,
  "sealed_at": tstr,
  "owner_scope": tstr,
  "verifier_boundary": {
    "bundle_admission_policy_evidence": true,
    "bundle_trust_roots_authoritative": false,
    "verifier_supplied_trust_roots_required": true,
    "verifier_supplied_adapter_allowlists_required": true,
    "server_operational_config_included": false
  },
  "artifacts": [...]
}
```

Each artifact row carries `owner`, `kind`, `version`, `ref`,
`digest_algorithm = "sha-256"`, `digest`, `valid_from`, and `valid_to`. Rows
may point at public registries or owner-local policy snapshots, but the digest
and validity window in the closure are the effective evidence for the exported
bundle. Required artifact kinds are:

- `formspec.signing-intent-registry.v1`
- `formspec.signature-method-registry.v1`
- `wos.signature-posture-floors.v1`
- `wos.signer-authority-shape.v1`
- `wos.identity-proofing-primitives.v1`
- `wos.signature-defaults.v1`
- `wos.signature-deny-rules.v1`
- `wos.signature-tombstones.v1`

An export that contains signature-affirmation events but omits both the policy
closure extension and member has no verifier-available evidence for the
admission policy in force for those signatures. The WOS validator reports this
as advisory `policy_closure_missing_for_signed_scope`; the absence remains a
valid no-policy-claim branch for exports with no signature-affirmation events.

## 6. WOS Tamper Kinds

WOS composed reports may use these `tamper_kind` values in fixture manifests and
human-facing diagnostics:

| `tamper_kind` | Requirement |
|---|---|
| `rescission_terminality_violation` | WOS-TV-002 |
| `clock_calendar_mismatch` | WOS-TV-003 |
| `signature_catalog_digest_mismatch` | WOS-TV-004 |
| `intake_handoff_catalog_digest_mismatch` | WOS-TV-007 |
| `missing_signed_acts_catalog` | WOS-TV-014 / WOS-TV-015 |
| `missing_policy_closure` | WOS-TV-022 / WOS-TV-023 |
| `policy_closure_digest_mismatch` | WOS-TV-024 |
| `policy_closure_invalid` | WOS-TV-023 / WOS-TV-025 / WOS-TV-026 |
| `policy_closure_unbound` | WOS-TV-022 |
| `signed_acts_catalog_digest_mismatch` | WOS-TV-016 |
| `signed_acts_catalog_invalid` | WOS-TV-015 / WOS-TV-018 |
| `signed_acts_catalog_unbound` | WOS-TV-014 |
| `signed_acts_render_drift` | WOS-TV-017 (advisory) / WOS-TV-018a (advisory) |
| `signed_acts_manifest_mismatch` | TR-CORE-180 (blocking) |
| `signed_acts_manifest_extension_digest_mismatch` | TR-CORE-180 (blocking) |
| `signed_acts_manifest_missing_member` | TR-CORE-180 (blocking) |
| `signed_acts_manifest_member_unbound` | TR-CORE-180 (blocking) |

Additional localizable WOS finding kinds MAY be emitted by implementations for
missing catalogs, malformed catalogs, duplicate rows, unresolved event hashes,
wrong event types, and field mismatches. Fixture `tamper_kind` values remain the
stable compatibility vocabulary; implementation-specific subcodes should be
reported as WOS findings, not added to the Core enum.

## 7. Implementation Mapping

The Rust implementation lives in `crates/trellis-verify-wos`. It depends on
`integrity-verify::trellis` and composes through the Core domain-validator seam.
It MUST not introduce a dependency from the integrity verifier back to WOS
runtime crates.
