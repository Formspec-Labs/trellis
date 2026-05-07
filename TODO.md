# Trellis — TODO

Forward-looking work sorted for the PROD-MVP release schedule. Priority still
tracks `Importance × Debt`; size tags are scheduling hints, never priority
inputs. Concurrent where prerequisites allow, under the ratified `v1.0.0`
Core + Companion surface.

Size: **XS** (≤1h) · **S** (≤1 session) · **M** (≤3 sessions) · **L** (multi-session).

---

## Gate — validated principles + ADRs

[`thoughts/adr/0001-0004-phase-1-mvp-principles-and-format-adrs.md`](thoughts/adr/0001-0004-phase-1-mvp-principles-and-format-adrs.md)
holds 7 principles and 4 decided ADRs: **DAG envelope with length-1 runtime**
(0001), **list-form anchors with single-anchor default** (0002), **§22/§24
reservations held but `MUST NOT populate`** (0003), **Rust as byte authority,
Python as cross-check** (0004). Filename keeps the deprecated `phase-1-mvp` slug.

Status: **accepted and ratified into `v1.0.0`**. Closed work lives in
[`COMPLETED.md`](COMPLETED.md) and [`ratification/ratification-checklist.md`](ratification/ratification-checklist.md).

**`v1.0.0` is a coherent-snapshot tag, not a freeze.** Nothing is released; no
production records exist. Architectural change that prevents future debt → make
it and retag. The revision window stays open until real adopters close it.

---

## Open

Ordered by PROD-MVP release schedule, then `Importance × Debt` inside each
band. Each item names its prerequisite inline.

**Cross-repo pointer — parent PLANNING.md.** Stack-wide rows live as `PLN-XXXX`
in [`/PLANNING.md`](../PLANNING.md). Items 1-14 + 17 cite parent rows;
items 15-16 + 18-24 are Trellis-internal envelope/verifier discipline
with no parent counterpart. **#15** (verify-layer domain coupling extraction)
is deferred architectural debt from the 2026-05-06 DI audit — `trellis-verify`
carries WOS/Formspec domain knowledge that should live in a consumer-owned crate.
The MVP-foundation cluster (PLN-0331..0349) consumes
`trellis-cose` / `trellis-verify` downstream — keep the public APIs stable for
composition. Cross-submodule Cargo path-dep posture is parent **PLN-0368**;
Trellis complies with the chosen pattern when it lands.

**`trellis-store-postgres` ↔ downstream `EventStore`:** the Postgres canonical
store (Wave 16/18 hardening + `append_event_in_tx`) is the Trellis-side half of
the composed reference-server write path. WOS-side Postgres adapter work is
parent **PLN-0332**, gated by **PLN-0368**, and reconciles the current
[`workspec-server/crates/wos-server/TODO.md`](../workspec-server/crates/wos-server/TODO.md)
**WS-020** / **WS-090** two-port scaffold into one Trellis-backed `EventStore`;
**WS-095** is the embedded / `trellis-store-memory` sibling, not the production
Postgres adapter. Keep `append_event_in_tx` and migration discipline stable; no
new TODO row unless a gap blocks the adapter.

**Signature-stack cluster** (everything about signatures): items **#2** + **#3**
(WOS-T4 + ADR 0073 shared-fixture residue), **#4** (identity attestation,
supersedes PLN-0310 → PLN-0381), **#13** (external recipient lifecycle,
parent PLN-0382), **#17** (tenant-scope export bundles spanning multiple
ledger scopes, parent PLN-0392).

ADR 0010 user-content Attestation primitive (closed Wave 23,
`b1b23ce..74cd52d`), `c2pa-manifest@v1` adapter (closed Wave 25,
`3eda94d..<commit-5-sha>`), and `custody-hook-encoding.md` v1.0 + Wave 27
PLN-0385 wire-shape drift correction (closed Wave 27 — see
[`COMPLETED.md`](COMPLETED.md); the four-field surface is `caseId` /
`recordId` / `eventType` / `record` per ADR-0061 §2.3, NOT the phantom
`tag` / `payload` / `prior_event_hash` / `producer_signature` cited in
the original PLN-0385 prose — Trellis chain linkage uses CDDL **`prev_hash`**
(Core §10.2); Respondent Ledger **`priorEventHash`** binds to that value when
wrapped; signing stays **COSE_Sign1** on the envelope. Trellis
owns the integrity artifact bytes; WOS owns the semantics. Both compose
under PLN-0379 + PLN-0380. Parent stack closure cluster spans
PLN-0379..0398 plus PLN-0355 (ESIGN gate, Trigger) and PLN-0370 (DocuSign
reframe).

**Cross-repo pointer — WOS Runtime §15 (Formspec coprocessor):** no Trellis-
center tasks for the core handoff. Processor and HTTP parity work lives in
parent [`work-spec/TODO.md`](../work-spec/TODO.md) **#66** and
[`workspec-server/crates/wos-server/TODO.md`](../workspec-server/crates/wos-server/TODO.md)
**WS-011**, **WS-074–WS-075** (plus **WS-072** for ADR 0066 server surfaces
once ratified). Items **#11** (ADR 0066) and **#16** (case ledger) may later
consume amended responses.

**Cross-repo pointer — ADR 0082 (Stack Public REST API Contract, accepted
2026-05-05):** no Trellis-center tasks. The WOS public REST API authored
this cycle composes Trellis at three seams without changing Trellis bytes:
(1) `bundle.schema.json` exposes `GET /api/v1/bundles/{urn}/download`
streaming Trellis Core §18 export-package bytes verbatim
(`Content-Type: application/cbor`); `Bundle.certificateOfCompletionDigest`
references Trellis ADR 0007's `presentation_artifact.content_hash`;
(2) `audit.schema.json` `AuditAttestationView` composes with item **#4**
PLN-0381 identity-attestation bundle shape — projection-only, the canonical
identity-attestation home stays Trellis-side; (3) parent **PLN-0408**
adds a `bundle-completed` literal to `NotificationType` so consumers
discover Trellis bundle completion via the notification feed instead of
polling. New parent **PLN-0407** + **PLN-0408** rows are WOS-API-internal;
new parent **PLN-0401** (utoipa) / **PLN-0402** (legacy-route deletion) /
**PLN-0405** (portal regen) / **PLN-0406** (Rust `ProvenanceKind` enum
extension) carry the implementation residue. Item **#8** (ADR 0070
`CommitAttemptFailure`) gains a typed downstream consumer in
`EventSubmissionResponse.correlationGroupResult` once 0070 ratifies.
Item **#17** (tenant-scope export, parent **PLN-0392**) gains a clearer
downstream consumer in the WOS `bundle.schema.json` shape when activated.

**Release train:** #1-5 are stack-proof hygiene and release-contract unblockers;
#6-9 are production substrate; #10-13 are rights-impacting case semantics;
#14-15 are release governance / architectural closeout; #16-24 are post-MVP or
adopter-triggered work.

 1. **PLN-0379..0398 cluster drift audit** — **S**.
    **Closed 2026-05-07 (Wave 43); retained here until the next planned TODO
    renumbering pass.**
    *Land before authoring against any sibling row in the parent stack-closure
    cluster (proactive; no external trigger).* Wave 27 closure of PLN-0385
    surfaced a phantom four-field surface (`tag` / `payload` /
    `prior_event_hash` / `producer_signature`) cited in parent prose but
    absent from every spec / crate / schema / fixture; correct surface per
    [`../work-spec/thoughts/adr/0061-custody-hook-trellis-wire-format.md`](../work-spec/thoughts/adr/0061-custody-hook-trellis-wire-format.md)
    §2.3 is `caseId` / `recordId` / `eventType` / `record`.
    `producer_signature` exists nowhere on that seam — envelope-level signing
    is **COSE_Sign1** on the Trellis envelope; chain bytes use Trellis **`prev_hash`**
    (Core §10.2), not a fifth custody-hook field. Sibling rows (PLN-0379, 0380, 0381, 0382, 0383, 0384, 0386, 0387)
    were authored from the same wos-server-centric mental model and plausibly
    carry parallel drift. Audit each sibling: cross-reference cited wire
    surface, schema names, event-type strings, and field labels against
    Trellis CDDL §28, work-spec schemas, custody-hook companion, and ADR-0061.
    2026-05-07 audit result: no sibling-row correction was required. Parent
    PLN-0379..0398 rows already preserve the accepted four-field WOS append
    input (`caseId` / `recordId` / `eventType` / `record`), Trellis
    `prev_hash`, and envelope COSE_Sign1 boundaries where those details are
    material. The phantom surface appears only in PLN-0385 historical
    correction text or explanatory downstream notes that explicitly reject it.
    See [`COMPLETED.md`](COMPLETED.md) Waves 27 and 43 for the discovery and
    audit records.

 2. **WOS-T4 residue — shared cross-repo fixture bundle re-seeding** — **S**.
    *Land when parent standardizes a single shared cross-stack fixture bundle.*
    Trellis consumes those declarative inputs rather than seeding a parallel
    corpus. Coordination, not a Trellis-center gap. Parent backlog:
    **PLN-0067** (shared bundle), **PLN-0068** (response-hash mismatch
    negative), **PLN-0069** (CI/conformance gate).

 3. **ADR 0073 handoff residue — shared fixture alignment** — **S**.
    *Same prerequisite as #2.* Workflow-initiated attach and public-intake
    create vectors are live; the residue is consuming from one shared bundle
    rather than parallel corpora. Parent backlog: **PLN-0067**.

 4. **Identity attestation bundle shape** — **S**.
    *Land after parent ratifies the event-type taxonomy in **PLN-0384**.*
    Parent **PLN-0381** is closed by ADR 0068 D-3.1: the
    `IdentityAttestation` Facts-tier record shape is now normative, and
    **PLN-0310** remains closed by supersession. Remaining Trellis-side action:
    register the canonical `wos.identity.*` identity-attestation event type
    under Core §6.7, replace the current `x-trellis-test/identity-attestation/v1`
    fixture-only allowance where appropriate, and declare how provider-neutral
    identity-proofing attestations travel in export bundles. Composes with
    PLN-0380 (signer-authority claim shape, distinct from authentication
    method). Cross-stack fixtures (Formspec → WOS provenance → Trellis
    envelope) prove composition.

 5. **Respondent Ledger ↔ Trellis `eventHash` MUST promotion** — **M**.
    *Prerequisite nuance:* Formspec Respondent Ledger §6.2 already requires
    `eventHash` / `priorEventHash` as **MUST** when events are Trellis-envelope
    wrapped; generic “integrity chaining enabled” rows remain **SHOULD**, and
    the JSON Schema does not structurally enforce the Trellis branch alone.
    Trellis-side work tracks **schema/lint/conformance** closure for that seam,
    **unconditional** SHOULD→MUST if the stack chooses it for all chained
    ledgers, and **PLN-0311** offline-authoring semantics — not a blanket wait
    on “Formspec has not promoted yet.” Parent backlog: **PLN-0311**
    (Respondent Ledger offline-authoring profile + chain semantics).
    *Progress 2026-05-07:* schema/conformance closure for the paired hash seam
    landed in Formspec. `eventHash` and `priorEventHash` now depend on each
    other structurally, so a non-chained ledger may omit both but a chained /
    Trellis-wrapped event cannot carry only one half. The first wrapped event
    still uses `priorEventHash: null`. Remaining work is the broader
    unconditional all-chained-ledgers policy decision and PLN-0311
    offline-authoring semantics.

 6. **ADR 0068 execution — tenant in envelope and verifier** — **M**.
     *Gates closed:* **PLN-0004** (D-1.1 grammar), **PLN-0005** (D-1.2
     payload.tenant authoritative), **PLN-0011** (D-4 tenant×ledger scoped),
     **PLN-0013** (D-3 global identity + per-tenant authority), **PLN-0015**
     (D-2 immutable tuple vs 0071 mutable pins). *Remaining gate:*
     **PLN-0012** (supersession carry-forward, deferred to 0066 cluster).
     Envelope reserves capacity under ADR 0003; activation is the runtime +
     verifier + vector work.
     Parent backlog: **PLN-0002**, **PLN-0009**, **PLN-0023** (tenant portion),
     **PLN-0030**.
    + [ ] Required `tenant` field in envelope header and bundle metadata; CDDL
      + Rust + dCBOR ordering pinned per ADR 0004.
    + [ ] Verifier refusal when expected tenant ≠ chain/bundle tenant; failure
      taxonomy distinct from hash/signature integrity.
    + [ ] Vectors: `tamper/0NN-tenant-mismatch`, `tamper/0NN-tenant-missing`,
      cross-tenant export-bundle rejection.

 7. **ADR 0081 execution — content-addressed artifact identity** — **S**.
    *Land after parent ratifies ADR 0081 (parent **PLN-0358**) and WOS lands
    the three-segment `*Ref` syntax (parent **PLN-0359**).* WOS emits a
    definition-hash event on `caseCreated` and `determination`; Trellis anchors
    via the existing `custodyHook` seam. No new Trellis primitive — the
    evidence-anchoring pattern handles it. Parent backlog: **PLN-0360**.
    + [ ] Register a definition-hash event-type tag under Core §6.7.
    + [ ] `custodyHook` ingest path; dCBOR-canonicalized; round-trip byte-exact.
    + [ ] Vector exercising definition-hash anchor + verifier cross-check;
      cross-stack three-way agreement (WOS spec + Trellis verifier + reference
      adapter).

 8. **ADR 0070 execution — `CommitAttemptFailure` ProvenanceKind** — **M**.
    *Land after parent accepts ADR 0070 (gated on parent **PLN-0035**
    failure-contract closure).* Trellis local append is the stack commit point
    per ADR 0070 D-1; this adds the Facts-tier evidence shape for retryable /
    budget-exhausted / terminal commit failures plus optional bundle-level
    summary. Parent backlog: **PLN-0044**, **PLN-0045**, **PLN-0089**
    (cross-repo failure-scenario bundle).
    + [ ] New `recordKind` literal under Core §6.7 / §19; Facts tier;
      reservation under ADR 0080's open-discriminator pattern.
    + [ ] Verifier reporting taxonomy distinguishing the three typed outcomes;
      advisory, not integrity failure.
    + [ ] Optional `failures.json` at bundle root.
    + [ ] Vectors: `append/0NN-commit-failure-retried`,
      `append/0NN-commit-failure-stalled`,
      `tamper/0NN-failures-json-mismatch`.

 9. **ADR 0069 execution — timestamp wire precision + chain-order verification**
    — **M**. **Closed 2026-05-07 (Wave 34); retained here until the next
    planned TODO renumbering pass.**
    *Land after ADR 0069 acceptance.* Parent backlog: **PLN-0400**; composes
    with **PLN-0083** chain-order / time-order verification and unblocks
    ADR 0067 statutory-clock precision. Current Trellis Core / Rust / Python /
    fixture bytes already moved off legacy bare seconds and use
    `timestamp = [uint, uint .le 999999999]` (`[seconds, nanos]`), with
    `tamper/041-timestamp-backwards` and
    `tamper/042-timestamp-legacy-uint-rejected` covering D-3 and legacy bare
    `uint` rejection. Parent ADR 0069 D-2.1 now blesses the current
    `[seconds, nanos]` Trellis CBOR shape instead of forcing a churn-only
    `uint64` nanosecond-counter migration.
    + [x] Decision: ADR 0069 D-2.1 blesses Trellis's current
      `[seconds, nanos]` encoding. No fixture regeneration for a `uint64`
      nanosecond counter.
    + [x] Sweep stale timestamp prose in Trellis Core / matrix / verifier
      comments so equality language names the chosen timestamp value type.
    + [x] Verifier rejects legacy bare-second `uint` encodings distinctly from
      signature/hash integrity failures (`legacy_timestamp_format`;
      `tamper/042-timestamp-legacy-uint-rejected`).
    + [x] Chain timestamp-order verification accepts non-decreasing envelope
      timestamps and rejects backwards order even when hash-chain validity
      still holds (`timestamp_order_violation`;
      `tamper/041-timestamp-backwards`).
    + [x] Final canonical-encoding negative:
      `tamper/045-timestamp-nanos-out-of-range` proves array-shaped
      `[seconds, nanos]` timestamps still reject `nanos > 999999999` with
      `timestamp_nanos_out_of_range`. No Trellis leap-second parser fixture
      lands here because the Trellis CBOR timestamp surface is numeric; any
      RFC3339 `23:59:60` coverage belongs to JSON-string stack surfaces.

10. **ADR 0071 execution — `CaseOpenPin` and migration transitions** — **M–L**.
    *Land after parent accepts ADR 0071 (gated on parent **PLN-0019** wire
    home + **PLN-0095** wire encoding).* Coordinates with WOS
    `MigrationPinChanged` (parent **PLN-0021**) and ops guardrails (parent
    **PLN-0027**). Parent backlog: **PLN-0023** (envelope/verifier obligations,
    pin portion), **PLN-0026** (cross-version replay determinism vectors).
    + [ ] Pin in envelope header (Core + CDDL) — align field name with ADR 0071
      **`pin`** / type **`CaseOpenPin`** (JSON/CDDL may use `caseOpenPin`
      camelCase); populated on case-open events.
    + [ ] Verifier: pin immutability unless `MigrationPinChanged` anchors a
      transition; envelope-version-lineage compatibility.
    + [ ] Vectors: pin-set, pin-mutation-rejected, valid-pin-transition under
      `MigrationPinChanged`.

11. **ADR 0066 execution — amendment / supersession / rescission / correction**
    — **L**.
    **Closed 2026-05-07 (Waves 40 and 47); retained here until the next
    planned TODO renumbering pass.**
    *Land stack implementation* (ADR 0066 **accepted** 2026-05-06 — Trellis
    TODO execution closed; sibling WOS/server rows continue in their own
    trackers) —
    [`../thoughts/adr/0066-stack-amendment-and-supersession.md`](../thoughts/adr/0066-stack-amendment-and-supersession.md).
    WOS checklist:
    [`../work-spec/TODO.md#adr-0066-exec-checklist`](../work-spec/TODO.md#adr-0066-exec-checklist).
    Parent backlog: **PLN-0055**, **PLN-0056**, **PLN-0050**
    (`ResponseCorrection` linkage), **PLN-0051** (supersession-start linkage).
    + [x] CDDL / traceability shape pinned for
      **`trellis.supersedes-chain-id.v1`**:
      `SupersedesChainIdPayload { chain_id: bstr, checkpoint_hash: digest }`
      under `EventPayload.extensions` per Core §6.7 / §28 and TR-CORE-169;
      null / absent means no superseded chain.
    + [x] Fixture alignment: encode the same identifier/payload in
      `append/015-supersession`.
    + [x] Single-chain vectors: `append/011-correction`, `012-amendment`,
      `013-rescission` (plus `014-reinstatement` from ADR 0066's fifth-mode
      revision).
    + [x] Verifier **D-3:** correction-preservation report output and
      chain-linkage with byte-equal predecessor checkpoint hash. The runtime
      verifier now surfaces `correction_preservations[]` for readable
      `correctionAuthorized` / future `responseCorrection` payloads, including
      target event hash, corrected field set, and optional original/corrected
      value pairs when producers carry them. Cross-chain supersession linkage
      is covered by the manifest-bound graph + predecessor-checkpoint verifier
      path (`verify/017`, `tamper/046` … `049`).
    + [x] Verifier **D-3 rescission terminality:** any same-chain
      `wos.governance.determination*` event after
      `wos.governance.determinationRescinded` is a
      `rescission_terminality_violation` unless an intervening
      `wos.governance.reinstated` event reopens the chain. Rust coverage now
      lives in `trellis-verify-wos` under WOS-TV-002; legacy fixture coverage
      remains TR-CORE-171 / `tamper/050-rescission-terminality` until fixture
      manifests grow a WOS-TV coverage bucket. Python still carries the older
      inline check.
    + [x] Core §18 / §19 prose + export-manifest hook:
      `ExportManifestPayload.extensions["trellis.export.supersession-graph.v1"]`
      binds optional `064-supersession-graph.json` with `graph_digest`; TR-CORE-170
      pins canonical JSON shape and verifier obligations.
    + [x] Coordinate remaining Formspec `ResponseCorrection` + WOS payload
      shapes for correction-preservation reports. Formspec now emits
      `response.correction-recorded` with `recordKind = "responseCorrection"`
      and a Trellis-readable `data` payload carrying
      `correctionTargetEventHash`, `correctedFieldSet`, `fieldValues`,
      `reason`, and `authorizationEventHash`; WOS already carries the sibling
      `CorrectionAuthorized` shape. Trellis correction-preservation report
      output can read both `correctionAuthorized` and `responseCorrection`
      records.
    + [x] Cross-chain normative graph shape: `064-supersession-graph.json` at
      bundle root carries `head_chain_id` / `predecessors`; cycles are integrity
      failures under Core §19 step 6e.
    + [x] Runtime verifier graph binding + vectors:
      `trellis-verify` and `trellis_py.verify` parse
      `trellis.export.supersession-graph.v1`, require and hash-check
      `064-supersession-graph.json`, validate Trellis canonical JSON,
      compare `head_chain_id` to `manifest.scope`, reject unbound graphs,
      compare event-level `trellis.supersedes-chain-id.v1` rows, reject direct
      cycles, validate non-null predecessor `bundle_path` presence/checkpoint
      digest, and cover the positive +
      `supersession_graph_linkage_mismatch` / `supersession_graph_cycle` /
      `supersession_predecessor_checkpoint_mismatch` paths with
      `verify/017-export-015-supersession-graph` and
      `tamper/046` … `048` (TR-CORE-170).
    + [x] Runtime verifier deep traversal follow-on: embedded predecessor
      exports are walked with an ancestor-aware path set, so a nested graph
      that points back to a parent chain fails with `supersession_graph_cycle`.
      Covered by `tamper/049-supersession-graph-nested-cycle`.
    + [x] Optional predecessor chain members in export bundle (ADR D-4):
      `070-predecessors/` carries embedded deterministic Trellis export ZIPs
      named by `064-supersession-graph.json` predecessor `bundle_path` entries.
    + [x] **Vector IDs:** ADR 0066 keeps the contiguous open range
      `append/011-correction` … `append/015-supersession`. Item **#12** clock
      vectors moved to the next open append range,
      `append/043-clock-started` … `append/046-clock-paused-resumed`, so the
      0066/0067 clusters no longer collide and no landed vector is renumbered.
      The parent ADR / WOS TODO references still need their own sync (same
      collision noted in
      [`../thoughts/adr/0066-stack-amendment-and-supersession.md`](../thoughts/adr/0066-stack-amendment-and-supersession.md)
      implementation plan vs clock fixtures).

12. **ADR 0067 execution — statutory clocks** — **M**.
    **Closed 2026-05-07 (Wave 39); retained here until the next planned TODO
    renumbering pass.**
    *Land stack implementation* (ADR 0067 **accepted** 2026-05-06 — Trellis
    export/verifier/vectors are closed). Coordinate payload hashes with WOS
    `clockStarted` / `clockResolved` (parent
    [`work-spec/TODO.md`](../work-spec/TODO.md#adr-0067-exec-checklist)).
    Parent backlog: **PLN-0159** (`open-clocks.json` export), **PLN-0160**
    (verifier diagnostics, severity per **PLN-0170**), **PLN-0161**
    (pause/resume composition), **PLN-0162** (vectors), **PLN-0164**
    (cross-stack composition fixture).
    + [x] **Export bundle:** normative `open-clocks.json` at bundle root —
      manifest-bound by `trellis.export.open-clocks.v1` /
      `open_clocks_digest`; root `sealed_at` equals
      `ExportManifestPayload.generated_at`; `open_clocks[]` carries
      `{ clock_id, clock_kind, computed_deadline, origin_event_hash }` for
      every `clockStarted` lacking a matching `clockResolved` at export time.
      Covered by TR-CORE-172. Runtime export/verify fixtures remain below.
    + [x] **Verifier — D-3 advisory:** open clock with
      `computed_deadline < bundle.sealed_at` and no `clockResolved` emits an
      advisory diagnostic, not an integrity failure. Rust now emits this from
      `trellis-verify-wos` after Core hash-checks `open-clocks.json`; Python
      still carries the older inline verifier path.
    + [x] **Verifier — D-4 composition:** Rust WOS adapter and Python export verifier
      walk clock records in chain order, track active/paused segments by
      `clockId`, and refuse a resumed `clockStarted` that changes `clockKind`
      or `calendarRef` after `clockResolved(resolution="paused")` with
      `clock_calendar_mismatch`. In Rust this is now WOS-TV-003 in
      `trellis-verify-wos`; Python still carries the older inline verifier
      path.
    + [x] **Vectors:** `append/043-clock-started`, `044-clock-satisfied`,
      `045-clock-elapsed`, `046-clock-paused-resumed`, plus
      `verify/018-export-043-open-clocks` and
      `tamper/051-clock-calendar-mismatch`. Parent `work-spec/TODO.md`
      numbering was synced from the stale **`014–018`** note to the active
      Trellis vector IDs.

13. **External recipient lifecycle — Trellis-side ingestion** — **M**.
    *Land after parent ratifies the stack ADR per **PLN-0382**.* Privacy
    Profile registers external systems as per-class recipients; ledgered
    `wos.governance.access-granted` / `access-revoked` events flow through
    `custodyHook`; recipient-rotation rule is per-event scope (past events
    keep existing key_bag immutably; future events scope to current
    recipients). Trellis-side: ingest the new event types; clarify Companion
    §6.4 + §9.4 + §25.6 + §8.6 `LedgerServiceWrapEntry` re-wrap semantics;
    matrix explicit. Closes "External recipient lifecycle" center commitment
    in VISION §V. Cross-stack fixture proves rotation across two events
    (PLN-0382 done-criterion). Composes with `wos.governance.*` namespace
    ratification at parent **PLN-0384**.

14. **Stack-level security disclosure policy** — **S**, stack-coordination.
    **Closed 2026-05-07 (Wave 46).**
    *Coordinates parent **PLN-0308**.* Trellis is in the security perimeter
    (envelope, verifier, export attack surface); without a published intake
    channel and scope, security reports route through private conversation.
    Stack-level [`../SECURITY.md`](../SECURITY.md) now names Trellis envelope,
    append, verify, export, COSE, HPKE, key registry, store, and
    conformance-vector behavior as in scope, with private intake and response
    expectations.

15. **Verify-layer domain coupling extraction — `trellis-verify` integrity-only
    + sibling `trellis-verify-wos` adapter** — **M–L**.
    **Closed 2026-05-07 (Waves 41-42); retained here until the next planned
    TODO renumbering pass.**
    *Plan ready:* [`thoughts/plans/2026-05-07-extract-trellis-verify-wos.md`](thoughts/plans/2026-05-07-extract-trellis-verify-wos.md).
    *Status 2026-05-07:* Rust and Python verifier extraction landed. `trellis-verify`
    now exposes the validator seam and no longer carries WOS event-type
    literals, WOS record parsers, WOS catalog field matching, rescission
    terminality, clock-calendar semantics, or WOS failure variants. The
    sibling `trellis-verify-wos` adapter owns those concerns. Python now
    mirrors that split with `trellis_py.verify` as the Core verifier and
    `trellis_py.verify_wos` as the composed WOS-domain validator.
    Five queued ADRs (#11 supersession terminality, #12 clock semantics, #6
    tenant, #8 commit-failure, #10 migration pins) will compound the violation
    with each ratification cycle if the inversion is not closed first.
    Approach (per plan): sibling adapter crate at `crates/trellis-verify-wos/`
    following the `trellis-interop-*` precedent (depends on `trellis-types` +
    `trellis-verify` only). No cross-repo move; no fixture migration.
    + [x] **`RecordValidator` trait in `trellis-verify`** (Phase 1):
      opaque-bytes / opaque-event-type-strings surface; `()` no-op default;
      dispatch hooks in `verify_event_set` and `verify_export_zip`.
      Foundational; lands first.
    + [x] **Sibling crate `trellis-verify-wos`** (Phase 2a) at
      `crates/trellis-verify-wos/`. Owns the 6 event-type literals, 4 record
      parsers, 4 record-detail types, intake-mode dispatch, rescission
      terminality, clock semantic checks, catalog field-matching, certificate
      event-type assertion, and `WosFinding` / `WosVerificationReport`
      aggregation. WOS event-type strings duplicated as crate-local constants
      (no `wos-core` dep, matching `trellis-interop-*` pattern).
    + [x] **Core §19 carve-out** (Phase 2b → Phase 3a): WOS-specific verifier
      obligations move to new normative `specs/wos-trellis-verification.md`
      (`WOS-TV-*` numbering); Core §19 retains integrity-only obligations;
      §6.7 gains a note on WOS event-type extension entries; §16 prose
      strengthened in terms of `RecordValidator`.
    + [x] **`VerificationFailureKind` shrink** (Phase 3a): ~20 WOS variants
      hard-deleted (no `#[deprecated]` shims; `v1.0.0` is a coherent-snapshot
      tag). Surfaces as `WosFinding::kind` strings in the WOS adapter.
    + [x] **Conformance harness** (Phase 4): extend `trellis-conformance` with
      a dev-dependency on `trellis-verify-wos`; WOS-coupled vectors run through
      the composed verifier, integrity-only vectors through `trellis-verify`
      with `&()`. Fixtures stay in `fixtures/vectors/` — no migration.
    + [x] **Consumer migration check** (Phase 3b): no live
      `wos-server` code dependency on `trellis-verify` exists in this checkout;
      only TODO/VISION references mention future exporter paths. `trellis-cli`
      and `trellis-interop-c2pa` stay on `trellis-verify`.
    + [x] **`trellis-py` cross-check** (Phase 0 / Phase 2c): grep for WOS
      coverage; mirror the carve in Python if present. 2026-05-07 split
      added `trellis_py.verify_wos`, removed WOS-domain execution from
      `trellis_py.verify`, and routed WOS-coupled conformance expectations
      through the composed Python verifier.

16. **Case ledger + agency log semantic definitions** — **M**.
    *Land when case-ledger / agency-log scoping opens.* Core §22 case ledger
    composes sealed response-ledger heads with WOS governance events; Core §24
    agency log is the operator-maintained log of case-ledger heads. Envelope
    hooks stay reserved under ADR 0003 with `MUST NOT populate` until this
    lands.

17. **Tenant-scope Trellis export shape** — **M**, Trigger.
    *Coordinates parent **PLN-0392**. Activate trigger:* first tenant-scope
    export use case. Core §18 ZIP layout is per-`ledger_scope`; tenant-scope
    spans many. Owner lean: option (a) — new `070-tenant-package-manifest.cbor`
    cataloging constituent per-scope ZIPs with cross-binding digests.
    Alternative (b): top-level package format nesting per-scope exports.
    Depends on item #13 (export must cover recipient-rotation events).
    Signature-stack: tenant-scope export bundles span signed events across
    ledger scopes — procurement + audit may demand a single bundle.
    + [ ] Choice ratified (lean: option (a)).
    + [ ] CDDL written.
    + [ ] Fixture vector for one tenant spanning two `ledger_scope`s.
    + [ ] Verifier accepts; secret-exclusion list (per ADR-0013 absorption)
      enforced.

18. **Disclosure-profile scope granularity (per-case)** — **M**.
    *Land when case-ledger composition opens.* Companion A.5.2 reserves an
    `extensions` slot for per-case refinement; current semantics are
    deployment-scope only.

19. **ADR 0005 follow-ons (erasure evidence)** — **M–L**.
    Four open questions from
    [`thoughts/adr/0005-crypto-erasure-evidence.md`](thoughts/adr/0005-crypto-erasure-evidence.md):
    + [ ] LAK rotation × erasure interaction — re-wrap cascade or coupled
      recipe; lands with the first live LAK rotation touching erasure-cascade
      subjects.
    + [ ] `hsm_receipt_kind` registry; lands with the second deployment on a
      different HSM vendor.
    + [ ] Legal-hold-coupled erasure lint (OC-78 vs §20.6 conflict detection).
    + [ ] Multi-operator quorum attestation shape — co-lands with the first
      federated deployment.

20. **`trellis.external_anchor.v1` priority interaction** — **S**.
    *Land when external anchoring opens.* O-5 posture-transition events may
    want higher anchor priority in deployments with external-anchor chains.
    Anchor substrate is adapter-tier per the
    [anchor-substrate spike](thoughts/specs/2026-04-24-anchor-substrate-spike.md)
    — center ships an `AnchorAdapter` trait + enumerates OpenTimestamps,
    Sigstore Rekor, and Trillian as first-class candidates. This item picks the
    priority policy per deployment (which adapter's `anchored_at_or_before`
    drives posture-transition priority when multiple adapters attest), declared
    in the Posture Declaration.

21. **Cadence subtypes beyond height-based** — **M**.
    **Closed 2026-05-07 (Wave 45); retained here until the next planned TODO
    renumbering pass.**
    *Land with a non-height adopter, or proactively under fixture-corpus
    breadth work.* `projection/003` and `projection/004` cover height-based
    cadence. `projection/006-cadence-positive-time` now covers a satisfied
    time-driven declaration, and `projection/007-cadence-event-gap` covers an
    event-driven declaration with a missing checkpoint. Hybrid cadence remains
    adopter-triggered because it needs a concrete policy for combining clock
    and event selectors.

22. **O-4 ledger-replay lint rules 7–13** — **M**.
    *Land when the first external adopter publishes a declaration to verify
    against actual ledger emission history.* Seven declaration-vs-runtime
    checks: `max_agents_per_case` ceiling, `max_invocations_per_day` ceiling,
    WOS autonomy-cap superset, delegation-chain monotonicity,
    actor-discriminator on emitted events, `agent_identity` attribution match,
    emitted types ⊆ `audit.event_types`. Static rules 1–6 + 11 cover the
    declaration-internal surface; these add the runtime cross-check.

23. **`scitt-receipt` adapter — execute per ADR 0008** — **M**.
    *Land when SCITT Architecture draft reaches WG Last Call OR an adopter
    requires SCITT-compatible checkpoint receipts, whichever fires first.*
    Implements `trellis-interop-scitt` against ADR 0008 §"Registry" for
    `derivation_version = 1` (semantic alignment). Re-signs the SCITT signed
    statement with a distinct SCITT-issuer key managed by the operator's SCITT
    service (not the checkpoint COSE signer). Unlocks the `scitt-receipt` kind;
    adds round-trip byte-exact vectors. Follow-up: `derivation_version = 2`
    when SCITT adopts a byte-conformance profile.

24. **`vc-jose-cose-event` adapter — execute per ADR 0008** — **M**.
    *Land when an SSI-native adopter (W3C VC 2.0 event envelopes) shows up.*
    Implements `trellis-interop-vc` per ADR 0008 §"Registry". Requires
    resolving three ADR 0008 open questions: VC `@context` hosting + content
    hash, issuer-resolution policy, and Posture-Declaration binding for
    ISC-08 payload-disclosure honesty per kind. Unlocks the
    `vc-jose-cose-event` kind.

---

## Ratification close-out

Closed. G-5 evidence in
[`ratification/ratification-checklist.md`](ratification/ratification-checklist.md);
Core + Companion at `1.0.0`; release tag cut at close-out.

---

## Tagged baseline

`v1.0.0` is a coherent snapshot: a second implementation written from
[`specs/trellis-core.md`](specs/trellis-core.md) +
[`specs/trellis-operational-companion.md`](specs/trellis-operational-companion.md) +
[`specs/trellis-agreement.md`](specs/trellis-agreement.md) byte-matches every
vector in `fixtures/vectors/`, and every ratification gate in
[`ratification/ratification-checklist.md`](ratification/ratification-checklist.md)
is closed. Future work may revisit any surface here when doing so prevents
architectural debt. Nothing is released.

---

## State lives in

| What | Where |
|---|---|
| Phase 1 ratification record (closed) | [`ratification/ratification-checklist.md`](ratification/ratification-checklist.md) |
| Trellis ADRs | [`thoughts/adr/`](thoughts/adr/) |
| Closed work | [`COMPLETED.md`](COMPLETED.md) |
| Stack vision (Trellis section §XI) | [`../VISION.md`](../VISION.md) |
| In-flight designs | [`thoughts/specs/`](thoughts/specs/) |
| Fixture corpus | `fixtures/vectors/` |
| Rust reference impl | `crates/` (workspace root: `Cargo.toml`) |
| Python cross-check (G-5) | `trellis-py/` |
| Green check | `uv run --with cbor2 --with cryptography python scripts/check-specs.py && cargo nextest run --workspace` |

Spec-sized work: move substance to [`thoughts/specs/`](thoughts/specs/), keep a pointer here. Landed work: move to [`COMPLETED.md`](COMPLETED.md).
