# Trellis — TODO

Forward-looking work sorted for the PROD-MVP release schedule. Priority tracks **Imp × Debt**; size tags are scheduling hints, never priority inputs. Size: **XS** (≤1h) · **S** (≤1 session) · **M** (≤3 sessions) · **L** (multi-session). Last audited 2026-05-15.

## Snapshot

**Where specs / schemas / crates / fixtures live:** invoke the `formspec-specs:trellis-core` skill — it carries the Phase 1 byte protocol, Operational Companion, Agreement, Requirements Matrix, ADR navigation, and fixture corpus map. Don't inline that here; it drifts.

| Operational state | |
|---|---|
| Ratification | Core + Companion at **`v1.0.0`** — a coherent-snapshot tag, NOT a freeze. Nothing is released; no production records exist. Architectural change that prevents future debt → make it and retag. The revision window stays open until real adopters close it. Closed G-5 evidence in [`ratification/ratification-checklist.md`](ratification/ratification-checklist.md). |
| Phase 1 ADRs (closed) | [`thoughts/adr/0001-0004-phase-1-mvp-principles-and-format-adrs.md`](thoughts/adr/0001-0004-phase-1-mvp-principles-and-format-adrs.md) — 7 principles + 4 decided ADRs: DAG envelope with length-1 runtime (0001), list-form anchors with single-anchor default (0002), §22/§24 reservations held but `MUST NOT populate` (0003), Rust as byte authority + Python as cross-check (0004). |
| Green check | `uv run --with cbor2 --with cryptography python scripts/check-specs.py && cargo nextest run --workspace` |
| Cross-stack composition | `trellis-store-postgres-async` + `integrity-*` + `trellis-verify-wos` + `trellis-service-client` are the normal Trellis-facing edges; **retired:** in-process `EventStore` / `WS-095` embedded substrate composition ([ADR 0106](../thoughts/adr/0106-wos-server-governance-overlay.md)). Keep `append_event_in_tx` + migration discipline stable; no new TODO row unless a gap blocks the adapter. |
| Fixture corpus | `fixtures/vectors/` (139 vectors green at HEAD per Python/Rust parity guard) |

**`trellis-server` module split (TWREF-086):** `crates/trellis-server/src/lib.rs` remains the composition root for Trellis-only wiring still centralized there (profile dispatch, bundle publication, CBOR/registry helpers, crate-root re-exports) plus modules it owns. **Landed extractions:** `event_repository.rs`, `artifacts.rs`, `scope_startup.rs`, `append.rs`, **`admission.rs`**, **`openapi.rs`**, **`http.rs`** (Axum `router` + HTTP handlers), **`state.rs`** (`TrellisServerState`, `state_from_env`, replay + tenant bootstrap). `FORMSPEC_RESPONSE_SUBMITTED` is a `pub use` of `trellis_service_client::FORMSPEC_APPEND_EVENT_TYPE_LITERAL` (string SOT in the client); `scripts/check-http-api-schema.py` reads that literal from `CLIENT_PATH`, WOS literals from `SERVER_PATH` / `work-spec` `kind.rs`. **Remaining follow-ups:** shrink `lib.rs` by moving leftover CBOR/registry/export clusters into focused modules; optionally shard `http.rs` into a `http/` tree (same pattern as `wos-server`) when route ownership stabilizes.

---

## Cross-repo pointers

Items 1–10 cite parent `PLN-XXXX` rows in [`/PLANNING.md`](../PLANNING.md); items 11–20 are Trellis-internal envelope/verifier discipline with no parent counterpart. The MVP-foundation cluster (**PLN-0331..0349**) consumes `integrity-*` + `trellis-verify-wos` downstream — keep the public APIs stable for composition.

**Signature-stack cluster:** items **#1** + **#2** (WOS-T4 + ADR 0073 shared-fixture residue), **#3** (identity attestation, supersedes **PLN-0310** → **PLN-0381**), **#8** (external recipient lifecycle, parent **PLN-0382**), **#10** (tenant-scope export, parent **PLN-0392**). Trellis owns the integrity artifact bytes; WOS owns the semantics. Compose under **PLN-0379** + **PLN-0380**. Closed-historical: ADR 0010 user-content Attestation primitive (Wave 23), `c2pa-manifest@v1` adapter (Wave 25), `custody-hook-encoding.md` v1.0 + Wave 27 PLN-0385 wire-shape drift correction. The four-field surface is `caseId` / `recordId` / `eventType` / `record` per ADR-0061 §2.3 (NOT the phantom `tag`/`payload`/`prior_event_hash`/`producer_signature` in the original PLN-0385 prose); chain linkage uses CDDL `prev_hash` (Core §10.2); Respondent Ledger `priorEventHash` binds to that when wrapped; signing stays COSE_Sign1 on the envelope.

**WOS Runtime §15 (Formspec coprocessor):** no Trellis-center tasks. Processor + HTTP parity work lives in parent [`work-spec/TODO.md`](../work-spec/TODO.md) **#66** and [`workspec-server/crates/wos-server/TODO.md`](../workspec-server/crates/wos-server/TODO.md) **WS-011**, **WS-074–WS-075** (plus **WS-072** for ADR 0066 server surfaces). Item **#9** (case ledger) may later consume amended responses.

**ADR 0082 (Stack Public REST API):** no Trellis-center tasks. WOS REST API composes Trellis at three seams without changing Trellis bytes — bundle download streams Core §18 export bytes verbatim; `AuditAttestationView` composes with item **#3**'s identity-attestation shape (projection only; canonical home stays Trellis-side); a `bundle-completed` notification replaces polling. Item **#6** and item **#10** each gain a typed downstream WOS consumer once they ratify.

---

## Critical path (#1–#3)

Stack-proof hygiene + release-contract unblockers. Land before deeper substrate work.

<!-- tk:start epic=fs-9cqf -->
<!-- GENERATED by scripts/generate-todo.mjs from tk epic fs-9cqf — edit tickets via tk, not this section -->

**P2 — standard:**

- **Trellis #3 — Identity attestation bundle shape (use canonical wos.assurance.identity_attestation)** · `fs-cz3j` · P2
   links Stack ADR (TBD) — identity attestation (PLN-0381) `fs-cfi1`, Identity attestation shape — generalize beyond signatures `fs-bmvg`

   Size S. Parent PLN-0381 closed by ADR 0068 D-3.1: IdentityAttestation Facts-tier record shape is now normative; PLN-0310 closed by supersession. Trellis-side action: use canonical wos.assurance.identity_attestation event type under WOS wos.<layer>.<record_kind> taxonomy; replace current x-trellis-test/identity-attestation/v1 fixture-only allowance where appropriate; declare how provider-neutral identity-proofing attestations travel in export bundles. Composes with PLN-0380 (signer-authority claim shape, distinct from authentication method). Progress 2026-05-08: Core §23.4 + Rust/Python WOS-composed verifiers admit wos.assurance.identity_attestation for ADR 0010 identity resolution through consumer-owned validation seam; Trellis center retains only x-trellis-test/* fixture identifier.

   **Acceptance:**
     - wos.assurance.identity_attestation replaces fixture-only x-trellis-test identifier where appropriate; provider-neutral identity-proofing export-bundle shape spec'd; cross-stack fixtures (Formspec → WOS provenance → Trellis envelope) prove composition.
     - GATE: parent PLN-0384 shared taxonomy / fixture ratification.

**P3 — sustaining:**

- **Trellis #1 — WOS-T4 residue: consume byte-populated bundle 007 trellis-events.cbor + trellis-export.zip** · `fs-mm86` · P3
   links T4-SIG-BUNDLE-007 — full path… `fs-5883`, CROSS-STACK-FIXTURES-001 — Byte-populated cross-stack… `fs-qikb`

   Size S. Trellis consumes declarative inputs from shared cross-repo fixture bundle rather than seeding parallel corpus. Signature substrate boundary architecture landed 2026-05-08: 7-bundle skeleton exists, manifests validate, cross-stack-fixture-harness passes (9 tests incl. 3 negative). Ed25519 COSE adapter path is landed; fixture byte generation, receipt embedding, and end-to-end export vectors remain. Trellis-side action: consume bundle 007's trellis-events.cbor and trellis-export.zip once byte-populated. Parent backlog: PLN-0067 (shared bundle), PLN-0068 (response-hash mismatch negative), PLN-0069 (CI/conformance gate).

   **Acceptance:** Trellis-side replay of bundle 007 byte-populated artifacts (trellis-events.cbor + trellis-export.zip) green; no parallel Trellis fixture corpus; cross-stack-fixture-harness passes against bundle 007.

- **Trellis #2 — ADR 0073 handoff residue: shared fixture alignment** · `fs-ve6h` · P3
   links ADR 0073 — case initiation and intake handoff `fs-7a0d`

   Size S. Workflow-initiated attach and public-intake create vectors are live; residue is consuming from one shared bundle rather than parallel corpora. Parent backlog: PLN-0067.

   **Acceptance:** Trellis-side workflow-attach and public-intake vectors replay from shared bundle (not local parallel corpus); CI conformance gate green.

<!-- tk:end -->

---

## ADR-gated execution (#4–#7)

Production substrate + case-semantics rows gated by parent ADR decisions. Each item names its ADR + parent `PLN` gate.

<!-- tk:start epic=fs-nb7t -->
<!-- GENERATED by scripts/generate-todo.mjs from tk epic fs-nb7t — edit tickets via tk, not this section -->

**P1 — high-leverage:**

- **Trellis #7 — ADR 0071 execution: CaseOpenPin and migration transitions** · `fs-n9qv` · P1
   links ADR 0071 — cross-layer migration and versioning `fs-i0lz`, #3 (migration) — Policy-based migration routing `fs-imxz`

   Size M-L. Coordinates with WOS MigrationPinChanged (parent PLN-0021) and ops guardrails (parent PLN-0027). Parent backlog: PLN-0023 (envelope/verifier obligations, pin portion), PLN-0026 (cross-version replay determinism vectors). GATE: parent accepts ADR 0071 (PLN-0019 wire home + PLN-0095 wire encoding).

   **Acceptance:**
     - Pin in envelope header (Core + CDDL) — field name 'pin' / type CaseOpenPin (JSON/CDDL may use caseOpenPin camelCase); populated on case-open events.
     - Verifier: pin immutability unless MigrationPinChanged anchors transition; envelope-version-lineage compatibility.
     - Vectors: pin-set, pin-mutation-rejected, valid-pin-transition under MigrationPinChanged.

**P2 — standard:**

- **Trellis #5 — ADR 0081 execution: content-addressed artifact identity (definition-hash anchor)** · `fs-c7eu` · P2
   links FORMSPEC-CONTENT-ADDRESSED-001 — Content-addressed artifact… `fs-36ta`

   Size S. WOS emits definition-hash event on caseCreated and determination; Trellis anchors via existing custodyHook seam. No new Trellis primitive — evidence-anchoring pattern handles it. Parent backlog: PLN-0360.

   **Acceptance:**
     - Register definition-hash event-type tag under Core §6.7. custodyHook ingest path; dCBOR-canonicalized; round-trip byte-exact.
     - Vector exercises definition-hash anchor + verifier cross-check; cross-stack three-way agreement (WOS spec + Trellis verifier + reference adapter).
     - GATE: parent ratifies ADR 0081 (PLN-0358) and WOS lands three-segment *Ref syntax (PLN-0359).

- **Trellis #6 — ADR 0070 execution: CommitAttemptFailure ProvenanceKind** · `fs-uj32` · P2
   links ADR 0070 — cross-layer failure and compensation `fs-qzg6`, DurableRuntime::AppendFailure typed enum `fs-vmsx`

   Size M. Trellis local append is stack commit point per ADR 0070 D-1; this adds Facts-tier evidence shape for retryable/budget-exhausted/terminal commit failures plus optional bundle-level summary. Parent backlog: PLN-0044, PLN-0045, PLN-0089 (cross-repo failure-scenario bundle). GATE: parent accepts ADR 0070 (PLN-0035 failure-contract closure); now accepted 2026-05-06.

   **Acceptance:**
     - New recordKind literal under Core §6.7/§19; Facts tier; reservation under ADR 0080 open-discriminator pattern.
     - Verifier reporting taxonomy distinguishes three typed outcomes (retryable/budget-exhausted/terminal); advisory, not integrity failure.
     - Optional failures.json at bundle root.
     - Vectors: append/0NN-commit-failure-retried, append/0NN-commit-failure-stalled, tamper/0NN-failures-json-mismatch.

- **Trellis #4 — ADR 0068 execution: tenant in envelope and verifier** · `fs-zo54` · P2
   links ADR 0068 — tenant and scope composition `fs-ekrn`, WS-020 — Second operational Storage impl (Postgres via sqlx) `fs-sdxe`, WS-107 — Scoped ownership isolation (SRV-001, DDIA… `fs-2jz7`

   Size M. Tenant in envelope + verifier. Gates CLOSED: PLN-0004 (D-1.1 grammar), PLN-0005 (D-1.2 payload.tenant authoritative), PLN-0011 (D-4 tenant×ledger scoped), PLN-0013 (D-3 global identity + per-tenant authority), PLN-0015 (D-2 immutable tuple vs 0071 mutable pins), PLN-0012 (supersession carry-forward: same-tenant reuses Tenant/DefinitionId/KernelId and mints new LedgerId; cross-tenant mints fresh bundle). Envelope reserves capacity under ADR 0003; activation is runtime + verifier + vector work. Parent backlog: PLN-0002, PLN-0009, PLN-0023 (tenant portion), PLN-0030.

   **Acceptance:**
     - Required tenant field in envelope header + bundle metadata; CDDL + Rust + dCBOR ordering pinned per ADR 0004.
     - Verifier refuses when expected tenant != chain/bundle tenant; failure taxonomy distinct from hash/signature integrity.
     - Vectors: tamper/0NN-tenant-mismatch, tamper/0NN-tenant-missing, cross-tenant export-bundle rejection.

<!-- tk:end -->

---

## Rights-impacting (#8–#10)

Export + recipient semantics that determine what auditors / procurement / regulators see. **#10 depends on #8** (export must cover recipient-rotation events).

<!-- tk:start epic=fs-hatn -->
<!-- GENERATED by scripts/generate-todo.mjs from tk epic fs-hatn — edit tickets via tk, not this section -->

**P2 — standard:**

- **Trellis #8 — External recipient lifecycle: Trellis-side ingestion** · `fs-p2su` · P2
   links Stack ADR (TBD) — external recipient lifecycle (PLN-0382) `fs-zlvy`, WS-099 — External recipient lifecycle endpoints… `fs-b6z5`

   Size M. Privacy Profile registers external systems as per-class recipients; ledgered wos.governance.access_granted/access_revoked events flow through custodyHook; recipient-rotation rule is per-event scope (past events keep existing key_bag immutably; future events scope to current recipients). Trellis-side: ingest new event types; clarify Companion §6.4 + §9.4 + §25.6 + §8.6 LedgerServiceWrapEntry re-wrap semantics; matrix explicit. Closes 'External recipient lifecycle' center commitment in VISION §V. Composes with wos.governance.* namespace ratification at parent PLN-0384. GATE: parent ratifies stack ADR per PLN-0382.

   **Acceptance:**
     - Ingest wos.governance.access_granted/access_revoked event types; Companion §6.4 + §9.4 + §25.6 + §8.6 re-wrap semantics clarified; matrix explicit.
     - Cross-stack fixture proves rotation across two events (PLN-0382 done-criterion).

**P3 — sustaining:**

- **Trellis #9 — Case ledger + agency log semantic definitions (§22/§24)** · `fs-f98x` · P3

   Size M. Core §22 case ledger composes sealed response-ledger heads with WOS governance events; Core §24 agency log is operator-maintained log of case-ledger heads. Envelope hooks stay reserved under ADR 0003 with MUST NOT populate until this lands. TRIGGER: case-ledger / agency-log scoping opens.

   **Acceptance:**
     - Core §22 case-ledger and §24 agency-log semantics normatively defined; envelope hooks activated (ADR 0003 reservation lifts); verifier obligations + vectors land.
     - TRIGGER: case-ledger / agency-log scoping use case surfaces.

- **Trellis #10 — Tenant-scope Trellis export shape (cross-ledger-scope bundle)** · `fs-peth` · P3
   blocked-by Trellis #8 — External recipient lifecycle: Trellis-side… `fs-p2su`

   Size M, Trigger. Coordinates parent PLN-0392. Core §18 ZIP layout is per-ledger_scope; tenant-scope spans many. Owner lean: option (a) — new 070-tenant-package-manifest.cbor cataloging constituent per-scope ZIPs with cross-binding digests. Alternative (b): top-level package format nesting per-scope exports. Signature-stack: tenant-scope export bundles span signed events across ledger scopes — procurement + audit may demand a single bundle. ACTIVATE TRIGGER: first tenant-scope export use case.

   **Acceptance:**
     - Choice ratified (lean: option (a)).
     - CDDL written.
     - Fixture vector for one tenant spanning two ledger_scope's.
     - Verifier accepts; secret-exclusion list (per ADR-0013 absorption) enforced.
     - DEPENDS on item #8 (fs-p2su) — export must cover recipient-rotation events.

<!-- tk:end -->

---

## Post-MVP / adopter-triggered (#11–#16)

Trigger-gated on internal milestones (case-ledger composition opens), external standards maturity (SCITT WG Last Call), or specific adopter requests (SSI VC 2.0, federated deployment, second HSM vendor). Tracked here so we don't re-litigate when triggers fire.

<!-- tk:start epic=fs-4gxd -->
<!-- GENERATED by scripts/generate-todo.mjs from tk epic fs-4gxd — edit tickets via tk, not this section -->

**P3 — sustaining:**

- **Trellis #11 — Disclosure-profile scope granularity (per-case)** · `fs-a9jb` · P3
   blocked-by Trellis #9 — Case ledger + agency log semantic definitions… `fs-f98x`

   Size M. Companion A.5.2 reserves extensions slot for per-case refinement; current semantics are deployment-scope only. TRIGGER: case-ledger composition opens.

   **Acceptance:** Per-case disclosure-profile scope semantics defined; Companion A.5.2 extensions slot activated; verifier + fixtures.

- **Trellis #12a — ADR 0005 follow-on: LAK rotation × erasure interaction** · `fs-g31m` · P3

   Size M-L. ADR 0005 open question. Re-wrap cascade or coupled recipe. TRIGGER: first live LAK rotation touching erasure-cascade subjects.

   **Acceptance:** Re-wrap cascade vs coupled recipe decided; CDDL + vectors land.

- **Trellis #12c — ADR 0005 follow-on: legal-hold-coupled erasure lint (OC-78 vs §20.6)** · `fs-gd5c` · P3

   Size M. ADR 0005 open question. Legal-hold-coupled erasure lint detects OC-78 vs §20.6 conflict.

   **Acceptance:** Lint rule detects conflict between OC-78 legal-hold preservation and §20.6 erasure; fixtures prove both pass and fail.

- **Trellis #14 — O-4 ledger-replay lint rules 7-13 (declaration-vs-runtime cross-check)** · `fs-k7i4` · P3

   Size M. Seven declaration-vs-runtime checks: max_agents_per_case ceiling, max_invocations_per_day ceiling, WOS autonomy-cap superset, delegation-chain monotonicity, actor-discriminator on emitted events, agent_identity attribution match, emitted types ⊆ audit.event_types. Static rules 1-6 + 11 cover declaration-internal surface; these add runtime cross-check. TRIGGER: first external adopter publishes a declaration to verify against actual ledger emission history.

   **Acceptance:** 7 lint rules implemented; declaration-vs-runtime cross-check passes against first external adopter's emission history; fixtures cover pass and fail per rule.

- **Trellis #12d — ADR 0005 follow-on: multi-operator quorum attestation shape** · `fs-kxnb` · P3

   Size M-L. ADR 0005 open question. TRIGGER: first federated deployment.

   **Acceptance:** Multi-operator quorum attestation shape ratified; co-lands with first federated deployment fixture.

- **Trellis #12b — ADR 0005 follow-on: hsm_receipt_kind registry** · `fs-p8if` · P3

   Size M-L. ADR 0005 open question. TRIGGER: second deployment on different HSM vendor.

   **Acceptance:** hsm_receipt_kind registry shape ratified; second-vendor vectors land.

**P4 — backlog / trigger-gated:**

- **Trellis #13 — trellis.external_anchor.v1 priority interaction** · `fs-tdke` · P4

   Size S. O-5 posture-transition events may want higher anchor priority in deployments with external-anchor chains. Anchor substrate is adapter-tier per anchor-substrate spike (thoughts/specs/2026-04-24-anchor-substrate-spike.md) — center ships AnchorAdapter trait + enumerates OpenTimestamps, Sigstore Rekor, Trillian as first-class candidates. This item picks priority policy per deployment (which adapter's anchored_at_or_before drives posture-transition priority when multiple adapters attest), declared in Posture Declaration. TRIGGER: external anchoring opens.

   **Acceptance:** Priority policy declared in Posture Declaration; adapter selection rule documented; vectors prove deterministic priority across multi-adapter deployments.

- **Trellis #15 — scitt-receipt adapter (per ADR 0008)** · `fs-urvk` · P4

   Size M. Implements trellis-interop-scitt against ADR 0008 §'Registry' for derivation_version=1 (semantic alignment). Re-signs SCITT signed statement with distinct SCITT-issuer key managed by operator's SCITT service (not checkpoint COSE signer). Unlocks scitt-receipt kind; adds round-trip byte-exact vectors. Follow-up: derivation_version=2 when SCITT adopts byte-conformance profile. TRIGGER: SCITT Architecture draft reaches WG Last Call OR adopter requires SCITT-compatible checkpoint receipts.

   **Acceptance:** trellis-interop-scitt adapter implements derivation_version=1; round-trip byte-exact vectors; scitt-receipt kind unlocked.

- **Trellis #16 — vc-jose-cose-event adapter (per ADR 0008)** · `fs-zv4u` · P4
   links ADR 0059 — Unified Ledger residue (~35% complete) `fs-qzft`

   Size M. Implements trellis-interop-vc per ADR 0008 §'Registry'. Requires resolving three ADR 0008 open questions: VC @context hosting + content hash; issuer-resolution policy; Posture-Declaration binding for ISC-08 payload-disclosure honesty per kind. Unlocks vc-jose-cose-event kind. TRIGGER: SSI-native adopter (W3C VC 2.0 event envelopes) shows up.

   **Acceptance:** Three ADR 0008 open questions resolved (@context hosting/content-hash, issuer-resolution, Posture-Declaration binding). trellis-interop-vc adapter; vc-jose-cose-event kind unlocked; round-trip vectors.

<!-- tk:end -->

---

## Guards + residue (#17, #19, #19a, #20)

Quality-of-implementation work: parity guards extending with new vectors, certificate-shape closures, primitive-boundary clarifications, and defense-in-depth fixes at the write path.

<!-- tk:start epic=fs-u62h -->
<!-- GENERATED by scripts/generate-todo.mjs from tk epic fs-u62h — edit tickets via tk, not this section -->

**P2 — standard:**

- **Trellis #19 — TRELLIS-CERTIFICATE-RECEIPT-EMBEDDING-001: embed VerificationReceipt in COC** `[5/4/4]=20` · `fs-qlgh` · P2
   links T4-SIG-CERT-001 — embed VerificationReceipt in Trellis… `fs-p92r`, FORMSPEC-SIGNATURE-ADAPTER-TRELLIS-001 — Optional… `fs-fmc9`

   Size S. Score [5/4/4]=20. Per Trellis ADR 0007 (as amended 2026-05-08 by ADR-0090): certificate-of-completion embeds VerificationReceipt for each signature in certificate's signature-event entries. Receipt is carried as COSE_Sign1 bytes alongside the UCA reference. Archived stack convergence plan: thoughts/archive/plans/2026-05-09-signature-wire-convergence-plan.md. GATE: receipt-bytes production lives in Formspec adapters (`fs-n6vp` WebCrypto, `fs-wxoz` ring, `fs-fmc9` Trellis-COSE) — the previously-named TRELLIS-FORMSPEC-SIGNATURE-ADAPTER-001 work was retired during stack convergence; Trellis embeds bytes once Formspec adapters produce them.

   **Acceptance:** Settle single normative receipt location (UCA payload, certificate signature-event row, or both with one authoritative binding rule); update trellis.certificate-of-completion.v1 shape per spec; update Rust verifier (trellis-verify certificate finalization) to validate receipt-aware certificate; update Python mirror; update trellis/specs/trellis-requirements-matrix.md with TR-CORE rows for receipt-bearing certificates.

**P3 — sustaining:**

- **Trellis #19a — TRELLIS-COSE-PRIMITIVE-BOUNDARY-001: clarify Trellis COSE substrate** `[6/3/5]=30` · `fs-j6am` · P3

   Size S. Score [6/3/5]=30. trellis-cose currently re-exports shared COSE_Sign1 primitives used by Trellis event-signing construction and trellis-verify parsing. Formspec detached-payload parsing also re-exports same shared primitive through its compatibility crate.

   **Acceptance:** Keep Trellis-specific constructors and Formspec adapter policy layered above the shared primitive; add profile-equivalence vectors when new overlapping Sig_structure behavior lands.

- **Trellis #20 — TRELLIS-003 residue: prev_hash write guard at append time** · `fs-ycws` · P3

   Size XS. DDIA remediation landed sequence-continuity validation + SequenceGap error in both stores (store-postgres:371-397, store-memory:129-140) plus canonical_event_hash BYTEA NULL migration v3. prev_hash comparison between incoming event and predecessor's stored hash is explicitly DEFERRED: store-postgres/src/lib.rs:391 carries TODO(TRELLIS-003). StoredEvent does not yet carry prev_hash field; trellis-verify performs full prev_hash chain verification at read time (trellis-verify/src/lib.rs:647-670 + VerificationFailureKind::PrevHashMismatch), so integrity guarantee holds — gap is defense-in-depth at write path. Land when StoredEvent gains prev_hash and append path can compare without schema-breaking migration.

   **Acceptance:**
     - Add prev_hash: Option<[u8;32]> to StoredEvent (backward-compatible).
     - Compare incoming prev_hash against predecessor's canonical_event_hash in append_event_in_tx (both stores); emit PrevHashMismatch.
     - Migration v4 adds prev_hash BYTEA NULL.
     - Vectors: append with correct prev_hash, append with wrong prev_hash → PrevHashMismatch, append with no prev_hash → skip (backward-compat).

**P4 — backlog / trigger-gated:**

- **Trellis #17 — TRELLIS-CONFORMANCE-PYTHON-DRIFT-001 Python/Rust WOS verifier parity guard** · `fs-jdg7` · P4
   links T4-SIG-HARNESS-001 — extend harness to assert bundles… `fs-5wrh`

   Size S. Status: GREEN; keep as guard row until next WOS signature vector lands. Previous drift around SignatureAffirmation optional fields has been corrected: Rust and Python WOS-composed verifiers now accept same current vector corpus. Verification: PYTHONPATH=trellis-py/src uv run --with cbor2 --with cryptography python -m trellis_py.conformance --vectors fixtures/vectors reports 139 total / 0 failed.

   **Acceptance:** When receipt-bearing certificates land, add Python/Rust vectors for receipt positive, missing receipt, wrong signature event, digest mismatch, and invalid receipt signature so parity remains vector-enforced instead of prose-enforced.

<!-- tk:end -->

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

Spec-sized work: move substance to [`thoughts/specs/`](thoughts/specs/), keep a pointer here. Landed work: move to [`COMPLETED.md`](COMPLETED.md).
