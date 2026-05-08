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
in [`/PLANNING.md`](../PLANNING.md). Items 1-8 + 10 cite parent rows;
items 9 + 11-16 are Trellis-internal envelope/verifier discipline with no
parent counterpart. The MVP-foundation cluster (PLN-0331..0349) consumes
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

**Signature-stack cluster** (everything about signatures): items **#1** + **#2**
(WOS-T4 + ADR 0073 shared-fixture residue), **#3** (identity attestation,
supersedes PLN-0310 → PLN-0381), **#8** (external recipient lifecycle,
parent PLN-0382), **#10** (tenant-scope export bundles spanning multiple
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
once ratified). Item **#9** (case ledger) may later consume amended responses.

**Cross-repo pointer — ADR 0082 (Stack Public REST API Contract, accepted
2026-05-05):** no Trellis-center tasks. The WOS public REST API authored
this cycle composes Trellis at three seams without changing Trellis bytes:
(1) `bundle.schema.json` exposes `GET /api/v1/bundles/{urn}/download`
streaming Trellis Core §18 export-package bytes verbatim
(`Content-Type: application/cbor`); `Bundle.certificateOfCompletionDigest`
references Trellis ADR 0007's `presentation_artifact.content_hash`;
(2) `audit.schema.json` `AuditAttestationView` composes with item **#3**
PLN-0381 identity-attestation bundle shape — projection-only, the canonical
identity-attestation home stays Trellis-side; (3) parent **PLN-0408**
adds a `bundle-completed` literal to `NotificationType` so consumers
discover Trellis bundle completion via the notification feed instead of
polling. New parent **PLN-0407** + **PLN-0408** rows are WOS-API-internal;
new parent **PLN-0401** (utoipa) / **PLN-0402** (legacy-route deletion) /
**PLN-0405** (portal regen) / **PLN-0406** (Rust `ProvenanceKind` enum
extension) carry the implementation residue. Item **#6** (ADR 0070
`CommitAttemptFailure`) gains a typed downstream consumer in
`EventSubmissionResponse.correlationGroupResult` once 0070 ratifies.
Item **#10** (tenant-scope export, parent **PLN-0392**) gains a clearer
downstream consumer in the WOS `bundle.schema.json` shape when activated.

**Release train:** #1-3 are stack-proof hygiene and release-contract
unblockers; #4-7 are production substrate / case-semantics rows gated by parent
decisions; #8-10 are rights-impacting export and recipient semantics; #11-16
are post-MVP or adopter-triggered work.

 1. **WOS-T4 residue — shared cross-repo fixture bundle re-seeding** — **S**.
    *Land when parent standardizes a single shared cross-stack fixture bundle.*
    Trellis consumes those declarative inputs rather than seeding a parallel
    corpus. Coordination, not a Trellis-center gap. Parent backlog:
    **PLN-0067** (shared bundle), **PLN-0068** (response-hash mismatch
    negative), **PLN-0069** (CI/conformance gate).

 2. **ADR 0073 handoff residue — shared fixture alignment** — **S**.
    *Same prerequisite as #1.* Workflow-initiated attach and public-intake
    create vectors are live; the residue is consuming from one shared bundle
    rather than parallel corpora. Parent backlog: **PLN-0067**.

 3. **Identity attestation bundle shape** — **S**.
    *Land after parent ratifies the event-type taxonomy in **PLN-0384**.*
    Parent **PLN-0381** is closed by ADR 0068 D-3.1: the
    `IdentityAttestation` Facts-tier record shape is now normative, and
    **PLN-0310** remains closed by supersession. Remaining Trellis-side action:
    use the canonical `wos.identity.identityAttestation` identity-attestation
    event type under the WOS `wos.<layer>.<recordKind>` taxonomy, replace the
    current `x-trellis-test/identity-attestation/v1`
    fixture-only allowance where appropriate, and declare how provider-neutral
    identity-proofing attestations travel in export bundles. Composes with
    PLN-0380 (signer-authority claim shape, distinct from authentication
    method). Cross-stack fixtures (Formspec → WOS provenance → Trellis
    envelope) prove composition.
    *Progress 2026-05-08:* Core §23.4 plus Rust/Python WOS-composed verifiers
    now admit `wos.identity.identityAttestation` for ADR 0010 identity
    resolution through the consumer-owned validation seam while Trellis center
    retains only the `x-trellis-test/*` fixture identifier. Remaining work still
    waits on PLN-0384 shared taxonomy / fixture ratification before replacing
    committed fixture bytes or closing the bundle-shape story.

 4. **ADR 0068 execution — tenant in envelope and verifier** — **M**.
     *Gates closed:* **PLN-0004** (D-1.1 grammar), **PLN-0005** (D-1.2
     payload.tenant authoritative), **PLN-0011** (D-4 tenant×ledger scoped),
     **PLN-0013** (D-3 global identity + per-tenant authority), **PLN-0015**
     (D-2 immutable tuple vs 0071 mutable pins), **PLN-0012**
     (supersession carry-forward: same-tenant reuses Tenant / DefinitionId /
     KernelId and mints a new LedgerId; cross-tenant mints a fresh bundle).
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

 5. **ADR 0081 execution — content-addressed artifact identity** — **S**.
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

 6. **ADR 0070 execution — `CommitAttemptFailure` ProvenanceKind** — **M**.
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

 7. **ADR 0071 execution — `CaseOpenPin` and migration transitions** — **M–L**.
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

 8. **External recipient lifecycle — Trellis-side ingestion** — **M**.
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

 9. **Case ledger + agency log semantic definitions** — **M**.
    *Land when case-ledger / agency-log scoping opens.* Core §22 case ledger
    composes sealed response-ledger heads with WOS governance events; Core §24
    agency log is the operator-maintained log of case-ledger heads. Envelope
    hooks stay reserved under ADR 0003 with `MUST NOT populate` until this
    lands.

10. **Tenant-scope Trellis export shape** — **M**, Trigger.
    *Coordinates parent **PLN-0392**. Activate trigger:* first tenant-scope
    export use case. Core §18 ZIP layout is per-`ledger_scope`; tenant-scope
    spans many. Owner lean: option (a) — new `070-tenant-package-manifest.cbor`
    cataloging constituent per-scope ZIPs with cross-binding digests.
    Alternative (b): top-level package format nesting per-scope exports.
    Depends on item #8 (export must cover recipient-rotation events).
    Signature-stack: tenant-scope export bundles span signed events across
    ledger scopes — procurement + audit may demand a single bundle.
    + [ ] Choice ratified (lean: option (a)).
    + [ ] CDDL written.
    + [ ] Fixture vector for one tenant spanning two `ledger_scope`s.
    + [ ] Verifier accepts; secret-exclusion list (per ADR-0013 absorption)
      enforced.

11. **Disclosure-profile scope granularity (per-case)** — **M**.
    *Land when case-ledger composition opens.* Companion A.5.2 reserves an
    `extensions` slot for per-case refinement; current semantics are
    deployment-scope only.

12. **ADR 0005 follow-ons (erasure evidence)** — **M–L**.
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

13. **`trellis.external_anchor.v1` priority interaction** — **S**.
    *Land when external anchoring opens.* O-5 posture-transition events may
    want higher anchor priority in deployments with external-anchor chains.
    Anchor substrate is adapter-tier per the
    [anchor-substrate spike](thoughts/specs/2026-04-24-anchor-substrate-spike.md)
    — center ships an `AnchorAdapter` trait + enumerates OpenTimestamps,
    Sigstore Rekor, and Trillian as first-class candidates. This item picks the
    priority policy per deployment (which adapter's `anchored_at_or_before`
    drives posture-transition priority when multiple adapters attest), declared
    in the Posture Declaration.

14. **O-4 ledger-replay lint rules 7–13** — **M**.
    *Land when the first external adopter publishes a declaration to verify
    against actual ledger emission history.* Seven declaration-vs-runtime
    checks: `max_agents_per_case` ceiling, `max_invocations_per_day` ceiling,
    WOS autonomy-cap superset, delegation-chain monotonicity,
    actor-discriminator on emitted events, `agent_identity` attribution match,
    emitted types ⊆ `audit.event_types`. Static rules 1–6 + 11 cover the
    declaration-internal surface; these add the runtime cross-check.

15. **`scitt-receipt` adapter — execute per ADR 0008** — **M**.
    *Land when SCITT Architecture draft reaches WG Last Call OR an adopter
    requires SCITT-compatible checkpoint receipts, whichever fires first.*
    Implements `trellis-interop-scitt` against ADR 0008 §"Registry" for
    `derivation_version = 1` (semantic alignment). Re-signs the SCITT signed
    statement with a distinct SCITT-issuer key managed by the operator's SCITT
    service (not the checkpoint COSE signer). Unlocks the `scitt-receipt` kind;
    adds round-trip byte-exact vectors. Follow-up: `derivation_version = 2`
    when SCITT adopts a byte-conformance profile.

16. **`vc-jose-cose-event` adapter — execute per ADR 0008** — **M**.
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
