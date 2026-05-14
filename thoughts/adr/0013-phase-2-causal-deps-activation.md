# ADR 0013 — Phase-2 `causal_deps` Activation Strategy

**Date:** 2026-05-14
**Status:** Proposed
**Supersedes:** —
**Superseded by:** —
**Related:**
- ADR 0001-0004 — event topology and DAG envelope rationale; `causal_deps` reservation intent preserved in Core §10.3.
- ADR 0007 — certificate-of-completion; cross-scope citation pattern that Phase-2 DAG generalizes.
- Core §10.3 (`specs/trellis-core.md:892-894`) — Phase-2 reservation clause (authoritative).
- Core §10.1 / §10.2 — Phase-1 strict linear chain.
- Core §10.4 — ledger scope and partitioning (cross-scope isolation).
- Core §6.7 Extension Registry — `trellis.causal_deps.v2` registration row (Core line 337).
- Core §19 verification algorithm — step 6.i (Phase-1 verifier MUST reject non-empty `causal_deps` at `version == 1`).
- WOS ADR 0093 (`../../work-spec/thoughts/adr/0093-case-is-its-trellis-ledger.md`) — "a case IS its Trellis ledger"; Phase-2 DAG composes with, not against, this commitment.
- Platform decision register (`../../thoughts/specs/2026-04-22-platform-decisioning-forks-and-options.md` lines 201, 221, 287) — HLC plus causal edges named as candidate center pattern; fork remains gated on product need.
- `TRELLIS-WOS-REFACTOR-TODO.md` — Trellis-as-service, multi-app substrate writers (formspec-server, wos-server, clients); the architecture under which multi-writer becomes load-bearing.
- Requirements matrix rows TR-CORE-020 (Phase-1 strict linear chain) and TR-CORE-024 (`causal_deps` MUST be null/empty in Phase 1).

---

## Decision

Phase-2 `causal_deps` is activated when a concrete multi-substrate-writer or cross-scope-causality production use case requires it and a complete implementation passes the Phase-2 conformance corpus (new version value, partial-order verifier, HLC-resolved Merkle linearization, Phase-1-bridge rejection, and new fixture vectors). Until that gate, the wire slot remains reserved per Core §10.3; no activation code ships. The decisions below fix the wire contract, verifier semantics, Merkle strategy, and consumer opt-in discipline so that when the gate opens the spec is already closed.

---

## Context

### §10.3 reservation

Core §10.3 (`trellis-core.md:892-894`) establishes the reservation:

> "Phase 2 MAY upgrade to an HLC-ordered causal DAG. The `causal_deps` field (§6.1) reserves the wire slot. Phase 1 events MUST emit `causal_deps` as `null` or `[]`. Phase 2+ producers populating `causal_deps` emit a new `version` value; Phase 1 verifiers MUST reject events whose `causal_deps` is non-empty at `version == 1`. This reservation exists so that Phase 2 does not require a header-version break."

The reservation is already normative; this ADR pins the activation contract so the reservation has teeth. No wire change is required today.

### Phase-1 linear chain

Core §10.1 is the immovable foundation: one canonical total order per ledger scope, events totally ordered by `sequence`, each event's `prev_hash` binding the predecessor's `canonical_event_hash`. This invariant is Phase-1 complete (Phase-1 stranger test closed; `trellis-core.md` §29). Phase-2 does not revoke it; it extends it with an additive partial-order layer.

### Scope partitioning today

Core §10.4 resolves multi-writer concurrency by scope isolation: one Formspec Response, one case, one operator, one scope — and MUST NOT allow competing canonical orders for the same scope. This suffices for Phase-1 deployments. The partition cost is that two events from different scopes that have a causal relationship (one cites the other as evidence) cannot be represented in the chain without re-stating the cited content. `causal_deps` is the mechanism that makes cross-scope citations auditable without duplication.

### Multi-app substrate writers

The TRELLIS-WOS-REFACTOR-TODO architecture (`TRELLIS-WOS-REFACTOR-TODO.md` §Architecture Thesis) establishes Trellis as a service boundary: formspec-server, wos-server, and authorized clients all write to the same Trellis service. Under scope partitioning that remains safe; under any future concurrent-append-within-scope model it requires HLC-resolution. This ADR closes the latter as a Phase-2 option, not a Phase-1 commitment.

### Platform decision register

`thoughts/specs/2026-04-22-platform-decisioning-forks-and-options.md` line 287 states: "HLC and causal dependencies remain a product and evidence fork." This ADR closes the fork's wire contract without closing the fork on whether to activate; the product-need gate (D-1) is the activation criterion.

---

## Decisions

### D-1 — Activation trigger and gate

Phase-2 `causal_deps` MUST NOT be activated in production code until all three of the following conditions are met:

1. **Product-need gate.** A concrete production use case is identified that requires cross-scope causality or concurrent-within-scope ordering. The canonical examples are: (a) a case-ledger appeal that references the original determination by `canonical_event_hash` across ledger scopes; (b) concurrent appends from two substrate writers (formspec-server and wos-server) within the same scope where sequencing by receipt order would misstate causal direction; (c) a cross-case evidence citation where omitting the `causal_deps` reference would force payload duplication. Speculative future need is not sufficient; a product decision record must name the use case.

2. **Implementation gate.** A complete Rust implementation of the Phase-2 verifier path (per D-5 below), the Phase-1-bridge rejection semantics (per D-6), and the HLC-resolved Merkle linearization (per D-4) MUST exist and pass the Phase-2 conformance corpus. No Phase-2 production events are admitted before the verifier is closed.

3. **Fixture gate.** The Phase-2 fixture corpus (per §Fixture plan below) MUST be byte-complete and passing under both the Rust verifier (`trellis-conformance`) and the Python cross-check (`trellis-py`), consistent with ADR 0004 byte-authority discipline.

Until all three conditions are met, the wire slot remains reserved; `check-specs.py` MUST continue to enforce `causal_deps == null or []` on any event whose `version == 1`.

### D-2 — Wire-level changes when activated

When Phase 2 activates, the following wire-level changes apply. No other changes to the Phase-1 envelope shape are permitted:

1. **New `version` value.** `EventPayload.version` increments to `2`. Phase-1 events are `version == 1`; Phase-2 events that use `causal_deps` MUST be `version == 2`. The version value is the verifier's gate: a Phase-1-only verifier (Core §19 step 6.i) MUST reject `version == 2` events as unknown-version. No hybrid `version == 1` event may carry non-empty `causal_deps` (Core §10.3 is normative today; it does not need to change).

2. **`causal_deps` populated.** Phase-2 producers MAY populate `causal_deps: [+ digest]` as a non-empty array of `canonical_event_hash` values. Each digest MUST refer to a chain-present event whose `canonical_event_hash` matches — either within the same `ledger_scope` or in a different `ledger_scope` that the verifier has access to (see D-5). Cross-scope references are permitted; cross-deployment references (to events in a ledger the verifier cannot resolve) degrade to advisory-only per D-5.

3. **HLC timestamp semantics.** Phase-2 events with non-empty `causal_deps` MUST carry an HLC-format `authored_at` timestamp: the high 48 bits are the physical wall-clock component (milliseconds since Unix epoch), and the low 16 bits are the logical counter. Phase-1 events use Unix seconds in the full 64-bit field; the HLC format preserves total-order compatibility because HLC timestamps are monotonically non-decreasing and their physical component dominates for events more than one millisecond apart. Implementations MUST ensure HLC time is monotone non-decreasing within a writer per the standard HLC rules (Kulkarni–Demirbas 2014). A Phase-2 verifier reading a Phase-1 event (version == 1) MUST treat its `authored_at` as `physical_ms = authored_at * 1000, logical = 0` for HLC-comparison purposes.

4. **`causal_deps` in CDDL.** The existing `causal_deps: [* digest] / null` rule in §28 (Core line 2736) and in the `EventPayload` definition (Core line 232) already admits the Phase-2 shape. No CDDL change is required; the `[+ digest]` non-empty form is structurally admitted today. The semantic activation is the `version == 2` gate plus the verifier obligation added in D-5.

### D-3 — Per-event opt-in; per-scope linear chain stays the default

Phase-2 DAG semantics activate **per-event**, not per-scope. A Phase-2 scope (one whose verifier supports `version == 2` events) may contain a mix of Phase-1-style events (`causal_deps == null or []`, relying solely on `prev_hash`) and Phase-2 DAG events (`causal_deps` non-empty, carrying explicit multi-parent references). The `prev_hash` chain is always present and always verified. A Phase-2 event with empty `causal_deps` is wire-identical to a Phase-1 event except for its `version` value; its `prev_hash` provides the single-parent chain link.

This design ensures:
- Producers that do not need DAG semantics emit `version == 1` events throughout the ledger's life and are never affected by Phase-2 activation.
- Producers that need DAG semantics for a specific event emit `version == 2` for that event only, and normal `version == 1` events elsewhere.
- A ledger may contain both versions without any scope-level declaration beyond the verifier's version-awareness.
- The Phase-1 stranger test (Core §29) remains valid for `version == 1` events regardless of what else appears in the scope.

### D-4 — Merkle scheme decision: HLC-resolved total order

Phase-1 Merkle trees (Core §11) are built over contiguous `sequence`-indexed leaves. Multi-parent events have a `sequence` value in the single linear chain, so the sequence-indexed Merkle tree structure is unchanged: **every event still has exactly one `sequence` position, determined by the append service at admit time**. The `prev_hash` chain is the admit-order chain; `causal_deps` is an application-semantic layer overlaid on top of it.

The three alternatives in the brief are resolved as follows:

- **Per-scope Merkle stays linear; `causal_deps` is a cross-reference (ADOPTED).** The Merkle scheme over `sequence`-indexed leaves is unchanged. A Phase-2 event with `causal_deps` appears at exactly one `sequence` position and is included in the Merkle tree at that position. The `causal_deps` field is included in `canonical_event_hash` computation (it is part of `EventPayload`; Core §9.2 hashes the full payload) and therefore in the Merkle leaf. No change to Checkpoint format (Core §11), to Merkle interior-node computation (Core §11.3), or to export package layout (Core §18).

- **Per-scope Merkle becomes DAG-aware (REJECTED).** Rejected because it would break the Phase-1 Checkpoint format, require a new `CheckpointPayload.version`, invalidate existing fixtures, and force the stranger test to re-run. The cost exceeds the benefit: audit-quality partial-order verification is available via the `causal_deps` field itself without changing the Merkle root semantics.

- **HLC-resolved total order for sequence assignment (ADOPTED, applies to concurrent-append case only).** When two events are submitted concurrently to the Canonical Append Service from different writers, the append service assigns `sequence` values using HLC comparison as the tiebreaker (higher HLC = higher sequence). This is an implementation policy for the append service, not a wire format change. The resulting sequence is auditable because each event carries its HLC timestamp; a verifier can replay the tiebreaker logic and confirm the sequence assignment was deterministic.

### D-5 — Verifier behavior with multi-parent events

A Phase-2 conforming verifier MUST, in addition to all Phase-1 verifier obligations (Core §19):

1. **Version gate.** On encountering an event with `version == 2`: proceed to Phase-2 verifier path. On encountering an event with `version == 1` and non-empty `causal_deps`: flag `causal_deps_non_empty_at_version_1` and set `integrity_verified = false` (this is already Core §19 step 6.i today; Phase-2 verifier inherits it unchanged).

2. **`causal_deps` structural check.** Verify each digest in `causal_deps` is a well-formed `digest` per Core §9.1 (SHA-256, 32 bytes). Malformed digest → `causal_deps_digest_malformed`.

3. **In-scope resolution.** For each digest in `causal_deps` that refers to an event within the same `ledger_scope` (matching scope prefix): resolve the event from the export bundle or store. Unresolved in-scope reference → `causal_deps_in_scope_unresolved` (integrity failure).

4. **Cross-scope resolution.** For each digest in `causal_deps` that refers to an event outside the current `ledger_scope`: the verifier MAY attempt resolution if the referenced ledger's export bundle is available (e.g., included in a Phase-3 composite export). If resolution succeeds, the verifier confirms the referenced event's `canonical_event_hash` matches the digest. If resolution fails because the referenced ledger is absent, the verifier records `causal_deps_cross_scope_unresolvable` as an **advisory finding only** — it MUST NOT set `integrity_verified = false` solely because a cross-scope reference cannot be resolved from the local export. The event's in-scope chain integrity is unaffected by the resolution status of cross-scope references.

5. **Temporal plausibility.** For each resolved causal predecessor P of event E: P's HLC timestamp MUST be `≤` E's HLC timestamp (predecessors do not post-date the event that cites them). Violation → `causal_deps_temporal_inversion` (integrity failure).

6. **No self-reference.** `causal_deps` MUST NOT contain E's own `canonical_event_hash`. Self-reference → `causal_deps_self_reference` (integrity failure).

7. **Report accumulation.** Phase-2 verifier outcomes accumulate into `VerificationReport.causal_deps_check` per event: `{sequence, causal_deps_ok: bool, failures: [* tstr], cross_scope_advisory: [* tstr]}`. Global `integrity_verified = false` if any in-scope check fails; cross-scope advisory failures are surfaced but do not flip global integrity.

### D-6 — Phase-1 → Phase-2 bridge

The forward-compatibility contract is already normative in Core §10.3; this ADR makes it explicit and bidirectional:

**Phase 1 events remain valid Phase-2 events.** A Phase-2 verifier reading a `version == 1` event MUST accept it and apply Phase-1 verifier semantics (Core §19 in full). Phase-1 events do not require re-issuance when a scope begins admitting Phase-2 events.

**Phase-2 events are NOT valid Phase-1 events.** A Phase-1-only verifier MUST reject any event with `version == 2` (Core §19 step — unknown `version` value). This is the existing behavior enforced by Core §10.3; no new verifier change is required in Phase-1 code.

**Mixed-version export bundles are valid.** An export bundle MAY contain a mix of `version == 1` and `version == 2` events in the same scope. The Phase-2 verifier processes each event on its own version semantics. The Merkle tree, `prev_hash` chain, and checkpoint structure are unchanged (per D-4).

**Phase-2 activation is non-destructive to existing deployments.** Existing Phase-1 stores, existing Phase-1 verifiers, and existing Phase-1 export bundles all remain valid and unaffected. Deployments that do not need Phase-2 semantics never activate it.

### D-7 — Cross-stack consumer impact

**Trellis service boundary (TRELLIS-WOS-REFACTOR-TODO D1).** The Trellis service append API accepts events from formspec-server, wos-server, and authorized clients. Phase-2 activation at the append API means: the service accepts `version == 2` events whose `causal_deps` field the client populates. The service MUST validate structural correctness (D-5 steps 1-2) at admit time and MAY validate in-scope temporal plausibility (D-5 step 5) against the current scope head. Cross-scope resolution at append time is NOT required; it is a verifier-time obligation.

**Formspec producers (formspec-server).** Formspec response events are scoped one-per-response (Core §10.4). There is no multi-writer concurrency within a single response scope. Therefore formspec-server response events will emit `version == 1` in all ordinary cases. The only Formspec scenario that activates `causal_deps` is a cross-scope citation: a Formspec intake event that explicitly names a prior case event as its causal predecessor (e.g., a reopened intake citing the original response hash). This is opt-in per D-3; formspec-server default stays linear.

**WOS producers (wos-server).** WOS governance events are scoped per case (WOS ADR 0093: "a case IS its Trellis ledger"). A single case may receive concurrent governance events from multiple WOS workflow stages or from multiple authorized writers (a signing event from a client concurrent with a workflow-state transition from wos-server). Under Phase-1 scope partitioning this resolves by admit order; under Phase-2 it resolves by HLC tiebreaker (D-4) with explicit causal references carried in `causal_deps`. wos-server producers opt in per D-3: ordinary sequential governance events remain `version == 1`; concurrent-append or cross-scope-evidence events upgrade to `version == 2`.

**HLC obligation for Phase-2 producers.** Any producer emitting `version == 2` events MUST maintain a per-writer HLC state per the monotone-non-decreasing rule in D-2 point 3. The Trellis service client library MUST expose an HLC state manager that producers use instead of raw wall-clock reads. Producers that do not need Phase-2 semantics are entirely unaffected.

**No migration required.** Existing Phase-1 events in production stores do not require re-hashing, re-signing, or re-sequencing. Phase-2 activation is purely additive; Phase-1 events remain valid under Phase-2 verifiers per D-6.

---

## Consequences

**No immediate code change required.** The wire slot is already reserved; Core §10.3 is already normative; Core §19 step 6.i already enforces `version == 1` rejection of non-empty `causal_deps`. This ADR adds no new obligations to Phase-1 code.

**When D-1 activation gate opens:** four implementation deliverables:

1. **Phase-2 verifier path in `trellis-verify`.** New code path activated by `version == 2`. Implements D-5 steps 1-7. Adds `VerificationReport.causal_deps_check`. New failure codes: `causal_deps_non_empty_at_version_1` (pre-existing behavior, now codified), `causal_deps_digest_malformed`, `causal_deps_in_scope_unresolved`, `causal_deps_temporal_inversion`, `causal_deps_self_reference`. Advisory code: `causal_deps_cross_scope_unresolvable`.

2. **HLC state manager in `trellis-core` or a new `trellis-hlc` crate.** Per-writer HLC counter with monotone-non-decreasing enforcement. Rust is byte authority per ADR 0004; the HLC timestamp format (48-bit physical + 16-bit logical) is fixed here and confirmed in `EventPayload.authored_at` semantics.

3. **Phase-2 Merkle linearization policy in the Canonical Append Service.** Concurrent-admit tiebreaker using HLC comparison (D-4). Implementation detail for the append service; no wire format change.

4. **New `version == 2` CDDL constraint.** Amend `trellis-core.md` §28 to add a normative note: `EventPayload.version == 2 => causal_deps: [+ digest]` (non-empty) is the Phase-2 activation indicator. `version == 1 => causal_deps: [* digest] / null` (empty or null; existing constraint). A `version == 2` event with empty `causal_deps` is structurally valid but semantically redundant; implementations SHOULD warn.

**Merkle and export are unchanged.** Per D-4, no Checkpoint format change, no export package layout change, no new required archive members.

**Per-scope linear chain stays the default.** Events that do not need DAG semantics emit `version == 1` indefinitely. The `prev_hash` chain is the primary integrity anchor. `causal_deps` is an additive application-semantic layer; it does not replace `prev_hash`.

**Cross-stack tests.** When Phase 2 activates, the DAG fixture corpus (§Fixture plan) MUST be added to `trellis-conformance` and `trellis-py` CI before any Phase-2 production events are admitted.

**WOS / Formspec consumers must opt in.** Default stays linear per D-7. The Trellis service client library is the opt-in mechanism; producers that import it and call `emit_version_1_event()` are entirely unaffected.

---

## Alternatives considered

**Never activate Phase 2.** Rejected. The wire slot reservation in Core §10.3 exists for a reason: cross-scope causality is a real product need in the multi-substrate-writer architecture (TRELLIS-WOS-REFACTOR-TODO). Refusing to define the activation contract leaves future implementers to invent it under pressure, risking inconsistency with the existing reservation.

**Activate Phase 2 as the default for all events.** Rejected. Phase-1 verification simplicity is load-bearing for the stranger test (Core §29). Making HLC timestamps and multi-parent verification mandatory for all events complicates Phase-1 conformance without delivering value to the large class of linear-chain use cases. Opt-in per-event (D-3) preserves both.

**Mandate HLC for all Phase-1 events now.** Rejected. Phase-1 `authored_at` is Unix seconds. Changing it to HLC format would invalidate existing fixtures, break the stranger test, and require re-signing all Phase-1 events. HLC is opt-in via Phase-2 (D-2 point 3); Phase-1 verifiers convert Phase-1 timestamps to HLC comparison units at verifier time only (D-5 step 3 prose).

**Make `causal_deps` a DAG-aware Merkle root input (per-scope Merkle becomes DAG-aware).** Rejected per D-4. Breaks checkpoint format, invalidates fixtures, requires new stranger test, delivers no audit-quality improvement over the linear Merkle + `causal_deps`-in-payload design.

**Cross-scope references as integrity failures when unresolvable.** Rejected. Cross-scope references are advisory when the referenced ledger's export is absent — treating them as hard failures would make single-scope exports that contain Phase-2 events impossible to verify in isolation, which violates the verification independence contract (Core §16). Advisory-only cross-scope failures (D-5 step 4) preserve independence.

---

## Fixture plan

Phase-2 fixtures MUST be added to `fixtures/vectors/` before any Phase-2 production admission (D-1 gate). Planned corpus:

| Vector | Purpose |
|---|---|
| `append/040-phase2-causal-deps-minimal` | Single `version == 2` event with one in-scope `causal_deps` reference; prev_hash chain intact; HLC timestamp present. |
| `append/041-phase2-causal-deps-cross-scope` | `version == 2` event with one cross-scope `causal_deps` reference; verifier accepts with `causal_deps_cross_scope_unresolvable` advisory when cross-scope bundle is absent. |
| `append/042-phase2-causal-deps-multi-parent` | `version == 2` event with two in-scope predecessors in `causal_deps`; Merkle linearization confirms leaf at correct `sequence`. |
| `append/043-phase2-linear-event-in-phase2-scope` | `version == 1` event interleaved with `version == 2` events in the same scope; Phase-2 verifier accepts the Phase-1 event unchanged. |
| `tamper/035-causal-deps-nonempty-at-version-1` | `version == 1` event with non-empty `causal_deps`; Phase-2 verifier flags `causal_deps_non_empty_at_version_1`. (This vector is also covered by Phase-1 verifier behavior per Core §19 step 6.i.) |
| `tamper/036-causal-deps-in-scope-unresolved` | `version == 2` event with in-scope `causal_deps` digest that does not match any chain-present event; verifier flags `causal_deps_in_scope_unresolved`. |
| `tamper/037-causal-deps-temporal-inversion` | `version == 2` event whose `causal_deps` predecessor has a later HLC timestamp than the citing event; verifier flags `causal_deps_temporal_inversion`. |
| `tamper/038-causal-deps-self-reference` | `version == 2` event with its own `canonical_event_hash` in `causal_deps`; verifier flags `causal_deps_self_reference`. |

---

## Requirements matrix rows

When Phase 2 activates, the following matrix rows MUST be added to `trellis-requirements-matrix.md`:

| ID | Clause | Obligation summary |
|---|---|---|
| TR-CORE-180 | §10.3 / D-2 | Phase-2 event with `version == 2` and non-empty `causal_deps` MUST carry HLC-format `authored_at`; physical component monotone non-decreasing per writer. |
| TR-CORE-181 | D-5 step 1 | Phase-2 verifier MUST reject `version == 2` events whose `causal_deps` is structurally malformed. |
| TR-CORE-182 | D-5 step 3 | Phase-2 verifier MUST flag `causal_deps_in_scope_unresolved` when an in-scope `causal_deps` digest does not resolve to a chain-present event; `integrity_verified = false`. |
| TR-CORE-183 | D-5 step 4 | Phase-2 verifier MUST NOT set `integrity_verified = false` solely because a cross-scope `causal_deps` reference is unresolvable from the local export. |
| TR-CORE-184 | D-5 step 5 | Phase-2 verifier MUST reject a `causal_deps` reference whose resolved predecessor carries a later HLC timestamp than the citing event. |
| TR-CORE-185 | D-6 | Phase-2 verifier MUST accept `version == 1` events and apply Phase-1 semantics unchanged. Phase-1 verifier MUST reject `version == 2` events. |

These rows and their fixture references (§Fixture plan above) MUST land in the same commit as the Phase-2 Rust implementation per CLAUDE.md "spec + matrix + fixture in the same commit" discipline.

---

## Cross-references

- **Trellis Core §10** — Phase-1 chain construction; §10.1 strict linear; §10.2 `prev_hash` requirements; §10.3 causal-deps reservation (authoritative); §10.4 scope partitioning.
- **Trellis Core §19** — Verification algorithm; step 6.i is the existing Phase-1 gate that this ADR extends into D-5.
- **Trellis Core §6.7** — Extension Registry; `trellis.causal_deps.v2` row (Core line 337) is the Phase-2 registration placeholder.
- **ADR 0004** — Rust byte authority; HLC timestamp format pins here, confirmed in Rust implementation at activation.
- **ADR 0093 (WOS)** — "a case IS its Trellis ledger." DAG within a case scope (in-scope `causal_deps`) composes cleanly. DAG across cases (cross-scope `causal_deps`) is the Phase-2 cross-scope citation model in D-5 step 4; WOS ADR 0093 does not change.
- **Platform decision register line 287** — HLC and causal-deps fork closed to the wire contract here; product-need gate (D-1) is the activation criterion.
- **Sibling ADRs in this batch** — concurrent work-spec and formspec-server ADRs govern app-level DAG primitives (workflow transition DAGs, statechart-and-DAG complementarity). Those are application-layer constructs; this ADR is the substrate-layer primitive. They compose at different layers: an app-level DAG event is one Trellis event; `causal_deps` links Trellis events, not app-level nodes.
- **TRELLIS-WOS-REFACTOR-TODO** — Trellis-as-service architecture; multi-app substrate writers; D-7 consumer impact analysis.
- **Core §16** — Verification independence; D-5 step 4's advisory-only cross-scope posture preserves independence.
- **Core §29** — Phase-1 stranger test; Phase-1 invariants remain intact per D-3 and D-6.

---

*End of ADR 0013.*
