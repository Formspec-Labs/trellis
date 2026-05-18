# CLAUDE.md — Trellis

Cryptographic integrity substrate beneath Formspec (intake) and WOS (governance). Parent [`../CLAUDE.md`](../CLAUDE.md) carries stack-wide conventions (HIGH PRIORITY writing rule, dev philosophy, worktrees, Red-Green-Refactor, Test-Before-Fix, commit convention). This file carries only Trellis-specific deltas and pointers.

## Read first

| For | Read |
|---|---|
| Behavioral interrupts + economic model | [`../CLAUDE.md`](../CLAUDE.md) — read first; interrupts are inline |
| Methods + methodology spine | [`../DEVELOPMENT-PHILOSOPHY.md`](../DEVELOPMENT-PHILOSOPHY.md) |
| Cross-stack ADRs (settled commitments, open forks) | [`../thoughts/adr/`](../thoughts/adr/) |
| Parent repo guide | [`../CLAUDE.md`](../CLAUDE.md) |
| One-page framing + internal pointers | [`README.md`](README.md) |
| Current tactical work | [`TODO.md`](TODO.md) |
| Authoritative roadmap (Phase 1 invariants, Tracks A–E) | [`thoughts/product-vision.md`](thoughts/product-vision.md) |
| Normative Phase 1 byte protocol | [`specs/trellis-core.md`](specs/trellis-core.md) |
| Normative operator obligations | [`specs/trellis-operational-companion.md`](specs/trellis-operational-companion.md) |
| Traceability (prose wins on conflict) | [`specs/trellis-requirements-matrix.md`](specs/trellis-requirements-matrix.md) |
| Active ADRs | [`thoughts/adr/`](thoughts/adr/) |
| Heading-level inventory | [`REFERENCE.md`](REFERENCE.md) |
| Closed work | [`COMPLETED.md`](COMPLETED.md) |

For public-facing stack framing, see [`../STACK.md`](../STACK.md) — lookup-only.

**Conflict resolution:** Owner signals in the current conversation override everything else. See [`../CLAUDE.md`](../CLAUDE.md) §Behavioral interrupts.

## Engineering philosophy — Trellis-specific deltas

- **Nothing is released.** `v1.0.0` is a coherent-snapshot tag, not a freeze. Zero production records exist. If a wire-shape change prevents architectural debt, make it and retag. Only real adopters close the revision window; there are none.
- **Rust is the byte authority (ADR 0004).** For anything spec prose cannot pin — CBOR ordering, COSE headers, ZIP metadata, Merkle steps, domain separation tags — Rust is canonical. Python (`trellis-py/`) is the cross-check. When they disagree: update spec prose if load-bearing and under-specified, update Python to match, add a vector if coverage was missing.
- **Maximalist envelope, restrictive Phase-1 runtime.** Reserve capacity in the wire shape now. Enforce Phase-1 scope with lint + runtime constraints, never by omitting capacity.
- **Dependency inversion is mandatory.** Trellis center crates define byte contracts, integrity primitives, and narrow ports. WOS, Formspec, Case Portal, or other consumer-specific semantics live in separate consumer-owned crates that depend inward on Trellis; Trellis does not depend outward on their schemas, event vocabularies, workflow states, or business validation rules.
- **No stubs.** `unimplemented!()` / `todo!()` / `NotImplementedError` are forbidden unless the blocker is an unresolved architectural decision — in which case STOP and surface it.
- **Vectors and Rust move together.** New `fixtures/vectors/` contract lands with matching `trellis-conformance` coverage in the same change train.
- **Spec + matrix + fixture in the same commit.** Every normative MUST has a `TR-CORE-*` / `TR-OP-*` row and (where testable) a byte-exact fixture.
- **Historical material is non-normative.** `specs/archive/` and `thoughts/archive/` — do not cite as normative.

## Trellis settled commitments

These are probed and accepted; they override speculative alternatives.

- **v1.0.0 is tagged, not released.** No production records exist. The tag marks current best understanding; wire shape stays rewritable as long as doing so prevents future architectural debt. Only real adopters close the revision window; there are none.
- **G-5 stranger test is the integrity anchor.** The strongest verifiability posture is byte-exact reproducibility across two independent implementations by a party with no ambient context — "G-5" is a shorthand for "fifth generation stranger" who has never heard of Trellis. Internal Rust/Python agreement (G-4 oracle) catches intra-team ambiguity; the stranger test catches spec ambiguity for an outside implementor. Every MUST in the spec should be independently derivable from the spec prose alone.
- **Rust is the byte authority (ADR 0004).** For decisions spec prose cannot pin — CBOR ordering, COSE headers, ZIP metadata, Merkle steps, domain separation tags — Rust is canonical. Python is the cross-check.
- **Maximalist envelope, restrictive Phase-1 runtime.** Reserve wire-shape capacity for later phases now. Enforce Phase-1 scope with lint + runtime constraints, not by omitting capacity. This is how the envelope stays forward-compatible without requiring version bumps on every new extension point.
- **Authority order tiebreaker.** When bytes disagree with prose: Rust wins, spec prose updates. When prose disagrees with Python: Python updates. When both disagree with the spec: the spec is the source of truth unless byte reality reveals a spec ambiguity, in which case the spec is updated first.

## Decision heuristics

Apply after stack-wide heuristics (in [`../DEVELOPMENT-PHILOSOPHY.md`](../DEVELOPMENT-PHILOSOPHY.md)):

1. **Phase-check.** Phase 1 (SBA PoC, single-agency intake) or Phase 2+? Phase 2+ defers; Phase 4 version-bumps the envelope regardless.
2. **Architectural-debt check.** Would keeping the current shape make a future change more expensive than changing now? If yes, change it.
3. **Byte-authority check.** Byte-level question? Rust is the oracle (ADR 0004).
4. **Reservation discipline.** New envelope field / hash slot / extension hook? YES at envelope layer if Phase-1 runtime restriction stays clean; runtime NO until the phase opens.

## Architecture

**Logic ownership.** Rust is the byte authority (ADR 0004). Python (`trellis-py/`) is the cross-check. When bytes disagree with prose, Rust wins and spec prose updates.

**Canonical encoding + signature suite.** dCBOR (RFC 8949 §4.2.2). Ed25519 over COSE_Sign1 (`alg = -8`), with `suite_id` registry reserving ML-DSA / SLH-DSA / hybrid codepoints. SHA-256 hash construction with domain separation tags. HPKE Base-mode payload-key wrap. COSE_Sign1 checkpoints over `(tree_size, tree_head_hash, suite_id, timestamp, anchor_ref?)`.

**Center-vs-adapter.** Center: `trellis-core` + `trellis-types` + `trellis-cddl`, with byte primitives owned by sibling `integrity-*` crates. Service boundary: `trellis-server-ports`, `trellis-service-client`, `trellis-server`, and `trellis-export-writer`. Adapters: `trellis-store-memory`, `trellis-store-postgres-async`, `trellis-verify-wos`, and interop crates; anchor substrates via `AnchorAdapter` trait (adopters pick OpenTimestamps / Rekor / Trillian per deployment; see spike in `thoughts/specs/2026-04-24-anchor-substrate-spike.md`).

**Consumer crate boundary.** If code needs WOS names, Formspec field semantics, portal workflows, intake handoff rules, respondent/case-ledger policy, or consumer-specific verification policy, it belongs outside Trellis center crates. Put it in an adapter or binding crate such as `trellis-verify-wos`, `wos-*`, or `formspec-*`, and pass only stable Trellis types, opaque payloads, extension namespaces, or trait calls across the boundary.

**Verification independence contract** (Core §16) is load-bearing: verifiers MUST NOT depend on derived artifacts, workflow runtime, or mutable DBs. Keep `integrity-verify` and Trellis/WOS verifier adapters free of non-essential dependencies.

**Downstream consumers.** Trellis is on our build track, co-engineered with consumers — not an external dependency they wait on. The primary downstream consumer today is the `wos-server` reference implementation, which calls Trellis through `trellis-service-client` and keeps WOS operational storage/projections outside the canonical substrate. End-state architectural framing for that consumer: [`../workspec-server/crates/wos-server/VISION.md`](../workspec-server/crates/wos-server/VISION.md). The Phase-1 envelope invariants (`specs/trellis-core.md`) are the byte commitments WOS append/export paths depend on; per-class DEK key-bag wrapping per [ADR-0074](../thoughts/adr/0074-formspec-native-field-level-transparency.md) inherits the same envelope discipline. "Case ledger" (Core §1.2) is the canonical scope name; "Respondent Ledger" / "Subject Ledger" naming is retired downstream when WOS-bound.

## Spec authoring contract

- CDDL inside `trellis-core.md` is structural authority. Rust type definitions MUST match. When they disagree, Rust wins per ADR 0004; update the CDDL.
- Behavioral semantics that CDDL cannot encode live in normative prose of `trellis-core.md` and `trellis-operational-companion.md`.
- Every testable normative row in `specs/trellis-requirements-matrix.md` SHOULD have a byte-exact fixture in `fixtures/vectors/`. `check-specs.py` enforces coverage.

## Build & test

```bash
# Targeted
cargo check --workspace
cargo nextest run -p trellis-core
cargo nextest run -p trellis-verify-wos
cargo nextest run -p trellis-conformance         # full-corpus replay (G-4 oracle)

# Full
cargo nextest run --workspace
cd trellis/trellis-py && python3 -m pytest -q   # from stack monorepo root; `cd trellis-py` from Trellis repo root
python3 scripts/check-specs.py            # spec discipline + fixture coverage

# Batched vector rollout only
TRELLIS_SKIP_COVERAGE=1 python3 scripts/check-specs.py
```

`make help` lists Makefile targets.

## Working norms — Trellis-specific

- **Inline by default for work under ~30 minutes.** Subagents earn their keep via isolation, parallelism, or genuinely large scope.
- **Plans: 3–5 tasks max.** If a plan wants 12 tasks, it is probably two plans.
- **Doc updates travel with the thing they document.** A commit adding a new Core §N also adds the corresponding `TR-CORE-NNN` row; closing a gate updates the checklist in the same commit.
- **Skill ceremony is optional when design is settled.** `superpowers:brainstorming` only when design space is genuinely open.
- **Parallel by default for independent work.** Use `run_in_background: true` for parallel subagents and follow-on vector batches.
- **Trust the model; prompt less.** Give the subagent the goal, the constraints, and the escalation rules.
- **Escalation over fabrication.** Return `NEEDS_CONTEXT` instead of papering over blockers with stubs.

## Submodule awareness

Checked out as `formspec/trellis/` inside the parent repo. Commits here are separate from parent commits — bump the parent submodule pointer when landing meaningful work. Never `--amend`, `--force`, or `--no-verify` without owner sanction. AI-authored commits end with:

```
Co-Authored-By: Claude <noreply@anthropic.com>
```
