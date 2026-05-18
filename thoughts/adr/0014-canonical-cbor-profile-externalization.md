# ADR 0014 — Canonical CBOR §4.2.2 Profile Externalization

**Date:** 2026-05-18
**Status:** Accepted
**Supersedes:** —
**Superseded by:** —
**Related:**
- ADR 0004 — Rust byte authority. The conformance oracle for this profile is the Rust source (`integrity-stack/crates/integrity-cbor/src/lib.rs::encode_canonical_cbor_value`); this ADR externalizes the rules that source enforces into a runtime-neutral document.
- Core §5.1 (`specs/trellis-core.md`) — replaced the prior inline §4.2.2 prose with a single-line reference to the new profile doc.
- `specs/canonical-cbor-profile.md` — the normative profile document this ADR ratifies.
- Requirements matrix row TR-CORE-179 — binds the profile doc's R1–R7 rule set to the Rust authority with per-rule file:line citations.
- Sibling closeout ADR `formspec-stack/thoughts/adr/0112-end-state-substrate-closeout.md` — Phase 1 / Phase 2 cadence separation, parity gate as permanent CI, and ScopedAdvisoryLease primitive.

---

## Decision

Publish the canonical CBOR §4.2.2 encoding rules as a standalone normative document at `specs/canonical-cbor-profile.md`. Reduce the prior inline §4.2.2 prose in `trellis-core.md §5.1` to a one-line reference. Bind the profile doc to the Rust authority via a new requirements-matrix row (TR-CORE-179).

The profile names seven rules (R1–R7): integer smallest-form, definite-length-only emission, §4.2.2 bytewise key sort on encoded keys, duplicate-key rejection, finite-float-only with negative-zero rejection, float-width compaction, and tag-restriction allowlist. Each rule cites the Rust enforcement location. Rules R6 and R7 are forward-compatibility commitments — currently inert in the Trellis substrate (no float-bearing or generic-tag preimage exists) — but any conformant runtime MUST implement them so the contract holds the day a float-bearing preimage shape lands.

---

## Context

The substrate's canonical CBOR rules were embedded inside `trellis-core.md §5` prose and exercised end-to-end by Rust (`integrity-cbor`) plus the Python cross-check (`trellis-py`). For Trellis-internal work that suffices: when prose and Rust disagree, ADR 0004 names Rust as authority and the spec updates to match.

The trust posture changes when third-party verifiers enter the picture. A regulator agency implementing a Trellis verifier in Go, .NET, Swift, or WASM-Rust needs a pinnable spec to implement against, not a Rust source-tree URL that may move and that requires reading Rust to understand. The implicit contract between Trellis-core prose and the Rust source is fine for co-engineered consumers; it is not the contract a third-party verifier can implement against.

The Phase-1 corpus already demonstrated that the contract is implementable: `trellis-py` mirrors `integrity-cbor`'s emission semantics function-for-function. What was missing was the document that names the contract independently of either implementation. This ADR closes that gap.

The end-state substrate closeout plan (`formspec-stack/thoughts/plans/2026-05-18-end-state-substrate-closeout.md`) Stream A puts the externalization first because every subsequent task (068 signed-acts manifest, Python derivation mirror, fixture regeneration, seal-fence verifier) leans on the profile being a pinnable artifact.

---

## Rationale

**Runtime neutrality is the long-term posture.** The trust story is "one canonical CBOR profile, N conformant runtimes, fixture corpus as regression evidence" — not "Rust plus a Python wrapper." Python is one conformant runtime today; Go, .NET, Swift, WASM-Rust are the same shape tomorrow. Each ships its own §4.2.2 encoder against the spec; each joins the parity matrix in CI; none reads Rust source as the conformance contract.

**Rust remains byte authority per ADR 0004.** Externalizing the profile does not relocate the byte authority. When the profile doc and Rust disagree, Rust wins and the profile updates in the same change train. The profile names the Rust source as the conformance oracle in its frontmatter and per-rule.

**The fixture corpus is the regression evidence.** Spec prose can drift from implementation; byte-exact fixtures cannot. The profile doc treats `fixtures/vectors/` as the regression contract — every implementation runs the corpus and asserts byte-identical output.

---

## Consequences

**Spec posture.** A future third-party runtime implementer reads `canonical-cbor-profile.md`, implements R1–R7 in their language, runs the fixture corpus, and joins the parity matrix. No Rust source-read required.

**Profile + Rust evolve together.** When `integrity-cbor` changes (a float-compaction fix, a new tag allowance, a parse-side defense-in-depth addition), the profile doc updates in the same commit train so the document and the bytes never diverge.

**Cross-runtime parity is a permanent CI invariant.** The closeout plan's Task A9 (and the sibling stack-level ADR-0112 Decision 6) commits the broader gate as a continuous check on `main`. The current gate script (`trellis/scripts/check_signed_acts_projection_parity.py`) is still signed-acts-specific; the generic-CBOR cross-runtime corpus naming every R1–R7 vector is tracked in the closeout plan and will promote TR-CORE-179's verification posture from `spec-cross-ref` to `test-vector` when it lands. This ADR's commitment is the externalized contract; the broader parity gate is the next step that gives the contract continuous evidence.

**Future runtimes are additive.** Adding a Go or WASM-Rust verifier is a matter of implementing the profile and adding the runtime to the parity matrix. Removing a runtime requires an ADR. The runtime list is not pinned anywhere except in the parity matrix's runtime registry.

**Externalization on crates.io / PyPI is enabled, not required.** The closeout plan names Trellis externalization as a long-term arc; publishing the canonical CBOR profile spec is the first step toward it but does not require that step today. The profile doc is pinnable now; the package publication can follow when adopter cadence demands.

---

## Alternatives considered

**Keep canonical-CBOR rules inline in `trellis-core.md §5`.** Rejected. The inline form was sufficient for co-engineered consumers reading the full Core spec but not for a third-party verifier who wants to implement only the encoding profile. Inline prose also entangled rule evolution with Core spec versioning; the profile doc can ratchet independently when (for example) a tag allowance lands without forcing a Core spec revision.

**Cite the Rust source as the contract; skip the profile doc.** Rejected. ADR 0004 names Rust as byte authority for resolving disagreements, not as the spec a third-party verifier implements against. A regulator implementing a Go verifier needs a document, not a source-tree URL.

**Defer externalization until a non-Python second runtime materializes.** Rejected. Writing the profile doc against the existing Rust+Python pair (where the contract is already met) is the right time to externalize; doing it under pressure when a Go verifier is mid-implementation would conflate "what does the contract say" with "what does this specific Go implementation need" — exactly the conflation the externalization is designed to prevent.

---

## Reopen criteria

Reopen this ADR only if any of:

1. The fixture corpus stops being adequate regression evidence (e.g., a runtime ships that passes the corpus but produces non-conformant output on an unrelated preimage shape). The remedy is to expand the corpus and amend the profile's §4 conformance contract, not to revisit the externalization decision itself.
2. ADR 0004's Rust byte-authority posture is itself revisited — that ADR's reversal would force a profile-authority re-decision.
3. A second non-Python runtime joins the matrix and surfaces an underspecified rule that the profile doc does not pin to Rust's behavior; the remedy is to add per-rule prose, not to revisit externalization.

---

*End of ADR 0014.*
