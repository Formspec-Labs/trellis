---
title: Trellis Operational Companion
version: 1.0.0
date: 2026-04-21
status: ratified
phase: 2
companion-to: trellis-core.md
---

# Trellis Operational Companion

**Version:** 1.0.0
**Date:** 2026-04-21
**Editors:** Formspec Working Group
**Companion to:** Trellis Core v1.0.0
**Phase:** 2 (Runtime-time integrity)

---

## Abstract

This document is the **operational companion** to the Trellis Core specification. Trellis Core defines the byte-level substrate — envelope format, canonical encoding, hash construction, signature profile, chain construction, checkpoint format, export package layout, and offline verification algorithm. Those bytes are necessary but not sufficient.

An operator whose bytes conform to Core can still violate the product claim. They can emit staff dashboards that silently drift from canonical records. They can crypto-shred a payload while leaving plaintext in a materialized view. They can advertise a privacy posture their service cannot deliver. They can let a delegated AI agent act without attestation. They can change custody mode without recording the transition. None of those failures show up in a byte-level vector; all of them poison the evidence the product promises.

This companion specifies the operator obligations that make Trellis Core honest in practice: posture and disclosure discipline, derived-artifact and projection discipline, operational contracts (append idempotency, delegated compute, lifecycle), sidecar bindings to Formspec response history and WOS workflow governance, the witnessing seams Phase 4 will populate, and the assurance obligations that bind all of the above.

This companion is a **Phase 2 deliverable**: it ships with the runtime-time-integrity tier of the delivery arc. Phase 1 (attested exports) requires conformance to Trellis Core only. Phase 2 and later tiers require conformance to Core **and** to this companion.

---

## Status of This Document

This document is the **ratified operational companion**. It is the second of the two Trellis W3C-style specifications described in the Trellis delivery arc:

1. **Trellis Core** — byte-level protocol (Phase 1).
2. **Trellis Operational Companion** (this document) — operator obligations layered on Core (Phase 2+).

This companion is stable for production use as of the 1.0.0 release. Where this companion elaborates a semantic already fixed by Trellis Core, Trellis Core governs. Where this companion defines operational detail that Trellis Core does not fix, this companion is the normative source.

---

## Relationship to Trellis Core

Trellis Core and this companion divide the Trellis specification surface along a single boundary: **bytes versus obligations**.

**Substrate authority.** As of 2026-05-12, the byte-level primitives that Trellis Core composes (CBOR encoding, COSE_Sign1 envelope, length-prefixed domain separation, deterministic ZIP) are owned upstream by `integrity-stack/crates/` (see Trellis Core §1 (Introduction) §1.5 and §7 (Signature Profile)'s signature profile composition). Trellis Core is the Trellis composition over that substrate; this companion is the operator-obligation layer above Trellis Core. The boundary below is unchanged in substance — Core still owns "bytes," this companion still owns "obligations" — but Core's authority over those byte structures is by composition over the substrate, not by independent re-specification.

**Trellis Core owns (as the Core profile composition over `integrity-stack/`):**

- canonical CBOR encoding (substrate: `integrity-cbor`),
- envelope shape, header fields, and reserved positions (substrate: `integrity-cose` for COSE_Sign1 envelope; `integrity-event` for identity-free event sequence / kind / hash primitives),
- hash construction over ciphertext (substrate: `integrity-canonical` for the domain-prefixed framing),
- signature suite identity and the signing-key registry,
- chain construction (`prev_hash`, causal-dependency reserve),
- checkpoint format and the append-head binding,
- export package layout (substrate: `integrity-bundle` for the deterministic ZIP byte structure),
- key-lifecycle cryptographic mechanics (crypto-shredding primitives, re-wrap rules, `LedgerServiceWrapEntry`),
- the offline verification algorithm,
- the verification-independence contract,
- the byte-level append-idempotency contract (stable keys, payload-hash comparison),
- redaction-aware commitment **slots** (the byte positions, not their population),
- the fact-admission state machine at the byte level.

**This companion owns:**

- what an operator MUST declare about its posture and metadata leakage,
- which deployment postures ("custody models") are recognized and what each requires,
- how posture transitions are recorded as canonical events,
- how redaction-aware commitment slots are populated, and how disclosure manifests are assembled,
- derived-artifact discipline (watermarks, rebuild, staleness, purge-cascade),
- projection runtime rules and integrity policy,
- snapshot-from-day-one requirements,
- staff-view integrity,
- the **operational** append-idempotency contract layered on Core's byte contract (retry budgets, API retry windows, dedup store lifecycle, replay-observable semantics for callers),
- delegated-compute honesty, authority attestation, and audit obligations,
- the lifecycle-and-erasure cascade across derived systems,
- the rejection taxonomy and its observable semantics,
- versioning and algorithm-agility operational obligations,
- the Respondent History sidecar binding to Formspec's Respondent Ledger,
- the Workflow Governance sidecar binding to WOS `custodyHook`,
- how grants and revocations are recorded as canonical facts (and why evaluators are derived),
- monitoring and witnessing seams (Phase 4 implementation deferred),
- operational conformance tests beyond Core vectors.

**Conflict rule.** Where this companion's text appears to conflict with Trellis Core, **Trellis Core prevails**. This companion MUST NOT redefine canonical truth, canonical order, canonical append attestation semantics, or the export-verification guarantees established by Core. A requirement in this companion that would weaken a Core invariant is NON-CONFORMANT with this companion itself and MUST be read against Core.

**Non-re-specification rule.** This companion does **not** re-specify any byte format. Every byte-level claim is made by citation to Core. Where this companion needs to refer to a byte-level artifact (envelope header, append attestation, checkpoint head, commitment slot, export manifest digest), it names the Core section that owns it rather than restating its shape.

---

## Table of Contents

1. Abstract
2. Status of This Document
3. Relationship to Trellis Core
4. Table of Contents
5. Introduction
6. Conformance
7. Terminology

**Part I — Posture and Disclosure Discipline**

8. Access Taxonomy
9. Custody Models
10. Posture-Transition Auditability
11. Posture-Declaration Honesty
12. Metadata Budget Discipline
13. Selective Disclosure Discipline

**Part II — Derived Artifacts and Projections**

14. Derived-Artifact Discipline
15. Projection Runtime Rules
16. Snapshot-from-Day-One
17. Staff-View Integrity

**Part III — Operational Contracts**

18. Append Idempotency (Operational)
19. Delegated-Compute Honesty
20. Lifecycle and Erasure
21. Rejection Taxonomy
22. Versioning and Algorithm Agility

**Part IV — Sidecars**

23. Respondent History Sidecar
24. Workflow Governance Sidecar
25. Grants and Revocations as Canonical Facts

**Part V — Witnessing and Monitoring (Phase 4 Preview)**

26. Monitoring and Witnessing Seams

**Part VI — Assurance**

27. Operational Conformance Tests
28. Security and Privacy Considerations (Operational)
29. References

**Appendices**

A. Declaration Document Template
B. Sidecar Examples

---

## 5. Introduction

Trellis Core answers the question "what bytes must a conforming implementation produce?" This companion answers the question "once the bytes are right, what must the operator still do?"

Those are different questions with different failure modes. A byte-level bug is caught by a test vector; an operational bug is caught — if at all — by an auditor noticing that a staff dashboard contradicts a signed checkpoint, by a respondent discovering that their redaction request left plaintext in a search index, or, worst, by a court hearing that an operator described its system more strongly than it could support.

The product claim behind Trellis is not "our bytes verify on an air-gapped laptop in 2045." The product claim is "every record produced by the platform is simultaneously a valid Formspec response, a governed WOS event, and an attested Trellis entry, and the evidence survives the system, the vendor, and the years." Bytes are the floor. This companion is the rest of the floor.

The structure of this document reflects the structure of operator failure modes. **Posture and disclosure discipline** (Part I) addresses how an operator describes its trust stance honestly, and how redaction is coordinated across envelope slots and disclosure manifests. **Derived artifacts and projections** (Part II) addresses the single largest class of integrity drift in canonical-ledger deployments: the staff dashboard or materialized view that silently becomes a second source of truth. **Operational contracts** (Part III) addresses the runtime behaviors that callers, adjudicators, and courts rely on — idempotent appends, delegated-compute attribution, lifecycle cascades, rejection semantics, algorithm agility. **Sidecars** (Part IV) addresses how Trellis composes with the adjacent specs that it exists to serve: Formspec's respondent history and WOS's workflow governance. **Witnessing and monitoring** (Part V) names the seams for Phase 4 without pretending Phase 4 has arrived. **Assurance** (Part VI) says what a conforming operator MUST demonstrate.

Every obligation in this companion is stated with RFC 2119 language. There are no bare-prose "we do X" statements: every operational expectation is a MUST, SHOULD, or MAY. Where a section defines a seam for a later Phase, this is stated explicitly — "SEAM DEFINED; IMPLEMENTATION DEFERRED TO PHASE N" — rather than implied.

---

## 6. Conformance

### 6.1 RFC 2119 Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in ALL CAPITALS.

### 6.2 Conformance Prerequisite

An implementation claiming conformance to this companion MUST also claim conformance to Trellis Core at a matching or higher version. Conformance to this companion without Core is undefined.

### 6.3 Conformance Tiers

This companion defines three tiers of operational maturity. Tiers are cumulative: a higher tier includes every obligation of every lower tier.

| Tier | Name | Summary |
|---|---|---|
| **OP-1** | **Operational Baseline** | Posture declaration published, custody model declared, posture transitions recorded as canonical facts, operational append idempotency implemented, lifecycle and erasure cascade implemented, rejection taxonomy implemented, versioning obligations met. |
| **OP-2** | **Projection-Disciplined** | Every derived artifact carries a watermark; every projection is rebuildable; staff-view integrity obligations met; snapshot-from-day-one cadence met; integrity sampling policy declared and exercised. |
| **OP-3** | **Sidecar-Integrated** | Respondent History sidecar bound to Formspec Respondent Ledger; Workflow Governance sidecar bound to WOS `custodyHook`; grants and revocations recorded as canonical facts with derived evaluators obeying §10 rebuild semantics. |

Phase 4 (Federation / Sovereign) adds a **OP-W** tier covering monitoring and witnessing obligations. OP-W is specified only as a seam in this document; see §26.

### 6.4 Conformance Roles

This companion defines the following operational roles. An implementation MAY claim more than one; it MUST satisfy every obligation applicable to each claimed role.

1. **Operator** — the party running a Trellis deployment. Publishes the posture declaration (§11), declares the custody model (§9), maintains the canonical append service (Core §2 (Conformance)), authors certificate-of-completion records that bind presentation artifacts to underlying signing chains (ADR 0007 / Core §6 (Event Format) §6.7 `trellis.certificate-of-completion.v1`), and discharges every obligation in Parts I and III. **Operator URIs MUST NOT appear in the `attestor` slot of `trellis.user-content-attestation.v1` events** (ADR 0010 §"Field semantics" `attestor` clause + Core §19 (Verification Algorithm) step 6d step 8 `user_content_attestation_operator_in_user_slot`); the user-content-attestation primitive is user-actor-only, and operator attestations to posture changes belong in Appendix §A.5's `Attestation` shape under domain tag `trellis-transition-attestation-v1` — the converse of A.5's operator-only authority-class semantics.
2. **Projection Producer** — produces derived projections (§15). Obligations in Part II.
3. **Authorization Evaluator** — a derived component that contributes to rights-impacting decisions (§14.6, §25).
4. **Respondent History Producer** — produces a Respondent History sidecar (§23).
5. **Workflow Governance Producer** — produces a Workflow Governance sidecar (§24).
6. **Monitor** (Phase 4 preview) — consumes checkpoint publications for drift and equivocation detection (§26).
7. **Witness** (Phase 4 preview) — issues independent attestations over observed checkpoint material (§26).
8. **Auditor** — an independent party comparing declared posture against observed behavior (§11.4, §27.6).

---

## 7. Terminology

Terms defined in Trellis Core govern where used; this section adds operational terms and restates a small number of Core terms where operational scope narrows them.

- **Operator** — the administrative principal responsible for a Trellis deployment. An Operator runs a Canonical Append Service (Core §2 (Conformance)), publishes a posture declaration (§11), and discharges the obligations in this companion.
- **Posture Declaration** — the machine- and human-readable document an Operator MUST publish alongside each export bundle describing its access taxonomy, metadata budget, custody model, external-anchor dependencies, and crypto-shredding scope. See §11.
- **Access Taxonomy** — the three-class partition of access to protected content: **provider-readable**, **reader-held**, **delegated-compute**. See §8.
- **Custody Model** — a named operational posture that fixes which principals can decrypt current content, historical content, and assist recovery; whether delegated compute exposes plaintext to ordinary service runtime; who controls canonical append attestation; and who administers exceptional access. See §9. Custody Models are this companion's term for what legacy drafts called companion modes A-E; the rename resolves the invariant-#11 namespace collision with the Respondent Ledger's Profile A/B/C.
- **Custody Hook** — the seam defined by WOS Kernel §10.5 through which a WOS runtime delegates custody of governance events to a ledger substrate. Trellis is the concrete implementation; see §24.
- **Projection** — a derived artifact that presents canonical state to a consumer (staff, respondent, or system). Every projection is a derived artifact; the term is used where presentation semantics matter.
- **Watermark** — metadata affixed to a derived artifact identifying the canonical state from which it was built. At minimum: `(tree_size, tree_head_hash)` per invariant #14. See §14.
- **Staff View** — a projection delivered to an adjudicator, reviewer, or operator. Staff views are a distinguished subclass of projection because they drive rights-impacting decisions and therefore have stricter obligations (§17).
- **Sidecar** — a subordinate, family-specific artifact layered over canonical records without redefining canonical truth. This companion specifies two: Respondent History (§23) and Workflow Governance (§24).
- **Rebuild Equivalence** — the property that a projection, materialized from canonical records at a declared checkpoint under a declared configuration, yields output semantically equivalent to the originally-produced projection for declared rebuild-deterministic fields. See §15.3.
- **Purge Cascade** — the set of operations that propagate cryptographic erasure or policy-driven purge through every derived artifact holding plaintext or plaintext-derived material. See §20.3.
- **Delegated Compute** — a specific grant under which a compute agent or model (typically an AI model) is allowed to process declared content for a declared purpose. Distinguished from provider-readable access and reader-held access. See §19.
- **Rights-Impacting Decision** — a decision that grants, denies, expands, contracts, delegates, or revokes access, authority, or capability. Authorization decisions are rights-impacting; routine read-model refreshes are not.
- **Metadata Budget** — a declaration, per canonical fact family, of which metadata is visible to which observer classes under ordinary operation. See §12.
- **Durable-Append Boundary** — the point at which a submitted append crosses from "accepted for processing" to "canonically admitted" in a way that binds attestation, retry handling, and export issuance. See §18.
- **Disclosure Manifest** — the artifact that describes, for an export or audience-specific presentation, which fields are revealed, which are committed-only, and which are withheld, with proofs tied to redaction-aware commitment slots (Core §13 (Commitment Slots Reserved)). See §13.

---

# Part I — Posture and Disclosure Discipline

## 8. Access Taxonomy

### 8.1 The Three Access Classes

**Requirement class: Companion requirement.**

Implementations handling protected content MUST distinguish the following three forms of access:

1. **Provider-readable access.** The service operator or ordinary service-side components can decrypt protected content during ordinary operation. The operator does not require a user action to read plaintext; plaintext flows through ordinary service code paths.
2. **Reader-held access.** An explicitly authorized human or tenant-side principal — not the service operator — holds decryption capability. The service runtime does not have general plaintext access for the content class. Decryption occurs under the reader's authority and is scoped by the Posture Declaration.
3. **Delegated-compute access.** A specific compute agent or model is granted scoped decryption capability for a declared purpose — typically an AI agent acting on a respondent's or operator's behalf. Delegated compute is distinguished from both provider-readable and reader-held access; it grants *scoped* plaintext visibility without conferring *standing* plaintext access to the ordinary service runtime.

### 8.2 Mandatory Declaration

**OC-01 (MUST).** For every class of protected content it handles, an Operator MUST declare, in its posture declaration (§11), which of the three access classes applies. An Operator that handles more than one content class MUST declare the access class for each; a single posture covering "all content" is conformant only if the Operator's behavior is actually uniform across content.

### 8.3 Non-Collapse

**OC-02 (MUST NOT).** An Operator MUST NOT collapse delegated-compute access into provider-readable access in its declared posture unless delegated compute actually grants standing plaintext access to the ordinary service runtime. A short-lived, scoped, audited grant to a compute agent is not equivalent to provider-readable access, and MUST NOT be described as such. The converse also holds: provider-readable access MUST NOT be described as delegated-compute access in order to soften its appearance.

### 8.4 Access-Class Inheritance

Custody models, bindings, and sidecars inherit the access taxonomy of the active Custody Model (§9). A sidecar MUST NOT use sidecar-local wording to weaken the declared access class.

---

## 9. Custody Models

### 9.1 Rationale and Naming

**Requirement class: Companion requirement.**

A *Custody Model* is a named operational posture covering custody, readability, delegated-compute behavior, recovery, canonical-attestation control, and exceptional access. Custody Models replace the legacy companion letters A-E to resolve the invariant-#11 namespace collision: the Formspec Respondent Ledger owns **Profile A/B/C** for respondent-side posture axes, and collapsing both into a single A-E naming confused three orthogonal concerns. In this companion:

- "Custody Model" = operator-side custody posture (this §9).
- "Posture Declaration" = the declarative object of §11, which carries a Custody Model reference.
- "Respondent Ledger Profile A/B/C" = Respondent Ledger posture axes (owned by Formspec; do not redefine here).
- "Conformance Class" = Core byte-level implementation class (owned by Trellis Core; not a custody term).

**This companion §9 is the canonical list of Custody Models.** The identifier set `CM-A` … `CM-F` and the normative semantics of each model are defined here. Trellis Core §21 (Posture / Custody / Conformance-Class Vocabulary) cites this section and does not restate the identifier set. The Trellis Requirements Matrix §2.2 and §4.3 cite this section and track the same identifier set.

### 9.2 The Six Standard Custody Models

**OC-03 (MUST).** An Operator MUST claim exactly one Custody Model per declared deployment scope. A deployment that handles more than one content class under more than one posture MUST declare multiple scopes, each with its own Custody Model. The six Standard Custody Models recognized by this companion are:

| Model | Short name | Access posture |
|---|---|---|
| **CM-A** | Provider-Readable Custodial | Provider-readable for current and historical content. |
| **CM-B** | Reader-Held with Recovery Assistance | Reader-held; a recovery authority may assist under declared conditions. |
| **CM-C** | Delegated Compute | Delegated compute is permitted and must declare whether plaintext reaches provider-operated components. |
| **CM-D** | Threshold-Assisted Custody | Decryption or recovery requires quorum cooperation across independent custodians. |
| **CM-E** | Organizational Trust | An organization or tenant authority controls recovery and access posture. |
| **CM-F** | Client-Origin Sovereign | Respondent/client-origin keys control ordinary decryption; operator recovery is absent unless separately declared. |

### 9.3 Required Fields per Model

**OC-04 (MUST).** Each Custody Model declaration MUST include at least the following fields, drawn from the Posture Declaration semantics (§11):

1. `custody_model_id` — one of `CM-A` … `CM-F`, or a registered extension.
2. `current_content_decryptors` — who can decrypt current content.
3. `historical_content_decryptors` — who can decrypt historical content.
4. `recovery_authorities` — who can assist recovery; empty if recovery-without-user is not supported.
5. `recovery_conditions` — declared preconditions under which recovery may be invoked.
6. `delegated_compute_posture` — whether delegated compute is permitted; if so, whether provider-operated, tenant-operated, client-side, or otherwise isolated; and whether delegated compute exposes plaintext to ordinary service components.
7. `attestation_control_authorities` — who controls issuance of canonical append attestations (Core §11 (Checkpoint Format)).
8. `exceptional_access_authorities` — actors who can invoke exceptional access, if any, and the governance under which they may do so.
9. `metadata_budget_ref` — URI reference to the metadata budget declaration (§12).

### 9.4 Model-Specific Obligations

**CM-A (MUST).** A deployment claiming CM-A MUST say so plainly and MUST NOT imply provider blindness. Delegated compute under CM-A is not confidentiality-improving because provider-readable operation already exists; the declaration MUST NOT describe delegated-compute under CM-A as increasing confidentiality.

**CM-B (MUST).** A deployment claiming CM-B MUST identify which principals may decrypt within scope and MUST identify who can assist recovery (`recovery_authorities`) and under what conditions. Reader-held access MUST NOT be described as provider-readable ordinary operation.

**CM-C (MUST).** A deployment claiming CM-C MUST state whether plaintext becomes visible to any provider-operated component during delegation. If yes, the declaration MUST additionally describe the residual-plaintext lifecycle — how long plaintext persists, which derived artifacts capture it, and how those artifacts are purged when the delegation ends.

**CM-D (MUST).** A deployment claiming CM-D MUST declare quorum thresholds, participant independence posture, and the exceptional-access process. Threshold participation MUST NOT be described more strongly than the actual recovery process supports; a single-party escape hatch invalidates a CM-D claim.

**CM-E (MUST).** A deployment claiming CM-E MUST identify the scope of organizational authority and any exceptional-access controls. CM-E MUST still distinguish provider-readable access from organization-controlled access where they differ; an organization may control access policy without itself being provider-readable.

**CM-F (MUST).** A deployment claiming CM-F MUST identify the client-origin key authority, the absence or presence of operator recovery, and the consequences of client key loss. CM-F MUST NOT imply legal or operational availability beyond what the key-custody design supports.

### 9.5 Combinations and Extensions

**OC-05 (MAY).** An Operator MAY register an extended Custody Model that composes properties of the six standard models, subject to the transition rules of §10 and the declaration honesty rules of §11. Extended models MUST use model identifiers outside the reserved `CM-A` … `CM-F` range.

### 9.6 Non-Collision with Respondent Ledger Profile A/B/C

**OC-06 (MUST NOT).** Custody Model identifiers MUST NOT reuse the labels `A`, `B`, or `C` as bare identifiers (use `CM-A`, `CM-B`, `CM-C`). Respondent Ledger Profile A/B/C remain owned by Formspec and are not interchangeable with Custody Models; a sidecar MUST NOT equate them.

---

## 10. Posture-Transition Auditability

### 10.1 Transitions Are Canonical Events

**Requirement class: Companion requirement.**

**OC-07 (MUST).** Any change in:

- Custody Model (§9),
- access taxonomy class (§8.1) for any declared content class,
- recovery authority or recovery conditions,
- delegated-compute posture,
- metadata budget,
- declared posture honesty statement (§11),

MUST be treated as a **Posture Transition**. Each transition MUST be recorded as a canonical event on the append-only chain (Core §6 (Event Format)), carrying at minimum the fields declared in §10.3.

### 10.2 No Silent Transitions

**OC-08 (MUST NOT).** An Operator MUST NOT change any posture element listed in §10.1 without recording a Posture Transition canonical event. An undocumented change is a conformance violation regardless of whether any downstream artifact breaks.

**OC-09 (MUST NOT).** An Operator MUST NOT retroactively rewrite a prior posture declaration. Corrections to past declarations MUST be represented as forward transitions; the prior declaration remains on the chain as part of the immutable record. Any operator correction of an over-stated prior posture MUST be declared as a transition (§10.1) with explicit acknowledgement that the prior declaration was inaccurate.

### 10.3 Required Transition-Event Semantics

**OC-10 (MUST).** A Posture Transition canonical event MUST carry semantic content sufficient to answer every one of these questions without network access:

1. **Identity** — a stable identifier for this transition, unique within its ledger scope.
2. **New posture binding** — an immutable reference to the posture declaration in force AFTER the transition (the prior posture is derived by state continuity against the most recent prior transition or initial declaration; a separate prior-reference field is not required).
3. **Actor** — the principal responsible for issuing the transition.
4. **Policy authority** — the governance authority under which the transition is made (for example, the governance body that approved a Custody Model change).
5. **Effective instant** — when the transition takes effect.
6. **Temporal scope** — one of `prospective`, `retrospective`, or `both`, declaring whether the transition applies to records appended after the effective time only, to prior records as well, or to both. Retrospective scope MUST NOT be used to rewrite prior records; it applies the new posture's disclosure and access rules to prior records' subsequent handling.
7. **Attestations** — signatures from the signing authorities required by §10.4. Where the attestation control authority (§9.3 field 7) changes across the transition, both the outgoing and incoming authorities SHOULD attest; where only the incoming authority can attest because the outgoing authority is unavailable or compromised, the declaration MUST record that fact.

The wire shape that realizes these Posture-transition obligations is normatively pinned in Appendix A.5.1 (custody-model transitions) and Appendix A.5.2 (disclosure-profile transitions, on the Respondent Ledger Profile A/B/C axis). An implementation that emits one of the Phase 1 concrete subtypes per §6.7 satisfies OC-10 by virtue of the subtype CDDL; implementations MUST NOT emit the abstract parent shape directly.

### 10.4 Scope of Transition Attestations

**OC-11 (MUST).** Narrowing Posture-transitions — transitions that reduce disclosure obligations or access surface on any Posture axis (for example, tightening metadata budgets, or contracting a disclosure profile) — MAY be attested by the new authority alone. Posture-expanding transitions — transitions that expand the access or disclosure surface along any Posture axis, including but not limited to any Custody-Model transition from a reader-held model to a provider-readable model — MUST be dually attested by both authorities where both exist; a unilateral expansion by the party gaining access is NON-CONFORMANT.

### 10.5 Downstream Obligations on Transition

**OC-12 (MUST).** On committing a Posture Transition:

- Projections consuming the affected content class MUST re-evaluate display and access gating against the new posture at or before the effective time (§17).
- Disclosure manifests (§13) that reference content appended under the prior posture MUST continue to honor the prior posture's declared disclosure rules unless the transition is `retrospective` and the new posture's rules are stricter.
- Authorization evaluators (§25) MUST treat the transition as a canonical grant-family fact and rebuild affected evaluator state accordingly.

---

## 11. Posture-Declaration Honesty

### 11.1 Required Publication

**Requirement class: Companion requirement. Expands Trellis Core invariant #15.**

**OC-13 (MUST).** An Operator MUST publish a **Posture Declaration** alongside each export bundle (Core §18 (Export Package Layout)). The Posture Declaration is a machine- and human-readable document that describes, for the export scope:

1. the **access taxonomy** class applicable to each content class in the export (§8),
2. the **Custody Model** in force at the time each canonical record in the export was appended (§9),
3. the **external-anchor dependency** posture — whether any tamper-evidence claim in the export depends on external witnesses or anchoring (§26), and if so which witnesses or anchors,
4. the **crypto-shredding scope** — which content classes and which keys may be destroyed, and the declared consequence for derived artifacts (§20.3),
5. a **metadata-leakage acknowledgement** — what metadata remains visible to the service and to other observers, per §12.

### 11.2 Invariant-#15 Floor

**OC-14 (MUST NOT).** An implementation MUST NOT describe trust posture more strongly than behavior supports.

- If payloads are provider-readable in ordinary operation, the posture declaration MUST say so plainly.
- If "tamper-evident" depends on an external anchor or witness, the declaration MUST name the dependency.
- Cryptographic controls alone MUST NOT be described as legal admissibility.
- A posture declaration that is silent on a required element is not conformant; silence is not neutrality.

### 11.3 Export-Bundle Binding

**OC-15 (MUST).** Each export bundle (Core §18 (Export Package Layout)) MUST either embed the Posture Declaration or carry an immutable, content-addressed reference to it. Verifiers (Core §19 (Verification Algorithm)) MUST treat the referenced Posture Declaration as part of the verified export; an export whose Posture Declaration is unavailable at verification time is verifiable for bytes but not for posture, and this fact MUST be surfaced to the relying party.

### 11.4 Auditor Comparison

**OC-16 (MUST).** An Auditor claiming conformance to this companion MUST be able to compare declared posture (from the Posture Declaration) against observed control-plane behavior. Operators MUST provide Auditor access to the control-plane surface required to perform that comparison without requiring access to protected payloads.

### 11.5 Mismatch Handling

**OC-17 (MUST).** A mismatch between declared posture and observed behavior is a **posture-honesty violation**. The Operator MUST:

1. record the mismatch as a canonical governance fact,
2. treat the correction as a Posture Transition under §10 (typically retrospective),
3. publish the corrected Posture Declaration and the record of the mismatch,
4. notify auditors and relying parties consistent with the metadata budget and disclosure manifest rules.

---

## 12. Metadata Budget Discipline

### 12.1 The Declaration-as-Table Form

**Requirement class: Companion requirement.**

**OC-18 (MUST).** For each declared scope, the Operator MUST publish a **Metadata Budget** as a declaration table. Prose-only budgets are NON-CONFORMANT: the budget MUST be structured, per-fact-family, and comparable to observed behavior by an auditor without natural-language interpretation.

The table form is normative. Prose commentary MAY accompany the table; it MUST NOT substitute for it.

### 12.2 Table Rows and Columns

**OC-19 (MUST).** Each row of the Metadata Budget table MUST describe one canonical fact family (for example, `intake_receipt`, `adjudication_decision`, `amendment`, `grant`, `revocation`, `lifecycle_erasure`). Each row MUST include at least the following columns:

| Column | Meaning |
|---|---|
| `fact_family` | Canonical fact family identifier, as declared in the active binding. |
| `visible_fields` | Envelope or canonical fields visible to which observer classes under ordinary operation. |
| `observer_classes` | Who MAY observe these fields — e.g., `provider`, `tenant_admin`, `reader`, `monitor`, `witness`, `auditor`. |
| `timing_leakage` | Timing, frequency, or access-pattern signals the deployment exposes for this family. |
| `access_pattern_leakage` | What a query-pattern observer can infer — e.g., which respondents are under active adjudication. |
| `linkage_stability` | Which identifiers remain stable across sessions, exports, or disclosures, and for how long. |
| `delegated_compute_effects` | Metadata or plaintext exposure introduced by delegated compute relative to nominal posture. |

### 12.3 Coverage Rule

**OC-20 (MUST).** The Metadata Budget table MUST cover every canonical fact family the Operator admits. A fact family that is appended but not listed is a budget gap and a conformance violation. Operators SHOULD update the Metadata Budget as part of any binding change that introduces a new fact family.

### 12.4 Visible-Metadata Ceiling

**OC-21 (SHOULD).** Visible metadata SHOULD be limited to what is required for:

- canonical verification,
- schema or semantic lookup,
- required audit-visible declarations,
- conflict gating,
- append processing.

**OC-22 (SHOULD NOT).** Implementations SHOULD NOT retain visible metadata merely to accelerate derived artifacts.

**OC-23 (MUST NOT).** Implementations MUST NOT retain visible append-related metadata merely for operational convenience when the same function can be satisfied by derived or scoped mechanisms.

### 12.5 Payload-Confidentiality Is Not Metadata Privacy

**OC-24 (MUST NOT).** An Operator MUST NOT describe payload confidentiality as equivalent to metadata privacy. A Metadata Budget that documents only payload protection and ignores metadata leakage is NON-CONFORMANT.

### 12.6 Posture Inheritance

**OC-25 (MUST).** A custody model, binding, or sidecar MUST remain consistent with the active Custody Model's Metadata Budget and MUST NOT imply weaker metadata leakage than the active budget declares. Sidecar-local wording MUST NOT be used to weaken or bypass the budget.

---

## 13. Selective Disclosure Discipline

### 13.1 Slot Population, Not Slot Redefinition

**Requirement class: Companion requirement.**

Trellis Core reserves **redaction-aware commitment slots** in the envelope header (Core §13 (Commitment Slots Reserved)) — the byte positions for per-field commitments (Pedersen, Merkle leaves, or equivalent) that enable later selective disclosure without envelope reissue. This companion specifies how those slots are **populated** and how **disclosure manifests** are assembled over them. Implementation of BBS+ or equivalent advanced selective-disclosure cryptography remains **deferred** to Phase 3+.

### 13.2 Population Rule

**OC-26 (MUST).** When an Operator admits a canonical record that is subject to later selective disclosure — for example, a record that may later be redacted for FOIA, sealed for child-welfare, or selectively disclosed to opposing counsel — the Operator MUST populate the redaction-aware commitment slots declared by the active binding (Core §13 (Commitment Slots Reserved)). Records appended without commitment slots populated are ineligible for later selective disclosure without envelope reissue, which is a NON-CONFORMANT path for Phase 2+.

### 13.3 Disclosure Manifest Structure

**OC-27 (MUST).** A **Disclosure Manifest** is the artifact that describes, for an export or audience-specific presentation, how selective disclosure was performed. A Disclosure Manifest MUST include at least:

1. `manifest_id` — stable identifier.
2. `export_ref` — reference to the export bundle to which this manifest applies.
3. `audience` — declared audience scope (for example, `foia_public`, `opposing_counsel`, `appellate_court`).
4. `disclosed_fields` — structured list of fields revealed, by canonical path.
5. `committed_only_fields` — structured list of fields that remain committed-but-withheld, with references to the Core §13 (Commitment Slots Reserved) commitment slots that prove integrity.
6. `withheld_fields` — structured list of fields neither disclosed nor committed (if any such class is supported by the active binding), with the authority under which they are withheld.
7. `redaction_authority` — the principal or policy authority under which redactions were performed.
8. `redaction_reason_class` — a classified reason (FOIA exemption, sealing order, minimization) without embedding protected content in the reason.
9. `commitment_proofs` — proof material tying `disclosed_fields` and `committed_only_fields` to the Core-reserved commitment slots.

### 13.4 Disclosure Honesty

**OC-28 (MUST NOT).** A Disclosure Manifest MUST NOT be presented as a rewrite of canonical truth. A disclosure-oriented artifact is derived; canonical records remain authoritative (Core §6 (Event Format)).

**OC-29 (MUST).** A Disclosure Manifest MUST preserve provenance distinctions — author-originated facts, canonical records, canonical append attestations, and later disclosure artifacts remain distinct (Core §3 (Terminology)).

### 13.5 Redaction Auditability

**OC-30 (MUST).** Each redaction represented by a Disclosure Manifest MUST be independently auditable: an Auditor MUST be able to verify that the commitment slots in the original canonical record match the commitments referenced by the manifest, without requiring access to the plaintext of withheld fields.

### 13.6 Deferral

**OC-31 (SEAM DEFINED; ADVANCED CRYPTO DEFERRED TO PHASE 3+).** This companion does not require BBS+, group signatures, or other advanced selective-disclosure cryptography. The Phase 2 requirement is population discipline (§13.2) and manifest structure (§13.3) over the Core-reserved slots. Phase 3+ deployment classes MAY elevate specific cryptographic mechanisms to MUST.

---

# Part II — Derived Artifacts and Projections

## 14. Derived-Artifact Discipline

### 14.1 The Invariant-#14 Requirement

**Requirement class: Companion requirement. Expands Trellis Core invariant #14.**

**OC-32 (MUST).** Every derived artifact — including but not limited to projections, materialized views, indexes, caches, staff dashboards, read models, timelines, snapshots, and evaluator state — MUST carry a **watermark** identifying the canonical state from which it was derived.

Traceability: TR-OP-001 and TR-OP-002.

The watermark MUST include at minimum:

1. `canonical_checkpoint_id` — the Core §11 (Checkpoint Format) checkpoint identifier the artifact references,
2. `tree_size` — the canonical append height or sequence position at build time,
3. `tree_head_hash` — the append-head reference (Core §11 (Checkpoint Format)),
4. `build_timestamp` — the time at which the artifact was built,
5. `projection_schema_id` — the schema and version identifier under which the artifact was produced,
6. `rebuild_path` — sufficient declared configuration history to rebuild the artifact from canonical records at the referenced checkpoint.

### 14.2 No Second Canonical Truth

**OC-33 (MUST NOT).** No projection, evaluator state, cache, snapshot, timeline, dashboard, queue, index, read model, materialized view, workflow runtime state, or any other derived artifact is authoritative for canonical facts. This is the operational restatement of the derived-artifact rule fixed by Core §15 (Snapshot and Watermark Discipline) — every derived artifact carries a watermark and a rebuild path precisely because it is not itself canonical truth; it applies regardless of the artifact's durability, retention, signing, or operational centrality.

### 14.3 Canonical Resolution

**OC-34 (MUST).** Where derived-artifact state conflicts with canonical records, the Operator MUST resolve to canonical records and treat the derived artifact as stale, inconsistent, or in need of rebuild. Resolving the other direction — treating the derived artifact as authoritative and "correcting" canonical records to match — is NON-CONFORMANT.

### 14.4 Declared Configuration History

**OC-35 (MUST).** The Operator MUST retain enough declared configuration history that a rebuild at a prior canonical checkpoint yields the same derived output that was produced at that checkpoint, for fields declared rebuild-deterministic (§15.3). Declared configuration includes projection schema versions, filter predicates, evaluator policy versions, translation tables, and aggregation rules.

### 14.5 Elevation Prohibition

**OC-36 (MUST NOT).** An Operator MUST NOT elevate a derived artifact to canonical status by configuration, policy, or disclosure. Derived artifacts reach canonical status only by being admitted as canonical records by the active binding (Core §10 (Chain Construction)).

### 14.6 Authorization Evaluators Are Derived

Authorization evaluators — derived components that contribute to rights-impacting decisions — are subject to the full derived-artifact discipline of this section, plus the stale-state behavioral discipline of §25. Silent fail-open behavior in an Authorization Evaluator is NON-CONFORMANT; see §25.

---

## 15. Projection Runtime Rules

### 15.1 Projection Categories

**Requirement class: Companion requirement.**

**OC-37 (MUST).** A Projection Producer MUST classify each projection it produces into one of:

1. **Consumer-Facing Projection** — a projection delivered to a human consumer (staff or respondent).
2. **System Projection** — an internal cache, index, read model, or materialized view consumed only by the platform itself.

Both categories carry the watermark obligations of §14.1. Consumer-Facing Projections additionally carry the display obligations of §15.2 and the staleness obligations of §15.4.

### 15.2 Watermark Display

**OC-38 (MUST).** Consumer-Facing Projections MUST display or otherwise make available to the consumer the watermark fields required for that consumer to assess freshness. An implementation MAY elide fields that are not meaningful to the consumer (for example, `projection_schema_id` on a respondent-scoped view), but MUST NOT elide the `canonical_checkpoint_id` or `tree_head_hash`.

Traceability: TR-OP-001 and TR-OP-002.

### 15.3 Rebuild Equivalence

**OC-39 (MUST).** Rebuilding a projection from canonical records, at the same canonical checkpoint and under the same declared configuration, MUST yield semantically equivalent output for every projection field declared **rebuild-deterministic**.

**OC-40 (MUST).** A Projection Producer MUST declare which fields of each projection are rebuild-deterministic. Fields that intentionally incorporate non-canonical inputs (for example, live operational metrics) MUST be declared non-deterministic and MUST NOT be relied upon for verification.

Traceability: TR-OP-005 and TR-OP-006.

### 15.4 Staleness Indication

**OC-41 (MUST).** If a projection is stale relative to a newer canonical checkpoint available to the Producer, the view MUST indicate stale status. A stale indicator MUST communicate freshness relative to canonical append height; it MUST NOT reveal the content of canonical updates that have not yet been projected (see §28).

### 15.5 Integrity Sampling Policy

**OC-42 (MUST).** Each conforming deployment MUST define a **projection integrity policy** that includes at least one of the following mechanisms, exercised on a declared cadence:

1. **Sampled rebuild comparison** — periodically or on demand, rebuild declared projection fields from canonical inputs for a sample of records or sequence ranges and compare against materialized projection state.
2. **Checkpoint-bound equivalence** — at declared epoch boundaries, record a content commitment (for example, a hash) for projection state in checkpoint or export material, and verify rebuild matches that commitment before treating the projection as authoritative for recovery.

**OC-43 (SHOULD).** Authorization-expanding projections — projections whose output is consumed by an Authorization Evaluator (§25) — SHOULD be checked at higher frequency than general read models.

### 15.6 Rebuild Fixture Integrity

**OC-44 (MUST).** Projection conformance tests MUST validate watermark presence and stale-status behavior. Rebuild verification fixtures MUST be protected against tampering; a compromised fixture could mask projection drift from canonical truth and defeat the verification discipline of this section.

### 15.7 Purge-Cascade Interaction

Purge-cascade obligations (§20.3) apply to every projection, including system projections. A projection that retains plaintext after a canonical crypto-shred event is NON-CONFORMANT regardless of whether the projection is consumer-facing.

---

## 16. Snapshot-from-Day-One

### 16.1 The Invariant-#14 Cadence Requirement

**Requirement class: Companion requirement. Expands Trellis Core invariant #14.**

**OC-45 (MUST).** An Operator MUST produce **checkpoint snapshots** from day one of operation. A deployment that relies on full-replay-only reconstruction is NON-CONFORMANT: at case-file scale, full-replay-only rebuild is operationally infeasible, and retrofitting snapshots later invalidates every derived artifact already shipped.

### 16.2 Cadence

**OC-46 (MUST).** Each deployment MUST declare a snapshot cadence. The cadence MAY be:

- **time-based** — snapshots produced at declared intervals (hourly, daily, per case-close),
- **height-based** — snapshots produced every N canonical records,
- **event-driven** — snapshots produced at specific canonical events (case submission, adjudication, sealing),
- **hybrid** — any composition of the above.

The declared cadence MUST be comparable to observed behavior by an Auditor. Absent snapshots where the cadence requires them is a conformance violation. Traceability: **TR-OP-008** anchors the cadence obligation for G-3 lint coverage; conformance fixtures reference TR-OP-008 via `coverage.tr_op`.

### 16.3 Snapshot Integrity Binding

**OC-47 (MUST).** Each snapshot MUST bind to the canonical chain such that:

1. The snapshot references the canonical checkpoint at which it was built (Core §11 (Checkpoint Format)).
2. The snapshot's integrity (its content commitment) is verifiable against the canonical chain by a verifier with access to the chain and the snapshot.
3. The snapshot itself is NOT canonical truth (§14.2); it is a derived artifact subject to §14 in full.

### 16.4 Snapshot as Recovery Substrate

**OC-48 (MUST).** A snapshot MAY be used to accelerate recovery or rebuild of derived artifacts. Where a snapshot is used as a recovery substrate, its rebuild equivalence (§15.3) MUST have been established — by sampled rebuild, checkpoint-bound equivalence, or both — before it is relied upon. A snapshot whose equivalence has not been established MUST NOT be used for recovery of rights-impacting state.

### 16.5 Retention and Purge Cascade

Snapshots that contain plaintext or plaintext-derived material are subject to the purge-cascade rules of §20.3. A snapshot MUST NOT be used to resurrect canonically-destroyed plaintext into live derived artifacts.

---

## 17. Staff-View Integrity

### 17.1 Staff Views Are Rights-Impacting Surfaces

**Requirement class: Companion requirement.**

Adjudicator-facing and reviewer-facing projections — "staff views" — are a distinguished subclass of Consumer-Facing Projection because they drive rights-impacting decisions. A staff view that quietly lies about canonical state can produce an adjudication that differs from what the canonical record would support; that is precisely the failure mode Trellis exists to prevent. Staff-view integrity therefore carries stricter obligations than respondent-facing views.

### 17.2 Watermark Propagation

**OC-49 (MUST).** Every staff view MUST carry and display the watermark fields of §14.1 such that the adjudicator can determine, at the moment of decision, the canonical checkpoint against which the view was built.

### 17.3 Stale-View Signaling

**OC-50 (MUST).** A staff view that is stale relative to a newer canonical checkpoint available to the Producer MUST signal stale status before the adjudicator can submit a rights-impacting action based on the view. The signal MUST NOT be dismissable by default; an adjudicator proceeding over a stale view MUST record acknowledgement of the stale status as part of the governance event.

### 17.4 Decision-Binding

**OC-51 (MUST).** When a rights-impacting decision is captured as a canonical event (Core §6 (Event Format)), the event MUST record the watermark of the staff view on which it was based. This binds the adjudicator's decision to the canonical state they actually saw — not to the canonical state at the moment the decision was recorded, and not to some later authoritative state.

### 17.5 No Silent Override

**OC-52 (MUST NOT).** A staff view MUST NOT override canonical truth. Where staff-view state and canonical records disagree, canonical records prevail (§14.3); the staff view is stale or inconsistent.

### 17.6 Respondent-Facing Integrity

Respondent-facing views are Consumer-Facing Projections and are subject to §15 in full. Respondent-facing views carry the additional obligation to respect the active Metadata Budget (§12) so that a respondent's own view does not leak metadata the budget withholds.

---

# Part III — Operational Contracts

## 18. Append Idempotency (Operational)

### 18.1 Core Byte Contract Assumed

**Requirement class: Companion requirement. Expands Trellis Core invariant #13.**

Trellis Core §17 (Append Idempotency Contract) fixes the **byte-level** contract: every `append` call carries a stable idempotency key; retries with the same key and payload MUST return the same canonical record reference; retries with the same key and a different payload MUST be rejected with `IdempotencyKeyPayloadMismatch`; and the idempotency identity is permanent within a ledger scope. This section specifies the **operational** obligations layered over that byte contract.

### 18.2 Retry Budgets

**OC-53 (MUST).** An Operator MUST declare a **retry budget** per append scope: the maximum number of retries a caller may submit against a single idempotency key before the key is considered exhausted. Further retries against an exhausted key MUST be rejected with a declared rejection class (§21).

### 18.3 API Retry Windows

**OC-54 (MUST).** An Operator MUST declare an **API retry window** for how long ordinary callers can expect low-latency retry responses for an idempotency key. Expiry of this API window MUST NOT permit key reuse within the same ledger scope. After the window expires, the service MAY answer through an archive lookup, slower rebuild, or declared rejection class, but it MUST NOT accept a different payload under the same `(ledger_scope, idempotency_key)`.

**OC-55 (MUST).** The API retry window and post-window behavior MUST be declared in the Posture Declaration (§11) such that callers know whether retries remain fast-path, archive-backed, or rejected without changing the Core identity rule.

### 18.4 Dedup Store Lifecycle

**OC-56 (MUST).** An Operator MUST maintain a **dedup store** sufficient to answer retries within the API retry window. The dedup store is a derived artifact subject to §14: it carries a watermark, is rebuildable from canonical records plus declared configuration, and MUST NOT be authoritative for canonical facts. Dedup-store compaction MUST preserve enough canonical or archived material to enforce permanent idempotency identity.

**OC-57 (MUST).** The dedup store MUST be durable enough that a single ordinary-operator failure (e.g., restart of the appending service) does not cause a retry within the API retry window to produce a different canonical outcome than the original submission.

### 18.5 Replay-Observable Semantics

**OC-58 (MUST).** For a given idempotency identity within a declared append scope, every successful retry MUST resolve to the same canonical record reference, or to the same declared no-op outcome. A caller replaying against a key that has already produced a canonical record MUST observe the identical record reference; a caller replaying against a key that produced a rejection MUST observe the same rejection class.

**OC-59 (MUST NOT).** Duplicate or retried submission handling MUST NOT create ambiguity about whether a canonical record was newly appended, previously appended, or not admitted.

### 18.6 Idempotent-Acceptance Consequences

**OC-60 (MUST).** If idempotent acceptance is supported (retries resolved to the previously appended record reference), the Operator MUST define the **verifier-visible consequences** of that behavior in the Posture Declaration. A verifier MUST be able to distinguish a newly appended record from an idempotent resolution to an existing record, where the active binding's proof model supports the distinction.

### 18.7 Durable-Append Boundary

**OC-61 (MUST).** An Operator MUST declare a **durable-append boundary** that governs attestation, retry handling, and export issuance for a canonical record. The boundary MUST be expressed such that consumers and verifiers can determine whether a given canonical record has crossed it.

**OC-62 (MUST).** Any proof material or referenced state required to recover or verify a canonical record within the declared export scope MUST be durably recoverable no later than the declared durable-append boundary.

### 18.8 Replica Completion Is Not Canonical

**OC-63 (MUST).** Replica completion state MUST remain operational state, not canonical truth. The presence, absence, or synchronization lag of any individual replica is a derived condition and MUST NOT be treated as modifying canonical facts.

### 18.9 Bundle-Publication Reservation Lifecycle

**OC-63a (SHOULD).** Operators backing the bundle-publication index with a durable store that reserves `(bundle_scope, seal_version)` before artifact writes (the Phase-1 Postgres reference adapter does this via the `trellis_bundle_publications` table with `ON CONFLICT DO NOTHING` on the PK) MUST account for dead reservations: rows where the reservation landed but the artifact-ref population path did not complete (process crash between reservation and ZIP write, network failure mid-upload). A dead reservation is hidden from `get_bundle_publication_by_digest` lookups by design — it does not falsely satisfy reads — but it blocks same-identity retries with different inputs because the PK is already occupied.

**Operational guidance (non-normative).** For Phase-1 single-tenant deployments, manual SQL cleanup is acceptable:

```sql
-- Identify dead reservations older than 1 hour
SELECT scope, seal_version, reserved_at
FROM trellis_bundle_publications
WHERE artifact_ref IS NULL
  AND reserved_at < NOW() - INTERVAL '1 hour';

-- Remove a specific dead reservation (operator-judgment; never invoked mid-publish)
DELETE FROM trellis_bundle_publications
WHERE scope = '<scope>'
  AND seal_version = <version>
  AND artifact_ref IS NULL;
```

The retention threshold is operator policy; one hour is a reference value, not a normative bound. The cleanup MUST NOT race a legitimate in-flight publish; `reserved_at` aging gives the in-flight path bounded time to complete before its row becomes a janitor candidate.

**Multi-tenant evolution path (informative).** When multi-tenant scale or distributed publication arrives, two approaches are tractable: (a) add a `reserved_at` TTL column plus a periodic janitor task that DELETEs dead reservations under a `reserved_at < NOW() - <ttl>` filter, or (b) hold the reservation in a Postgres advisory lock with transaction scope (auto-released on process exit) instead of a durable row. The Phase-1 PK-reservation pattern survives both evolutions; only the cleanup mechanism changes. Track at the platform-level when a real multi-tenant trigger appears (see formspec-stack `thoughts/plans/2026-05-18-end-state-substrate-closeout.md` long-term question 2 on `ScopedAdvisoryLease` backend neutrality).

**Why this is operational, not Core.** Core §17 (Append Idempotency Contract) fixes byte-level append idempotency; bundle publication is downstream of append and uses a different identity (`(bundle_scope, seal_version)`, not `(ledger_scope, idempotency_key)`). The dead-reservation concern is adapter-shaped: the SQLite and in-memory bundle-publication adapters have no equivalent failure mode. Conformant Phase-1 verifiers do not observe this state; this subsection is operator-facing.

---

## 19. Delegated-Compute Honesty

### 19.1 Scope: AI Agents and Scoped Delegates

**Requirement class: Companion requirement.**

Delegated compute is the access class under which an AI agent (or any compute agent acting on behalf of a principal) is granted scoped plaintext access to process declared content for a declared purpose. It is distinct from provider-readable access and from reader-held access; misrepresenting one as another is a posture-honesty violation (§11).

This section applies in particular to AI agents acting on respondent or operator behalf — for example, an assistive drafting model, a pre-fill model, an adjudication-support model, or an intake-triage model. These agents are within-scope for the WOS autonomy-cap regime; this companion specifies the Trellis-side attestation and audit obligations.

### 19.2 Required Grant Structure

**OC-64 (MUST).** A delegated-compute grant MUST be:

1. **Explicit** — recorded as a canonical grant-family fact (see §25) before compute begins.
2. **Attributable** — to a principal, policy authority, or comparable authority.
3. **Scoped** — to declared content or classes of content. A grant without scope is NON-CONFORMANT.
4. **Auditable** — compute-agent activity under the grant MUST be recordable against the grant reference.

**OC-65 (SHOULD).** A delegated-compute grant SHOULD be **time-bounded** or **purpose-bounded**. A grant without any such bound is conformant only if the Operator's declared governance explicitly permits open-ended grants.

### 19.3 Authority Attestation

**OC-66 (MUST).** Each delegated-compute grant MUST carry an **authority attestation** identifying the principal and governance under which the grant was issued. The attestation MUST be recorded as part of the grant canonical fact so that later verifiers can trace a compute output back to the authority that authorized it.

### 19.4 Attribution of Compute Output

**OC-67 (MUST).** If workflow, policy, adjudication, access decisions, or materially consequential system actions rely on delegated-compute output, the Operator MUST:

1. **Record that output as a canonical fact** or maintain a canonical reference to a stable output artifact.
2. Preserve an auditable link to the **authorizing principal** (the grantor).
3. Preserve an auditable link to the **compute agent identity** (the grantee).
4. Preserve an auditable link to the **scope** of delegated access relevant to that output.
5. Declare whether the relied-upon output is **advisory**, **recommendatory**, or **decision-contributory**.

### 19.5 No Scope Drift

**OC-68 (MUST NOT).** A delegated-compute grant MUST NOT be interpreted as conferring standing plaintext access to the ordinary service runtime. A grant to a scoped compute agent does not expand the Operator's general readability posture.

**OC-69 (MUST NOT).** Delegated-compute grants MUST NOT be silently extended. Any expansion of grant scope is a new grant and MUST be recorded as a separate canonical fact; expiry MUST be recorded as a canonical revocation.

### 19.6 Interaction with WOS Autonomy Caps

WOS governs AI autonomy caps — which agents may act on whose behalf and with what authority — at the governance layer. Trellis governs the custody and attribution of the compute activity. An operator MUST NOT treat Trellis attestation as a substitute for WOS autonomy-cap evaluation; the two are independent gates. A compute output bearing a valid Trellis delegation attestation but issued under a WOS autonomy cap violation is NON-CONFORMANT at the WOS layer regardless of the Trellis attestation.

### 19.7 Custody-Hook Binding

Where a WOS runtime uses Trellis as its custody backend via WOS Kernel §10.5 `custodyHook`, delegated-compute grants issued within the WOS governance envelope MUST be recorded through the `custodyHook` path as Trellis canonical grants. See §24 for the `custodyHook` binding.

### 19.8 Supply-Chain Considerations

**OC-70 (SHOULD).** Operators SHOULD declare the provenance of compute-agent artifacts — model identifiers, version references, training-data provenance where claimed — as part of the authority attestation (§19.3). Supply-chain misrepresentation is a posture-honesty violation (§11.2).

### 19.9 Delegated-Compute Declaration Document

**OC-70a (MUST).** An Operator running any agent-in-the-loop deployment whose access class includes `delegated_compute` (§8.1, Appendix A.2) MUST publish a **Delegated-Compute Declaration** per Appendix A.6 alongside the Posture Declaration (§11). The declaration binds the static claims of §§19.2–19.8 to machine-checkable fields — scope, authority, audit event types, attribution discriminator, supply-chain posture — so that a verifier or auditor can reconcile the Operator's asserted delegation behavior against on-ledger evidence.

**OC-70b (MUST).** The Declaration's `posture_declaration_ref` MUST resolve to a Posture Declaration whose access-taxonomy row for every listed `content_class` declares `access_class = delegated_compute`. A Declaration whose referenced posture does not declare delegated-compute access for one of its listed content classes is NON-CONFORMANT.

**OC-70c (MUST).** Every event emitted under a Declaration's scope MUST attribute to exactly one of `actor_human` or `actor_agent_under_delegation` (invariant #15; Appendix A.6 rule 11). Dual-population or empty-population is NON-CONFORMANT. This obligation flows through to Core §19 (Verification Algorithm): a chain in which delegated-compute events fail the actor-discriminator rule fails `integrity_verified` through the operational-conformance path.

**OC-70d (MUST).** The Declaration's `[signature]` block MUST be structurally valid even when its content is a placeholder: `alg` MUST equal a Phase-1 registered value (currently only `"EdDSA"` per Core §7 (Signature Profile) §7.1 / §7.2); `signer_kid` MUST be a non-empty string identifier resolving in the Operator's key registry; `cose_sign1_b64` MUST be a non-empty base64-shaped string. Phase-1 reference declarations MAY ship with placeholder signature bytes provided the field shapes are valid; conforming production declarations MUST replace the placeholder with a real COSE_Sign1 value. The structural check is independent of crypto verification and runs without a key snapshot. Traceability: **TR-OP-047** — enforced by `scripts/check-specs.py` rule R14.

**OC-70e (MUST).** Across all O-4 Declaration documents in a deployment corpus, the `supersedes` graph MUST be acyclic, resolvable, AND temporal-in-force per Appendix A.6 rule 15. Every non-empty `supersedes` value MUST point to a `declaration_id` carried by another Declaration; `declaration_id` values MUST be unique across the corpus; no chain MUST revisit a node. Empty-string and absent `supersedes` denote "no predecessor" (root of a chain). For each edge `successor -> predecessor`, the predecessor MUST have been in force at the successor's `effective_from`: the predecessor's `effective_from` is at or before the successor's `effective_from`, and the predecessor's `scope.time_bound` (when present) is strictly after the successor's `effective_from`. Absent `scope.time_bound` (key absent per the A.6 nullable-field convention) is open-ended. Successor declarations supersede predecessors in chronological order; the chain is the auditor's path back to the prior declaration in force at any point in the deployment timeline. Appendix A.6 rule 15 is the contract; this section cites it. Traceability: **TR-OP-048** — enforced by `scripts/check-specs.py` rule R15 (`check_declaration_supersedes_acyclic`).

---

## 20. Lifecycle and Erasure

### 20.1 Lifecycle Facts Are Canonical

**Requirement class: Companion requirement.**

**OC-71 (MUST).** If an Operator supports any lifecycle operation whose outcome affects compliance posture, retention posture, or recoverability claims — including retention, legal hold, archival, key destruction, sealing, schema upgrade, or export issuance — it MUST represent that operation as a canonical lifecycle fact (Core §6 (Event Format)).

**OC-72 (MAY).** An Operator MAY support a subset of lifecycle operations or none. The conformance obligation attaches only where the operation exists.

### 20.2 Sealing and Precedence

**OC-73 (MUST).** An Operator MUST define whether sealed cases, sealed records, or equivalent sealed scopes permit later lifecycle or governance facts. Ambiguity here produces adjudication errors under seal; clarity is a conformance requirement.

**OC-74 (MUST).** An Operator MUST define whether retention or legal-hold rules take precedence when both apply. **Legal hold SHOULD take precedence over retention** in the default configuration: a record on legal hold MUST NOT be destroyed by a retention rule without a governance-layer override. Operators that invert this precedence MUST declare so explicitly and justify the inversion in their governance documentation.

### 20.3 Crypto-Shredding Scope

**OC-75 (MUST).** Trellis Core owns the cryptographic mechanics that make crypto-shredding work: Core §9 (Hash Construction) requires `content_hash` over ciphertext so that destroying the payload DEK leaves the chain verifiable, and the HPKE key-bag wrap defined therein holds the DEK that erasure destroys. This companion adds the **operational** obligation: cryptographic erasure is **incomplete** until the **purge cascade** completes across every derived artifact holding plaintext or plaintext-derived material subject to the erasure event.

Traceability: TR-OP-004.

### 20.4 Purge-Cascade Obligation

**OC-76 (MUST).** If canonical lifecycle facts declare that protected content has been cryptographically destroyed, sealed, or otherwise made inaccessible, every derived artifact that holds plaintext or plaintext-derived material subject to that declaration MUST be invalidated, purged, or otherwise made unusable according to the Operator's declared policy.

An implementation that retains plaintext in a derived artifact after a canonical erasure event is NON-CONFORMANT regardless of the mechanism by which canonical content was destroyed.

Traceability: TR-OP-004.

### 20.5 Cascade Scope

**OC-77 (MUST).** The purge cascade MUST reach every class in the cascade-scope enumeration (Appendix A.7). The enumeration is a machine-checkable artifact: implementations MUST iterate its values programmatically, and new conformance fixtures exercising purge-cascade verification MUST reference the class by its enumerated identifier rather than by prose description.

Backups are governed by the Operator's retention and recovery policy; backups MUST NOT be used to resurrect destroyed plaintext into live derived artifacts.

Traceability: TR-OP-004.

### 20.6 Documentation and Evidence

**OC-78 (MUST).** Every cryptographic erasure performed by the Operator MUST be accompanied by a canonical `trellis.erasure-evidence.v1` event per §20.6.2 below. The Posture Declaration documents *policy* — which content becomes irrecoverable, who retains access (if anyone, e.g. a sealed-access authority), what evidence of destruction is preserved, what metadata remains visible after destruction — and the canonical event records *execution* (which key was destroyed, when, under which cascade scopes, by which attesting authorities). Phase-1 adopters performing retention-expired erasure (`reason_code = 1`) or subject-requested erasure (`reason_code = 2`) MUST emit per §20.6.2; absence is a posture-honesty violation per §11.

#### 20.6.1 Erasure-Evidence ReasonCode Table

The `trellis.erasure-evidence.v1` event family (§20.6.2) carries a `reason_code: uint` field. The registered values for this family are:

| code | meaning |
|---|---|
| 1 | `retention-expired` (age-based policy fired) |
| 2 | `subject-requested-erasure` (data-subject exercised an erasure right) |
| 3 | `legal-order-compelling-erasure` |
| 4 | `operator-initiated-policy-change` (e.g., dropping support for a data class) |
| 5 | `key-compromise-mitigation` (destruction as part of incident response) |
| 255 | `Other` — rationale documented in Posture Declaration narrative |

This table is the Erasure-Evidence family's entry under the **Core §6 (Event Format) §6.9 ReasonCode Registry** — append-only, family-local. The numeric values 1–5 here are **not interchangeable** with the same numeric values in the custody-model Posture-transition family (§A.5.1) or the disclosure-profile Posture-transition family (§A.5.2); cross-family reinterpretation is forbidden. Code `255 = Other` is the only cross-family invariant per Core §6 (Event Format) §6.9. New codes append, never reinterpret prior values; deprecated codes retain their integer with a `deprecated` annotation. Traceability: **TR-OP-104**.

#### 20.6.2 Erasure-Evidence Event Shape

Each cryptographic erasure (OC-78) is recorded as a canonical event whose `EventPayload.extensions` (Core §6 (Event Format) §6.7) carries `trellis.erasure-evidence.v1` with the payload shape `ErasureEvidencePayload` defined normatively in **ADR 0005 §"Wire shape"** (`thoughts/adr/0005-crypto-erasure-evidence.md`). The CDDL pinned in that ADR is byte-authoritative for the wire shape; this section cites the ADR rather than restating CDDL so that the prose, the normative grammar, and the Rust/Python decoders cannot drift. The ADR's §"Field semantics" table accompanies that grammar with one paragraph per field. Fixture vectors live under `fixtures/vectors/append/023..027` (positive corpus) and `fixtures/vectors/tamper/017..019` (negative cases); export-bundle integration lives at `fixtures/vectors/export/009-erasure-evidence-inline` with optional manifest catalog `064-erasure-evidence.cbor` per Core §18 (Export Package Layout) §18.2 and verifier obligations in Core §19 (Verification Algorithm).

The `Attestation` rule used by `ErasureEvidencePayload.attestations` is shared verbatim with §A.5 (Posture Transition Event Families) — same shape, same `trellis-transition-attestation-v1` domain separation (Core §9 (Hash Construction) §9.8), same dCBOR preimage. Verifier MUST process attestations under the same domain tag for both transition events and erasure-evidence events; introducing a second domain tag would be a wire break. Traceability: **TR-OP-105** (§20.6.2 schema-conformance row).

#### 20.6.3 Erasure-Evidence Operator Obligations

**OC-141 (MUST).** Every `cascade_scopes` entry declared in an `ErasureEvidencePayload` (§20.6.2) MUST be one of (a) a value registered in Appendix A.7 (`CS-01` … `CS-06`) or (b) an append-only registry-extension identifier per the same A.7 discipline. Emitting free-text scope identifiers is non-conformant. The field is per-event execution accounting (what was cascaded by the time this evidence was signed); it does not relax OC-77 — the operator's purge cascade for a conforming erasure still MUST eventually reach every A.7 class where plaintext or plaintext-derived material exists for the destroyed key's scope. Operators MAY use `completion_mode = "in-progress"` or `"best-effort"` when work is intentionally incomplete; declaring scopes not yet cascaded is a signed over-claim detectable by auditors and (under O-3 evolution) by machinery. Traceability: **TR-OP-106**.

**OC-142 (MUST).** For every canonical event whose `authored_at` strictly exceeds the `destroyed_at` recorded for any `kid_destroyed` in chain order (where `destroyed_at` is the single agreed value per `kid_destroyed` after OC-145), within the **Phase-1 verifier surfaces enforced by ADR 0005 §"Verifier obligations" step 8** (i.e. `norm_key_class ∈ {"signing", "subject"}` after the `wrap`→`subject` normalization in step 2), the Operator MUST NOT sign that event under that kid AND MUST NOT emit a `key_bag.entries` row wrapped under that kid. This emit-side obligation pairs with the verify-side check; the Phase-1 verifier flags `post_erasure_use` and `post_erasure_wrap` respectively, both forcing `integrity_verified = false`. Subtree obligations for `recovery`, `scope`, `tenant-root`, and extension-`tstr` classes co-land with ADR 0006 milestones — out of Phase-1 scope here. Traceability: **TR-OP-107**.

**OC-143 (SHOULD).** Operators SHOULD require dual attestation (one `prior` + one `new` per the §A.5 `Attestation.authority_class` rule) for erasure events whose `reason_code ∈ {3, 5}` (legal order, compromise mitigation) AND for erasure events whose `subject_scope.kind ∈ {per-tenant, deployment-wide}`. The specific policy is declared per deployment in the Posture Declaration; operators MAY register stricter rules per `reason_code` × `subject_scope.kind` combinations. Mirrors the §A.5.3 step 4 rule for Widening / Orthogonal posture changes — both axes treat governance-boundary-crossing as the dual-attestation trigger. Traceability: **TR-OP-108**.

**OC-144 (MUST).** Each `ErasureEvidencePayload.destroyed_at` MUST be ≤ the `authored_at` of the canonical event that carries the extension (the *hosting event*). This pins the destruction claim to not-after the signed emission and forecloses the clock-skew game where a future-dated `destroyed_at` would vacuously forbid nothing under OC-142. Verifier check: ADR 0005 §"Verifier obligations" step 4. Violation is a structure failure (`erasure_destroyed_at_after_host`). Traceability: **TR-OP-109**.

**OC-145 (MUST).** For any fixed `kid_destroyed` (byte-equal `bstr`), every `trellis.erasure-evidence.v1` payload in the same `ledger_scope` MUST carry the same `destroyed_at` value (integer equality). Rationale: one physical key has one destruction instant; legitimate retries and `completion_mode` updates re-use the same `destroyed_at` and typically the same `evidence_id`. Two payloads naming the same `kid_destroyed` with disagreeing `destroyed_at` are non-conformant — a structure failure with code `erasure_destroyed_at_conflict`. Distinct `evidence_id` values with identical `kid_destroyed` + identical `destroyed_at` are allowed (e.g., duplicate emission attempts); reporting tools SHOULD dedupe by `(kid_destroyed, destroyed_at)`. Verifier check: ADR 0005 §"Verifier obligations" step 5. Traceability: **TR-OP-113**.

**OC-146 (MUST).** When `kid_destroyed` resolves to exactly one `KeyEntry` row (Core §8 (Key Registry) §8.7 / ADR 0006) in the export's unified key registry, the payload's `key_class` after `wrap`→`subject` normalization MUST equal that row's `kind` (text-string equality). When the export still uses the legacy flat `SigningKeyEntry` registry (no `KeyEntry` rows present) and `kid_destroyed` resolves there, the normalized `key_class` MUST be `"signing"`. Within a single `kid_destroyed` group of payloads, all members MUST agree on `key_class` after normalization (mismatch is `erasure_key_class_payload_conflict`). When `kid_destroyed` does not resolve to any registry row (Phase-1 opaque-HPKE recipients per ADR 0005 §"Field semantics"), registry-bind is skipped; the chain-consistency check still applies for `norm_key_class ∈ {"signing", "subject"}` per OC-142. Verifier check: ADR 0005 §"Verifier obligations" step 2. Traceability: **TR-OP-114**.

### 20.7 Legal Sufficiency

**OC-79 (MUST NOT).** An Operator MUST NOT imply that cryptographic controls alone guarantee admissibility or legal sufficiency in all jurisdictions.

**OC-80 (MAY).** An Operator MAY claim stronger evidentiary posture only to the extent supported by process, signature semantics, canonical append attestations, records practice, and applicable law.

### 20.8 Signing-Key Rotation Grace

**OC-147 (MUST).** An Operator that emits a `Rotating` signing-key registry entry MUST declare the rotation-grace overlap in the embedded registry row itself: `valid_from` is the first instant at which the old key remains accepted alongside its successor, and `valid_to` is the last instant at which that old key remains a new-signature authority. While `valid_to = null`, the overlap is still open in that registry snapshot; once the operator closes the overlap, it MUST publish a registry snapshot whose old-key row is `Retired` or `Revoked` and whose successor row is the active signing authority. The operator MUST NOT represent indefinite dual-active issuance as a completed rotation. Traceability: **TR-OP-133**.

---

## 21. Rejection Taxonomy

### 21.1 Rejection Is Observable

**Requirement class: Companion requirement.**

**OC-81 (MUST).** An Operator MUST define rejection behavior for at least the following failure classes, and MUST expose a rejection class to the caller for each. The rejection class is an observable of the caller-facing interface; it is how callers tell "my signature was bad" from "your service is rate-limiting me."

### 21.2 Required Rejection Classes

**OC-82 (MUST).** The Operator MUST define and expose at minimum the following rejection classes:

| Class | Triggered by |
|---|---|
| `invalid_signature` | Invalid signature or invalid required authored authentication. |
| `malformed_fact` | Malformed author-originated fact or malformed canonical record under the active conformance class or binding. |
| `unsupported_version` | Unsupported schema, algorithm, or suite identifier. |
| `duplicate_submission` | A retried submission handled under the Operator's declared idempotency rule (§18). |
| `exhausted_idempotency_key` | Retries beyond the declared retry budget (§18.2). |
| `revoked_authority` | Revoked or expired delegated-compute authority or other revoked authorization. |
| `unauthorized_access` | Unauthorized access or disclosure attempt. |
| `posture_violation` | Submission that would violate the active posture declaration (e.g., attempting to append under a Custody Model that does not permit the declared attestation authority). |
| `lifecycle_state` | Submission against a sealed, retention-expired, or otherwise lifecycle-gated scope. |

An Operator MAY define additional rejection classes; it MUST document each in its Posture Declaration.

### 21.3 Rejected Records Are Not Canonical

**OC-83 (MUST NOT).** Rejected submissions MUST NOT be treated as canonically appended. A rejection is terminal for the submission within its idempotency identity; a subsequent retry of the same key MUST observe the same rejection class under §18.5.

### 21.4 Idempotent-No-Op Rejection

**OC-84 (MUST).** If duplicate submissions are accepted as idempotent no-ops or resolved as references to an already-appended canonical record, the Operator MUST define that behavior explicitly, including the observable distinction between "newly appended" and "resolved-to-existing."

### 21.5 Rejection Evidence

**OC-85 (SHOULD).** An Operator SHOULD emit structured rejection evidence sufficient for the caller to:

1. determine the rejection class,
2. correlate the rejection to the submitted idempotency key,
3. understand whether retry is possible (e.g., `invalid_signature` is typically not retriable without a new signature; `duplicate_submission` is definitionally not retriable).

---

## 22. Versioning and Algorithm Agility

### 22.1 Everything That Matters Is Versioned

**Requirement class: Companion requirement.**

**OC-86 (MUST).** An Operator MUST version:

1. canonical algorithms and any schema or semantic digests, embedded copies, or immutable references needed for historical verification,
2. author-originated fact semantics where conformance-class- or binding-specific semantics exist,
3. canonical record semantics, append semantics, export verification semantics, and Custody Model semantics.

### 22.2 Historical Verifiability

**OC-87 (MUST).** An Operator MUST preserve enough information to verify historical records under the algorithms and rules in effect when they were produced. A 2045 verifier MUST be able to resolve a 2026 signature after key and suite rotations; this is the Trellis Core invariant that this companion operationalizes.

**OC-88 (MUST).** An Operator MUST preserve enough **immutable interpretation material** to verify historical records without live registry lookups, mutable references, or out-of-band operator knowledge.

### 22.3 No Silent Reinterpretation

**OC-89 (MUST NOT).** An Operator MUST NOT silently reinterpret historical records under newer rules without an explicit migration mechanism. Semantic reinterpretation is a Posture Transition (§10) or a binding migration, both of which are canonical events.

**OC-90 (MUST).** Algorithm or schema evolution MUST NOT silently invalidate prior export verification. Where an evolution would break verification of prior exports, the Operator MUST publish a migration path that preserves verification of prior material under the rules in effect when it was produced.

### 22.4 Out-of-Band Knowledge Prohibited

**OC-91 (MUST NOT).** An Operator MUST NOT rely on out-of-band operator knowledge to interpret historical records. If a piece of interpretation material is required for verification, it MUST be content-addressed and either embedded in the export or referenced immutably.

### 22.5 Suite Rotation Operational Obligations

**OC-92 (MUST).** When rotating signature suites (Core `suite_id`), key registries, or payload-format versions, the Operator MUST:

1. record the rotation as a canonical governance fact,
2. continue publishing the key registry snapshots required to verify records appended under prior suites,
3. update the Posture Declaration to reflect the new active suite,
4. ensure the export-bundle assembly path continues to emit verifiable exports for the entire chain history.

### 22.6 Registry Discipline

**OC-93 (SHOULD; TR-OP-130).** Operators SHOULD define versioned registries for at least: fact kinds, schema or semantic digests, Custody Model identifiers, lifecycle-fact kinds, disclosure or export artifact kinds, and sidecar identifiers where used. Each registry MUST be resolvable to a content-addressed digest for inclusion in the export manifest under Core §18 (Export Package Layout), satisfying invariant #6 (Registry-snapshot binding).

---

# Part IV — Sidecars

## 23. Respondent History Sidecar

### 23.1 Purpose and Binding

**Requirement class: Companion requirement.**

The Respondent History Sidecar preserves stable respondent-visible meaning across drafts, submissions, amendments, validation cycles, and schema migrations, without turning respondent-history semantics into canonical truth. It is the concrete binding between Formspec's Respondent Ledger (Formspec §13) and Trellis canonical records.

Formspec owns the authored semantics of form fields, validation, and version pinning. Trellis Core owns the canonical byte-level admission of Respondent Ledger events. This sidecar specifies the operator obligations that make respondent-visible history coherent across both.

### 23.2 Scope

**OC-94 (MUST).** A Respondent History Sidecar MUST scope itself to respondent-originated or respondent-visible material history. It MAY expose respondent-history moments such as draft, save, submit, amendment, attachment, validation, prepopulation, or materially relevant attestation boundaries.

**OC-95 (MUST).** A Respondent History Sidecar MUST treat respondent-history views as projections or scoped interpretations over canonical truth, not as a separate source of truth. No second canonical append model is permitted (§14.2).

### 23.3 Stable Path Semantics

**OC-96 (MUST).** Where the sidecar defines stable path semantics for addressing logically stable locations within a form, those paths:

1. SHOULD remain stable across non-material presentation changes,
2. SHOULD identify semantically meaningful positions rather than transient rendering positions,
3. MUST distinguish structural path meaning from display-order accidents,
4. SHOULD define behavior when a path is deprecated, split, merged, or migrated,
5. SHOULD support respondent-history deltas and validation snapshots without relying on UI telemetry.

### 23.4 Item-Key Semantics

**OC-97 (MUST).** Where the sidecar defines item-key semantics for stable identification of repeatable items, attachments, or list elements, those keys:

1. SHOULD identify a stable logical item across save, submit, amend, and export cycles,
2. SHOULD distinguish a changed item from a newly inserted item when the family can do so reliably,
3. SHOULD define when keys are preserved, regenerated, merged, or invalidated,
4. MUST NOT rely on ephemeral client rendering state as the sole source of identity.

### 23.5 Validation Snapshot Structure

**OC-98 (SHOULD).** Validation snapshots SHOULD:

1. capture materially relevant validation outcomes rather than keystroke-level activity,
2. bind the applicable stable paths and item keys where relevant,
3. distinguish blocking validation, advisory validation, and informational validation,
4. record the validation boundary or scope to which the snapshot applies,
5. permit later verification of what validation result existed at a material history boundary.

### 23.6 Amendment Cycle Semantics

**OC-99 (SHOULD).** Amendment cycles SHOULD:

1. distinguish amendment initiation, amendment in progress, amendment submission, and amendment completion,
2. define whether amendment cycles operate against a prior canonical submission, a prior respondent-visible version, or another declared baseline,
3. preserve linkage between the amended artifact and the prior baseline,
4. distinguish additive amendment, corrective amendment, superseding amendment, and partial amendment where those concepts exist,
5. define whether abandoned amendments remain visible in respondent-history views.

### 23.7 Migration Outcome Semantics

**OC-100 (SHOULD).** Migration outcomes SHOULD distinguish at least:

1. unchanged carry-forward,
2. transformed carry-forward,
3. split or merged outcomes,
4. dropped or deprecated outcomes,
5. review-required outcomes,
6. migration failure outcomes.

A migration sidecar SHOULD define whether migration outcomes become canonical facts, derived migration metadata, or export-visible annotations.

### 23.8 Materiality Discipline

**OC-101 (MUST).** A Respondent History Producer MUST prioritize material respondent-side state changes over raw UI telemetry. Keystroke, focus, blur, rendering, and equivalent ephemeral interface events MUST NOT be required to be captured as canonical facts; they are out of scope.

### 23.9 Coverage Honesty

**OC-102 (MUST NOT).** A respondent-history export or view MUST NOT imply broader workflow, governance, custody, or compliance coverage than the declared sidecar scope actually provides. A timeline view that presents only respondent-visible moments MUST NOT be read as a complete adjudication history.

### 23.10 Binding to Respondent Ledger and Trellis Core

**OC-103 (MUST).** The Respondent History Sidecar MUST bind its canonical facts to the Formspec Respondent Ledger (Formspec §13) and to Trellis Core canonical records. Binding means:

1. Each respondent-history moment that is canonical is appended as a Respondent Ledger event through the active Trellis binding (Core §6 (Event Format)).
2. Each respondent-history projection carries the watermark fields of §14.1 referencing the Trellis canonical checkpoint.
3. Respondent-facing export views are derived artifacts subject to §15.

---

## 24. Workflow Governance Sidecar

### 24.1 Purpose and Binding

**Requirement class: Companion requirement.**

The Workflow Governance Sidecar preserves rich workflow, governance, review, and provenance semantics over canonical truth, without allowing workflow runtime state to override the canonical-record / derived-artifact distinction. It is the concrete binding between WOS's governance envelope and Trellis canonical records, via the WOS Kernel §10.5 `custodyHook` seam.

### 24.2 Non-Redefinition

**OC-104 (MUST NOT).** The Workflow Governance Sidecar MUST NOT redefine WOS runtime semantics. Workflow execution, governance evaluation, and runtime envelope behavior remain authoritative in WOS. This sidecar specifies only how WOS events bind to Trellis canonical records.

### 24.3 Canonical-vs-Operational Distinction

**OC-105 (MUST).** A Workflow Governance Producer MUST distinguish in its configuration and any projections it produces:

1. **Operational workflow state that remains non-canonical** — in-flight task assignments, transient queue memberships, scheduler ticks, ephemeral session data. This state is WOS runtime state; it is not canonical truth.
2. **Workflow events that become canonical facts** — intake receipts, review-open and review-close events, adjudicative decisions, governance outcomes — but only where the active binding declares them canonically admissible.
3. **Derived dashboards, queues, and status views** — which remain derived artifacts under §14 and are subject to §15.

### 24.4 Non-Elevation

**OC-106 (MUST NOT).** No operational sequencing, queue depth, scheduler event, or workflow runtime state is canonical truth solely by virtue of its operational role. Elevation to canonical status requires the workflow event to be admitted as a canonical record through the active Trellis binding (Core §10 (Chain Construction)).

### 24.5 Governance Fact Families

**OC-107 (SHOULD).** Where the sidecar defines governance and processing fact families — intake receipt facts, assignment facts, review-open/close facts, adjudication facts, approval/denial facts, escalation facts, verification-upgrade facts, export-issuance facts, lifecycle-boundary facts — it SHOULD define which of them are canonically admissible and which remain operational.

### 24.6 Review and Adjudication Semantics

**OC-108 (SHOULD).** Where review and adjudication semantics are defined, the sidecar SHOULD distinguish:

1. review assignment,
2. review in progress,
3. review completion,
4. recommendation,
5. adjudicative decision,
6. appeal or reconsideration,
7. override or exception.

The sidecar SHOULD define which review outputs are canonical facts and which are derived workflow state.

### 24.7 Approval, Escalation, and Recovery

**OC-109 (SHOULD).** Approval, escalation, retry, and recovery semantics SHOULD distinguish:

1. timer-driven operational behavior,
2. human approval or review actions,
3. system retries,
4. recovery procedures,
5. compensating actions,
6. exceptional handling.

**OC-110 (MUST NOT).** Operational sequencing alone MUST NOT be mistaken for canonical order.

### 24.8 Runtime Is Derived

**OC-111 (MUST).** Workflow and orchestration engines — Temporal, Camunda, AWS Step Functions, or equivalents — are derived processors (Core §2 (Conformance) / §14 of this companion). Their runtime state is a derived artifact under §14.

A workflow or orchestration engine contributes to canonical truth only by submitting facts through the Canonical Append Service under the active binding's admission rules. The engine MUST NOT write canonical records out-of-band, replay them into canonical order independently, or reinterpret admitted records.

### 24.9 `custodyHook` Binding

**OC-112 (MUST).** Where a WOS runtime uses Trellis as its custody backend via WOS Kernel §10.5 `custodyHook`, the binding MUST:

1. route every WOS governance event destined for custody through the Trellis Canonical Append Service (Core §2 (Conformance)) under the wire-level contract of Core §23 (Composition with WOS `custodyHook`),
2. record the returned canonical append attestation as the durable evidence of the governance event,
3. preserve the provenance distinction between the WOS governance envelope and the Trellis canonical record — the `custodyHook` does not replace WOS; it gives WOS a durable substrate.

The WOS-authored append surface crossing `custodyHook` is exactly the accepted
four-field WOS contract:

1. `caseId` — WOS TypeID-structured case identifier.
2. `recordId` — WOS TypeID-structured authored-record identifier.
3. `eventType` — registered outcome-neutral `wos.*` event-type identifier.
4. `record` — the authored WOS record rendered as dCBOR.

The WOS-owned semantic idempotency input is exactly `(caseId, recordId)`,
bound under the domain tag `trellis-wos-idempotency-v1` per Core §23 (Composition with WOS `custodyHook`) §23.5. The
minimum WOS-facing receipt is `{ canonical_event_hash }`; Operators MAY expose
additive local convenience fields, but MUST NOT treat them as required
`custodyHook` contract fields.

**OC-113 (MUST).** The `custodyHook` binding MUST NOT redefine the Trellis canonical append semantics. An Operator MUST NOT use `custodyHook` to admit records under alternate proof models or alternate Custody Models within the same declared scope. The wire-level obligations of Core §23 (Composition with WOS `custodyHook`) — `wos.*` event-type namespace (§23.4), idempotency-key construction (§23.5), autonomy-cap attribution (§23.6), non-redefinition (§23.7) — are requirements on the Operator running a WOS-Trellis deployment and MUST be implemented without alteration.

**OC-113a (MUST).** For any two WOS governance records whose causal relation is established by WOS-runtime provenance (per WOS Kernel §4 Lifecycle and §8 Facts tier), the admitting chain order MUST respect that relation: the canonical event admitting the earlier record MUST have a smaller `sequence` (Core §6 (Event Format) §6.2) than the canonical event admitting the later record within the common `ledger_scope` (Core §23 (Composition with WOS `custodyHook`) §23.3). Records that are causally concurrent per WOS MAY be ordered by the admitting Canonical Append Service at its discretion; the chosen order is canonical once admitted. Causality verification itself is a WOS-runtime obligation outside Core §19 (Verification Algorithm). Out-of-order admission relative to a WOS-established causal relation — for example, a late-arriving governance decision admitted after a record it causally precedes — is NON-CONFORMANT; the deployment MUST treat the late decision as a posture-correcting forward event under §10.2 rather than inserting it into prior positions. The ordering obligation extends across the composed case-ledger scope (Core §22 (Composition with Respondent Ledger) §22.4) where present, not just within a single `ledger_scope`.

**OC-113b (MUST).** The Workflow Governance Sidecar (Appendix B.2) MUST enumerate every registered `wos.*` event-type identifier the deployment admits and MUST mark each as canonical or operational per §24.5. A WOS-Trellis deployment that admits a `wos.*` identifier not listed in its sidecar is NON-CONFORMANT; the sidecar is the operator-facing catalog for what custody-routing the Operator has declared.

### 24.10 Posture-Transition Auditability for WOS Governance

**OC-113c (MUST).** Custody transitions (§10.1) driven by WOS governance decisions — for example, a WOS adjudicative decision that alters recovery authority, or a WOS review outcome that expands delegated-compute scope — are Posture Transitions regardless of the governance body that authored them. The Operator MUST record each such transition as a canonical event per §10 and MUST NOT treat a WOS-internal governance envelope as a substitute for the §10.3 transition-event semantics. The WOS governance record and the Trellis posture-transition canonical event are distinct facts on the chain (Core §23 (Composition with WOS `custodyHook`) §23.2 item 7): the first is a `wos.*` record attesting to the WOS decision; the second is an `EventPayload.extensions["trellis.custody-model-transition.v1"]` (or disclosure-profile equivalent) record attesting to the resulting Trellis-layer posture change.

The Trellis posture-transition event MUST be admitted AFTER its authorizing `wos.*` governance record within the common `ledger_scope`. The transition event's `declaration_doc_digest` MUST reference the `PostureDeclaration` in force after the transition per Appendix A.5.1 / A.5.2 and the verification rules in Appendix A.5.3, and its payload's `extensions` MAY carry a `trellis.wos_authorizing_record` key whose value is the `canonical_event_hash` (Core §9 (Hash Construction) §9.2) of the authorizing governance record. Canonical events admitted between the `wos.*` governance record and the Trellis posture-transition event admit under the PRIOR posture; the transition's `temporal_scope` field (Appendix A.5.1 / A.5.2) governs whether the new posture applies retrospectively to those intermediates.

### 24.11 Delegated-Compute Flow-Through for WOS Autonomy

**OC-113d (MUST).** When a WOS action is taken by an AI agent under a WOS autonomy level other than `manual` (WOS AI Integration §5.2), the resulting WOS governance record admitted through `custodyHook` is a delegated-compute event and is subject to §19 (Delegated-Compute Honesty) in full. Specifically:

1. The Operator MUST publish a Delegated-Compute Declaration (§19.9, Appendix A.6) whose scope covers the content classes the agent read or authored while producing the governance record.
2. The Operator MUST record the delegated-compute grant per §19.2 as a canonical fact before the agent-authored governance record is admitted.
3. The admitted event MUST attribute to exactly one of `actor_human` or `actor_agent_under_delegation` per OC-70c. For `assistive` autonomy (WOS AI Integration §5.2), `actor_human` attribution is required when a human explicitly confirmed before admission; `actor_agent_under_delegation` is required when the agent authored the record directly.

**OC-113e (MUST NOT).** A Trellis delegated-compute attestation MUST NOT be treated as a substitute for WOS autonomy-cap evaluation (§19.6). A WOS-Trellis deployment whose Trellis-layer attestations are conformant but whose WOS autonomy-cap is violated is NON-CONFORMANT at the WOS layer; the Operator MUST NOT present Trellis-layer conformance as evidence of WOS-layer conformance.

### 24.12 Provenance Across Export

**OC-114 (MUST).** Workflow export views MUST preserve provenance distinctions (Core §3 (Terminology)) and MUST NOT imply broader coverage than their declared export scope actually includes. A workflow timeline that omits half the governance events MUST NOT be labeled as a complete case history.

---

## 25. Grants and Revocations as Canonical Facts

### 25.1 Grants and Revocations Are Canonical

**Requirement class: Companion requirement.**

**OC-115 (MUST).** Access grants and revocations that affect canonical authorization semantics MUST be recorded as append-only canonical facts through the active Trellis binding.

This rule is load-bearing: if a grant is not canonical, authorization decisions premised on it are not independently verifiable. Every rights-impacting decision needs a canonical record to point to.

### 25.2 Delegation Facts

**OC-116 (MUST).** If delegation affects authorization, legal authority, or access posture, delegation grants and revocations MUST be canonical facts. Delegated-compute grants (§19) are a specific case of this rule.

### 25.3 Evaluators Are Derived

**OC-117 (MAY).** Authorization evaluators MAY be derived artifacts computed over canonical grant and revocation facts.

**OC-118 (MUST).** If derived, an Authorization Evaluator:

1. MUST be rebuildable from canonical grant and revocation facts,
2. MUST NOT be authoritative for grant existence, grant history, or revocation history,
3. MUST preserve canonical grant and revocation semantics even when evaluator state is absent, stale, or rebuilding.

### 25.4 Traceability to Canonical Facts

**OC-119 (MUST).** An Authorization Evaluator MUST be able to trace every input contributing to a rights-impacting decision back to the canonical facts from which the input was derived. Evaluator inputs that cannot be traced to canonical facts MUST NOT contribute to rights-impacting decisions.

### 25.5 Rebuild Behavior

**OC-120 (MUST).** An Authorization Evaluator MUST define its rebuild behavior, including:

1. the canonical inputs required to rebuild evaluator state,
2. the declared configuration history required to rebuild deterministically,
3. the procedure by which a rebuild is initiated, completed, and verified,
4. the expected relationship between a rebuilt evaluator and canonical records at the rebuild checkpoint (typically strict equivalence on grant and revocation outcomes).

### 25.6 Behavior Under Stale, Missing, Inconsistent, or Unavailable State

**OC-121 (MUST).** An Authorization Evaluator MUST define its behavior when evaluator state is:

1. **stale** relative to current canonical facts,
2. **missing** (no evaluator state exists for the scope),
3. **inconsistent** with canonical facts (evaluator state disagrees with canonical records),
4. **unavailable during rebuild** (evaluator state cannot be consulted because it is being rebuilt or is otherwise temporarily inaccessible).

For each of these conditions, the implementation MUST declare — in advance, as part of its conformance statement — whether a rights-impacting decision under that condition:

- is **deferred** (the decision is not made until the condition is resolved),
- **fails closed** (the default is to deny the rights-expanding outcome),
- falls back to a **declared recovery evaluator** sourced from canonical facts, or
- is **rejected outright**.

**OC-122 (NON-CONFORMANT).** Silent fail-open behavior — granting or preserving access because evaluator state cannot be consulted — is NON-CONFORMANT. Unspecified behavior under any of the four conditions enumerated above is NON-CONFORMANT.

### 25.7 Canonical Semantics Prevail

**OC-123 (MUST).** An Authorization Evaluator MUST preserve canonical grant and revocation semantics regardless of evaluator state. Evaluator state MUST NOT override, suppress, delay, or reinterpret a grant or revocation recorded as a canonical fact. Where evaluator state and canonical facts disagree, canonical facts prevail and the evaluator MUST be treated as stale or inconsistent per §25.6.

### 25.8 Cryptographic-Erasure Interaction

**OC-124 (MUST).** Cryptographic-erasure events recorded as canonical lifecycle facts (§20) invalidate any evaluator state that depends on cryptographically destroyed material. Such invalidation cascades into evaluator state exactly as it cascades into other derived artifacts (§20.5).

---

# Part V — Witnessing and Monitoring (Phase 4 Preview)

## 26. Monitoring and Witnessing Seams

### 26.1 Seam Definition; Implementation Deferred

**Requirement class: Seam definition.**

**SEAM DEFINED; IMPLEMENTATION DEFERRED TO PHASE 4.** Full witnessing and monitoring obligations — including transparency-witness networks, cross-operator equivocation detection, and quorum-witnessed checkpoints — are Phase 4 (Federation / Sovereign) content. This section defines the **seams** on which Phase 4 will build, so that Phase 2+ deployments can expose monitoring-compatible interfaces now and avoid a wire-format break when Phase 4 lands.

### 26.2 Subordination to Canonical Correctness

**OC-125 (MUST).** Monitoring and witnessing are subordinate assurance postures, not replacements for canonical append semantics. An Operator that supports external witnessing or anchoring MUST NOT treat witness presence as a precondition for canonical record validity unless an explicit deployment class or binding says so.

- Witness absence does not invalidate canonical records.
- Witness disagreement does not rewrite canonical order.
- Deployment classes MAY elevate witness participation to a correctness precondition; such elevation MUST be explicit.

### 26.3 Checkpoint Publication Interface

**OC-126 (MUST, if monitoring is supported).** An Operator that claims monitoring support MUST expose a checkpoint publication interface that exposes, at minimum:

| Resource | Description |
|---|---|
| Append scope identifier | Stable identifier for the declared append scope. |
| Checkpoint identifier | Stable identifier for the checkpoint within the declared append scope. |
| Append position | Monotonic log index at checkpoint time. |
| Append-head reference | Canonical append-head reference (Core §11 (Checkpoint Format)). |
| Checkpoint time | Service-declared time at which the checkpoint was produced. |
| Consistency proof material | Sufficient proof to verify that this checkpoint extends any earlier published checkpoint within the same scope. |
| Inclusion proof material | Optional per-record inclusion proof where the binding supports it. |
| Pagination and range query | Support for listing checkpoints by position or time range. |

### 26.4 Publication Obligations

**OC-127 (MUST).** An Operator supporting monitoring:

- MUST publish checkpoints at a cadence declared by the active deployment class or binding,
- MUST NOT publish checkpoints whose append-head reference does not correspond to a canonical append-head actually established under Core §11 (Checkpoint Format),
- MUST NOT revise a previously published checkpoint; corrections MUST be represented as later checkpoints and MUST NOT rewrite append-position assignments,
- MUST preserve sufficient proof material to allow consistency proofs between any two published checkpoints within the same declared append scope.

### 26.5 Monitor Sub-Roles

**OC-128 (MUST).** A monitoring-capable deployment recognizes at minimum four sub-roles (full specification deferred to Phase 4):

1. **Passive Consistency Monitor** — verifies append-head consistency between successive observed checkpoints.
2. **Active Equivocation Detector** — compares checkpoints observed from multiple vantage points and treats incompatible append-heads at the same position as equivocation evidence.
3. **External Anchoring Witness** — publishes append-head digests into an external log (transparency log, blockchain, timestamping authority) to produce anchor records.
4. **Audit Witness** — issues independent witness attestations over observed checkpoint material for later verifier or auditor consumption.

### 26.6 Witness Attestation Semantics (Seam)

**OC-129 (Seam).** A witness attestation MUST declare which property it attests to, from the set:

- observation of an append-head,
- append-growth consistency,
- inclusion proof validity,
- temporal anchoring into an external log.

A witness attestation MUST NOT be presented as a canonical append attestation. The canonical-vs-witness distinction MUST be preserved across export packaging.

### 26.7 Equivocation Evidence Format (Seam)

**OC-130 (Seam).** Evidence of Operator equivocation — publication of incompatible append-heads at the same position within the same scope — MUST be structured so that a relying party outside the active monitoring deployment can verify it independently. The full evidence format, quorum rules, and enforcement postures are Phase 4 material.

### 26.8 Detection Is Not Enforcement

**OC-131 (MUST NOT).** A monitor detecting a consistency failure or equivocation MUST NOT rewrite canonical records, invalidate previously issued canonical append attestations, or bind the behavior of other monitors, witnesses, or relying parties. Detection is observational; enforcement is a binding or deployment-class choice.

### 26.9 Privacy Bounds

**OC-132 (MUST NOT).** Witnesses and monitors MUST NOT observe protected payload plaintext, reader-held access material, or authorization decisions beyond what is necessary to validate the claimed monitoring role. Append-head references commit to, but do not reveal, protected payload content; this property MUST be preserved across the witnessing interface.

### 26.10 Rate and Abuse Considerations

**OC-133 (SHOULD).** Checkpoint interfaces SHOULD be rate-limited to prevent denial-of-service against the Canonical Append Service. Authenticated access SHOULD be required where exposure of proof material is itself sensitive.

---

# Part VI — Assurance

## 27. Operational Conformance Tests

### 27.1 Beyond Core Vectors

**Requirement class: Companion requirement.**

Trellis Core vectors validate byte-level behavior: encoding, hashing, signing, chain construction, checkpoint format, export-package assembly, offline verification. An implementation passing every Core vector is byte-conformant. This section defines what an implementation MUST additionally demonstrate to claim operational conformance.

**Erasure-evidence verifier surface (ADR 0005 / Core §19 (Verification Algorithm) step 6b).** Core fixture corpus rows `append/023..027` (positive `trellis.erasure-evidence.v1` hosts), `tamper/017..019` (`post_erasure_use`, `post_erasure_wrap`, and export-catalog digest mismatch), and `export/009-erasure-evidence-inline` (optional `064-erasure-evidence.cbor` catalog under `trellis.export.erasure-evidence.v1`) are the byte-authoritative offline checks that a Phase-1 verifier implements ADR 0005 steps 1–10 together with the export-manifest catalog discipline in Core §18 (Export Package Layout) §18.2. Companion OC-135 cascade tests in §27.3 remain a distinct obligation; these vectors pin the chain-level and export-level erasure-evidence obligations that feed cascade completeness arguments.

**Certificate-of-completion verifier surface (ADR 0007 / Core §19 (Verification Algorithm) step 6c).** Core fixture corpus rows `append/028..030` (positive `trellis.certificate-of-completion.v1` hosts: minimal single-signer, multi-signer countersigned, and template-pinned), `tamper/020..026` (per ADR 0007 *Fixture plan*: `presentation_artifact_content_mismatch`, `certificate_chain_summary_mismatch`, `signing_event_unresolved`, `attestation_insufficient` reuse, `response_ref_mismatch`, HTML-without-`template_hash` structure failure, and `certificate_id_collision`), and `export/010-certificate-of-completion-inline` (optional `065-certificates-of-completion.cbor` catalog under `trellis.export.certificates-of-completion.v1`) are the byte-authoritative offline checks that a verifier implements ADR 0007 steps 1–8 together with the export-manifest catalog discipline in Core §18 (Export Package Layout) §18.2. The certificate binds a rendered presentation artifact (PDF or HTML) to the underlying chain via ADR 0072 attachment lineage; rendering-drift checks (re-rendering from `template_id` + chain data) are NOT required. Traceability: **TR-OP-131** (operator authoring discipline: `certificate_id` stability, idempotent re-emission, HTML-`template_hash` requirement) and **TR-OP-132** (Posture-Declaration counter-signature requirement per `workflow_status`).

### 27.2 Projection Rebuild Tests

**OC-134 (MUST).** An implementation claiming OP-2 or higher MUST pass a projection-rebuild test suite that exercises:

1. watermark presence on every projection produced by the implementation (§14.1),
2. staleness indication for projections lagging behind canonical checkpoints (§15.4),
3. rebuild equivalence for declared rebuild-deterministic fields (§15.3),
4. rebuild fixture integrity (§15.6).

The test suite MUST include at least one staff-view scenario in which a rights-impacting decision is bound to a watermark (§17.4).

### 27.3 Crypto-Shred Cascade Tests

**OC-135 (MUST).** An implementation MUST pass a crypto-shred-cascade test suite that verifies, for each declared purge-cascade scope (§20.5):

1. that a canonical erasure fact triggers invalidation or purge in every in-scope derived artifact,
2. that a plaintext-bearing artifact left behind is detectable and reported as a cascade failure,
3. that backup-resurrection is prevented — no live derived artifact may be restored from backup to a state containing destroyed plaintext.

### 27.4 Rejection Semantics Tests

**OC-136 (MUST).** An implementation MUST pass a rejection-taxonomy test suite that validates:

1. each declared rejection class (§21.2) is observably distinguishable by the caller,
2. idempotent retries resolve per §18.5 to the declared outcome,
3. rejected submissions are not canonically appended (§21.3).

### 27.5 Metadata-Budget Compliance Tests

**OC-137 (MUST).** An implementation MUST pass a metadata-budget compliance test suite that validates:

1. each canonical fact family the implementation admits is listed in the Metadata Budget (§12.3),
2. observed metadata visibility matches declared visibility for each observer class (§12.2),
3. access-pattern leakage (query timing, response-size patterns) does not exceed the declared budget.

### 27.6 Auditor Workflow Tests

**OC-138 (MUST).** An implementation MUST support an Auditor claiming conformance to this companion performing end-to-end comparison of declared posture against observed control-plane behavior (§11.4). The Auditor MUST be able to:

1. retrieve the Posture Declaration for any in-scope export (§11),
2. observe the control-plane behavior corresponding to each declared element,
3. flag mismatches as posture-honesty violations (§11.5) without accessing protected payloads.

### 27.7 Transition-Auditability Tests

**OC-139 (MUST).** An implementation MUST pass a transition-auditability test suite that validates:

1. Posture Transitions are recorded as canonical events with the required fields (§10.3),
2. no posture element listed in §10.1 changes without a corresponding transition event (§10.2),
3. transition attestations conform to §10.4 (dual attestation where required).

### 27.8 Idempotency Replay Tests

**OC-140 (MUST).** An implementation MUST pass an idempotency-replay test suite that validates retry budget, API retry window behavior, dedup-store lifecycle, and replay-observable semantics per §18.

---

## 28. Security and Privacy Considerations (Operational)

### 28.1 Staff-View UI Side Channels

A staff-view UI can leak canonical state through indicators that are not themselves watermark fields: record counts, search-result ordering, pagination offsets, "new items" badges. Operators MUST evaluate such indicators against the active Metadata Budget (§12). A UI indicator that reveals information withheld from the declared observer class is a metadata-budget violation regardless of how it is rendered.

Stale-status indicators (§15.4) MUST NOT be used as a covert channel for the content of unprojected updates. A staleness signal communicates freshness relative to canonical append height; it MUST NOT encode the content of pending updates.

### 28.2 Staff-View Leakage Across Audience Boundaries

An adjudicator granted access to a staff view for case X MUST NOT be able to infer, from UI artifacts, the existence of case Y or the content of canonical records outside their granted scope. Operators SHOULD evaluate cross-audience leakage paths — search-index spillover, autocomplete, shared caches, shared dashboards — against declared Custody Model boundaries.

### 28.3 Projection Poisoning

A projection poisoning attack is the injection of non-canonical inputs into a projection such that its output differs from what a rebuild from canonical records would produce. Defenses include:

- rebuild equivalence checks (§15.3),
- integrity-sampling policy (§15.5),
- protected rebuild fixtures (§15.6),
- authorization-expanding projections checked at higher frequency (§15.5).

An implementation that permits a projection to produce rights-impacting output from non-canonical inputs is NON-CONFORMANT under §14.

### 28.4 Idempotency-Key Leakage

Idempotency keys are themselves observables. An Operator that permits idempotency keys to be brute-forced, replayed by unauthorized parties, or otherwise leaked exposes the integrity of the append contract. Operators SHOULD:

- require authenticated submission for all append calls,
- use sufficiently entropic idempotency-key formats,
- avoid returning more information in duplicate-submission responses than is required for the caller to correlate the retry.

### 28.5 Delegated-Compute Supply Chain

Delegated-compute agents — AI models in particular — are a supply-chain surface. An agent whose provenance, version, or training data is misrepresented can be used to produce outputs attributed to a principal who would not have authorized them under accurate information. Operators SHOULD declare delegated-compute agent provenance (§19.8) and SHOULD treat supply-chain misrepresentation as a posture-honesty violation (§11.2).

### 28.6 Purge-Cascade Completeness

Purge-cascade operations (§20.3) MUST NOT leave residual plaintext in system projections, caches, backups, evaluator state, or rebuild fixtures. An incomplete cascade undermines the confidentiality guarantees of cryptographic erasure recorded as a canonical lifecycle fact. Operators SHOULD treat cascade completeness as a safety-critical test dimension.

### 28.7 Authorization Evaluator Safety

An Authorization Evaluator whose stale-state behavior is undeclared, silently fail-open, or permissive by omission is a security defect regardless of implementation effort (§25.6, §25.7). Deployments SHOULD treat these obligations as safety-critical and include them in any monitoring-and-witnessing posture.

### 28.8 Metadata-Leakage Patterns

Payload confidentiality does not imply metadata privacy (§12.5). Timing patterns, access-pattern observability, and disclosure linkability are all disclosed by the Metadata Budget but are often under-modeled by implementers. Operators SHOULD model these as part of routine privacy impact analysis, not as afterthoughts.

### 28.9 Posture-Transition Attack Surface

Posture Transitions (§10) expand or narrow the access surface of a deployment. A malicious actor with authority to issue a transition from a reader-held to a provider-readable Custody Model could retroactively expand their own plaintext access. Defenses:

- dual attestation for expansion transitions (§10.4),
- retrospective-scope declarations (§10.3 field 7) that are visible to auditors and respondents,
- monitoring and witnessing of transition events as first-class canonical facts (§26).

### 28.10 Verification Posture Gating

Implementations MUST NOT attach high-stakes outcomes — adverse action, selective disclosure issuance, commitment-driven analytics — to records that have not reached a verification posture appropriate for the outcome class declared in the Posture Declaration. Silent escalation of verification posture is NON-CONFORMANT.

---

## 29. References

### 29.1 Normative References

- **[Trellis Core]** — Trellis Core Specification v1.0.0. Canonical byte-level substrate for Trellis.
- **[RFC 2119]** — Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels," BCP 14, RFC 2119, March 1997.
- **[RFC 8174]** — Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words," BCP 14, RFC 8174, May 2017.
- **[RFC 8259]** — Bray, T., Ed., "The JavaScript Object Notation (JSON) Data Interchange Format," STD 90, RFC 8259, December 2017.
- **[RFC 3986]** — Berners-Lee, T., Fielding, R., Masinter, L., "Uniform Resource Identifier (URI): Generic Syntax," STD 66, RFC 3986, January 2005.
- **[Formspec Core]** — Formspec Core Specification. Authored semantics for form fields, validation, calculation, and version pinning.
- **[Formspec Respondent Ledger]** — Formspec Respondent Ledger Specification §13 and §15A. Respondent-side history and Profile A/B/C posture axes.
- **[WOS Kernel §10.5]** — WOS Kernel Specification, §10.5 `custodyHook`. Seam for delegating custody of governance events to a ledger substrate.
- **[WOS Kernel §12]** — WOS Kernel Specification, §12 Separation Principles. Generic separation of audit, governance, execution, and case state.
- **[WOS Assurance §2]** — WOS Assurance Specification, §2 Assurance Levels. Assurance-level taxonomy invoked by verification posture gating.
- **[WOS Governance §2.9]** — WOS Workflow Governance, §2.9 Schema Upgrade. The generic named-lifecycle-operation pattern under which Posture Transitions are specified.

### 29.2 Informative References

- **Product Vision** — Trellis delivery arc, Phase 1–4 description, and the invariants this companion operationalizes (particularly #11, #13, #14, #15).
- **Unified Ledger Companion (draft)** — legacy source draft mined into this companion; retained for historical traceability.
- **Unified Ledger Companion Requirements Matrix (ULCOMP-R)** — traceability matrix linking this companion's requirements to the pre-normalization draft row IDs.
- **Trellis Spec Family Normalization Plan §7** — the source of the append-idempotency, snapshot-from-day-one, and metadata-budget-as-table form requirements operationalized here.
- **Projection and Runtime Discipline (draft)** — the pre-normalization companion absorbed into Part II of this document.
- **Monitoring and Witnessing (draft)** — the pre-normalization companion absorbed into Part V of this document.
- **Pre-normalization posture drafts** — historical inputs; key-lifecycle cryptographic mechanics remain owned by Core, while transition auditability and metadata-budget discipline are absorbed here.

---

# Appendix A — Declaration Document Template

This appendix provides a template for the Posture Declaration required by §11. The template is illustrative; conforming Posture Declarations MAY use any serialization that preserves the semantics. Operators SHOULD publish a machine-readable form (JSON or CBOR) alongside any human-readable form.

## A.1 Top-Level Structure

```
PostureDeclaration {
  declaration_id:            URI              # stable identifier
  operator_id:               URI              # the Operator principal
  scope:                     URI              # the declared deployment scope
  effective_from:            timestamp        # when this declaration takes effect
  supersedes:                URI | null       # prior declaration, if any
  custody_model:             CustodyModelRef  # §9
  access_taxonomy:           AccessTaxonomyTable  # §8 / §A.2
  metadata_budget:           MetadataBudgetTable  # §12 / §A.3
  external_anchor_dependency: ExternalAnchorDependency  # §11.1
  crypto_shredding_scope:    CryptoShreddingScope       # §11.1 / §20
  metadata_leakage_acknowledgement: string     # §11.1 human-readable
  idempotency_policy:        IdempotencyPolicy  # §18
  rejection_classes:         RejectionClassTable # §21
  registries:                RegistryReferences  # §22.6
  posture_honesty_statement: string           # §11.2 human-readable floor
  signature:                 OperatorSignature # signed by the Operator
}
```

## A.2 Access Taxonomy Table Row

```
AccessTaxonomyRow {
  content_class:   string                 # e.g. "respondent_pii", "adjudication_reasoning"
  access_class:    enum {                 # §8.1
    provider_readable,
    reader_held,
    delegated_compute
  }
  decryptor_classes: [string]             # principals who may decrypt within scope
  delegated_compute_exposure: enum {      # applies where access_class = delegated_compute
    provider_operated,
    tenant_operated,
    client_side,
    isolated_enclave
  } | null
}
```

## A.3 Metadata Budget Table Row

```
MetadataBudgetRow {
  fact_family:                 string
  visible_fields:              [string]
  observer_classes:            [string]   # e.g. "provider", "tenant_admin", "reader", "monitor"
  timing_leakage:              string
  access_pattern_leakage:      string
  linkage_stability:           string
  delegated_compute_effects:   string
}
```

## A.4 Custody Model Registry

A Custody Model Registry entry MUST include the fields of §9.3. Registered extension models use identifiers outside `CM-A` ... `CM-F`.

```
CustodyModelEntry {
  custody_model_id:                 string       # one of CM-A ... CM-F, or extension
  current_content_decryptors:       [string]
  historical_content_decryptors:    [string]
  recovery_authorities:             [string]
  recovery_conditions:              string
  delegated_compute_posture:        DelegatedComputePosture
  attestation_control_authorities:  [string]
  exceptional_access_authorities:   [string]
  metadata_budget_ref:              URI
}
```

## A.5 Posture Transition Event Families

Two concrete Posture-transition subtypes are normative in Phase 1. Both ride in `EventPayload.extensions` under the identifiers registered in Core §6 (Event Format) §6.7 — Posture-transition codes `trellis.custody-model-transition.v1` and `trellis.disclosure-profile-transition.v1` — and are subject to the state-continuity check in Core §19 (Verification Algorithm) step 6. A.5.1 and A.5.2 are the emitted forms; there is no separately-emitted abstract parent.

Shared named CDDL rule used by both subtypes:

```cddl
Attestation = {
  authority:       tstr,                     ; principal URI
  authority_class: "prior" / "new",          ; which side of the transition is attesting
  signature:       bstr,                     ; detached Ed25519 over the transition attestation preimage
                                             ; (dCBOR([transition_id, effective_at, authority_class])
                                             ;  under domain tag trellis-transition-attestation-v1)
}
```

### A.5.1 Custody-Model Transition

Traceability: **TR-OP-042** (schema conformance). The concrete CDDL form emitted in `EventPayload.extensions["trellis.custody-model-transition.v1"]`:

```cddl
CustodyModelTransitionPayload = {
  transition_id:          tstr,                          ; stable within ledger_scope
  from_custody_model:     "CM-A" / "CM-B" / "CM-C" /
                          "CM-D" / "CM-E" / "CM-F" / tstr, ; tstr permits registered extension models per §A.4
  to_custody_model:       "CM-A" / "CM-B" / "CM-C" /
                          "CM-D" / "CM-E" / "CM-F" / tstr,
  effective_at:           uint,                          ; Unix seconds UTC
  reason_code:            uint,                          ; registered reason; 255 is Other / append-only catch-all
  declaration_doc_digest: digest,                        ; under domain tag trellis-posture-declaration-v1 (Core §9 (Hash Construction) §9.8)
                                                         ; MUST resolve to declaration in force AFTER the transition
  transition_actor:       tstr,                          ; principal URI
  policy_authority:       tstr,                          ; governance authority URI
  temporal_scope:         "prospective" / "retrospective" / "both",
  attestations:           [* Attestation],               ; see parent shape
  extensions:             { * tstr => any } / null,
}
```

Reason codes (registered, extensible via registry append-only):

| code | meaning |
|---|---|
| 1 | `initial-deployment-correction` |
| 2 | `key-custody-change` |
| 3 | `operator-boundary-change` |
| 4 | `governance-policy-change` |
| 5 | `legal-order-compelling-transition` |
| 255 | `Other` (append-only catch-all; free-text rationale in Posture Declaration) |

This table is the Custody-Model Transition family's entry under the Core §6 (Event Format) §6.9 ReasonCode Registry — append-only, family-local. Code values 1–5 here are not interchangeable with the same numeric values in the disclosure-profile Posture-transition family (§A.5.2) or in the erasure-evidence family (Companion §20.6.1, ADR 0005); reinterpretation across families is forbidden. Code `255 = Other` is the only cross-family invariant per Core §6 (Event Format) §6.9. Traceability: **TR-OP-046**.

### A.5.2 Disclosure-Profile Posture-Transition

Posture-transition on the Respondent Ledger Profile A/B/C axis. Traceability: **TR-OP-043** (schema conformance). The concrete CDDL form emitted in Posture-transition code `trellis.disclosure-profile-transition.v1` under `EventPayload.extensions`:

```cddl
DisclosureProfileTransitionPayload = {
  transition_id:          tstr,
  from_disclosure_profile: "rl-profile-A" / "rl-profile-B" / "rl-profile-C", ; Respondent Ledger Profile A/B/C axis (Posture axis)
  to_disclosure_profile:   "rl-profile-A" / "rl-profile-B" / "rl-profile-C", ; Respondent Ledger Profile A/B/C axis (Posture axis)
  effective_at:           uint,
  reason_code:            uint,
  declaration_doc_digest: digest,
  scope_change:           "Narrowing" / "Widening" / "Orthogonal",
                                                         ; single enum; forecloses both-set / both-clear bugs
  transition_actor:       tstr,
  policy_authority:       tstr,
  temporal_scope:         "prospective" / "retrospective" / "both",
  attestations:           [* Attestation],
  extensions:             { * tstr => any } / null,
}
```

Phase 1 Posture-transitions on the disclosure-profile axis are **deployment-scope only**. Per-case granularity is a Phase 3 concern (the case ledger exists only in Phase 3); the `scope_change` field's meaning is deployment-level narrowing/widening/reclassification. A reserved extension slot is available in `extensions` for Phase 3 refinement to per-case granularity.

Reason codes (registered, extensible via registry append-only):

| code | meaning |
|---|---|
| 1 | `initial-deployment-correction` |
| 2 | `audience-scope-change` (e.g., adding or removing a downstream consumer class that changes disclosure-profile applicability; disclosure-only — A.5.1 code 2 is custody-only) |
| 3 | `disclosure-policy-realignment` (operator-initiated reclassification not driven by a governance order; disclosure-only — A.5.1 code 3 is custody-only) |
| 4 | `governance-policy-change` |
| 5 | `legal-order-compelling-transition` |
| 255 | `Other` (append-only catch-all; free-text rationale in Posture Declaration) |

This table is the Disclosure-Profile Posture-Transition family's entry under the Core §6 (Event Format) §6.9 ReasonCode Registry — append-only, family-local. The Phase-1 codes mirror A.5.1 wherever the meaning is shared (codes 1, 4, 5); the disclosure-only codes (2, 3) fill A.5.1's custody-specific slots so that meaning-equivalent transitions across families share their numeric value. Deployments needing a disclosure-specific reason not covered here MUST use code `255 = Other` until a successor row is registered. Code values 1–5 here are not interchangeable with the same numeric values in the custody-model Posture-transition family (§A.5.1) or in the erasure-evidence family (Companion §20.6.1, ADR 0005). **Pin note:** this seed table locks at first runtime use per Core §6 (Event Format) §6.9 ReasonCode Registry governance — once a Phase-1 producer emits a registered code on the wire, the (code, meaning) binding is append-only; renumbering after first runtime use is a wire break. Traceability: **TR-OP-046**.

### A.5.3 Verification semantics

Traceability: **TR-OP-044** (verifier rule), **TR-OP-045** (co-publish rule). A conforming verifier processing a chain with transitions MUST:

1. Validate the payload against the concrete CDDL in A.5.1 / A.5.2 (mismatch is a structure failure).
2. Check `from_*` state matches the state established by the most recent prior transition of the same kind in the same `ledger_scope`, or matches the deployment's initial declaration if no prior transition exists. Mismatch accumulates as a localizable `continuity_mismatch` failure per Core §19 (Verification Algorithm) step 6.
3. Check `declaration_doc_digest` resolves to a Posture Declaration whose content digest under `trellis-posture-declaration-v1` (Core §9 (Hash Construction) §9.8) equals the stored digest. If the declaration is present in the export but its recomputed digest does NOT match, this is tamper evidence and is recorded per Core §19 (Verification Algorithm) step 6.c by setting both `declaration_resolved = false` and `continuity_verified = false`; the latter fails `integrity_verified` via Core §19 (Verification Algorithm) step 9.
4. Verify every `attestations[*].signature`. Required attestation count follows OC-11 (which is normative across every Posture axis), with the conservative default that ambiguous scope changes require dual attestation:
   - `scope_change = "Widening"` — MUST be dually attested by both prior and new authorities where both exist.
   - `scope_change = "Orthogonal"` — MUST be dually attested. `Orthogonal` is the non-narrowing default and does not qualify for the reduced-attestation carve-out.
   - `scope_change = "Narrowing"` — MAY be attested by the new authority alone.
   - For Custody-Model transitions (which have no `scope_change` field), the Posture-expanding cases named in OC-11 (transitions expanding provider-readable access) MUST be dually attested; narrowing cases MAY be attested by the new authority alone.

Outcomes accumulate into `VerificationReport.posture_transitions` (Core §19 (Verification Algorithm)). State continuity or attestation failures flip `integrity_verified = false`.

## A.6 Delegated-Compute Declaration Document

Per-deployment declaration artifact mandated by OC-70a (§19.9) for every agent-in-the-loop deployment. On-disk format is TOML frontmatter + Markdown body: the frontmatter carries the machine-checkable claim; the body carries operator narrative. The conformance runner ingests the frontmatter; human readers see both in one artifact.

This per-deployment declaration is distinct from the per-grant `DelegatedComputeGrant` canonical fact (Appendix B.4): the declaration is a deployment-scope posture artifact that frames the operator's delegation regime — who may delegate to whom, under what authority, with what attribution discipline — and is signed once per deployment revision. Each individual grant remains a canonical event on the ledger per §19.2 (OC-64). A single A.6 declaration governs many B.4 grants issued under its scope.

TOML frontmatter conventions for this declaration are:

1. Fields typed as `uint | null`, `URI | null`, `timestamp | null`, or `string | null` encode `null` by **omitting the key**. TOML has no native null literal; sentinel strings such as `"null"` and numeric sentinels such as `0` are NON-CONFORMANT for nullable fields.
2. `signature: OperatorSignature` serializes as a `[signature]` table with exactly `cose_sign1_b64`, `signer_kid`, and `alg`. `cose_sign1_b64` is the base64-encoded COSE_Sign1 bytes over the canonicalized frontmatter preimage; `signer_kid` identifies the operator key; `alg` names the signature suite.
3. `audit.registry_ref` is OPTIONAL but, when present, MUST identify the operator event-type registry used to resolve `audit.event_types` for rule 3 below. If absent, the registry reference MUST be supplied by the referenced Posture Declaration or another operator registry binding.

```
DelegatedComputeDeclaration {                 # TOML frontmatter shape
  declaration_id:            URI              # stable identifier
  operator_id:               URI              # MUST equal PostureDeclaration.operator_id
  posture_declaration_ref:   URI              # MUST resolve with delegated_compute = true in A.2 (OC-70b)
  effective_from:            timestamp
  supersedes:                URI | null

  scope: {                                    # §19.1
    authorized_actions:      [string]         # MUST be drawn from {read, propose, commit_on_behalf_of} in Phase 1;
                                              # "decide" is reserved and NON-CONFORMANT — see rule 4 (invariant #15)
    content_classes:         [string]         # references A.2 content_class values
    max_agents_per_case:     uint | null      # Phase 1 deployments without a case ledger MUST set null;
                                              # Phase 3+ deployments with case-scope MUST set a ceiling
    max_invocations_per_day: uint | null
    time_bound:              timestamp | null # §19.2
    purpose_bound:           string | null    # §19.2
  }

  authority: {                                # §19.3
    grantor_principal:       URI              # human / role granting delegation
    grantor_role_tier:       string           # WOS governance tier identifier
    wos_autonomy_cap_ref:    URI              # WOS autonomy cap this grant is under
    delegation_chain:        [URI]            # ordered chain of grantors; newest first
  }

  audit: {                                    # §19.4 / §19.7
    registry_ref:             URI | null       # optional event-type registry pointer; key absence means null
    event_types:             [string]         # MUST each appear in operator event-type registry (Core §6 (Event Format) §6.7)
  }

  attribution: {                              # §19.4 / invariant #15
    agent_identity:          URI              # stable identity for this agent
    actor_discriminator_rule: string          # "exactly_one_of(actor_human, actor_agent_under_delegation)"
    attribution_fields_emitted: [string]      # which attribution fields the agent emits on every event
  }

  supply_chain: {                             # §19.8
    runtime_enclave:         string           # MUST match A.2 delegated_compute_exposure
    model_identifier:        string | null    # e.g. model family + version hash
  }

  signature: OperatorSignature                # TOML table: {cose_sign1_b64, signer_kid, alg}
}
```

Cross-check surface (the first 6 enforced statically by the spec lint, remainder by the Rust conformance crate once G-4 lands):

1. `posture_declaration_ref` resolves and the referenced A.2 row for every listed `content_class` has `access_class = delegated_compute`.
2. `operator_id` equals the referenced PostureDeclaration's `operator_id`.
3. Every `audit.event_types` string appears in the operator's event-type registry (Core §6 (Event Format) §6.7).
4. `scope.authorized_actions` does not contain the string `"decide"` (Phase 1 non-conforming value).
5. `attribution.actor_discriminator_rule` is the exact literal string above.
6. `supply_chain.runtime_enclave` equals the `delegated_compute_exposure` value for every listed content class in A.2.
7. If the ledger exposes case scope (Phase 3+), declared `max_agents_per_case` ceiling holds in the ledger for every case scope. In Phase 1 deployments without a case scope, `max_agents_per_case` MUST be `null` and rule 7 is vacuously satisfied.
8. Declared `max_invocations_per_day` ceiling holds for the agent identity.
9. `authority.wos_autonomy_cap_ref` resolves to a WOS autonomy cap whose scope is a superset of `scope`.
10. `delegation_chain` is monotonic and every intermediate grantor is resolvable under `policy_authority` at the time of delegation.
11. Every emitted event under this declaration's scope honors `actor_discriminator_rule` (exactly one of the two actor fields populated).
12. Every emitted event's `agent_identity` attribution field equals `attribution.agent_identity`.
13. Every emitted event type is contained in `audit.event_types`.
14. `signature` verifies against the COSE_Sign1 preimage of the frontmatter bytes (domain-separated per Core §9 (Hash Construction) §9.1).
15. `supersedes` chain is acyclic and each linked declaration was in force at the time of the successor's `effective_from`.

Worked example (SSDI intake triage): the declaration identifies a triage-drafting agent authorized to `read` intake payloads and `propose` adjudication drafts; a human adjudicator remains the sole `commit_on_behalf_of` principal. Reference declaration doc to be authored as a follow-on under `fixtures/declarations/`.

## A.7 Cascade-Scope Enumeration

Normative enumeration of classes the purge cascade (§20.5) MUST reach. Registry append-only; new classes bump the identifier and extend, never replace.

| identifier | class | reference |
|---|---|---|
| `CS-01` | consumer-facing and system projections | §15 |
| `CS-02` | evaluator state that incorporated the destroyed material | §25 |
| `CS-03` | snapshots retained for performance or recovery | §16 |
| `CS-04` | caches, indexes, and materialized views | §15 |
| `CS-05` | rebuild fixtures that contain the destroyed material | §14 / §20.4 |
| `CS-06` | respondent-facing history views and workflow export views | §§23–24 |

A conformance fixture exercising purge-cascade verification (O-3) MUST reference the class by identifier in its manifest. A conforming implementation MUST iterate the enumeration programmatically when applying OC-77; iterating by prose is NON-CONFORMANT.

---

# Appendix B — Sidecar Examples

This appendix provides illustrative sidecar shapes. These examples are non-normative; a conforming sidecar MAY use any serialization that preserves the semantics specified in Part IV.

## B.1 Respondent History Sidecar — Minimal Shape

```
RespondentHistorySidecar {
  sidecar_id:               URI
  form_ref:                 URI                # Formspec definition reference
  response_ref:             URI                # Formspec response reference
  canonical_checkpoint_ref: URI                # Trellis checkpoint
  watermark:                Watermark          # §14.1
  stable_paths:             [StablePath]       # §23.3
  item_keys:                [ItemKey]          # §23.4
  history_moments:          [HistoryMoment]    # §23.2
  validation_snapshots:     [ValidationSnapshot]  # §23.5
  amendment_cycles:         [AmendmentCycle]   # §23.6
  migration_annotations:    [MigrationOutcome] # §23.7
}

HistoryMoment {
  moment_id:        URI
  moment_class:     enum {
    draft, save, submit, attachment_add, attachment_replace,
    validation_boundary, prepopulation_applied,
    amendment_start, amendment_submit, attestation_boundary
  }
  canonical_ref:    URI                      # the canonical record this moment was projected from
  occurred_at:      timestamp
}
```

## B.2 Workflow Governance Sidecar — Minimal Shape

```
WorkflowGovernanceSidecar {
  sidecar_id:                 URI
  case_ref:                   URI               # WOS case reference
  canonical_checkpoint_ref:   URI               # Trellis checkpoint
  watermark:                  Watermark         # §14.1
  custody_hook_binding:       CustodyHookBinding  # §24.9
  admitted_event_types:       [AdmittedEventType]  # §24.9 OC-113b; the operator-facing catalog
  governance_facts:           [GovernanceFact]  # §24.5
  review_chain:               [ReviewEvent]     # §24.6
  approval_events:            [ApprovalEvent]   # §24.7
  provenance_trace:           ProvenanceTrace   # §24.12
}

CustodyHookBinding {
  wos_runtime_id:             URI
  wos_spec_version:           string            # WOS spec version in force for this deployment
  trellis_append_scope:       URI               # Trellis ledger_scope per Core §23 (Composition with WOS `custodyHook`) §23.3
  governance_envelope_refs:   [URI]             # WOS governance envelopes whose custody is anchored here
  autonomy_policy_ref:        URI | null        # URI of the WOS Agent Config `autonomyPolicy` governing
                                                #   admitted event types. REQUIRED when the WOS deployment
                                                #   publishes an `autonomyPolicy` per WOS Agent Config §3
                                                #   AND the Operator declares any `admitted_event_types`
                                                #   entry that may be agent-authored under that policy.
                                                #   MAY be null otherwise.
  delegated_compute_decl_ref: URI | null        # URI of the Delegated-Compute Declaration (Appendix A.6).
                                                #   REQUIRED when any admitted event type is subject to
                                                #   §24.11 delegated-compute honesty obligations.
                                                #   Independent of `autonomy_policy_ref`.
}

AdmittedEventType {
  event_type:                 string            # registered `wos.*` identifier, Core §14 (Registry Snapshot Binding)
  admissibility:              enum { canonical, operational }  # §24.5
  wos_record_kind:            string            # WOS Kernel §8 / §10.4 record kind this identifier wraps
}

GovernanceFact {
  fact_id:                    URI
  fact_family:                string            # e.g. "intake_receipt", "adjudication_decision"
  canonical_ref:              URI               # Trellis canonical record reference
  admissibility:              enum { canonical, operational }  # §24.5
}
```

## B.3 Disclosure Manifest — Minimal Shape

```
DisclosureManifest {
  manifest_id:                URI
  export_ref:                 URI               # export bundle reference
  audience:                   string            # e.g. "foia_public"
  disclosed_fields:           [DisclosedField]  # §13.3
  committed_only_fields:      [CommittedField]  # §13.3
  withheld_fields:            [WithheldField]   # §13.3
  redaction_authority:        URI
  redaction_reason_class:     string
  commitment_proofs:          [CommitmentProof] # §13.5
}
```

## B.4 Delegated-Compute Grant — Minimal Shape

```
DelegatedComputeGrant {
  grant_id:               URI
  grantor:                URI               # authorizing principal (§19.3)
  grantee:                URI               # compute agent identity (§19.4)
  policy_authority:       URI               # governance authority (§19.3)
  scope:                  GrantScope        # §19.2
  time_bound:             timestamp | null  # §19.2
  purpose_bound:          string | null     # §19.2
  agent_provenance:       AgentProvenance   # §19.8
  recorded_as_canonical_fact_ref: URI       # §25.1
  signature:              Signature
}
```

## B.5 Projection Watermark — Minimal Shape

Non-normative illustration of the normative `Watermark` CDDL from Core §15 (Snapshot and Watermark Discipline) §15.2. Field names, types, and optionality mirror that normative shape field-for-field; implementations MUST conform to the Core text, not to this illustration.

```
Watermark {
  scope:                bytes                # ledger_scope of the producing chain
  tree_size:            uint
  tree_head_hash:       bytes                # digest
  checkpoint_ref:       bytes                # checkpoint_digest
  built_at:             uint                 # Unix seconds UTC when the artifact was built
  rebuild_path:         string               # implementation-defined deterministic identifier
  projection_schema_id: URI | absent         # REQUIRED for projections governed by §14.1;
                                             # OMITTED for non-projection derivatives
}
```

## C. Traceability Anchors

This non-normative appendix anchors the traceability matrix rows that correspond to Operational Companion obligations. The prose in §§1–28 and Appendices A–B is normative where it uses BCP 14 keywords; `TR-OP-*` rows in `trellis-requirements-matrix.md` are traceability aids and must be corrected if they conflict with this document.

Operational traceability rows:

- TR-OP-001, TR-OP-002, TR-OP-003, TR-OP-004, TR-OP-005, TR-OP-006, TR-OP-007, TR-OP-008
- TR-OP-010, TR-OP-011, TR-OP-012, TR-OP-013, TR-OP-014, TR-OP-015, TR-OP-016, TR-OP-017
- TR-OP-020, TR-OP-021, TR-OP-022
- TR-OP-030, TR-OP-031, TR-OP-032, TR-OP-033, TR-OP-034
- TR-OP-040, TR-OP-041
- TR-OP-042, TR-OP-043, TR-OP-044, TR-OP-045 — Posture-transition event auditability (Appendix A.5)
- TR-OP-050, TR-OP-051, TR-OP-052, TR-OP-053
- TR-OP-060, TR-OP-061
- TR-OP-070, TR-OP-071, TR-OP-072, TR-OP-073, TR-OP-074
- TR-OP-080
- TR-OP-090, TR-OP-091, TR-OP-092
- TR-OP-100, TR-OP-101, TR-OP-104, TR-OP-105, TR-OP-106, TR-OP-107, TR-OP-108, TR-OP-109, TR-OP-113, TR-OP-114, TR-OP-131, TR-OP-132, TR-OP-133
- TR-OP-110, TR-OP-111, TR-OP-112
- TR-OP-120, TR-OP-121, TR-OP-122
- TR-OP-130

---

*End of Trellis Operational Companion v1.0.0.*
