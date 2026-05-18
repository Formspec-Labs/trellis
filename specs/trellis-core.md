---
title: Trellis Core Specification (Phase 1)
version: 1.0.0
date: 2026-04-21
status: ratified
editors: Formspec / WOS / Trellis Working Group
---

# Trellis Core Specification (Phase 1)

**Version:** 1.0.0
**Date:** 2026-04-21
**Editors:** Formspec / WOS / Trellis Working Group
**Companion to:** Formspec Core v1.0, Formspec Respondent Ledger v0.1, WOS Kernel v1.0

---

## Abstract

Trellis is the cryptographic integrity substrate for the Formspec / WOS / Trellis stack. It specifies a byte-exact, append-only, offline-verifiable envelope format for individual **events** (atomic append units); hash-chained **response ledgers** (scoped to one Formspec Response); signed **checkpoints** over contiguous event ranges; and a deterministic **export package** that a stranger with only the package in hand can verify on an air-gapped laptop decades after it was produced. This document is the Phase 1 Core: it normatively fixes the wire format, the Ed25519/COSE_Sign1 signature profile, the dCBOR canonical encoding, the SHA-256 hash construction, the signing-key registry, the HPKE Base-mode payload-key wrap, the reserved commitment and causal-dependency slots, the append idempotency contract, the export ZIP layout, and the verification algorithm. Phase 2 runtime-integrity behavior and Phase 3 case-ledger / agency-log composition are strict supersets of this core by using reserved extension containers; they do not redefine the event payload or checkpoint payload. The Trellis Operational Companion covers projection discipline, metadata budgets, and posture-transition auditability; it is a separate normative document.

## Status of This Document

This is the **ratified Phase 1 Core** deliverable of the Trellis specification family: the constitutional byte-level substrate on which Phase 2 runtime integrity and Phase 3 portable case files are built. The Phase-1 stranger test is closed: an independent implementation, reading only this document and the cited normative references, produced byte-identical output against the committed fixture corpus (§29).

Operational guarantees that depend on live system behavior — projection snapshot policy, metadata-budget declaration tables, posture-transition auditability, rights-impacting evaluator rebuild — are normatively delegated to the **Trellis Operational Companion** (Phase 2 deliverable), which is a separate document. This core does not block on the companion: Phase 1 ships complete without it.

This core may be cited in production procurement. Previous `thoughts/archive/drafts/*` material and earlier split-out companion drafts now archived under `specs/archive/` are consolidated and superseded by this file for all Phase 1 normative purposes. Where the earlier documents contained material that is operational rather than constitutional, that material migrates to the Operational Companion and not to this document.

## Table of Contents

1. Introduction
2. Status and Non-Goals *(combined into §1)*
3. Conformance
4. Terminology
5. Canonical Encoding
6. Event Format
7. Signature Profile
8. Signing-Key Registry
9. Hash Construction
10. Chain Construction
11. Checkpoint Format
12. Header Policy
13. Commitment Slots Reserved
14. Registry Snapshot Binding
15. Snapshot and Watermark Discipline
16. Verification Independence Contract
17. Append Idempotency Contract
18. Export Package Layout
19. Verification Algorithm
20. Trust Posture Honesty
21. Posture / Custody / Conformance-Class Vocabulary
22. Composition with Respondent Ledger
23. Composition with WOS `custodyHook`
24. Agency Log (Phase 3 Superset Preview)
25. Security and Privacy Considerations
26. IANA Considerations
27. Test Vector Requirements
28. Appendix A — Full CDDL
29. Appendix B — Example Events and Exports
30. References

---

## 1. Introduction

### 1.1 What Trellis is

Formspec captures what a respondent answered. WOS governs the workflow that adjudicates it. Trellis is the layer that makes the resulting record **survive the system, the vendor, and the years**. A Trellis envelope is the smallest atomic unit of attested record in the stack: one COSE_Sign1 signature over a deterministically encoded CBOR object whose content hash is taken over ciphertext, whose signing key is resolvable against an export-embedded key registry, and whose append position is attested by a signed checkpoint over the preceding tree.

Trellis is not a workflow engine. It is not an identity platform. It is not an orchestrator. It is the integrity substrate against which three levels of Formspec / WOS structure compose.

### 1.2 Three scopes of append-only structure

This stack uses three nested scopes of append-only structure. Every requirement in this specification is qualified by scope.

- **Event.** An atomic append: one field edit, one governance action, one signature. Defined in §6.
- **Response ledger.** A hash-chained sequence of events for one Formspec Response. Sealed at submission. Phase 1's primary scope.
- **Case ledger.** A hash-chained sequence of governance events composing one or more sealed response-ledger heads with WOS governance events into one adjudicatory matter. Phase 3. Its event format is this specification's event format; its head format is a strict superset of this specification's checkpoint format (§24).
- **Agency log.** An operator-maintained log whose *entries* are case-ledger heads plus arrival metadata and optional witness signatures. Phase 3. Structurally CT-style; it proves that a case existed at time T and was not quietly deleted.
- **Federation log.** A log of agency-log heads witnessed by an independent operator. Phase 4.

Throughout this document, "ledger" is always qualified by scope. "Log" is reserved for structures whose entries are other ledgers' heads. All five are Trellis-shaped: same envelope, same hash, same signing profile, different scopes.

For governed Formspec/WOS deployments, one Trellis ledger per case is a first-class Phase 1 deployment pattern: the Phase 1 event and checkpoint formats above are sufficient for a case scope today. Response ledgers remain a tributary pattern for non-governed or response-local use, and may be composed into a case ledger per §22.4. Phase labels name additional composition and witnessing features; they do not imply a different case-ledger wire shape. Traceability: **TR-CORE-080**.

### 1.3 Non-goals

This specification does not define:

- workflow semantics (those live in WOS),
- form data-capture semantics (those live in Formspec),
- storage backends (Postgres, blob stores, object stores are implementation choices),
- transport protocols (HTTPS, mTLS, gRPC, IPFS are transport choices),
- post-quantum cryptography as a Phase 1 shipping requirement (§7.3 reserves the seam; Phase 1 ships Ed25519),
- a BBS+ / Pedersen selective-disclosure implementation (§13 reserves the slots; implementation deferred to Phase 2+),
- legal admissibility in any jurisdiction (§20).

### 1.4 Phase supersetting commitment

**The Phase 1 envelope IS the Phase 3 case-ledger event format.** Phase 2 and Phase 3 are strict supersets: they add runtime attestation (Phase 2) and case-scoped composition (Phase 3); they do not redefine the event. Later phases add data only through reserved extension containers defined in §6 and §11, and preserve the Phase 1 payload fields byte-for-byte. Phase 1 verifiers reject unknown top-level payload fields; forward compatibility comes from registered extension containers, not from accepting arbitrary top-level data. This is a normative commitment (§6.5 MUST-clause).

### 1.5 Substrate authority (`integrity-stack/`)

**This specification is the Trellis Core profile composition over the shared `integrity-stack/` byte substrate.** As of 2026-05-12 (per `formspec-stack/thoughts/archive/plans/2026-05-12-integrity-stack-case-boundary-refactor.md` Phase 6), every byte-level primitive that Trellis composes is owned upstream by a substrate crate in `integrity-stack/crates/`:

| Trellis section | Byte primitive | Substrate authority |
|---|---|---|
| §5 Canonical Encoding (dCBOR rules, map ordering, definite lengths) | CBOR encoding helpers | `integrity-stack/crates/integrity-cbor/` |
| §7 Signature Profile (COSE_Sign1 envelope, `Sig_structure`, protected-header serialization) | COSE_Sign1 byte structure | `integrity-stack/crates/integrity-cose/` |
| §9.1 Domain separation discipline (`len(tag) ‖ tag ‖ len(component) ‖ component` framing); §9.3 Content hash framing | Length-prefixed hash-domain framing (`integrity-canonical/length-prefix` family), distinct from the canonical JSON `domain ‖ NUL ‖ JCS(value)` family (`integrity-canonical-json-v1`) | `integrity-stack/crates/integrity-canonical/` |
| §6.1 Event Format (sequence, prev_hash, content_hash structure as identity-free primitives) | Event-sequence / event-kind value types | `integrity-stack/crates/integrity-event/` |
| §18 Export Package Layout (deterministic ZIP byte rules: STORED-only, zero extra fields, fixed mtime, lexicographic ordering, central-directory ordering, ZIP64 thresholds) | Deterministic ZIP byte structure | `integrity-stack/crates/integrity-bundle/` |

The Trellis Core text below is the **profile composition**: it pins the Trellis-specific protected-header labels (`suite_id = -65537`, `artifact_type = -65538`; label `-65539` is retired per ADR 0109 — see §7.4 and §26.2.1), the Trellis-specific domain-separation tags (`trellis-event-v1`, `trellis-author-event-v1`, `trellis-content-v1`, `trellis-checkpoint-v1`, `trellis-export-manifest-v1`, `trellis-merkle-leaf-v1`, `trellis-merkle-interior-v1`, and the application-specific tags registered in §9.8), the Trellis Phase 1 signature suite (`suite_id = 1` → Ed25519 over COSE_Sign1), the Trellis HPKE wrap discipline, the Trellis chain-construction rules (§10), the Trellis checkpoint format (§11), the Trellis export package layout and required archive members (§18), and the offline verification algorithm (§19) — none of which the substrate crates define. Where `integrity-canonical` is named below, Trellis §9 composes the length-prefixed hash-domain family; it is not referring to the Formspec canonical JSON `domain ‖ NUL ‖ JCS(value)` profile except where a JSON-profile section names that family explicitly.

Where this document restates byte-level rules that the substrate owns (encoding rules in §5, COSE_Sign1 envelope rules in §7.4, the length-prefixed domain-separation framing in §9.1, the deterministic-ZIP rules in §18.1), the restatement is **for reader-coherence only**; if a future revision of this document drifts from substrate behavior, the substrate prevails by construction. A conformant implementation is one that composes the substrate primitives in the orders pinned here; an implementation that re-implements a substrate primitive locally and disagrees with substrate output is non-conformant.

Implementations of this specification SHOULD depend directly on `integrity-stack/` crates rather than maintaining parallel byte-encoding code paths. The Rust reference (`trellis-core`, `trellis-export-writer`, `trellis-verify-wos`, and `trellis-cli`) consumes the substrate crates by path under `Cargo.toml` workspace coupling; cross-language implementations SHOULD likewise treat the substrate vectors (when available) as the byte-authoritative cross-implementation reference for the primitives, with Trellis-specific vectors (§29, `fixtures/vectors/**`) authoritative for the Trellis Core profile composition.

Traceability: **TR-CORE-177** (substrate-authority anchor row).

---

## 2. Conformance

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in BCP 14 ([RFC 2119], [RFC 8174]) when, and only when, they appear in all capitals as shown here.

### 2.1 Conformance classes

An implementation MAY claim one or more of the following conformance classes. A claim MUST satisfy every requirement applicable to each claimed class.

1. **Fact Producer.** Produces signed events. Typical: Formspec respondent client, WOS governance runtime.
2. **Canonical Append Service.** Admits events into canonical order, forms a Merkle tree over event hashes, issues signed checkpoints.
3. **Verifier.** Validates an export package offline.
4. **Derived Processor.** Builds projections from canonical truth. (Snapshot and rebuild discipline in §15; full operational detail in the Operational Companion.)
5. **Export Generator.** Assembles export packages that a Verifier can validate without network access.

Phase 1 conformance for each class requires satisfying every MUST in every section of this document tagged to that class. A second implementation that passes the fixture suite of §29 demonstrates conformance as the class(es) it implements.

### 2.2 RFC 2119 scope

RFC 2119 keywords in this document govern byte-level wire format (§§5–11), verifier behavior (§19), export contents (§18), and the trust-posture honesty floor (§20). They do not govern UX, transport, storage backend choice, or any matter explicitly delegated to a companion.

---

## 3. Terminology

- **Event.** The atomic append unit defined by §6.
- **Canonical event hash.** The SHA-256 digest over the dCBOR-encoded `CanonicalEventHashPreimage` under domain separator `trellis-event-v1` (§9.2).
- **Prior event hash.** The canonical event hash of the immediately preceding event in the same response ledger (§10.2).
- **Content hash.** The SHA-256 digest over the ciphertext body of an event's payload (§9.3). Computed over ciphertext so that per-subject key destruction (crypto-shredding) erases the payload without invalidating the chain.
- **`suite_id`.** Registered identifier for the full signature suite (curve + signature algorithm + digest) used on a given event, checkpoint, or manifest (§7). It is carried in the COSE protected header.
- **`kid`.** Signing-key identifier, unique within the signing-key registry of an export (§8.2). It is carried in the COSE protected header.
- **Payload reference.** A tagged reference to encrypted payload bytes: either inline ciphertext with nonce, or a content-addressed external ciphertext reference (§6.4).
- **Signing-key registry.** The append-only registry of `SigningKeyEntry` records embedded in every export (§8).
- **Key bag.** Per-event set of HPKE-wrapped content-encryption keys, one per recipient (§9.4).
- **`LedgerServiceWrapEntry`.** Append-only record of a service-side re-wrap after a Long-lived Authority Key rotation (§8.6); does not mutate the original event's `key_bag` or canonical event hash.
- **Canonical append attestation.** A signed checkpoint plus an inclusion proof that a given event hash appears at a given position in the canonical tree.
- **Checkpoint.** A COSE_Sign1 whose payload is a `CheckpointPayload` over a ledger scope and tree head (§11).
- **Tree head hash.** The Merkle root over the sequence of canonical event hashes up to `tree_size`, under the RFC-6962-compatible construction of §11.3.
- **Watermark.** The tuple `(tree_size, tree_head_hash)` identifying the canonical state from which a derived artifact or agency-log entry was built (§15).
- **Idempotency key.** A stable, caller-supplied, opaque identifier of up to 64 bytes, or a UUIDv7, that identifies an append attempt (§17).
- **Export package.** A deterministic ZIP with the contents of §18.
- **Response ledger / case ledger / agency log / federation log.** See §1.2.
- **Conformance class.** See §2.1. Legacy drafts called these "profiles"; this document renames them to eliminate the tri-namespace overload (§21).
- **Custody model.** See §21. The legacy companion draft's "Profiles A–E" (provider-readable / reader-held / delegated / threshold / organizational) are renamed "Custody Models" here.
- **Posture.** See §21. The Respondent Ledger spec's Profile A/B/C letters name posture axes (privacy × identity × integrity-anchoring); Trellis refers to them as "Respondent Ledger Profile A/B/C" without renaming. Their normative home remains Respondent Ledger §15A.

When a normative clause below uses one of these terms, it means exactly what is defined here — not the same term as it may appear in `thoughts/archive/drafts/` material or in superseded drafts.

---

## 4. Non-goals and authority boundaries

This Phase 1 core does not extend or reinterpret semantics owned by other specifications. The following cross-repo authority boundary is normative.

- **Formspec** is authoritative for Definition structure, Response semantics, FEL evaluation, validation algorithm, relevance and calculation, version pinning, and the four-phase processing model. Trellis does not restate those; a `formspec.authored` event is a Trellis envelope wrapping a Formspec artifact whose meaning is fixed by Formspec.
- **WOS** is authoritative for actor model, case state, deontic governance, autonomy caps, and workflow runtime semantics. A `wos.governance` event is a Trellis envelope wrapping a WOS artifact whose meaning is fixed by WOS.
- **Trellis** is authoritative for the envelope bytes, the hash chain, the checkpoint format, the export package, and the verification algorithm — and for nothing else. The Trellis verifier does not evaluate Formspec validation rules, it does not run WOS deontic checks, and it does not decide workflow outcomes. It verifies integrity and provenance distinctions; the admissibility of what it attests to remains bound to Formspec and WOS.

Trellis-bound Formspec processors MUST implement at least Formspec Core conformance. Trellis-bound WOS runtimes MUST implement at least WOS Kernel conformance. Where Trellis behavior depends on Formspec Definition or Response semantics (for example, version-pinning determinism, calculated-field provenance), processing MUST be delegated to a Formspec-conformant processor; Trellis MUST NOT restate the Formspec rule.

---

## 5. Canonical Encoding

**Requirement class:** Fact Producer, Canonical Append Service, Verifier, Export Generator.

**Substrate authority.** Per §1.5, the dCBOR encoding helpers (`encode_uint`, `encode_bstr`, `encode_tstr`, `encode_major_len`, map-ordering and definite-length enforcement, CBOR map lookup) are owned by `integrity-stack/crates/integrity-cbor/`. The rules below name the profile and Trellis composition obligations; the substrate crate is the byte-authoritative implementation of the exact encoding behavior. An implementation that calls substrate helpers, in the orders pinned by this section, is correct by composition. The Trellis-specific concerns in §5 are the choice of dCBOR (RFC 8949 §4.2.2 Core Deterministic Encoding) as the pinned canonical encoding for every Trellis byte-level structure, and the reproducibility obligation (§5.2) that fixtures byte-match across implementations.

### 5.1 Pinned encoding: dCBOR

Canonical encoding for every substrate byte follows the **[`specs/canonical-cbor-profile.md`](canonical-cbor-profile.md)** normative document (TR-CORE-179), which publishes the RFC 8949 §4.2.2 Core Deterministic Encoding rules as a standalone runtime-neutral contract (rules R1–R7: integer smallest-form, definite-length-only, bytewise key sort on encoded key bytes, duplicate-key rejection, finite-float-only, smallest-width float emission, and tag restrictions). The Rust authority remains `integrity-stack/crates/integrity-cbor/src/lib.rs::encode_canonical_cbor_value` per ADR 0004; the canonical CBOR profile names the rules a third-party runtime implements to conform and identifies where each rule is enforced in the Rust source.

All Trellis byte-level structures — events, checkpoints, signing-key registry entries, export manifests, inclusion proofs, consistency proofs — are serialized as **deterministic CBOR (dCBOR)** under that canonical CBOR profile. Implementations MUST compose the substrate dCBOR encoder and decoder rather than locally redefining any rule named in the canonical CBOR profile. Trellis structures use byte strings (`bstr`) for binary material and text strings (`tstr`) only for human-readable identifiers.

Implementations MUST NOT emit non-deterministic CBOR. A record that does not round-trip byte-for-byte through the substrate dCBOR encoder is not a canonical record.

### 5.2 Reproducibility requirement

Every byte-level test vector in the fixture suite of §29 MUST reproduce byte-for-byte on a second, independent implementation. Cross-implementation byte-match is the success criterion for this encoding choice. An implementation that produces semantically-equivalent-but-byte-different output is non-conformant; dCBOR exists precisely to remove that latitude.

### 5.3 CDDL grammar fragment

All structured types in this specification are described by [RFC 8610] CDDL. The authoritative grammar is in Appendix A (§28); each section below gives the fragment relevant to that section.

```cddl
; Canonical encoding base type.
; All bstr fields are raw bytes; tstr fields are UTF-8.
; All maps are encoded dCBOR per §5.1.
canonical-bytes = bytes  ; dCBOR-encoded
digest = bstr .size 32   ; SHA-256, 32 bytes
```

---

## 6. Event Format

**Requirement class:** Fact Producer (produces), Canonical Append Service (admits), Verifier (validates), Export Generator (includes).

### 6.1 Normative structure

An **event** is the atomic append unit. Every append to any Trellis-shaped structure (response ledger, case ledger, agency log, federation log) is one event. On the wire an event is a COSE_Sign1 object whose protected headers identify the signing suite and key, and whose payload is the dCBOR encoding of `EventPayload`.

```cddl
Event = COSESign1Bytes ; RFC 9052 COSE_Sign1 tagged CBOR value.

EventPayload = {
  version:           uint .size 1,          ; wire-format version, = 1 for Phase 1
  ledger_scope:      bstr,                  ; replay boundary, §10.4
  sequence:          uint,                  ; monotonic within ledger scope
  prev_hash:         digest / null,         ; §10; null only for sequence == 0
  causal_deps:       [* digest] / null,     ; §10.3 reserved; null or [] in Phase 1
  author_event_hash: digest,                ; §9.5; excludes itself and signatures
  content_hash:      digest,                ; SHA-256 over ciphertext, §9.3
  header:            EventHeader,           ; §12
  commitments:       [* Commitment] / null, ; §13 reserved
  payload_ref:       PayloadRef,            ; inline or external ciphertext, §6.4
  key_bag:           KeyBag,                ; §9.4
  idempotency_key:   bstr .size (1..64),    ; §17
  extensions:        { * tstr => any } / null, ; reserved top-level extension container
}
```

An `EventPayload` is a CBOR map with exactly these keys. Additional top-level keys are reserved for future phases and MUST NOT be emitted by Phase 1 producers; Phase 1 verifiers encountering an unknown top-level key MUST reject the event. Additive extension is performed via `EventPayload.extensions` and `EventHeader.extensions`, which are explicitly reserved for forward-compatible growth.

`idempotency_key` is a stable, caller-supplied byte string whose uniqueness scope is the pair `(ledger_scope, idempotency_key)` (§17.3): within a given `ledger_scope`, a specific `idempotency_key` value identifies exactly one canonical event forever. A Fact Producer MUST construct `idempotency_key` by a rule that produces equal bytes for equivalent authored submissions and distinct bytes otherwise; the recommended construction is a UUIDv7 ([RFC 9562]), with a deterministic hash of the authored fact's causal identity permitted where retry semantics require it (§17.2). The size bound `.size (1..64)` is structural; the uniqueness and construction obligations above are the normative value-level discipline.

### 6.2 Sequence and prev_hash

- `sequence` is a non-negative integer, monotonic within ledger scope. The first event in a ledger has `sequence = 0`.
- `ledger_scope` is the response-ledger, case-ledger, agency-log, or federation-log identifier. It is signed and hashed so a genesis event or copied event cannot replay into another scope.
- `prev_hash` is `null` if and only if `sequence == 0`. Otherwise it MUST be the canonical event hash (§9.2) of the immediately preceding event in the same `ledger_scope`.
- Phase 1 chain construction is strict linear (§10). `causal_deps` MUST be either `null` or the empty array `[]` in Phase 1 events.

### 6.3 author_event_hash

`author_event_hash` is the integrity digest of the author-originated portion of the event: the signed envelope, the ciphertext, and the key bag at the moment of signing. It is computed per §9.5 and MUST NOT change after signing, even under service-side key rotation (§8.6).

### 6.4 content_hash over ciphertext

`content_hash` is `SHA-256` over the exact ciphertext bytes named by `payload_ref`. This hash is over **ciphertext, not plaintext** (§9.3). This choice is load-bearing for crypto-shredding: destroying the per-subject content-encryption key erases the plaintext without invalidating the hash chain, because verification checks the ciphertext hash and the signature — neither of which depends on plaintext.

`payload_ref` is one of two tagged structures:

```cddl
PayloadRef = PayloadInline / PayloadExternal

PayloadInline = {
  ref_type:   "inline",
  ciphertext: bstr,
  nonce:      bstr .size 12,
}

PayloadExternal = {
  ref_type:       "external",
  content_hash:   digest,
  availability:   AvailabilityHint,
  retrieval_hint: tstr / null,
}

AvailabilityHint = &(
  InExport:     0,  ; bytes are present in the export payload directory
  External:     1,  ; bytes are retrievable from a content-addressed external store
  Withheld:     2,  ; bytes intentionally omitted for disclosure/readability reasons
  Unavailable:  3,  ; bytes unavailable; verifier must report omitted checks
)
```

For `PayloadInline`, `content_hash` MUST equal the hash of `ciphertext`. When the payload is encrypted under the Phase 1 suite, `ciphertext` is the output of ChaCha20-Poly1305 over the plaintext payload using the 32-byte DEK, the `PayloadInline.nonce`, and zero-length associated data `aad = h''`. For `PayloadExternal`, `EventPayload.content_hash` MUST equal `PayloadExternal.content_hash`; if ciphertext bytes are not present in the export, an offline verifier reports that payload integrity and readability checks could not run (§19) rather than pretending they succeeded.

`PayloadInline.nonce` is pinned to a 12-byte `bstr` to match the ChaCha20-Poly1305 AEAD nonce size fixed by the Phase 1 HPKE suite in §9.4. A future HPKE suite registration (§9.4) that changes the AEAD algorithm MAY require a different nonce length; such a suite MUST introduce a replacement `PayloadRef` variant rather than silently widening this constraint.

### 6.5 Phase-superset extension points

The following extension points are reserved for Phase 2 / Phase 3 superset growth. Phase 1 producers MUST NOT populate them except as `null` or empty maps/lists, with one exception: the §6.7 registered-identifier carve-out — registered identifiers whose Phase column is `1` MAY be emitted by Phase 1 producers (§6.7 is authoritative for which specific keys). Phase 1 verifiers MUST accept empty containers and MUST process Phase 1 registered identifiers per each identifier's verification obligation. Phase 2+ producers MUST populate them according to later-phase specifications; Phase 1+Phase 2 bridge verifiers MUST reject records whose extension-point usage violates this specification.

- `causal_deps` — Phase 2 HLC / DAG causal ordering.
- `commitments` — Phase 2+ per-field redaction-aware commitments (§13).
- `EventPayload.extensions` — additive top-level event metadata without top-level field growth.
- `header.extensions` — additive header fields without a version bump (§12.3).
- `header.witness_ref` — Phase 4 transparency-witness references.

**Normative phase-superset commitment.** The byte shape produced by a Phase 1 Export Generator MUST be byte-identical to what a Phase 3 case-ledger event of the same logical content would produce at Phase 1 semantic equivalence. A later-phase event MAY add fields under the reserved extension points above, but MUST NOT rename, remove, reorder, or redefine any field of §6.1 in a way that breaks Phase 1 verification. "Strict superset" means semantic and structural preservation through reserved extension containers. It does not mean Phase 1 verifiers accept unknown top-level fields.

### 6.6 Signature scope

An Event signature is the RFC 9052 COSE_Sign1 signature over `EventPayload` using COSE's standard `Sig_structure` preimage:

```text
["Signature1", protected, external_aad, payload]
```

`payload` is the exact dCBOR bytes of `EventPayload`. `external_aad` is the zero-length byte string for Phase 1. The COSE protected header MUST contain `alg`, `kid`, and `suite_id` (§7.4). No signature bytes are present in `EventPayload`, so event signing is non-circular by construction.

### 6.7 Extension Registration

`EventPayload.extensions`, `EventHeader.extensions`, and `CheckpointPayload.extensions` (§11.6) are keyed by text-string identifiers drawn from an IANA-style namespace rooted at the `trellis.` prefix. The registration discipline is:

- Keys starting with `trellis.` are reserved to this specification family and registered by the Trellis Working Group (later: IANA).
- Keys starting with `x-` are vendor / deployment local and MUST NOT be relied on across operators.
- A registered key specifies: the container it lives in (`EventPayload.extensions`, `EventHeader.extensions`, `CheckpointPayload.extensions`, `ExportManifestPayload.extensions`), its CDDL type, the Phase that produces it, and the verification obligation (ignore-if-unknown vs. reject-if-unknown-at-version).
- Registration is append-only; meaning does not change after registration.

Registered extension identifiers:

| Container | Identifier | Phase | Purpose |
|---|---|---|---|
| `EventPayload.extensions` | `trellis.custody-model-transition.v1` | 1 | Custody-model Posture-transition record; payload shape per Companion §10 and Appendix A.5.1. Reject-if-unknown-at-version. |
| `EventPayload.extensions` | `trellis.disclosure-profile-transition.v1` | 1 | Posture-transition record for the disclosure-profile axis; payload shape per Companion §10 and Appendix A.5.2. Reject-if-unknown-at-version. |
| `EventPayload.extensions` | `trellis.erasure-evidence.v1` | 1 | Cryptographic-erasure evidence record per ADR 0005; payload shape `ErasureEvidencePayload` (ADR 0005 §"Wire shape" / Companion §20.6.2). Verifier obligations in §19 (extension processing for erasure evidence; the 10-step checklist is enumerated in ADR 0005 §"Verifier obligations"). Reject-if-unknown-at-version. |
| `EventPayload.extensions` | `trellis.staff-view-decision-binding.v1` | 1 | Staff-view decision-binding record carrying the §15.2 `Watermark` seen by the adjudicator for a rights-impacting decision; payload shape `StaffViewDecisionBinding`. Reject-if-unknown-at-version. |
| `EventPayload.extensions` | `trellis.evidence-attachment-binding.v1` | 1 | Evidence attachment-binding record from ADR 0072 / Formspec Respondent Ledger §6.9. `PayloadExternal` names the attachment ciphertext bytes; this extension carries the binding metadata. Reject-if-unknown-at-version. |
| `EventPayload.extensions` | `trellis.certificate-of-completion.v1` | 1 | Certificate-of-completion record per ADR 0007: binds a presentation artifact (PDF or HTML) to the underlying signing chain via ADR 0072 attachment lineage and `signing_events` digests. Payload shape `CertificateOfCompletionPayload` (ADR 0007 §"Wire shape"). Verifier obligations in §19 step 6c. Reject-if-unknown-at-version. |
| `EventPayload.extensions` | `trellis.user-content-attestation.v1` | 1 | User-content attestation primitive per ADR 0010: one user (non-operator; Companion §6.4) attesting to one in-chain content event with a declared `signing_intent` URI (RFC 3986; semantics owned by WOS Signature Profile §1.3 / PLN-0380). Binds the host event by hash + position (`attested_event_hash` + `attested_event_position`), the attestor's identity-attestation event (`identity_attestation_ref`), and the attestation timestamp (`attested_at`, exact equality with envelope `authored_at`). Payload shape `UserContentAttestationPayload` (§28). Verifier obligations in §19 step 6d under domain tag `trellis-user-content-attestation-v1` (§9.8). Reject-if-unknown-at-version. |
| `EventPayload.extensions` | `trellis.supersedes-chain-id.v1` | 1 | Cross-chain supersession linkage per stack ADR 0066: payload shape `SupersedesChainIdPayload` (§28) carries `chain_id` and `checkpoint_hash` for the superseded chain (hash-anchored; verifier resolves linkage at bundle composition time). Map key in `EventPayload.extensions` is this registered identifier. Reject-if-unknown-at-version. Traceability: TR-CORE-169. |
| `EventPayload.extensions` | `trellis.rkaf-finding.v1` | 1 | `rkaf:Finding` (PKAF ADR-0093) anchoring binding per ADR 0012. Payload shape `RkafFindingPayload` (ADR 0012 §"Wire shape"); records one PKAF Finding (detection by a BVR / lint rule / validator) as an in-chain event extension. The host event's `trellis-event-v1` COSE_Sign1 + Merkle inclusion IS the anchor (no Finding-specific signature; no new domain-separation tag — ADR 0012 §"Decision" R3). Verifier obligations in §19 step 6f under the closed-taxonomy snapshot keyed by the payload's `pkaf_version`. PKAF §4.6 anchor type URI `urn:rkaf:anchor:trellis/1`; URN-form wire-canonical anchor IRI shape per ADR 0012 §"Anchor IRI resolution". Reject-if-unknown-at-version. Traceability: TR-CORE-178. |
| `EventPayload.extensions` | `trellis.causal_deps.v2` | 2 | Migrated HLC / DAG causal dependency structure. |
| `EventPayload.extensions` | `trellis.external_anchor.v1` | 2 | Per-event external anchor reference (e.g., OpenTimestamps). |
| `EventHeader.extensions` | `trellis.witness_signature.v1` | 4 | Transparency-witness cosignature slot. |
| `CheckpointPayload.extensions` | `trellis.agency_log.arrival_timestamp.v1` | 3 | Agency-log arrival timestamp at witness-operator ingest. |
| `CheckpointPayload.extensions` | `trellis.agency_log.witness_signature.v1` | 3 | Agency-log per-head witness cosignature. |
| `CheckpointPayload.extensions` | `trellis.case_ledger.composed_response_heads.v1` | 3 | Case-ledger head composition manifest. |
| `CheckpointPayload.extensions` | `trellis.case_ledger.case_scope_metadata.v1` | 3 | Case-scope adjudication metadata. |
| `ExportManifestPayload.extensions` | `trellis.export.attachments.v1` | 1 | Binds optional `061-attachments.cbor` (SHA-256 digest + `inline_attachments` flag). Verifier obligations and manifest entry shape per stack ADR 0072 (evidence integrity and attachment binding). Reject-if-unknown-at-version. |
| `ExportManifestPayload.extensions` | `trellis.export.witness-key-registry.v1` | 1 | Binds optional `031-witness-key-registry.cbor` via `witness_key_registry_digest` (SHA-256 of the registry member bytes) and `entry_count`. Reference-with-optional-inline pattern for witness-key history; small registries MAY be inlined by domain-specific adapters, but the archive member is the canonical verifier input when present. Reject-if-unknown-at-version. |
| `ExportManifestPayload.extensions` | `trellis.export.seal-fence.v1` | 1 | Manifest-resident export identity and high-water fence. Carries `identity_rule = "trellis-export-seal-fence-v1"`, `bundle_scope`, `export_attempt_id`, `seal_version`, `event_count`, `high_water_sequence`, `head_checkpoint_digest`, `events_digest`, and `policy_closure_digest`. `export_attempt_id` is `sha256:<hex>` over the v1 preimage defined in §18.3e. This binds Trellis-local export identity to the signed manifest without adding a separate archive member. Reject-if-unknown-at-version. |
| `ExportManifestPayload.extensions` | `trellis.export.signature-affirmations.v1` | 1 | Binds optional `062-signature-affirmations.cbor` via `signature_catalog_digest` (SHA-256 of the catalog bytes). Chain-derived WOS signature catalog; Trellis Core treats this as a registered, digest-bound extension member, while WOS row semantics are specified by [`wos-trellis-verification.md`](wos-trellis-verification.md). Reject-if-unknown-at-version. |
| `ExportManifestPayload.extensions` | `trellis.export.signed-acts.v1` | 1 | Binds optional `066-signed-acts.cbor` via `catalog_digest` (SHA-256 of the catalog bytes), `catalog_ref = "066-signed-acts.cbor"`, and `derivation_rule`. Chain-derived WOS/Formspec SignedAct projection; Trellis Core treats this as a registered, digest-bound extension member, while projection semantics are specified by [`wos-trellis-verification.md`](wos-trellis-verification.md). Reject-if-unknown-at-version. |
| `ExportManifestPayload.extensions` | `trellis.export.signed-acts.manifest.v1` | 1 | Binds optional `068-signed-acts-manifest.cbor` via `manifest_digest` (SHA-256 of the manifest bytes), `catalog_ref = "068-signed-acts-manifest.cbor"`, and `derivation_rule = "signed-acts-manifest-v1"`. Byte-deterministic verdict-bound sorted array of `(canonical_event_hash, event_type)` tuples covering `wos.kernel.signature_affirmation` and `wos.kernel.signature_admission_failed` events per WOS-TV-014a/015a; mismatch surfaces `signed_acts_manifest_mismatch` (blocking; `integrity_verified = false`). Extension absent + member present → `signed_acts_manifest_member_unbound` (blocking). Reject-if-unknown-at-version. Traceability: TR-CORE-180. |
| `ExportManifestPayload.extensions` | `trellis.export.policy-closure.v1` | 1 | Binds optional `067-policy-closure.cbor` via `closure_digest` (SHA-256 of the closure bytes), `closure_ref = "067-policy-closure.cbor"`, and `closure_version`. WOS/Formspec effective admission-policy evidence; Trellis Core treats this as a registered, digest-bound extension member, while policy-boundary semantics are specified by [`wos-trellis-verification.md`](wos-trellis-verification.md). Reject-if-unknown-at-version. |
| `ExportManifestPayload.extensions` | `trellis.export.intake-handoffs.v1` | 1 | Binds optional `063-intake-handoffs.cbor` via `intake_catalog_digest` (SHA-256 of the catalog bytes). Chain-derived WOS intake catalog carrying the Formspec `IntakeHandoff` plus canonical Response bytes needed for offline `responseHash` verification; Trellis Core treats this as a registered, digest-bound extension member, while WOS row semantics are specified by [`wos-trellis-verification.md`](wos-trellis-verification.md). Reject-if-unknown-at-version. |
| `ExportManifestPayload.extensions` | `trellis.export.supersession-graph.v1` | 1 | Binds optional `064-supersession-graph.json` via `graph_digest` (SHA-256 of Trellis canonical JSON bytes). Graph is chain-derived from ADR 0066 supersession linkage; verifier obligations in §19. Reject-if-unknown-at-version. Traceability: TR-CORE-170. |
| `ExportManifestPayload.extensions` | `trellis.export.certificates-of-completion.v1` | 1 | Binds optional `065-certificates-of-completion.cbor` via `catalog_digest` (bare SHA-256 over the catalog member bytes — same hash construction as the four sibling catalogs `trellis.export.attachments.v1`, `trellis.export.signature-affirmations.v1`, `trellis.export.intake-handoffs.v1`, `trellis.export.erasure-evidence.v1`). Chain-derived catalog over admitted `trellis.certificate-of-completion.v1` events; entry shape per ADR 0007 §"Export manifest catalog". Catalog is performance convenience for auditor UX; exporters who omit it are conformant. Reject-if-unknown-at-version. |
| `ExportManifestPayload.extensions` | `trellis.export.open-clocks.v1` | 1 | Binds optional `open-clocks.json` via `open_clocks_digest` (SHA-256 of Trellis canonical JSON bytes). Chain-derived catalog over open statutory clocks: every `clockStarted` lacking a matching `clockResolved` at export time appears with `clock_id`, `clock_kind`, `computed_deadline`, and `origin_event_hash`. Core verifier obligations cover member presence and digest binding in §19; WOS clock semantics are specified by [`wos-trellis-verification.md`](wos-trellis-verification.md). Reject-if-unknown-at-version. Traceability: TR-CORE-172. |

Phase 1 producers MUST emit all `*.extensions` containers as `null` or empty maps, EXCEPT for registered identifiers whose Phase column is `1`, which MAY be emitted by Phase 1 producers and MUST be processed by Phase 1 verifiers per the identifier's reject-if-unknown-at-version obligation. Phase 1 verifiers MUST reject unknown top-level fields (strict-superset semantics) but MUST preserve unknown registered keys inside an `extensions` container. Phase 2+ additions MUST go in a reserved `extensions` container with a registered identifier and MUST NOT be added at the top level of `EventPayload`, `EventHeader`, `CheckpointPayload`, or `ExportManifestPayload`.

### 6.8 Three event surfaces (authored / canonical / signed)

An event exists as three distinct CDDL-level surfaces during its production lifecycle. Each surface has a defined CBOR byte shape, and the three shapes are **not interchangeable**: they differ in which fields are present and in whether the bytes are wrapped in a COSE_Sign1 envelope. Fixture vectors and cross-implementation byte-match tests (§27) refer to these surfaces by name. Traceability: TR-CORE-018.

- **Authored form.** The `AuthorEventHashPreimage` CDDL struct (§9.5). This is the event map an author constructs **before** computing `author_event_hash`: it carries every field that contributes to the author-originated integrity digest but does **not** carry `author_event_hash` itself, and carries no COSE signature material. Its dCBOR serialization is the input to the `trellis-author-event-v1` hash (§9.5). A fixture that pins "the authored bytes" refers to `dCBOR(AuthorEventHashPreimage)`.

- **Canonical form.** The `EventPayload` CDDL struct (§6.1). This is the full event map **including** the computed `author_event_hash`, ready to be signed. It contains no COSE signature bytes — signing is external to the payload. Its dCBOR serialization is the input to the `trellis-event-v1` hash (§9.2) — wrapped in `CanonicalEventHashPreimage` for domain separation — and is the exact payload bytes placed inside the COSE_Sign1 envelope. A fixture that pins "the canonical bytes" refers to `dCBOR(EventPayload)`.

- **Signed form (wire form).** The `Event = COSESign1Bytes` CDDL type (§6.1, §7.4). This is the COSE_Sign1 tag-18 envelope carrying the canonical form as its payload bstr, the Ed25519 signature over the RFC 9052 `Sig_structure`, and the protected-header map pinned by §7.4. This is what appears in `010-events.cbor` (§18.4), in ledger storage, and on the wire. A fixture that pins "the signed bytes" or "the wire bytes" refers to the full COSE_Sign1 tag-18 CBOR encoding.

The three forms have different bytes, different CDDL types, and different roles. An implementor producing test vectors MUST emit each form separately when requested; a verifier decoding a wire event reconstructs the canonical form by extracting the COSE payload, and reconstructs the authored form by projecting the canonical form onto the `AuthorEventHashPreimage` shape (dropping `author_event_hash`). The Phase 1 CDDL grammar does not introduce new type names for these surfaces beyond the three already defined; the names "authored form", "canonical form", and "signed form" are spec-level vocabulary for referring to the existing CDDL types.

### 6.9 ReasonCode Registry

Several Trellis event families carry a `reason_code: uint` field in their payload — Custody-Model Transition (Companion §A.5.1), disclosure-profile transition (Companion §A.5.2), and Erasure Evidence (Companion §20.6.1). The codes are **registered per family**, not shared across families: code `3` means a different thing in a custody-model transition than it does in an erasure-evidence record, and merging the namespaces would either silently reinterpret existing values or force a renumber that breaks the wire. Each family's table is **append-only** under the same discipline as §6.7 — meaning does not change after registration; new codes append; deprecated codes retain their integer value with a `deprecated` annotation.

**Cross-family floor.** The integer value `255` is reserved across every family as `Other` — an append-only catch-all whose human-readable rationale lives in the deployment's Posture Declaration narrative. A code value of `255` MUST NOT be used by any family for a more specific meaning. This is the only cross-family invariant; codes `1..254` are family-local.

**Registered families:**

| Family | Payload | Table |
|---|---|---|
| Custody-Model Transition | `CustodyModelTransitionPayload.reason_code` | Companion §A.5.1 |
| disclosure-profile Posture-transition | `DisclosureProfileTransitionPayload.reason_code` | Companion §A.5.2 |
| Erasure Evidence | `ErasureEvidencePayload.reason_code` | Companion §20.6.1 (mirrored in ADR 0005 §"Reason codes") |

**Authoring discipline.** A new `reason_code` value MUST land in the family's table first, paired with a matrix-row update where the requirement is normative (Phase-1 reason-code values are matrix-tracked under their owning family's TR-OP rows). Operators MUST NOT emit unregistered codes; verifiers receiving an unregistered code report it as a structure failure with `unregistered_reason_code` in the relevant `*_failures[].code` namespace.

**Phase-1 verifier obligation.** Phase-1 verifiers MUST validate that decoded `reason_code` values belong to the registered set for the carrying family (or equal `255`). Out-of-range values fail `structure_verified` per Core §19 step 1.

Traceability: **TR-CORE-069** (registry rule), **TR-OP-046** (custody-model + disclosure-profile Posture-transition codes), **TR-OP-104** (erasure-evidence codes; reserved against the ADR 0005 promotion path).

---

## 7. Signature Profile

**Requirement class:** Fact Producer, Verifier.

**Substrate authority.** Per §1.5, the COSE_Sign1 byte envelope — protected-header construction, RFC 9052 `Sig_structure` array assembly, payload-mode handling (embedded vs. detached), and Ed25519 sign/verify helper operations — is owned by `integrity-stack/crates/integrity-cose/`. The substrate crate also owns the COSE label allocation discipline used by Trellis: `COSE_LABEL_ALG = 1`, `COSE_LABEL_KID = 4`, `COSE_LABEL_SUITE_ID = -65537`, and `COSE_LABEL_ARTIFACT_TYPE = -65538`. The substrate crate additionally owns `COSE_LABEL_METHOD_URI = -65540` for the consumer detached-signature envelope shape (ADR 0109); Trellis substrate envelopes never carry that label. Label `-65539` is tombstoned per ADR 0109; verifiers reject envelopes presenting it. The Trellis Signature Profile in §7 is the Trellis-specific composition of those substrate primitives: it pins `alg = -8` (EdDSA) and `suite_id = 1` (Ed25519) as the Phase 1 mandatory suite, requires `artifact_type` under integer label `-65538` with the closed enum values (`"event"`, `"checkpoint"`, `"manifest"`), specifies the migration discipline that makes a 2026 signature resolvable in 2045 (§7.3), and reserves the `suite_id` registry codepoints (§7.2). Substrate test vectors cover the COSE_Sign1 byte envelope; Trellis fixtures (§29, `fixtures/vectors/**`) cover the Trellis profile composition.

Every signed artifact in Trellis — events, checkpoints, manifests, and signing-key-registry administrative entries — is a COSE_Sign1 value and carries an explicit `suite_id` identifying the signature suite used. A verifier that encounters an unregistered `suite_id` MUST reject the artifact. The `suite_id` registry (§26.2) is part of the IANA considerations.

### 7.1 Pinned Phase 1 suite

**Phase 1 pins `suite_id = 1` to Ed25519-over-COSE_Sign1.** Concretely: the signature is COSE_Sign1 ([RFC 9052]) with `alg = -8` (EdDSA) and the signing key a 32-byte Ed25519 public key ([RFC 8032]). The digest algorithm used by dependent constructions (canonical event hash, content hash, checkpoint tree head) is SHA-256 ([FIPS 180-4]).

A Phase 1 Fact Producer MUST use `suite_id = 1` in the COSE protected header. A Phase 1 Verifier MUST accept any registered `suite_id` whose suite it recognizes, and MUST reject any unregistered `suite_id`.

### 7.2 `suite_id` IANA-style registry

The registry is a content-addressed append-only list; the Phase 1 initial contents are:

| `suite_id` | Signature suite | Digest | Status | Notes |
|---|---|---|---|---|
| 0 | Reserved | — | Reserved | MUST NOT appear on any canonical artifact. |
| 1 | Ed25519 / COSE_Sign1 / EdDSA | SHA-256 | **Active (Phase 1)** | Phase 1 mandatory suite. |
| 2 | Reserved for ML-DSA-65 ([FIPS 204]) | SHA-256 | Reserved | Phase 2+ post-quantum suite candidate. |
| 3 | Reserved for SLH-DSA-128s ([FIPS 205]) | SHA-256 | Reserved | Phase 2+ hash-based signature candidate. |
| 4 | Reserved for hybrid (Ed25519 + ML-DSA-65) | SHA-256 | Reserved | Phase 2+ migration-period hybrid. |
| 5–15 | Reserved | — | Reserved | IANA codepoint reservation, see §26. |

Future suites MUST be registered in the `suite_id` registry before any verifier is required to accept them. A record with an unregistered `suite_id` is not a canonical record.

### 7.3 Migration obligation (multi-decade verifiability)

A verifier running in 2045 MUST be able to resolve a signature produced in 2026 after intervening key rotations, and MUST be able to resolve a signature produced with `suite_id = 1` after the Trellis family has migrated its active default to a post-quantum suite. This imposes three obligations on Phase 1 implementations:

1. Every signed artifact MUST carry its `suite_id` in the COSE protected header (§7.4). A verifier MUST use that `suite_id`, not the "current" suite.
2. Every export MUST include a signing-key registry (§8) capable of resolving the signing `kid` referenced by every event, checkpoint, and manifest in the export, as that key existed at signing time.
3. Crypto parameters (curve, digest, length constraints) MUST be determined by `suite_id`, not by the verifier's current default. A verifier that "upgrades" a 2026 signature to 2045 semantics by reinterpreting it is broken.

Phase 1 does not ship a post-quantum suite. It pins the migration seam and the obligation.

### 7.4 COSE protected headers and Sig_structure

Trellis uses RFC 9052 COSE_Sign1 directly. Implementations MUST use a normal COSE library's signing preimage, not a Trellis-specific self-reference workaround.

**Payload mode.** Every Trellis ledger/export COSE_Sign1 artifact — Event, Checkpoint, Export Manifest, and signing-key-registry administrative entry — is the CBOR tag-18 4-array `[protected, unprotected, payload, signature]` of [RFC 9052] §4.2, with the payload bstr carried at array position 3 (i.e., embedded). For those artifacts, the `payload` field MUST NOT be `nil`, and a verifier MUST reject a COSE_Sign1 whose payload bstr is absent or replaced with `nil`.

COSE_Sign1 envelopes used as detached signatures over externally supplied canonical bytes — the consumer detached-signature shape per ADR 0109, owned by `integrity-cose` — MAY set `payload = nil`. These envelopes are NOT Trellis substrate artifacts (Event, Checkpoint, Export Manifest, or signing-key-registry administrative entries); their protected-header shape and dispatch are defined by `integrity-cose` and consumer specs. A detached verifier MUST reconstruct the RFC 9052 `Sig_structure` over the externally supplied bytes. If an envelope embeds a payload and the caller also supplies external bytes, the verifier MUST first require byte equality between the embedded payload and the supplied bytes; mismatch is a verification failure before primitive signature acceptance.

For every Trellis substrate COSE_Sign1 artifact, the protected header MUST contain:

| Header | Label (integer key) | Value |
|---|---|---|
| `alg` | `1` (per [RFC 9052] §3.1) | COSE algorithm identifier. Phase 1: `-8` (EdDSA). |
| `kid` | `4` (per [RFC 9052] §3.1) | 16-byte signing-key identifier resolvable in `signing-key-registry.cbor` (§8). |
| `suite_id` | `-65537` | Trellis signature-suite identifier. Phase 1: `1`. |
| `artifact_type` | `-65538` | Substrate structural role. Closed-enum tstr value: `"event"`, `"checkpoint"`, or `"manifest"`. Required per ADR 0109. |

`artifact_type` is required on every Trellis substrate envelope per ADR 0109 Bound pre-decision #1. The enum is closed at three values — future expansion requires a Trellis-owned spec amendment, not a registry append. A verifier MUST reject envelopes whose `artifact_type` is absent or carries any value outside the closed enum.

**Retired label.** COSE label `-65539` is permanently retired by ADR 0109. New envelopes MUST NOT emit it. Verifiers MUST reject any envelope presenting `-65539` with a named "retired dispatch label present" error. Future Trellis-allocated labels skip `-65539`; the codepoint is not reused.

**Consumer detached-signature envelope.** Authored signatures, verification receipts, and other consumer-owned signed artifacts use a separate envelope shape — MAP_3 with `{alg, kid, method_uri}` at COSE label `-65540` (`method_uri`). The label is owned by `integrity-cose`; Trellis Core does not reference `-65540` on substrate envelopes. URI values are consumer-owned and namespaced (Formspec: `urn:formspec:sig-method:*` and `urn:formspec:receipt-method:*`; WOS reserves `urn:wos:attestation-method:*`). See `thoughts/registries/uri-prefix-coordination.md` at the stack root.

**Label rationale and registry.** `alg` and `kid` use the integer labels registered in [RFC 9052] §3.1. The Trellis-specific headers `suite_id` and `artifact_type` use negative integer labels in the COSE private-use range (per [RFC 9052] §1.4 / §11.3), placed below `-65536` to stay clear of the 16-bit-wide IANA-assigned ranges. Label `-65539` was previously allocated and is now retired per ADR 0109. Future Trellis-introduced protected-header keys MUST be assigned sequentially-descending integer labels from this namespace, skipping `-65539`, and registered alongside the `suite_id` registry (§26.2). Implementations MUST NOT use text-string labels for these headers; the integer labels above are the only conformant encoding.

**Protected-header map serialization.** The COSE protected header is itself a CBOR map wrapped in a bstr; its bytes determine the `Sig_structure` preimage and therefore the signature. The protected-header map MUST be serialized per the dCBOR rules of §5.1. Because §5.1 specifies byte-wise lexicographic ordering of the canonical CBOR encoding of each key, CBOR integer keys are effectively ordered by numeric value for single-byte-encoded keys and by their encoded bytes otherwise; duplicate keys MUST be rejected. A verifier MUST recompute `Sig_structure` using the exact protected-header bstr bytes present in the COSE envelope; it MUST NOT re-serialize the map.

To sign an Event, Checkpoint, or Export Manifest:

1. Build the artifact payload map (`EventPayload`, `CheckpointPayload`, or `ExportManifestPayload`) with no signature field.
2. Serialize the payload map as dCBOR (§5).
3. Construct a COSE_Sign1 object whose payload is those bytes.
4. Populate the protected header with `alg`, `kid`, `suite_id`, and `artifact_type` — all four required on substrate envelopes per ADR 0109.
5. Sign the RFC 9052 `Sig_structure` array `["Signature1", protected, external_aad, payload]`, with `external_aad` equal to the zero-length byte string for Phase 1.

A verifier uses the protected-header `kid` to resolve the public key via the signing-key registry (§8), uses protected-header `suite_id` and `alg` to select the suite, uses protected-header `artifact_type` to select the payload decoder schema, and verifies the COSE_Sign1 signature over the standard `Sig_structure`. For embedded Trellis substrate artifacts, the signed payload bytes are the COSE payload bstr. For consumer detached signatures (separate envelope shape owned by `integrity-cose`), the signed payload bytes are supplied by the caller and checked under the payload-mode rule above. Signature verification is independent of all other verification steps.

`artifact_type` is a schema selector (which payload decoder runs), not a runtime dispatcher. Semantic dispatch for events — selecting the validator plugin — uses `EventHeader.event_type` inside the canonical event payload (§23.4 prefix-registration pattern). Checkpoint and Manifest artifacts dispatch directly through the substrate; no plugin dispatch axis applies. This is the ADR 0109 surface-split — wire format here, semantic identity in signed payload, validator plugin selection one level deeper inside the envelope structure.

---

## 8. Key Registry

**Requirement class:** Canonical Append Service (maintains), Export Generator (snapshots), Verifier (resolves).

### 8.1 Why this exists

A COSE signature without a resolvable key is unverifiable after rotation. Phase 1 exports MUST include a key registry snapshot so that verification is self-contained at any future date, including dates after every key the registry references has been rotated out of operational use.

The key registry is a single dCBOR array embedded in every export at `030-signing-key-registry.cbor` (filename retained for wire-shape stability across the Phase-1 v1.0.0 corpus). It carries one row per key the export references, regardless of class. Phase 1 populates only signing-class entries; the envelope reserves capacity for tenant-root, scope, subject, and recovery classes per ADR 0006 (§8.7).

### 8.2 `SigningKeyEntry` (signing-class wire shape)

```cddl
SigningKeyEntry = {
  kid:           bstr .size 16,           ; unique key identifier; §8.3
  pubkey:        bstr,                    ; raw public key bytes per suite_id
  suite_id:      uint,                    ; §7.2
  status:        SigningKeyStatus,        ; §8.4
  valid_from:    timestamp,               ; key activation time
  valid_to:      timestamp / null,        ; null for currently-active keys
  supersedes:    bstr / null,             ; kid this entry replaces, if any
  attestation:   bstr / null,             ; optional HSM / KMS attestation, suite-defined
}

SigningKeyStatus = &(
  Active:   0,
  Rotating: 1,
  Retired:  2,   ; no new signatures, historical verification permitted
  Revoked:  3,   ; hard-reject events signed under this key after valid_to
)
```

`SigningKeyEntry` is the **legacy flat shape** retained for byte-for-byte preservation of the Phase-1 v1.0.0 corpus. Implementations that emit the unified `KeyEntry` taxonomy (§8.7) carry the same eight fields plus a leading `kind: "signing"` discriminator on the flat signing arm; the structural and semantic content is identical. Verifiers MUST accept both shapes per the dispatch rule in §8.7.

### 8.3 `kid` format

`kid` is a 16-byte opaque identifier. An implementation MAY derive it, or MAY assign it by administrative policy; either MUST produce a `kid` unique within the registry. The derivation is class-agnostic per §8.7: any registered key — signing or otherwise — has a `kid` derivable from its `suite_id` and raw public-key bytes by the construction below.

**Derived `kid` construction (pinned).** When a `kid` is derived, it MUST be the first 16 bytes of:

```
SHA-256( dCBOR_encode_uint(suite_id_integer) || pubkey_raw )
```

where:

- `dCBOR_encode_uint(x)` is the canonical dCBOR encoding of the unsigned integer `x` per §5.1 (smallest representation; for example, `suite_id = 1` encodes as the single byte `0x01`),
- `pubkey_raw` is the raw public-key bytes for the suite (for Phase 1 `suite_id = 1`, the 32-byte Ed25519 public key per [RFC 8032]),
- `||` denotes byte-string concatenation.

Byte order is fixed: the dCBOR-encoded `suite_id` precedes `pubkey_raw`. Implementations MUST NOT re-order, re-prefix, or re-length-delimit the concatenation; the two byte sequences are concatenated directly.

**Administratively assigned `kid`.** An administrative assignment MAY produce any `bstr` of 1..32 bytes (the `SigningKeyEntry.kid` CDDL is pinned to `bstr .size 16` for Phase 1; administrative assignment within Phase 1 MUST therefore produce exactly 16 bytes). The assignment MUST be consistent with dCBOR-decodability — the `kid` is carried as a `bstr` in the COSE key structure and in the COSE protected header (§7.4). Administrative `kid` values MUST NOT overlap any derived `kid` value already present in the registry; uniqueness within the registry is required regardless of assignment method.

### 8.4 Lifecycle

Legal `status` transitions:

- `Active → Rotating`: a successor key has been provisioned; both keys accept signatures.
- `Rotating → Retired`: successor is fully deployed; the old key accepts no new signatures but remains verifiable for historical material.
- `Rotating → Revoked`: compromise detected during rotation.
- `Active → Revoked`: compromise detected without intermediate Rotating state.
- `Retired → Revoked`: late detection of compromise.

`Revoked` is terminal. `Retired` is terminal for signature issuance but not for verification of historical records. `Destroyed` is out of scope for Phase 1 signing keys (signing-key destruction is an operational action represented in the agency log, §24); the private key material MAY be destroyed, but the `SigningKeyEntry` MUST remain in the registry to preserve historical verifiability.

**Rotation-grace overlap.** A `Rotating` signing key is a new-signature authority only inside the overlap interval declared by that registry entry: `valid_from <= signature_time <= valid_to`; `valid_to = null` means the overlap is still open in the embedded snapshot. Outside that interval, `Rotating` is not a new-signature authority. Verifier surfaces that validate signing-time authority, including §19 step 6d step 6 for user-content attestations, MUST apply this predicate at the attestation's signed time.

The lifecycle above applies to `kind = "signing"` entries (§8.7). Non-signing classes carry their own activation/supersession discipline declared in §8.7.2; they do not use the `SigningKeyStatus` enum.

### 8.5 Registry snapshot in every export

Every export package (§18) MUST include a complete registry snapshot resolvable for every `kid` referenced by any event, checkpoint, or `LedgerServiceWrapEntry` in the export. "Complete" means: for any `kid` cited, the entry for that `kid`, every entry that `supersedes` points to transitively, and every entry that is a supersession ancestor of the cited `kid`. A verifier encountering a `kid` that cannot be resolved against the embedded registry MUST reject the export.

### 8.6 `LedgerServiceWrapEntry` under LAK rotation

A service-side Long-lived Authority Key (LAK) used to wrap payload content-encryption keys (§9.4) MAY rotate independently of event signing keys. Rotation that changes the LAK-wrapping of historical payloads MUST NOT modify any Phase 1 `Event` (including its `key_bag`, `author_event_hash`, or `content_hash`). Instead, a service-side re-wrap produces an append-only `LedgerServiceWrapEntry`:

```cddl
LedgerServiceWrapEntry = {
  ledger_id:          bstr,                ; scope identifier
  author_event_hash:  digest,              ; target event
  lak_version:        uint,                ; new LAK version
  ephemeral_pubkey:   bstr .size 32,       ; X25519 ephemeral public key, unique per wrap (§9.4)
  wrapped_dek:        bstr,                ; HPKE-wrapped DEK, §9.4
  created_at:         timestamp,                ; wrap creation time
  signature:          COSESign1Bytes,      ; service signature, same COSE suite as §7
}
```

This is load-bearing for invariant #7 (key-bag immutability under rotation). Historical `author_event_hash` values MUST reproduce after any LAK rotation, because no field covered by `author_event_hash` ever changes; the new wrap is a separate canonical artifact.

The `ephemeral_pubkey` freshness and `wrapped_dek` construction obligations for every `LedgerServiceWrapEntry` are normatively pinned in §9.4: each wrap MUST use an X25519 ephemeral keypair unique across every wrap in the containing ledger scope, and the ephemeral private key MUST be destroyed after wrap. The §9.4 obligations apply to rotation-wrap entries identically to initial-wrap entries; this section does not introduce separate semantics.

### 8.7 `KeyEntry` taxonomy (ADR 0006)

The unified key registry admits a tagged-union `KeyEntry` discriminated by a top-level `kind` field. Six reserved classes cover Phase-1 through Phase-4 key material; an extension `tstr` escape on `kind` follows the Core §6.7 append-only registry pattern for future classes. **Phase-1 runtime restriction:** only `kind = "signing"` is populated in the signing-key registry in practice; `tenant-root`, `scope`, `subject`, `recovery`, and `witness` are envelope reservations (the wire admits them; the runtime warns on emit per Companion §27 lint and the Phase-1 lint addition below). Witness-key history for export verification lives in the optional `031-witness-key-registry.cbor` member and its `trellis.export.witness-key-registry.v1` manifest binding.

**Wire-shape backward compatibility.** A registry row MAY use either of two encodings, and verifiers MUST accept both:

1. The legacy `SigningKeyEntry` flat map (§8.2) — eight fields, no `kind` discriminator. Resolution semantics: `kind` is implicitly `"signing"`. Phase-1 v1.0.0 corpus fixtures use this shape.
2. The unified `KeyEntry` shape — `kind` is the top-level discriminator. The signing arm carries the same eight fields as `SigningKeyEntry` plus the leading `kind: "signing"` field; non-signing arms carry a per-class `attributes` sub-map per §8.7.2.

A verifier dispatches on the **presence** of a `kind` field at the top level of the entry map: present → `KeyEntry` dispatch (§8.7.1); absent → legacy `SigningKeyEntry` (§8.2). Both paths converge on identical signature-verification, lifecycle, and supersession rules for the signing class; the only on-wire difference is the `kind` field itself.

#### 8.7.1 CDDL — `KeyEntry` discriminator

```cddl
; Registry admits exactly one of these encodings, plus the legacy
; SigningKeyEntry shape (§8.2) for byte-shape preservation across the
; Phase-1 v1.0.0 corpus. Verifiers dispatch on the presence of `kind`.
KeyEntry = KeyEntrySigning / KeyEntryNonSigning

KeyEntrySigning = {
  kind:          "signing",
  kid:           bstr .size 16,
  pubkey:        bstr,                    ; algorithm pinned by suite_id
  suite_id:      uint,
  status:        SigningKeyStatus,        ; §8.4
  valid_from:    timestamp,
  valid_to:      timestamp / null,
  supersedes:    bstr / null,
  attestation:   bstr / null,
}

KeyEntryNonSigning = {
  kind:          "tenant-root" / "scope" / "subject" / "recovery" / "witness" / tstr,
  kid:           bstr .size 16,
  suite_id:      uint,
  attributes:    TenantRootKeyAttributes / ScopeKeyAttributes /
                 SubjectKeyAttributes / RecoveryKeyAttributes /
                 WitnessKeyAttributes /
                 { * tstr => any },
  extensions:    { * tstr => any } / null,
}
```

For reserved literals (`tenant-root`, `scope`, `subject`, `recovery`, `witness`), `attributes` MUST decode as the corresponding structure in §8.7.2 — pairing a literal `kind` with the wrong inner map shape is a structure failure (`key_entry_attributes_shape_mismatch`). For an extension `kind` `tstr` that the verifier does not recognize, see §8.7.3 *Unknown `kind`*.

#### 8.7.2 Reserved non-signing class shapes

```cddl
TenantRootKeyAttributes = {
  pubkey:           bstr .size 32,
  tenant_ref:       tstr,
  effective_from:   timestamp,
  supersedes:       bstr .size 16 / null,
  ; NO status field: tenant-root keys are activation-scoped, not rotating.
}

ScopeKeyAttributes = {
  pubkey:              bstr .size 32,
  scope_ref:           bstr,                  ; ledger_scope byte-string
  parent_tenant_ref:   tstr,
  effective_from:      timestamp,
  supersedes:          bstr .size 16 / null,
}

SubjectKeyAttributes = {
  pubkey:            bstr .size 32,
  subject_ref:       tstr,
  authorized_for:    [+ bstr],
  effective_from:    timestamp,
  valid_to:          timestamp / null,
  supersedes:        bstr .size 16 / null,
}

RecoveryKeyAttributes = {
  pubkey:                  bstr .size 32,
  authorizes_recovery_for: [+ bstr .size 16],   ; kids of signing keys only
  activation_quorum:       uint,
  activation_quorum_set:   [+ bstr .size 16] / null,
  effective_from:          timestamp,
  supersedes:              bstr .size 16 / null,
}

WitnessKeyAttributes = {
  pubkey:                  bstr .size 32,
  witness_kind:            "local-server" / "rfc3161-tsa" /
                           "ethereum-anchor" / "open-timestamps" / tstr,
  effective_from:          timestamp,
  valid_to:                timestamp / null,
  supersedes:              bstr .size 16 / null,
}

WitnessKeyRegistry = {
  version:                 1,
  entries:                 [* WitnessKeyRegistryEntry],
}

WitnessKeyRegistryEntry = {
  kid:                     bstr .size 16,
  pubkey:                  bstr .size 32,
  suite_id:                uint,
  witness_kind:            "local-server" / "rfc3161-tsa" /
                           "ethereum-anchor" / "open-timestamps" / tstr,
  effective_from:          timestamp,
  valid_to:                timestamp / null,
  supersedes:              bstr .size 16 / null,
}
```

#### 8.7.3 Verifier obligations for `KeyEntry` dispatch

A conforming verifier resolving a `kid` in the embedded registry MUST:

1. **Decode** the registry array; for each entry detect dispatch path: top-level `kind` field present → `KeyEntry`; absent → `SigningKeyEntry` (§8.2).
2. **Validate `kind`** against the closed taxonomy `{"signing", "tenant-root", "scope", "subject", "recovery", "witness"}` plus any registered extension. Unknown `kind` per §8.7.3 *Unknown `kind`*.
3. **Dispatch on `kind`:** for `"signing"`, validate the flat eight-field set (parity with §8.2); for reserved non-signing kinds, validate `attributes` against the matching CDDL group; structural mismatch → `key_entry_attributes_shape_mismatch`.
4. **Class-specific invariants** (Phase-2+ activation; Phase-1 verifiers MAY skip with a warning):
   - `signing`: existing §8.4 lifecycle.
   - `tenant-root` / `scope`: `effective_from ≤ authored_at` for events claiming this scope.
   - `subject`: `effective_from ≤ authored_at ≤ valid_to` (when non-null) for `KeyBagEntry` wraps referencing this subject-kid.
   - `recovery`: NOT acceptable as a signing kid for any non-recovery event. A `recovery`-class kid in a COSE_Sign1 protected header for an ordinary event is a class-confusion attack; verifier MUST reject with `key_class_mismatch`.
   - `witness`: NOT acceptable as a signing kid for an Event, Checkpoint, Export Manifest, or signing-key-registry administrative entry. Witness-class keys are only for external witness attestations or optional export-level witness verification.
5. **Supersession acyclicity** across per-class `supersedes` chains.

**Unknown `kind`.** When the verifier encounters an entry whose `kind` is not one of the six reserved literals and not in the verifier's extension registry: it MUST record `unknown_key_class` and MUST NOT coerce the entry into a reserved class. It MUST NOT set `integrity_verified = false` solely for unknown `kind` (forward-compatibility, mirrors the unknown-extension-event-type pattern). If a downstream artifact (signature, HPKE wrap, erasure-evidence subtree) requires that `kid` to be interpreted under the unknown class and the verifier lacks normative rules, it MUST fail closed for that obligation with an explicit capability-gap code.

#### 8.7.4 Phase-1 lint discipline

Phase-1 lint (`scripts/check-specs.py`) emits a warning for any `KeyEntry` whose `kind != "signing"`. This is a reservation-permitted-but-unused signal, not a verifier failure: the wire admits the reservation; the runtime warns to surface that the deployment is exercising a Phase-2+ surface ahead of phase activation. Phase-2+ lifts the warning when the relevant custody model activates per ADR 0006.

#### 8.7.5 Traceability

TR-CORE-039 anchors the unified `KeyEntry` taxonomy + verifier dispatch on `kind`. TR-CORE-047 anchors Phase-1 reservation acceptance + non-signing lint warning. TR-CORE-048 anchors class-dispatch failures (`key_entry_attributes_shape_mismatch`, `key_class_mismatch`). TR-CORE-049 anchors the unknown-`kind` capability-gap rule.

#### 8.7.6 Cross-class references (ADR 0005 reconciliation)

ADR 0005 `ErasureEvidencePayload.key_class` uses the five literals `signing`, `tenant-root`, `scope`, `subject`, and `recovery` (after `wrap`→`subject` normalization). The reserved `witness` class exists on `KeyEntry` (§8.7) but MUST NOT appear in `ErasureEvidencePayload.key_class`: witness material is out of scope for cryptographic-erasure credential checks. **Normative name for HPKE / subject-wrap material is `subject`**; the wire string `"wrap"` is a deprecated synonym retained for pre-reconciliation interop. Verifiers MUST normalize `"wrap"` → `"subject"` before any `kind` comparison or registry resolution. `kid_destroyed` resolves against the **single** key registry: signing-class entries via the legacy shape OR the `KeyEntry` signing arm; non-signing classes via `KeyEntry` non-signing arms.

---

## 9. Hash Construction

**Requirement class:** Fact Producer, Canonical Append Service, Verifier.

**Substrate authority.** Per §1.5, the length-prefixed domain-separation framing —`SHA-256(len(tag) ‖ tag ‖ len(component) ‖ component)` with 4-byte big-endian length prefixes — is owned by `integrity-stack/crates/integrity-canonical/`. The substrate crate exports the canonical framing primitive and the SHA-256 / SHA-384 / SHA-512 digest helpers used by every byte-level integrity construction in the stack (Formspec response signing, Trellis event/content/checkpoint hashing). The Trellis-specific concerns in §9 are the Trellis domain-tag namespace (§9.8: `trellis-event-v1`, `trellis-author-event-v1`, `trellis-content-v1`, `trellis-checkpoint-v1`, `trellis-export-manifest-v1`, `trellis-merkle-leaf-v1`, `trellis-merkle-interior-v1`, and the per-application tags), the choice of components per construction (`CanonicalEventHashPreimage`, `AuthorEventHashPreimage`, `CheckpointHashPreimage`, `ExportManifestHashPreimage`), the ciphertext-vs-plaintext discipline (§9.3 / §6.4 — load-bearing for crypto-shredding), the HPKE Base-mode payload-key wrap (§9.4), and the `author_event_hash` construction immutable under signing-key rotation (§9.5). The framing rule is restated below in skeleton form for reader-coherence; the substrate's framing function is the byte-authoritative implementation.

### 9.1 Domain separation discipline

Every hash computation in Trellis is domain-separated by a length-prefixed UTF-8 byte tag. The generic form is:

```
digest = SHA-256(
    len(tag)       as 4-byte big-endian unsigned ||
    tag            as UTF-8 bytes ||
    len(component) as 4-byte big-endian unsigned ||
    component      as raw bytes
)
```

Multi-component inputs repeat the `len(component) || component` pair for each input, in the fixed order specified for the construction. Length-prefixing (not delimiter-based framing) removes component-boundary ambiguity. The generic procedure is referenced below by domain tag only. The length-prefix form applies uniformly regardless of component count: a single-component construction (for example, `author_event_hash` over `dCBOR(AuthorEventHashPreimage)`) uses the same `len(tag) || tag || len(component) || component` shape with exactly one `len(component) || component` pair; there is no unprefixed or concatenated variant for the single-component case.

### 9.2 Canonical event hash (`trellis-event-v1`)

The canonical event hash is:

```
canonical_event_hash = SHA-256(
    "trellis-event-v1" domain-separated per §9.1 over
    dCBOR(CanonicalEventHashPreimage)
)
```

```cddl
CanonicalEventHashPreimage = {
  version:       uint .size 1,
  ledger_scope:  bstr,
  event_payload: EventPayload,
}
```

`event_payload` is the decoded `EventPayload` carried as the COSE payload. It contains `author_event_hash`, but it contains no signature bytes. The domain tag `trellis-event-v1` reserves the `-v1` slot for this construction; a future version bump would use `-v2`. Verifiers MUST match the domain tag to the event payload's `version` field.

### 9.3 Content hash (`trellis-content-v1`, over ciphertext)

```
content_hash = SHA-256(
    "trellis-content-v1" domain-separated per §9.1 over
    the exact ciphertext bytes named by payload_ref
)
```

`content_hash` is over **ciphertext**, never plaintext. Hashing plaintext forecloses crypto-shredding: once the DEK is destroyed, plaintext cannot be recovered, so a plaintext hash binds the chain to something that no longer exists — forcing either non-erasure (violating GDPR Article 17 / FOIA redaction obligations) or chain breakage (violating the append-only invariant). Hashing ciphertext preserves both: erasure destroys the DEK, the ciphertext remains hash-verifiable, and the chain stands.

### 9.4 Key bag and HPKE wrap

The payload content-encryption key (DEK) is wrapped for one or more recipients in the event's `key_bag`:

```cddl
KeyBag = {
  entries: [* KeyBagEntry],
}
KeyBagEntry = {
  recipient:        bstr,                ; stable recipient identifier (e.g., "ledger-service", DID)
  suite:            uint,                ; HPKE suite identifier, Phase 1 fixed to 1
  ephemeral_pubkey: bstr .size 32,       ; X25519 ephemeral public key, unique per wrap
  wrapped_dek:      bstr,                ; HPKE-sealed DEK
}
```

Phase 1 HPKE suite 1 ([RFC 9180]) is **Base mode**, KEM = `DHKEM(X25519, HKDF-SHA256)`, KDF = `HKDF-SHA256`, AEAD = `ChaCha20-Poly1305`.

Choice of ChaCha20-Poly1305 over AES-256-GCM for payload AEAD is for constant-time implementability on WASM and non-AES-NI hardware; it is not a security claim about one over the other. Both satisfy the confidentiality requirement. Deployments that require AES-256-GCM MAY register an additional HPKE suite in Phase 2.

For each `KeyBagEntry`, Phase 1 producers call RFC 9180 `SetupBaseS` / `Seal` with `info = h''` and AEAD associated data `aad = h''`. The plaintext input to `Seal` is the 32-byte payload DEK. `KeyBagEntry.ephemeral_pubkey` stores the HPKE encapsulated public key `enc`; `KeyBagEntry.wrapped_dek` stores the AEAD ciphertext-and-tag returned by `Seal`. A future suite registration MAY define a non-empty `info` or `aad`, but suite 1 is pinned to zero-length values so a verifier can reproduce the wrapped-DEK bytes from only the fixture inputs.

**AEAD nonce determinism (payload layer).** `PayloadInline.nonce` (§6.4) MUST be derived deterministically from the authored event content so that a retry with the same `idempotency_key` (§17) and identical authored bytes produces byte-identical ciphertext. The Phase 1 derivation is:

```
nonce = HKDF-SHA256(
    salt = dCBOR(idempotency_key),
    ikm  = SHA-256(plaintext_payload),
    info = "trellis-payload-nonce-v1",
    length = 12
)
```

where `plaintext_payload` is the exact payload bytes to be encrypted. This construction binds the nonce to both the idempotency identity (preventing cross-key collisions) and the exact payload content (preventing same-key, different-payload silent divergence). The `ikm` is the SHA-256 hash of the plaintext rather than the plaintext itself so that the derivation has a fixed-length input and does not require the HKDF layer to handle large payloads.

A Canonical Append Service MAY memoize the ciphertext per `(ledger_scope, idempotency_key)` as an implementation optimization, but memoization is not normative; the deterministic derivation alone is sufficient to guarantee retry byte identity. A verifier does not re-derive or validate the nonce; the rule is a producer obligation that makes the idempotency contract (§17.3) decidable without mutable state.

**Private-payload protection floor.** A Fact Producer MUST NOT append plaintext content for a private payload class declared `reader_held` or `provider_readable = false` in the active Posture Declaration (§20). Public metadata MAY remain public only where Trellis defines it as public metadata; private or user content MUST be represented by protected ciphertext and payload references. The §9.4 fixture carve-out below is structural-only: it permits pinned ephemeral keys so HPKE test vectors can reproduce byte-for-byte; it is not a plaintext durable-bundle deployment profile. Traceability: **TR-CORE-034**.

Traceability: **TR-CORE-144** (matrix row).

Every `KeyBagEntry` (hereafter "wrap") MUST use a fresh X25519 ephemeral keypair, unique across every wrap in the containing ledger scope. For the avoidance of doubt: in an event with N recipients the `key_bag` contains N `KeyBagEntry` rows with N distinct `ephemeral_pubkey` values, generated from N distinct ephemeral private keys; no `ephemeral_pubkey` value produced by any author in any event in the same ledger scope may recur in any later event. The `ephemeral_pubkey` is persisted in the envelope so the recipient can perform ECDH; the corresponding ephemeral private key MUST be used exactly once and destroyed after the wrap is sealed. Reusing an ephemeral private key across wraps, within the same event, across events in the same ledger scope, or across ledger scopes, is a non-conformance.

**Test-vector carve-out.** Language-neutral byte-level test vectors under `fixtures/vectors/**` MAY pin the ephemeral private key as a fixture artifact, because §5.2 and §27 require every fixture to reproduce byte-for-byte across independent implementations and that requirement would otherwise be unsatisfiable for HPKE wraps. A fixture that pins an ephemeral private key MUST: (a) commit the pinned private key under `fixtures/vectors/_keys/` with a filename that names the owning vector, (b) declare in its `manifest.toml` that the pinned key is a test artifact, and (c) state in its `derivation.md` that a production implementation MUST generate the ephemeral in-process and destroy it after single use. The carve-out applies to fixtures only; no production `Fact Producer`, `Canonical Append Service`, or `Verifier` may rely on it. Traceability: **TR-CORE-033** (matrix row) — enforced by `scripts/check-specs.py` rule R17, which fails loud when any `(ledger_scope, ephemeral_pubkey)` pair recurs across distinct vector dirs in the corpus and when any `key_bag.entries` list contains a duplicate `ephemeral_pubkey`.

Authentication note: HPKE Base mode provides no sender authentication at the wrap layer. This is adequate because (a) `author_event_hash` covers the key bag, (b) the event is Ed25519-signed per §7, and (c) any modification to the key bag invalidates the signature. Use of HPKE Auth mode would add sender-key management at the wrap layer without strengthening the envelope; the envelope signature is the authentication boundary.

### 9.5 `author_event_hash` construction

```
author_event_hash = SHA-256(
    "trellis-author-event-v1" domain-separated per §9.1 over
    dCBOR(AuthorEventHashPreimage)
)
```

```cddl
AuthorEventHashPreimage = {
  version:         uint .size 1,
  ledger_scope:    bstr,
  sequence:        uint,
  prev_hash:       digest / null,
  causal_deps:     [* digest] / null,
  content_hash:    digest,
  header:          EventHeader,
  commitments:     [* Commitment] / null,
  payload_ref:     PayloadRef,
  key_bag:         KeyBag,
  idempotency_key: bstr .size (1..64),
  extensions:      { * tstr => any } / null,
}
```

`author_event_hash` binds the envelope payload, payload reference, and key bag at the moment of signing. It excludes itself and all signature material by construction: `AuthorEventHashPreimage` has no `author_event_hash` field and no COSE signature field. It is immutable under rotation because none of its inputs is altered by service-side re-wraps (§8.6); re-wraps produce append-only `LedgerServiceWrapEntry` records outside the author-event scope.

### 9.6 Checkpoint digest (`trellis-checkpoint-v1`)

```
checkpoint_digest = SHA-256(
    "trellis-checkpoint-v1" domain-separated per §9.1 over
    dCBOR(CheckpointHashPreimage)
)
```

```cddl
CheckpointHashPreimage = {
  version:            uint .size 1,
  scope:              bstr,
  checkpoint_payload: CheckpointPayload,
}
```

### 9.7 Export manifest digest (`trellis-export-manifest-v1`)

```
export_manifest_digest = SHA-256(
    "trellis-export-manifest-v1" domain-separated per §9.1 over
    dCBOR(ExportManifestHashPreimage)
)
```

```cddl
ExportManifestHashPreimage = {
  version:          uint .size 1,
  scope:            bstr,
  manifest_payload: ExportManifestPayload,
}
```

The export manifest (§18.3) is also signed as a COSE_Sign1 object. The digest construction above is used when another artifact needs to refer to the manifest by content address.

### 9.8 Domain-tag registry

Phase 1 reserves these domain tags. An implementation MUST NOT use any of these tags for any purpose other than its defined construction. A future version's constructions MUST bump the version suffix and register the new tag.

- `trellis-event-v1` — canonical event hash (§9.2)
- `trellis-author-event-v1` — author event hash (§9.5)
- `trellis-content-v1` — content hash (§9.3)
- `trellis-checkpoint-v1` — checkpoint digest (§11.2)
- `trellis-export-manifest-v1` — export manifest digest (§9.7)
- `trellis-merkle-leaf-v1` — Merkle tree leaf hash (§11.3)
- `trellis-merkle-interior-v1` — Merkle interior-node hash (§11.3)
- `trellis-posture-declaration-v1` — Posture-declaration document digest referenced from custody-model and disclosure-profile Posture-transition events (§6.7 registered extensions; Companion §10)
- `trellis-transition-attestation-v1` — Posture-transition attestation signature preimage `dCBOR([transition_id, effective_at, authority_class])` per Companion A.5 `Attestation` shared rule
- `trellis-presentation-artifact-v1` — SHA-256 preimage for rendered presentation artifacts, including `PresentationArtifact.content_hash` carried by `trellis.certificate-of-completion.v1` events (ADR 0007) and WOS `SignatureAffirmationInput.presentationHash` when a signing attestation references a rendered document. Domain-separates PDF / HTML presentation bytes from event-payload, content, checkpoint, and Merkle-tree hashing.
- `trellis-user-content-attestation-v1` — Ed25519 signature preimage for `UserContentAttestationPayload.signature` carried by `trellis.user-content-attestation.v1` events (ADR 0010). Inner preimage is `dCBOR([attestation_id, attested_event_hash, attested_event_position, attestor, identity_attestation_ref, signing_intent, attested_at])`. Distinct from `trellis-transition-attestation-v1` so a wrongly-typed user-content attestation cannot cross-validate against the operator-actor posture-transition family, and vice versa.
- `trellis-wos-preledger-idempotency-v1` — SHA-256 preimage for WOS direct case-ledger creation before the case ledger exists. Inner preimage is `dCBOR({ "tenant": tenant, "idempotency_token": token })`, with `tenant` and `token` supplied by the WOS boundary operation that emits `wos.kernel.case_created`. Distinct from the custody-hook `trellis-wos-idempotency-v1` tag, whose WOS-owned input is `(caseId, recordId)`.

---

## 10. Chain Construction

**Requirement class:** Fact Producer (computes prev_hash), Canonical Append Service (enforces order), Verifier (replays chain).

### 10.1 Phase 1: strict linear chain

Phase 1 canonical order is **strict linear** per ledger scope. Events are totally ordered by `sequence`, and each event's `prev_hash` references the canonical event hash of the immediately preceding event. There is exactly one canonical order per ledger scope.

### 10.2 `prev_hash` requirements

- For `sequence == 0`: `prev_hash` MUST be `null`.
- For `sequence == N > 0`: `prev_hash` MUST equal the `canonical_event_hash` (§9.2) of the event with `sequence == N-1` in the same ledger.
- A Canonical Append Service MUST reject any submission whose `prev_hash` does not satisfy this constraint.
- A Verifier MUST verify the chain by recomputing each event's `canonical_event_hash` and checking that it appears as `prev_hash` in the next event.

### 10.3 Reserved: causal dependencies (Phase 2)

Phase 2 MAY upgrade to an HLC-ordered causal DAG. The `causal_deps` field (§6.1) reserves the wire slot. Phase 1 events MUST emit `causal_deps` as `null` or `[]`. Phase 2+ producers populating `causal_deps` emit a new `version` value; Phase 1 verifiers MUST reject events whose `causal_deps` is non-empty at `version == 1`. This reservation exists so that Phase 2 does not require a header-version break.

### 10.4 Ledger scope and partitioning

Canonical order is scoped to a declared **ledger scope** — one Formspec Response for response ledgers, one case for case ledgers, one operator for agency logs, and so on. An implementation MAY partition a logical system into multiple ledgers by scope, but MUST NOT allow competing canonical orders for the same scope. There MUST be exactly one `sequence = 0`, `sequence = 1`, …, per scope.

### 10.5 Append-only invariant

A Canonical Append Service MUST NOT rewrite a canonical event once it has been admitted. "Admitted" means: `canonical_event_hash` is computed, the append attestation is issued, and any subscribed verifier is entitled to expect byte-for-byte reproduction of the event on demand. Correction is always a new event; there is no in-place edit.

### 10.6 Append head artifact

Every successful `append` operation returns a structured **append head** describing the post-append state of the targeted ledger scope. This artifact is the structural companion to the `prev_hash` invariant (§10.2): the next event's `prev_hash` is equal to the previous append's `AppendHead.canonical_event_hash` field, by construction. Traceability: TR-CORE-083.

```cddl
AppendHead = {
  scope:                bstr,            ; ledger scope identifier, equal to the
                                         ; just-appended event's ledger_scope
  sequence:             uint,            ; sequence of the just-appended event
                                         ; (0-indexed, monotonic within scope)
  canonical_event_hash: digest,          ; canonical_event_hash of the just-appended
                                         ; event per §9.2
}
```

An `AppendHead` is serialized as dCBOR (§5.1). Its bytes are fully determined by the just-appended event's canonical form (§6.8); a verifier or a second implementation that recomputes `canonical_event_hash` for the same event and constructs the same `(scope, sequence, canonical_event_hash)` tuple will produce byte-identical `AppendHead` bytes. The artifact carries no signature: it is an integrity-derived return value, not an independent attestation. Append attestation over a range of events is the Checkpoint artifact of §11; `AppendHead` names the single-event post-append state and is the contract between `append` and its caller.

`AppendHead` does not appear in the Phase 1 export package (§18); exports carry the full event sequence plus checkpoints, from which every intermediate `AppendHead` is reproducible. It is a return-value artifact for in-process use, for API responses, and for fixture vectors that pin the expected post-append state.

---

## 11. Checkpoint Format

**Requirement class:** Canonical Append Service (issues), Verifier (validates).

### 11.1 Purpose

A **checkpoint** is a COSE_Sign1 signed tree head over the Merkle tree of canonical event hashes in a ledger scope up to some `tree_size`. The COSE payload is `CheckpointPayload`. Checkpoints enable:

- inclusion proofs (a given event hash appears at a given position),
- consistency proofs (a later tree is an append-only extension of an earlier tree),
- optional external anchoring (Phase 2+ transparency-log witnessing).

### 11.2 `Checkpoint` structure

```cddl
Checkpoint = COSESign1Bytes ; payload is dCBOR(CheckpointPayload)

CheckpointPayload = {
  version:       uint .size 1,          ; = 1 for Phase 1
  scope:         bstr,                  ; ledger scope identifier
  tree_size:     uint,                  ; count of events committed to
  tree_head_hash: digest,               ; Merkle root, §11.3
  timestamp:     timestamp,                  ; checkpoint issuance time
  anchor_ref:    bstr / null,           ; §11.5; Phase 1 optional
  prev_checkpoint_hash: digest / null,  ; previous checkpoint's digest, or null for the first
  extensions:    { * tstr => any } / null, ; §11.6; reserved for Phase 3+ heads
}
```

The checkpoint **digest** under domain tag `trellis-checkpoint-v1` is:

```
checkpoint_digest = SHA-256(
    "trellis-checkpoint-v1" domain-separated per §9.1 over
    dCBOR(CheckpointHashPreimage)
)
```

`prev_checkpoint_hash` chains checkpoints so a verifier can validate an ordered sequence without retrieving every event.

### 11.3 Merkle tree construction

The tree is RFC-6962-compatible with domain-separated leaf and interior hashes:

- **Leaf hash:** `SHA-256("trellis-merkle-leaf-v1" domain-separated per §9.1 over canonical_event_hash)`.
- **Interior hash:** `SHA-256("trellis-merkle-interior-v1" domain-separated per §9.1 over (left_hash || right_hash))`.
- **Odd-node promotion:** when a level has an odd number of nodes, the final node is carried up to the next level unchanged (RFC 6962 §2.1 semantics).

The tree is constructed over the sequence `[canonical_event_hash(0), canonical_event_hash(1), ..., canonical_event_hash(tree_size - 1)]` in canonical order.

### 11.4 Inclusion and consistency proofs

An **inclusion proof** for `canonical_event_hash` at position `leaf_index` under a checkpoint with `tree_size = N` is an audit path allowing the verifier to recompute `tree_head_hash` from the leaf. A verifier MUST recompute the root and check bitwise equality with the checkpoint's `tree_head_hash`.

A **consistency proof** between an earlier checkpoint `(m, head_m)` and a later checkpoint `(n, head_n)` where `m < n` is a proof path allowing the verifier to recompute both heads and confirm that the tree at size `n` is an append-only extension of the tree at size `m`.

Both proofs are included in exports (§18.3). A Canonical Append Service that publishes a checkpoint whose consistency proof against any prior head fails is in violation of the append-only invariant (§10.5) and MUST be treated by a verifier as a tampered source.

### 11.5 `anchor_ref` (reserved for Phase 2+ external witnessing)

`anchor_ref` is an optional opaque reference to an external witness or anchor (for example, an OpenTimestamps Bitcoin anchor, a transparency-log cosignature, an RFC 3161 TSA receipt). Phase 1 MUST accept `null`, and MUST NOT require a non-null value. Phase 1 producers MAY emit a value; Phase 1 verifiers MUST NOT fail verification solely on the absence of an anchor. Phase 4 (federation) elevates anchoring to MUST under a separate registered deployment class.

Exports that bundle anchor-proof material (for example, `bitcoin/headers.cbor` bundling Bitcoin block headers) do so under a Phase 2+ registered deployment class; Phase 1 verification MUST NOT depend on such material.

### 11.6 Head-format extension container

`CheckpointPayload.extensions` is the only Phase 1 reservation for Phase 3 case-ledger head data. Phase 1 emission and rejection rules for this container are governed by §6.7 (authoritative); in summary, Phase 1 producers MUST emit `extensions` as `null` or an empty map, and Phase 1 verifiers MUST reject unknown top-level fields in `CheckpointPayload` while preserving and ignoring unknown registered keys inside `extensions`.

Phase 3 case-ledger heads MUST embed or preserve the Phase 1 checkpoint payload unchanged. Additional head data is carried only in `extensions`, for example:

```cddl
CaseLedgerHeadExtensions = {
  ? composed_response_heads: [* digest],
  ? case_scope_metadata: CaseScope,
  ? witness_signatures: [* WitnessSignature],
}
```

The extension container is load-bearing for invariant #12: agency-log adoption is not a wire-format break for any Phase 1 checkpoint already in the field.

### 11.7 Interop sidecar derivation (non-normative)

The `CheckpointPayload` fields — `scope`, `tree_size`, `tree_head_hash`, `timestamp`, and the RFC-6962-compatible Merkle construction of §11.3–§11.4 — are intentionally shape-equivalent to a SCITT-style signed-log-statement-plus-inclusion-proof. A conforming implementation MAY emit a SCITT-receipt interop sidecar as a deterministic derivation of a checkpoint plus a target event hash; the normative discipline, registry, and Phase-1 reservation-with-lockoff rules live in [ADR 0008 — Interop Sidecar Discipline](../thoughts/adr/0008-interop-sidecar-discipline.md). Phase-1 verification is unaffected: core checkpoint verification MUST NOT depend on any interop sidecar.

---

## 12. Header Policy

**Requirement class:** Fact Producer, Canonical Append Service, Verifier.

The event header is where Trellis makes an explicit, normatively-enumerated trade-off between what is plaintext (available for routing, classification, retention) and what is a commitment to an encrypted or private value. Implementations MUST NOT move fields across this boundary without a `version` bump.

### 12.1 `EventHeader` shape

```cddl
EventHeader = {
  event_type:    bstr,                    ; registered event-type identifier (§14)
  authored_at:   timestamp,                    ; plaintext; routing, retention, audit
  retention_tier: uint .size 1,           ; 0..3; plaintext
  classification: bstr,                   ; registered classification identifier; plaintext
  outcome_commitment: digest / null,      ; §12.2; commitment, NOT plaintext outcome
  subject_ref_commitment: digest / null,  ; §12.2; commitment, NOT plaintext subject
  tag_commitment: digest / null,          ; §12.2; commitment, NOT plaintext tags
  witness_ref:   bstr / null,             ; reserved for Phase 4
  extensions:    { * tstr => any } / null, ; additive; §12.3
}
```

`event_type` and `classification` resolve against the bound registry snapshot per §14.4. The reserved test prefix `x-trellis-test/` (§14.6) exempts conformance-fixture identifiers from live registry lookup; production deployments MUST NOT admit events whose `event_type` or `classification` bear that prefix.

### 12.2 Plaintext vs. committed declaration table

The following declaration is normative. Phase 1 events MUST place each field in the named layer; Phase 1 verifiers MUST reject an event whose header places a field in the wrong layer.

| Field | Layer | Rationale |
|---|---|---|
| `event_type` | Plaintext header | Structural verification, registry lookup (§14). MUST be outcome-neutral (see §12.4). |
| `authored_at` | Plaintext header | Routing, retention computation, audit timelines. MAY be coarsened per Operational Companion. |
| `retention_tier` | Plaintext header | Required for retention enforcement without decryption. |
| `classification` | Plaintext header | Required for routing and access-decision prefiltering. MUST NOT reveal outcome. |
| `outcome_commitment` | Commitment (plaintext is in ciphertext payload) | Determinations (granted / denied / eligible / ineligible) are HIPAA / adjudication sensitive; outcome in plaintext is a metadata disclosure. Commitment allows verifiers with payload access to check; observers learn nothing. |
| `subject_ref_commitment` | Commitment | Subject identity is sensitive in most jurisdictions. Plaintext subject in the header enables passive re-identification via envelope metadata alone. |
| `tag_commitment` | Commitment | Tags like `adverse-decision`, `appeal-pending` leak outcome indirectly. |
| `witness_ref` | Plaintext header (when present) | Phase 4 external witness references are structural. |
| `extensions` | Plaintext additive | Additive header fields (§12.3); MUST NOT carry outcome or subject material. |

The commitment construction for each `*_commitment` field is:

```
commitment = SHA-256(
    "trellis-header-commitment-v1" domain-separated per §9.1 over
    dCBOR([committed_value, commitment_nonce])
)
```

where `commitment_nonce` is a fresh 16-byte random value stored inside the encrypted payload (never in the envelope). Without the nonce, low-entropy committed values (for example, boolean eligibility) are trivially recoverable by hash-candidate brute force; the nonce makes the commitment hiding against external observers while remaining verifiable by payload holders.

### 12.3 `extensions` sub-map

`EventHeader.extensions` is a map from text-string keys to arbitrary CBOR values governed by the same registration discipline as every other `*.extensions` container: see §6.7. Keys beginning with `trellis.` are reserved to this specification family; keys beginning with `x-` are vendor / deployment local. Unknown registered keys MUST be preserved by intermediaries (round-tripped) and MAY be ignored by verifiers. `extensions` MUST NOT be used to smuggle fields that belong in the committed layer (outcome, subject, sensitive tags); doing so is a trust-posture-honesty violation (§20).

### 12.4 Event-type granularity

Registered `event_type` values MUST be outcome-neutral. Concretely: `wos.determination` is registered; `wos.determination.adverse` and `wos.determination.favorable` MUST NOT be. Outcome is carried in `outcome_commitment` and the encrypted payload. Event types within the same classification SHOULD be indistinguishable by commitment count or envelope shape so that the fixed plaintext fields do not leak outcome signal.

---

## 13. Commitment Slots Reserved

**Requirement class:** Fact Producer, Verifier.

Phase 1 reserves wire-level slots for per-field cryptographic commitments that enable redaction-aware export and selective disclosure in Phase 2+. The implementation of selective disclosure (BBS+, Pedersen with range proofs, Merkle-leaf revelation) is deferred. The slots are normative now because retrofitting them requires a wire-format break, and because Phase 3 portable case files without selective disclosure force either all-or-nothing disclosure or envelope reissue.

### 13.1 `Commitment` structure

```cddl
Commitment = {
  scheme:        uint,                ; commitment scheme identifier, §13.3
  slot:          uint,                ; position in fixed-per-event-type vector
  value:         bstr,                ; scheme-defined commitment bytes
  metadata:      bstr / null,         ; scheme-defined auxiliary data
}
```

### 13.2 Fixed-position vectors

For each registered `event_type`, the event-type registry (§14) MAY declare a fixed number of commitment slots and their intended field associations. Every event of a given type MUST carry exactly that number of commitments. Unused slots MUST be filled with a scheme-defined identity value (for example, a commitment to zero with random blinding for Pedersen; an all-zeros digest for Merkle) that is indistinguishable from populated slots.

### 13.3 Scheme registry (initial)

| `scheme` | Meaning | Status |
|---|---|---|
| 0 | Reserved | Reserved |
| 1 | Merkle leaf over dCBOR-serialized field value with salt | Reserved (Phase 2+) |
| 2 | Pedersen commitment over Ristretto255 | Reserved (Phase 2+) |
| 3 | BBS+ attribute commitment | Reserved (Phase 2+) |

Phase 1 producers MUST emit `commitments` as `null` or `[]`. Phase 1 verifiers MUST accept either. Phase 2+ implementations fill the slots under the registered scheme, and Phase 2+ verifiers accept according to the registry.

### 13.4 Why slots, not implementation, in Phase 1

Fixing the scheme in Phase 1 would lock in a scheme that the selective-disclosure field is still standardizing (BBS+ draft cadence, post-quantum disclosure schemes). Fixing the slot reservation now costs nothing; fixing the scheme now risks an obsolete choice. Slot reservation makes Phase 2 additive; not reserving would make Phase 2 a break.

---

## 14. Registry Snapshot Binding

**Requirement class:** Export Generator (embeds), Verifier (resolves historical meaning).

### 14.1 The problem

Signature verification without registry binding proves **byte integrity only** — it proves the signed bytes are unmodified, but it does not prove what those bytes **meant** at signing time. A 2045 verifier looking at a 2026 event needs to know: what did `event_type = "wos.determination"` signify in 2026? What was the commitment schema for that type? What classification vocabulary was in force?

Resolving those questions against a live registry in 2045 is insufficient, because the registry may have evolved, been migrated, or ceased to exist. Resolving against the registry **snapshot** that was in force at signing time is what preserves semantic verifiability.

### 14.2 Bound registry

Every export package (§18) MUST embed the domain registry in force at signing time, content-addressed by its SHA-256 digest. The registry covers at minimum:

- event-type taxonomy: `event_type` → semantic name, commitment schema, privacy classification,
- role vocabulary: actor roles admissible under the bound WOS and Formspec versions,
- governance rules: the WOS governance ruleset identifier and its digest,
- classification vocabulary: allowed values of `header.classification`.

### 14.3 `RegistryBinding`

```cddl
RegistryBinding = {
  registry_digest: digest,             ; SHA-256 over canonical registry bytes
  registry_format: uint,               ; 1 = dCBOR; 2+ reserved
  registry_version: tstr,              ; human-readable version string
  bound_at_sequence: uint,             ; sequence in the ledger where binding took effect
}
```

An export manifest MUST contain one or more `RegistryBinding` entries. The first binding MUST cover `sequence = 0`. Subsequent bindings, if any, MUST appear in monotonic `bound_at_sequence` order and each MUST be preceded by an explicit binding event in the canonical order.

### 14.4 Verifier obligation

A verifier resolving `event_type` (or any other registry-bound field) for an event at sequence `S` MUST resolve against the binding whose `bound_at_sequence` is the largest value `≤ S`, using the embedded registry bytes, not a live lookup. A verifier that performs a live registry lookup to interpret a historical event is non-conformant.

### 14.5 Registry migration discipline

Registry changes that affect interpretation (event-type semantics, commitment layout, privacy tier) MUST emit a new `RegistryBinding` fact in the canonical ledger before events using the new interpretation are admitted. This is the same rule that governs `construction_id` migration in the prior binding draft, applied to the registry-snapshot layer here.

### 14.6 Reserved test identifiers

The text-string prefix `x-trellis-test/` is reserved across every registry-bound identifier namespace (`event_type`, `classification`, and any future Phase 1 registry-bound string field in `EventHeader`). Identifiers bearing this prefix are reserved for use by conformance fixtures (§27) and interoperability test vectors; they are not resolvable against any deployed registry binding and are not governed by §14.4's verifier-obligation to resolve against a `RegistryBinding`. Traceability: TR-CORE-073.

A fixture vector MAY use any identifier matching the pattern `x-trellis-test/<slug>` (for example, `x-trellis-test/append-minimal` as an `event_type`, or `x-trellis-test/unclassified` as a `classification`) without pinning a corresponding entry in an external registry. A verifier processing a test vector MUST accept `x-trellis-test/*` identifiers in the bound registry without live-resolution, provided the embedded registry snapshot declares them.

Production deployments MUST NOT accept events bearing `x-trellis-test/*` identifiers. A Canonical Append Service operating under a non-test deployment binding MUST reject any submission whose `event_type` or `classification` begins with `x-trellis-test/`. The `x-` prefix family remains reserved for vendor / deployment-local identifiers per §6.7; the `x-trellis-test/` sub-prefix is specifically reserved within that family for Trellis Working Group conformance fixtures.

---

## 15. Snapshot and Watermark Discipline

**Requirement class:** Derived Processor, Export Generator.

### 15.1 Core rule

Every derived artifact and every agency-log entry MUST carry a **watermark** `(tree_size, tree_head_hash)` identifying the canonical state from which it was derived, plus a deterministic **rebuild path** from the canonical chain to the derived artifact. Full-replay from `sequence = 0` is not a valid Phase 1 implementation for any system holding more than trivial quantities of case data — at case-file scale, full replay is operationally infeasible, and retrofitting snapshots invalidates every derived view already shipped.

This section owns the **core rule** (watermark + rebuild-path requirement). The **operational elaboration** — snapshot cadence, purge cascade after crypto-shredding, staleness handling, index rebuild guarantees — belongs to the Operational Companion. The core rule belongs here because the watermark is part of the canonical export and the rebuild path is part of the verification contract.

### 15.2 `Watermark`

```cddl
Watermark = {
  scope:                bstr,
  tree_size:            uint,
  tree_head_hash:       digest,
  checkpoint_ref:       digest,              ; checkpoint_digest (§11.2)
  built_at:             timestamp,           ; artifact build time
  rebuild_path:         tstr,                ; implementation-defined deterministic identifier
  ? projection_schema_id: tstr,              ; optional; projection schema version identifier
                                             ; (URI per RFC 3986 when present)
}
```

A derived artifact's `Watermark` MUST be verifiable against the canonical chain: the named `checkpoint_ref` MUST exist in the export (or be resolvable against a referenced checkpoint chain), and the chain of events up to `tree_size` under that checkpoint's `tree_head_hash` MUST verify.

The `projection_schema_id` field is REQUIRED whenever the bearer is a projection governed by Companion §14.1 (it identifies the projection schema version under which the derived artifact was built) and MUST be OMITTED for non-projection derivatives (for example, agency-log entries per §15.4). When present it MUST be a URI conforming to RFC 3986 (the `tstr` in the CDDL is a syntactic relaxation; the normative type is URI, matching Companion Appendix B.5).

### 15.3 Rebuild path

`rebuild_path` is a deterministic identifier that, combined with the canonical events up to `tree_size` and with the declared configuration history of the derived processor, allows a recipient to rebuild the derived artifact and confirm byte-for-byte equivalence. The rebuild path is not a guarantee of performance; it is a guarantee that the derived artifact is not authoritative and can be regenerated.

**Rebuild-output encoding.** Rebuilt derived artifacts MUST use dCBOR (§5) as their canonical encoding whenever the artifact shape admits CBOR serialization. Two conforming implementations that rebuild the same derived artifact from the same canonical events and configuration history MUST produce byte-equal output. Fields whose determinism depends on external state (wall-clock timestamps, per-implementation resource IDs) MUST be declared in the rebuild-path identifier as non-deterministic; byte-equality is required over the declared-deterministic portion only (Companion §15.3 OC-40).

**Phase 1 export scope.** Phase 1 exports (§18) do NOT carry Companion projection artifacts such as `Watermark` records; those are runtime state, not Phase 1 export members. Phase 1 exports MAY carry **chain-derived** catalog bytes that are fully determined by the signed event sequence and registered manifest extensions — for example the optional `061-attachments.cbor` attachment manifest bound under `ExportManifestPayload.extensions` per `trellis.export.attachments.v1` (stack ADR 0072; §18.2, §19), the optional `062-signature-affirmations.cbor` signature-affirmation catalog bound under `trellis.export.signature-affirmations.v1` (WOS Signature Profile / stack WOS-T4 closeout; §18.2), the optional `063-intake-handoffs.cbor` intake-handoff catalog bound under `trellis.export.intake-handoffs.v1` (stack ADR 0073; §18.2), the optional `066-signed-acts.cbor` verifier-facing SignedAct projection bound under `trellis.export.signed-acts.v1` (§18.2), and the optional `068-signed-acts-manifest.cbor` verdict-bound signed-acts manifest bound under `trellis.export.signed-acts.manifest.v1` (§18.2). Phase 1 WOS/Formspec exports MAY also carry `067-policy-closure.cbor` effective admission-policy evidence bound under `trellis.export.policy-closure.v1`; this member is not chain-derived, so it is limited to owner-scoped rule inputs that could change whether an act was admitted, and it MUST NOT supply verifier trust roots, verifier adapter allowlists, or server operational configuration. Such members MUST NOT introduce new authority beyond what the signed chain and declared policy evidence already attest. The intake-handoff catalog is permitted because it carries the exact Formspec handoff and canonical Response bytes needed to replay `responseHash` offline; it does not redefine the WOS decision records. The SignedAct projection is permitted because it is a deterministic view over WOS/Formspec signing evidence already present in the chain; it cannot admit a signing act that is absent from the signed source records. Core verification digest-binds registered export members; WOS catalog row and policy-closure semantics live in [`wos-trellis-verification.md`](wos-trellis-verification.md). If watermarks are later added to exports (Phase 2+), they MUST be carried inside `ExportManifestPayload.extensions` under a registered identifier (e.g., `trellis.watermarks.v1`), never as a new top-level manifest field.

### 15.4 Rule applies to agency-log entries

Phase 3 agency-log entries (§24) are themselves derived artifacts in the sense that they compose case-ledger heads with arrival metadata. They MUST carry a watermark. An agency log that cannot be rebuilt from the canonical underlying case ledgers is non-conformant — regardless of how well its own internal integrity is preserved.

---

## 16. Verification Independence Contract

**Requirement class:** Verifier, Export Generator.

### 16.1 Normative requirement

Export verification MUST NOT depend on:

- derived artifacts (projections, evaluator state, caches, indexes, timelines),
- workflow runtime state (task queues, orchestration state, session state),
- mutable service databases,
- live access to the producing service's APIs, beyond what the export package explicitly names as optional external proof material.

The verifier MUST be able to complete every obligation in §19 on an air-gapped laptop, given only the export ZIP and whatever optional external proof material (for example, a Bitcoin header bundle for OpenTimestamps anchor verification) the package names.

Core verification is byte- and envelope-oriented. It MUST NOT require knowledge
of consumer event-type namespaces, workflow lifecycle rules, jurisdictional
clock calendars, or WOS record shapes to decide Core `structure_verified` and
`integrity_verified`. Implementations MAY expose a domain-validation hook
alongside Core verification (for example, a `RecordValidator` that receives
opaque event-type strings, canonical event hashes, readable payload bytes, and
registered export-member bytes). Such validators produce consumer-owned
findings and MAY project those findings into a composed report, but they do not
expand the Core §19 obligation set.

### 16.2 No live registry lookups

A Phase 1 verifier MUST NOT perform a live registry lookup to interpret an event. Registry meaning is bound per §14 at signing time and embedded in the export per §18.

### 16.3 Optional external anchors

A package MAY reference external anchoring (transparency log URL, Bitcoin block anchor, RFC 3161 TSA receipt). Such references MUST be marked explicitly as optional external proof material in the manifest and MUST NOT be required for baseline Phase 1 verification. A Phase 1 verifier that the package's signed tree head and consistency-proof material verify MUST return "verified" even if the external anchor cannot be fetched. Phase 4 deployments MAY register a deployment class that elevates external anchoring to required; absent such a class, anchoring is additive.

**AnchorAdapter extension point (informative).** The wire shape of `ExternalAnchor` is defined in Appendix A §28; production of external anchor evidence is a per-deployment adapter concern, not a Core byte protocol. The reference center crate provides an `AnchorAdapter` trait so adopters can plug in OpenTimestamps, Sigstore Rekor, Trillian, or another anchoring substrate without changing center-crate code. The Phase-1 reference server passes `external_anchors: Vec::new()`; no runtime consumer is required. Design context lives in `thoughts/specs/2026-04-24-anchor-substrate-spike.md` (normative-adjacent until a Core/Companion ADR promotes a specific adapter contract).

### 16.4 Omitted-payload honesty

If a package omits ciphertext bytes or payload readability material (because payloads are reader-held and the verifier is not a reader, or because payloads are intentionally redacted), the package MUST still verify the structure, signatures, provenance, and append claims that are verifiable from included bytes. The verification algorithm (§19) returns `structure_verified`, `integrity_verified`, and `readability_verified` separately, plus a list of omitted payload checks. A package that silently fails — that omits both material and the declaration of omission — is non-conformant.

---

## 17. Append Idempotency Contract

**Requirement class:** Fact Producer, Canonical Append Service, Verifier.

### 17.1 Why this is wire contract, not operator convention

Every `append` call carries a stable `idempotency_key`. Without a wire-contract idempotency semantic, every operator implements dedup locally, implementations diverge exactly at the boundary where they matter (network retry at submission), and interop between a primary and a second implementation is blocked. Idempotency at the envelope layer is the only construction that survives multiple operators composing one agency log.

### 17.2 `idempotency_key`

`idempotency_key` is a byte string of 1–64 bytes. It MAY be a UUIDv7 ([RFC 9562]), a stable caller-assigned identifier, or any value chosen by the Fact Producer so long as the producer guarantees that equivalent authored submissions produce equal keys.

The structural bound `bstr .size (1..64)` (§6.1, §28) is enforced by Phase 1 producers and verifiers. An authored event whose `idempotency_key` is empty or longer than 64 bytes MUST be rejected with the structured code `idempotency_key_length_invalid` (§17.5); this is a structural-reject path orthogonal to the §17.3 retry-vs-conflict resolution.

The recommended convention is UUIDv7, because:

- it is globally unique without coordination,
- it encodes wall-time in the first bytes (useful for archival debugging),
- RFC 9562 pins its format, avoiding legacy UUIDv4 randomness variance.

Callers may substitute a deterministic hash of the authored fact's causal identity (for example, `SHA-256(session_id || field_path || proposed_value)`) if that better matches their retry semantics.

Traceability: **TR-CORE-158** (structural `bstr .size (1..64)` bound + `idempotency_key_length_invalid` rejection), **TR-CORE-161** (`idempotency_key` participates in the `AuthorEventHashPreimage` and `EventPayload` dCBOR preimages — implementations MUST parse the field and MUST NOT compute `author_event_hash` or `canonical_event_hash` against a preimage that omits it).

### 17.3 Resolution semantics

An idempotency identity is the pair `(ledger_scope, idempotency_key)`. **The identity is permanent within that ledger scope.** For a given `ledger_scope`, a specific `idempotency_key` value identifies exactly one canonical event forever; key reuse within the same ledger scope after any TTL expiry is forbidden. A Canonical Append Service MUST NOT reuse the same idempotency identity for a different authored payload after a clock interval, API TTL, dedup-store compaction, or operator lifecycle event. Retry budgets, API TTLs, and dedup-store lifecycle are operational policy and are explicitly deferred to the Trellis Operational Companion §18 (Append Idempotency (Operational)); those operator-layer concerns do not relax this Core identity rule.

**Pre-ledger genesis idempotency.** A deployment that creates a ledger and appends its genesis event in one boundary operation does not yet have an existing ledger row to consult, but it still MUST NOT rely on an HTTP deduplication cache as the source of truth. For WOS direct case-ledger creation, the pre-ledger reservation identity is `(tenant, idempotency_token)` and the event's `idempotency_key` is the 32-byte digest produced with the `trellis-wos-preledger-idempotency-v1` tag in §9.8. The Canonical Append Service MUST reserve `(tenant, idempotency_token)` durably in the same transaction or recovery unit that creates the case ledger and admits the genesis event. Successful replay of the same reservation resolves to the original genesis event; reuse with different case identity or different authored payload is a §17.3 conflict and MUST NOT create a second ledger. After the genesis event exists, normal `(ledger_scope, idempotency_key)` resolution applies to that event forever.

For a given `idempotency_key` within a declared ledger scope, a Canonical Append Service MUST resolve every successful retry to exactly one of:

1. **Same canonical reference.** The exact canonical event hash that was admitted on the first successful submission. The service returns the same `canonical_event_hash`, and the payload `content_hash` is byte-equal to the original.
2. **Declared no-op.** A successful retry against a key that was admitted but whose subsequent retry carries a payload that is byte-identical (post-dCBOR canonicalization and post-§9.4 deterministic AEAD nonce) returns a structured no-op response referencing the original canonical event hash.
3. **Reject on conflict.** A retry that shares `idempotency_key` but whose payload would produce a different `content_hash`, `author_event_hash`, or `canonical_event_hash` MUST be rejected with the structured error `IdempotencyKeyPayloadMismatch` (§17.5). This is invariant #13 of the vision document, lifted to normative text: same key, different payload means deterministic rejection, auditable.

The service MUST NOT, on retry, create a new canonical order position with a different canonical event hash under the same `idempotency_key`. Duplication at the same `idempotency_key` with a different hash is undefined canonical order.

Traceability: **TR-CORE-159** (clauses 1+2 byte-equal retry semantics — same canonical reference / declared no-op), **TR-CORE-160** (clause 3 `IdempotencyKeyPayloadMismatch` rejection + verifier-side `tamper_kind = "idempotency_key_payload_mismatch"`), **TR-CORE-162** (`(ledger_scope, idempotency_key)` scope-permanence — cross-scope reuse permitted, in-scope reuse forbidden regardless of operator policy).

### 17.4 Operational retry policy boundary

Core defines the permanent, scope-permanent idempotency identity and deterministic replay/rejection semantics. The Operational Companion §18 (Append Idempotency (Operational)) defines retry budgets, API-facing TTLs, dedup-store retention lifecycle, and how operators document storage compaction. No operational policy may cause `(ledger_scope, idempotency_key)` to accept a different payload after any expiry; operator policy may only decide how long the *accept-or-reject decision* stays fast (before falling back to a replay-from-chain lookup), never what the decision is.

Traceability: **TR-CORE-162** (operator-policy boundary — TTL, compaction, lifecycle MAY NOT relax the §17.3 scope-permanent rule).

### 17.5 Rejection codes

The following rejection codes are normative for Phase 1. Each is a structured, verifiable response, not a free-form error string.

| Code | Meaning |
|---|---|
| `IdempotencyKeyPayloadMismatch` | Same `(ledger_scope, idempotency_key)`, different payload/hash material — see §17.3. |
| `idempotency_key_length_invalid` | `idempotency_key` is empty or longer than 64 bytes (§6.1 / §17.2 `bstr .size (1..64)`). Structural reject; orthogonal to §17.3 conflict resolution. |
| `prev_hash_mismatch` | `prev_hash` does not match the predecessor's canonical event hash (§10.2). |
| `sequence_gap` | `sequence` is not `prev.sequence + 1`. |
| `unknown_suite_id` | `suite_id` is not registered (§7.2). |
| `unresolvable_kid` | COSE protected-header `kid` cannot be resolved in the active registry (§8.5). |
| `registry_digest_mismatch` | Event's bound registry does not match export manifest (§14). |
| `hash_construction_mismatch` | Event uses a hash construction not registered. |
| `missing_required_field` | Envelope is missing a required field. |
| `header_layer_violation` | A field appears in the wrong layer per §12.2. |
| `chain_break` | General category for chain-integrity failures at verification time. |

Additional codes MAY be registered in Phase 2+.

---

## 18. Export Package Layout

**Requirement class:** Export Generator (produces), Verifier (consumes).

**Substrate authority.** Per §1.5, the deterministic-ZIP byte structure — entry ordering, local-file-header rules (zero extra-field length, fixed `1980-01-01T00:00:00Z` mtime in DOS time, zero external file attributes), the central-directory ordering, CRC32 computation, and the STORED-only compression-method requirement — is owned by `integrity-stack/crates/integrity-bundle/`. The substrate crate exports `BundleEntry`, the ZIP local-file-header / central-directory writer, and the deterministic-archive assembler used by every bundle composition in the stack. The Trellis-specific concerns in §18 are the export package's required archive members (§18.2), the filename-prefix convention (`000-`, `010-`, `020-`, `030-`, `040-`, `050-`, `060-`, `061-`, `062-`, `063-`, `064-`, `066-`, `067-`, `068-`, `070-`, `090-`, `098-`, `099-`) that makes lexicographic order the required processing order, the manifest digest binding for every archive member (§18.3), the optional chain-derived catalog members (`061-attachments.cbor`, `062-signature-affirmations.cbor`, `063-intake-handoffs.cbor`, `064-supersession-graph.json`, `065-certificates-of-completion.cbor`, `066-signed-acts.cbor`, `068-signed-acts-manifest.cbor`, `open-clocks.json`), the optional WOS/Formspec effective policy-evidence member (`067-policy-closure.cbor`), the head-format version commitment (§18.7) that pins Phase-1-vs-Phase-3 forward composition, and the `verify.sh` / `README.md` orientation members. The substrate is the byte-authoritative implementation of the ZIP wire shape; this section is the byte-authoritative spec for the Trellis archive composition.

### 18.1 Deterministic ZIP

An export package is a deterministic ZIP archive. "Deterministic" means:

- entries ordered in byte-wise lexicographic order of their UTF-8 filename — this single lexicographic order IS the required processing order; there is no separate "manifest first" rule because the `000-` prefix on the manifest filename already places it first lexicographically,
- entry names are prefixed (`000-`, `010-`, `020-`, `030-`, `040-`, `050-`, `060-`, `061-`, `062-`, `063-`, `064-`, `066-`, `067-`, `068-`, `070-`, `090-`, `098-`, `099-`) so that lexicographic ordering produces the required processing order deterministically,
- compression method is **`STORED` (ZIP method 0) only** for every entry; DEFLATE is forbidden because DEFLATE output is not deterministic across libraries without fully pinning every DEFLATE parameter, and this specification refuses to open that door,
- local file headers have extra-field length zero,
- file modification time is fixed to `1980-01-01T00:00:00Z` in DOS time (the ZIP epoch minimum),
- external file attributes are zero,
- the ZIP central-directory entries are written in the same order as local-file entries (i.e., lexicographic by filename),
- no ZIP64 unless the package exceeds 4 GiB or an entry exceeds 4 GiB.

The archive name SHOULD follow the pattern `trellis-export-<scope>-<tree_size>-<short_head_hash>.zip`.

A conforming implementation can reproduce the archive layout with a `zip -X -0` style invocation over files already named with the prefixes below, provided it suppresses extra fields and normalizes timestamps and attributes as required above. Example recipe (schematic; shell-level determinism still requires suppressing the zip tool's default extended-timestamp and UID/GID attributes):

```sh
# Build a deterministic Trellis export ZIP (Fix-4 recipe)
# -X     strip extra file attributes (UID/GID, extended timestamps)
# -0     compression method STORED only
# Files already carry the 000-/010-/... prefixes so lexicographic order
# equals required processing order.
TZ=UTC find trellis-export-<scope>-<tree_size>-<shorthash>/ -type f -print0 \
  | sort -z \
  | xargs -0 touch -d "1980-01-01T00:00:00Z"
zip -X -0 trellis-export-<scope>-<tree_size>-<shorthash>.zip \
  trellis-export-<scope>-<tree_size>-<shorthash>/000-manifest.cbor \
  trellis-export-<scope>-<tree_size>-<shorthash>/010-events.cbor \
  trellis-export-<scope>-<tree_size>-<shorthash>/020-inclusion-proofs.cbor \
  trellis-export-<scope>-<tree_size>-<shorthash>/025-consistency-proofs.cbor \
  trellis-export-<scope>-<tree_size>-<shorthash>/030-signing-key-registry.cbor \
  trellis-export-<scope>-<tree_size>-<shorthash>/031-witness-key-registry.cbor \
  trellis-export-<scope>-<tree_size>-<shorthash>/040-checkpoints.cbor \
  trellis-export-<scope>-<tree_size>-<shorthash>/050-registries/... \
  trellis-export-<scope>-<tree_size>-<shorthash>/060-payloads/... \
  trellis-export-<scope>-<tree_size>-<shorthash>/061-attachments.cbor \
  trellis-export-<scope>-<tree_size>-<shorthash>/062-signature-affirmations.cbor \
  trellis-export-<scope>-<tree_size>-<shorthash>/063-intake-handoffs.cbor \
  trellis-export-<scope>-<tree_size>-<shorthash>/064-supersession-graph.json \
  trellis-export-<scope>-<tree_size>-<shorthash>/066-signed-acts.cbor \
  trellis-export-<scope>-<tree_size>-<shorthash>/067-policy-closure.cbor \
  trellis-export-<scope>-<tree_size>-<shorthash>/068-signed-acts-manifest.cbor \
  trellis-export-<scope>-<tree_size>-<shorthash>/open-clocks.json \
  trellis-export-<scope>-<tree_size>-<shorthash>/070-predecessors/... \
  trellis-export-<scope>-<tree_size>-<shorthash>/090-verify.sh \
  trellis-export-<scope>-<tree_size>-<shorthash>/098-README.md \
  trellis-export-<scope>-<tree_size>-<shorthash>/099-trellis-cli-linux-x86_64 \
  trellis-export-<scope>-<tree_size>-<shorthash>/099-trellis-cli-linux-aarch64 \
  trellis-export-<scope>-<tree_size>-<shorthash>/099-trellis-cli-darwin-arm64
```

Implementations that cannot coerce a platform `zip` into fully deterministic output MUST use a library-level ZIP writer that emits the fixed fields above directly.

### 18.2 Required archive members

```
trellis-export-<scope>-<tree_size>-<shorthash>/
  000-manifest.cbor               ; §18.3 — COSE_Sign1 over ExportManifestPayload
  010-events.cbor                 ; §18.4 — dCBOR array of Event
  020-inclusion-proofs.cbor       ; §18.5 — dCBOR map leaf_index → proof
  025-consistency-proofs.cbor     ; §18.5 — dCBOR array of consistency proofs
  030-signing-key-registry.cbor   ; §8.5 — dCBOR array of SigningKeyEntry and LedgerServiceWrapEntry
  031-witness-key-registry.cbor   ; OPTIONAL — dCBOR WitnessKeyRegistry (§8.7, §18.3d; `trellis.export.witness-key-registry.v1`)
  040-checkpoints.cbor            ; §18.6 — dCBOR array of Checkpoint
  050-registries/                 ; §14 — embedded domain-registry bytes
    <registry_digest_hex>.cbor    ; one file per distinct RegistryBinding
  060-payloads/                   ; OPTIONAL — encrypted payloads if inlined or included
    <content_hash_hex>.bin
  061-attachments.cbor            ; OPTIONAL — dCBOR array of attachment-manifest entries (chain-derived; §6.7 `trellis.export.attachments.v1`, stack ADR 0072)
  062-signature-affirmations.cbor ; OPTIONAL — dCBOR array of signature-affirmation catalog entries (chain-derived; §6.7 `trellis.export.signature-affirmations.v1`)
  063-intake-handoffs.cbor        ; OPTIONAL — dCBOR array of intake-handoff catalog entries (chain-derived; §6.7 `trellis.export.intake-handoffs.v1`, stack ADR 0073)
  064-supersession-graph.json     ; OPTIONAL — Trellis canonical JSON supersession graph (chain-derived; §6.7 `trellis.export.supersession-graph.v1`, stack ADR 0066)
  066-signed-acts.cbor            ; OPTIONAL — dCBOR SignedAct projection catalog (chain-derived; §6.7 `trellis.export.signed-acts.v1`)
  067-policy-closure.cbor         ; OPTIONAL — dCBOR effective admission-policy evidence (§6.7 `trellis.export.policy-closure.v1`, WOS/Formspec binding)
  068-signed-acts-manifest.cbor   ; OPTIONAL — dCBOR signed-acts manifest (verdict-bound; §6.7 `trellis.export.signed-acts.manifest.v1`, WOS-TV-014a/015a)
  open-clocks.json                ; OPTIONAL — Trellis canonical JSON open-clock catalog (chain-derived; §6.7 `trellis.export.open-clocks.v1`, stack ADR 0067)
  070-predecessors/               ; OPTIONAL — embedded deterministic Trellis export ZIPs named by `064-supersession-graph.json` predecessor `bundle_path` entries
  090-verify.sh                   ; §18.8 — self-contained verifier invocation
  098-README.md                   ; §18.9 — human-readable orientation
  099-trellis-cli-linux-x86_64 ; OPTIONAL — statically linked verifier CLI binary
  099-trellis-cli-linux-aarch64 ; OPTIONAL — statically linked verifier CLI binary
  099-trellis-cli-darwin-arm64 ; OPTIONAL — statically linked verifier CLI binary
  099-trellis-cli-windows-x86_64.exe ; OPTIONAL — statically linked verifier CLI binary
```

Files marked OPTIONAL may be omitted; a verifier MUST NOT fail solely on their absence.

`064-supersession-graph.json`, when present, is a Trellis canonical JSON
document so that
`ExportManifestPayload.extensions["trellis.export.supersession-graph.v1"].graph_digest`
can bind the exact bytes. Its root object has exactly two required members and
one optional member per predecessor:

```json
{
  "head_chain_id": "<lowercase hex of ChainId bytes>",
  "predecessors": [
    {
      "chain_id": "<lowercase hex of predecessor ChainId bytes>",
      "checkpoint_hash": "<lowercase hex SHA-256 digest>",
      "bundle_path": null
    }
  ]
}
```

`head_chain_id` is the chain exported by this package and MUST equal the
manifest `scope` bytes encoded as lowercase hex. Each predecessor row MUST
match one `EventPayload.extensions["trellis.supersedes-chain-id.v1"]` value
reachable from the exported head chain, with byte-equal `chain_id` and
`checkpoint_hash`. `bundle_path` is `null` when the predecessor chain is not
embedded. If a predecessor package is embedded, `bundle_path` is a relative
archive member path under `070-predecessors/` naming a deterministic Trellis
export ZIP for that predecessor chain; verifiers that do not support nested
predecessor verification MUST still verify the graph bytes and hash linkage.
Traceability: **TR-CORE-170**.

`open-clocks.json`, when present, is a Trellis canonical JSON document so that
`ExportManifestPayload.extensions["trellis.export.open-clocks.v1"].open_clocks_digest`
can bind the exact bytes. Its root object has exactly two required members:

```json
{
  "open_clocks": [
    {
      "clock_id": "statutory-review-window:case-123",
      "clock_kind": "statutory-review-window",
      "computed_deadline": [1777604800, 0],
      "origin_event_hash": "<lowercase hex SHA-256 digest>"
    }
  ],
  "sealed_at": [1777000000, 0]
}
```

`sealed_at` is the export's sealing timestamp and MUST equal
`ExportManifestPayload.generated_at`. `open_clocks` is ordered by
`origin_event_hash` bytewise ascending, then `clock_id` UTF-8 bytewise
ascending. Each row represents one admitted `clockStarted` event for which no
matching `clockResolved` event is admitted by the exported head. `clock_id` and
`clock_kind` are WOS-owned strings carried by the source clock payload;
`computed_deadline` is a Core timestamp (`[seconds, nanos]`); and
`origin_event_hash` is the lowercase hex encoding of the `clockStarted`
canonical event hash. Verifiers use this member for ADR 0067 advisory
diagnostics; the catalog is not an integrity failure merely because an open
clock is overdue at `sealed_at`.
Traceability: **TR-CORE-172**.

`031-witness-key-registry.cbor`, when present, is a dCBOR `WitnessKeyRegistry`
document. The member carries witness-key history needed to verify optional
external witness attestations without rewriting the signing-key registry used
for canonical event signatures. If the export manifest carries
`ExportManifestPayload.extensions["trellis.export.witness-key-registry.v1"]`,
the member MUST be present and its SHA-256 digest MUST match
`witness_key_registry_digest`. If the member is present without the manifest
extension, a Phase-1 verifier treats it as unbound advisory bytes and MUST NOT
use it for integrity claims.

Members under `070-predecessors/` are optional predecessor-chain export
packages. Each member MUST itself be a deterministic Trellis export ZIP
conforming to §18.1. The member path MUST be named by exactly one
`predecessors[*].bundle_path` value in `064-supersession-graph.json`; unlisted
members under `070-predecessors/` are ignored by Phase-1 verifiers unless the
operator's export policy declares strict predecessor-package completeness. When
`bundle_path` is non-null, the verifier obligation is the checkpoint hash match
in §19 step 6e.

For this member, **Trellis canonical JSON** means: UTF-8; no byte-order mark;
no insignificant whitespace outside string values; object members sorted by
Unicode code point of their property names; arrays in authored order; strings
escaped only as required by JSON; lowercase hexadecimal for byte fields; and a
single trailing `\n` byte. Numbers are not used in this JSON member. These
rules are local to `064-supersession-graph.json`; Trellis envelope bytes remain
dCBOR-authoritative.

### 18.3 `ExportManifest`

```cddl
SignedExportManifest = COSESign1Bytes ; payload is dCBOR(ExportManifestPayload)

ExportManifestPayload = {
  format:           tstr,                 ; "trellis-export/1"
  version:          uint .size 1,         ; = 1 for Phase 1
  generator:        tstr,                 ; generator identifier
  generated_at:     timestamp,              ; manifest generation time
  scope:            bstr,                 ; ledger scope
  tree_size:        uint,                 ; events covered
  head_checkpoint_digest: digest,         ; §11.2
  registry_bindings: [+ RegistryBinding], ; §14
  signing_key_registry_digest: digest,    ; SHA-256 of 030-signing-key-registry.cbor
  events_digest:    digest,               ; SHA-256 of 010-events.cbor
  checkpoints_digest: digest,             ; SHA-256 of 040-checkpoints.cbor
  inclusion_proofs_digest: digest,        ; SHA-256 of inclusion-proofs.cbor
  consistency_proofs_digest: digest,      ; SHA-256 of consistency-proofs.cbor
  payloads_inlined: bool,                 ; true if 060-payloads/ is present
  external_anchors: [* ExternalAnchor],   ; §16.3; optional (see Appendix A §28 for ExternalAnchor)
  posture_declaration: PostureDeclaration, ; §20
  head_format_version: uint,              ; §18.7; Phase 1 = 1
  omitted_payload_checks: [* OmittedPayloadCheck], ; §16.4, §19
  ? interop_sidecars: [* InteropSidecarEntry] / null, ; §18.3a; Phase-1 partial
  extensions:       { * tstr => any } / null,
}
```

The manifest binds every other archive member by digest. A verifier MUST check that every digest in the manifest matches the actual archive contents.

**Interop sidecars (§18.3a).** `interop_sidecars` is reserved under ADR 0003
lock-off discipline. The reservation is **partially active** in Phase 1:
`c2pa-manifest@v1` (Wave 25) and `did-key-view@v1` (Wave 29) dispatch to
per-entry verification (ADR 0008 §"Phase-1 verifier obligation"); the two
remaining registered kinds (`scitt-receipt`, `vc-jose-cose-event`) are still
locked off pending their per-kind triggers. Phase-1 verifiers receiving a
populated entry under either locked kind MUST fail with
`interop_sidecar_phase_1_locked`. Phase-1 verifiers receiving a populated
`c2pa-manifest@v1` or `did-key-view@v1` entry MUST run path-(b) verification:
digest-binds only, no `source_ref` resolution; failure surfaces are
`interop_sidecar_content_mismatch`,
`interop_sidecar_missing`,
`interop_sidecar_kind_unknown`,
`interop_sidecar_unlisted_file`,
`interop_sidecar_derivation_version_unknown`,
`interop_sidecar_path_invalid`. The C2PA-tooling-path
(reading the C2PA manifest assertion) is documented in ADR 0008 §"`c2pa-manifest`"
as a consumer pattern; it is NOT part of the Phase-1 core verifier (Core §16).
Traceability: **TR-CORE-145** (envelope reservation; Phase-1 lock-off
governance), **TR-CORE-163** (`interop_sidecar_content_mismatch` digest
recompute), **TR-CORE-164** (`interop_sidecar_kind_unknown` closed-registry
gate), **TR-CORE-165** (`interop_sidecar_unlisted_file` manifest-completeness
gate), **TR-CORE-166** (`interop_sidecar_derivation_version_unknown`
ISC-06 version pin), and **TR-CORE-167** (`interop_sidecar_path_invalid`
path-prefix invariant; verifier unit tests, no tamper ZIP), and
**TR-CORE-168** (`interop_sidecar_missing` listed-file presence gate).

**Supersession graph (§18.3b).** `trellis.export.supersession-graph.v1` is the
manifest extension hook for ADR 0066 cross-chain supersession. When the
extension is present, `064-supersession-graph.json` MUST be present and its
SHA-256 digest MUST equal `graph_digest`. When `064-supersession-graph.json` is
present, the extension MUST be present. An exporter SHOULD emit both the member
and extension for any export whose chain contains a
`trellis.supersedes-chain-id.v1` event extension or whose relying-party use
case requires predecessor traversal. Omission does not make the single-chain
export structurally invalid; it means the export cannot prove cross-chain
supersession completeness without external predecessor material.
Traceability: **TR-CORE-170**.

**Open statutory clocks (§18.3c).** `trellis.export.open-clocks.v1` is the
manifest extension hook for open statutory-clock export. When the extension is
present, `open-clocks.json` MUST be present and its SHA-256 digest MUST equal
`open_clocks_digest`. When `open-clocks.json` is present, the extension MUST be
present. Exporters SHOULD emit both the member and extension for any export
whose chain contains an admitted `clockStarted` event without a matching
admitted `clockResolved` event at the exported head. Omission does not make the
single-chain export structurally invalid; it means offline reviewers must
recompute open-clock state from the event stream rather than relying on the
catalog. Trellis Core verifies the member binding only. Domain validators, such
as WOS-Trellis verification, own overdue advisories and pause/resume calendar
semantics.
Traceability: **TR-CORE-172**.

**Seal fence (§18.3e).** `trellis.export.seal-fence.v1` is the manifest
extension hook for Trellis-local export identity. When present, the extension
MUST carry the `SealFenceManifestExtension` shape in Appendix A §28. The
`identity_rule` value MUST be `trellis-export-seal-fence-v1`. The
`bundle_scope` MUST equal `ExportManifestPayload.scope`; `event_count` MUST
equal `ExportManifestPayload.tree_size`; `high_water_sequence` MUST equal
`event_count - 1`; `head_checkpoint_digest` MUST equal
`ExportManifestPayload.head_checkpoint_digest`; and `events_digest` MUST equal
`ExportManifestPayload.events_digest`.

For identity rule `trellis-export-seal-fence-v1`, `export_attempt_id` MUST be
`"sha256:" || lowercase_hex(SHA-256-DS("trellis-export-attempt-v1",
dCBOR(ExportAttemptPreimage)))`, where SHA-256-DS is the Trellis
length-prefixed domain-separation construction from §9.1 and:

```cddl
ExportAttemptPreimage = {
  bundle_scope:           bstr,
  seal_version:           uint,
  high_water_sequence:    uint,
  high_water_event_hash:  digest,
}
```

`high_water_event_hash` is the canonical event hash of the last event covered
by the export. `seal_version` is a monotonic producer-owned export version for
the scope; the Phase-1 Trellis server uses `tree_size` for this value. Retrying
the same `(bundle_scope, seal_version)` MUST either produce the same
`export_attempt_id` and byte-identical export object or fail as an identity
conflict.

`policy_closure_digest` is `SHA-256(067-policy-closure.cbor)` when the export
carries `trellis.export.policy-closure.v1`. It is `null` only when the export
does not claim bundle-resident policy-closure evidence. A `null` value is not
evidence that policy was irrelevant; WOS/Formspec deployments that require
policy evidence report that posture through their domain validators.
Phase-1 verifiers that implement extension version 1 MUST reject the export
when any seal-fence field disagrees with the manifest, event stream, derived
`export_attempt_id`, or policy-closure member presence.

**Future versioning.** Verifiers of extension version 1 (today's runtime)
MAY accept an export whose manifest omits `trellis.export.seal-fence.v1` —
the absence short-circuit at
`integrity-stack/crates/integrity-verify/src/trellis/export.rs::verify_seal_fence_extension`
exists only for backwards compatibility with pre-G2 exports written at
`seal_version = 1` before the extension was registered. For any
`seal_version >= 2` (when introduced), the extension MUST be present and
verifiers MUST fail-close on absence under the registered version. The
absence short-circuit branch SHALL be removed at the first version bump.

**Signed-acts manifest (§18.3f).** `trellis.export.signed-acts.manifest.v1` is
the manifest extension hook for the substrate-anchored 068 signed-acts manifest.
When the extension is present, its `manifest_digest` field MUST equal
`SHA-256(068-signed-acts-manifest.cbor)`. The `catalog_ref` field MUST equal
the string `"068-signed-acts-manifest.cbor"`. The `derivation_rule` field MUST
equal the string `"signed-acts-manifest-v1"`; new derivation rules require a
new extension key (v2+, per WOS-TV-015a stability contract). When the extension
is present but `068-signed-acts-manifest.cbor` is absent, the verifier MUST
fail with `signed_acts_manifest_missing_member`. When
`SHA-256(068-signed-acts-manifest.cbor)` does not equal `manifest_digest`, the
verifier MUST fail with `signed_acts_manifest_extension_digest_mismatch`. When
re-derived manifest bytes do not match the member bytes, the verifier MUST fail
with `signed_acts_manifest_mismatch`. When the member is present but the
extension is absent, the verifier MUST fail with
`signed_acts_manifest_member_unbound`. All four failure kinds set
`integrity_verified = false` and `relying_party_result = invalid`.
Traceability: TR-CORE-180.

```cddl
OmittedPayloadCheck = {
  content_hash: digest,
  reason:       tstr,
}
```

### 18.4 `010-events.cbor`

A dCBOR array of `Event` COSE_Sign1 records in canonical order, starting at `sequence = 0` up to `sequence = tree_size - 1`. Concatenation and ordering are canonical; byte-match reproducibility is mandatory.

### 18.5 `inclusion-proofs.cbor` and `consistency-proofs.cbor`

- **Inclusion proofs.** A dCBOR map from `leaf_index` (uint) to `InclusionProof` under the final head. Every event in the export MUST have an inclusion proof.
- **Consistency proofs.** A dCBOR array of `ConsistencyProof` records linking each intermediate checkpoint to the next, plus a proof from the first checkpoint's head to the final head. This enables a verifier to confirm append-only growth without storing every intermediate tree.

```cddl
InclusionProof = {
  leaf_index:  uint,
  tree_size:   uint,
  leaf_hash:   digest,
  audit_path:  [* digest],
}
ConsistencyProof = {
  from_tree_size: uint,
  to_tree_size:   uint,
  proof_path:     [* digest],
}
```

### 18.6 `040-checkpoints.cbor`

A dCBOR array of all `Checkpoint` COSE_Sign1 records issued for this scope up to and including the final checkpoint of the export. Checkpoints are ordered by `tree_size` ascending. Each checkpoint payload's `prev_checkpoint_hash` MUST match the previous checkpoint's digest.

### 18.7 Head format version and superset commitment

The `head_format_version` field identifies the checkpoint / head format. Phase 1 ships version 1. Phase 3 case-ledger heads are a strict superset at a later version number: they preserve the Phase 1 `CheckpointPayload` fields unchanged and carry additional fields only in `CheckpointPayload.extensions` (§11.6). A Phase 1 verifier reading a later head format under a Phase-1-declared scope MAY return `unknown_head_format`, but it MUST NOT accept unknown top-level checkpoint fields as though they were Phase 1.

**Relationship to `CheckpointPayload.version`.** `ExportManifestPayload.head_format_version` (§18.3) and `CheckpointPayload.version` (§11.2) are distinct fields with distinct meanings. `head_format_version` names the envelope profile a verifier should apply to the head composition; `CheckpointPayload.version` is the version of the Checkpoint structure itself. In Phase 1 both values are `1`. Phase 3 will bump `head_format_version` to `2` (case-ledger head composition), while `CheckpointPayload.version` MAY remain `1` because the Checkpoint structure itself is a strict superset, not a redefinition — Phase 3 additions go in `CheckpointPayload.extensions`. A verifier MUST select its Phase behavior from `head_format_version`, not from `CheckpointPayload.version`.

This is invariant #12 lifted normatively: **agency-log adoption is not a wire-format break for any Phase 1 export already in the field.**

### 18.8 `verify.sh`

`090-verify.sh` is a POSIX shell script that invokes the verifier binary appropriate for the current platform (detected via `uname`) and exits with `0` on verification success. The script MUST NOT require network access. Its full source SHOULD be at most a few dozen lines; its authority is the verifier binary, not the script.

### 18.9 `README.md`

`098-README.md` is a human-readable orientation file. Normative only in that it MUST state: the scope, the `tree_size`, the final `tree_head_hash`, the posture declaration (§20), which payload checks were omitted offline, and the verification invocation. It SHOULD NOT describe the export as legally admissible (§20.4).

---

## 19. Verification Algorithm

**Requirement class:** Verifier.

Given an export ZIP `E`, a verifier MUST implement the following algorithm. All steps MUST run without network access. Time and memory bounds: linear in the number of events for structure and integrity, O(log N) per inclusion proof, O(log N) per consistency proof. The output separates structure, ciphertext integrity, and payload readability because exports may intentionally omit ciphertext bytes or decryption material.

**Failure classes (normative).** The algorithm distinguishes two classes of failure:

- **Fatal failures.** The verifier MUST abort immediately and return a report with `structure_verified = false`. Fatal failures are: invalid manifest structure, manifest signature invalid, archive-member digest mismatch against the manifest, signing-key-registry resolution failure for any manifest or checkpoint `kid`, and checkpoint signature invalid.
- **Localizable failures.** The verifier MUST continue, accumulate the failure in the report's per-artifact failure list, and report on a per-event or per-proof basis. Localizable failures are: individual event hash mismatches, individual event signature failures, individual payload integrity failures (including ciphertext-hash mismatches), individual inclusion-proof failures, and individual consistency-proof failures between non-head checkpoints.

The intent is that a single tampered event does not hide other tampering: localizable failures are enumerated, not short-circuited.

```text
VERIFY(E) -> VerificationReport

1. Open E as a deterministic ZIP (§18.1). If the ZIP layout is non-deterministic,
   abort with report.layout_error.

2. Read 000-manifest.cbor as SignedExportManifest. Verify its COSE_Sign1:
     a. Resolve protected-header kid via embedded 030-signing-key-registry.cbor.
        If unresolvable, abort with report.unresolvable_manifest_kid.
     b. Verify protected-header alg and suite_id are registered and consistent.
     c. Verify the RFC 9052 Sig_structure signature over the embedded manifest payload.
        A manifest with `payload = nil` is non-conformant in this verifier path.
        If invalid,
        abort with report.manifest_signature_invalid.
     d. Decode the COSE payload as ExportManifestPayload; reject unknown top-level fields.

3. Verify digests bound by the manifest:
     a. SHA-256(010-events.cbor) == manifest.events_digest
     b. SHA-256(040-checkpoints.cbor) == manifest.checkpoints_digest
     c. SHA-256(020-inclusion-proofs.cbor) == manifest.inclusion_proofs_digest
     d. SHA-256(025-consistency-proofs.cbor) == manifest.consistency_proofs_digest
     e. SHA-256(030-signing-key-registry.cbor) == manifest.signing_key_registry_digest
     f. For each RegistryBinding rb in manifest.registry_bindings:
          SHA-256(050-registries/<rb.registry_digest>.cbor) == rb.registry_digest
     f2. If manifest.extensions carries `trellis.export.witness-key-registry.v1`:
          SHA-256(031-witness-key-registry.cbor) == witness_key_registry_digest
        and the decoded registry entry count equals `entry_count`.
     g. If manifest.extensions carries `trellis.export.supersession-graph.v1`:
          SHA-256(064-supersession-graph.json) == graph_digest.
        If `064-supersession-graph.json` is present without that manifest
        extension, record `supersession_graph_unbound`.
     h. If manifest.extensions carries `trellis.export.signed-acts.manifest.v1`:
          - If `068-signed-acts-manifest.cbor` is absent from the archive,
            fail with `signed_acts_manifest_missing_member`.
          - Else: SHA-256(068-signed-acts-manifest.cbor bytes) == extension's
            `manifest_digest`; mismatch → fail with
            `signed_acts_manifest_extension_digest_mismatch`.
        If `068-signed-acts-manifest.cbor` is present without the extension,
        fail with `signed_acts_manifest_member_unbound`.
        (Re-derivation comparison — `signed_acts_manifest_mismatch` — is
        performed in the domain validator step after event processing, since it
        requires the readable event stream.)
     i. After processing all registered extension members: enumerate the
        archive's members. If any member is not bound by either the manifest
        itself (via a top-level digest field), a registered extension's
        `catalog_ref`, or the manifest's `interop_sidecars` list, fail with
        `bundle_unbound_member`. This is a Core-level structural invariant
        covering every extension; the per-extension rules above are not a
        substitute for this sweep. Traceability: TR-CORE-181.
   Any mismatch ⇒ abort with report.archive_integrity_failure.

4. For each Event COSE_Sign1 e in 010-events.cbor (in order):
     a. Resolve protected-header kid via 030-signing-key-registry.cbor.
        Check the resolved `SigningKeyEntry` lifecycle against
        `payload.header.authored_at`:
          - If `status = Revoked` and `valid_to != null` and
            `payload.header.authored_at > valid_to`, record
            `revoked_authority` in `report.event_failures` for that event
            and continue.
          - If `status = Revoked` and `valid_to = null`, treat the registry
            entry as malformed and reject the export.
        `Retired` is historical-verification-permitted (§8.4) and does not
        itself fail verification of historical events.
     b. Verify protected-header alg and suite_id, then verify the COSE Sig_structure (§7.4).
        An Event with `payload = nil` is non-conformant in this verifier path.
     c. Decode the embedded COSE payload as EventPayload; reject unknown top-level fields.
     d. Recompute author_event_hash(payload) per §9.5. Check equals payload.author_event_hash.
     e. Recompute canonical_event_hash(payload) per §9.2.
     f. Check payload.ledger_scope == manifest.scope.
     g. If payload.payload_ref is PayloadInline:
          check SHA-256(payload_ref.ciphertext) under §9.3 == payload.content_hash.
        If payload.payload_ref is PayloadExternal and 060-payloads/<content_hash>.bin exists:
          check SHA-256(file bytes) under §9.3 == payload.content_hash.
        If payload.payload_ref is PayloadExternal and bytes are absent:
          record report.omitted_payload_checks[payload.content_hash] and continue
          with the remaining structure and chain checks for this event.
     h. If payload.sequence == 0: check payload.prev_hash == null. Else check
        payload.prev_hash == canonical_event_hash(events[payload.sequence - 1]).
        Independently, verify payload.header.authored_at >= prior event's
        payload.header.authored_at (non-decreasing timestamps along chain order
        per ADR 0069 D-3). This check is unconditional — it runs even when
        prev_hash linkage fails, so both `prev_hash_break` and
        `timestamp_order_violation` can fire for the same event.
        A backwards timestamp is a `timestamp_order_violation` integrity failure
        recorded in report.event_failures; equal timestamps are permitted.
        If the readable payload is an ADR 0066 correction record
        (`correctionAuthorized` today, or `responseCorrection` when the
        Formspec producer lands), add a `CorrectionPreservationOutcome` to
        `report.correction_preservations`. This report evidence surfaces the
        target event hash, corrected field set, and any producer-supplied
        original/corrected value pairs; it is not an integrity predicate by
        itself because the upstream producer owns the correction payload shape
        (traceability: TR-CORE-174).
     i. Check payload.causal_deps is null or [] (Phase 1 strict-linear, §10.3).
     j. Resolve the RegistryBinding applicable to payload.sequence per §14.4;
        check payload.header.event_type and related fields against the bound registry.
     k. If the bound registry or WOS semantics identify payload.header.event_type
        as a rights-impacting decision event, EventPayload.extensions MUST carry
        `trellis.staff-view-decision-binding.v1`; absence is a structure failure
        for that event and MUST be recorded in report.event_failures. When
        EventPayload.extensions carries `trellis.staff-view-decision-binding.v1`,
        decode the extension payload as `StaffViewDecisionBinding` (§6.7,
        Appendix A). Check that its `watermark` validates against the §15.2
        `Watermark` shape, including `projection_schema_id` because staff views
        are projections, and that `stale_acknowledged` is a boolean. Malformed
        binding payloads are structure failures for that event and MUST be
        recorded in report.event_failures.
     l. On any failure, record in report.event_failures and continue — do NOT abort;
        the final verdict is false, but the report enumerates every failure.

5. For each Checkpoint COSE_Sign1 c in 040-checkpoints.cbor (in order):
     a. Resolve protected-header kid and verify COSE Sig_structure.
        A Checkpoint with `payload = nil` is non-conformant in this verifier path.
     b. Decode the embedded COSE payload as CheckpointPayload; reject unknown top-level fields.
     c. Recompute Merkle root over canonical_event_hash(events[0..payload.tree_size])
        per §11.3. Check bit-equal to payload.tree_head_hash.
     d. If not the first checkpoint: check payload.prev_checkpoint_hash == digest of prior c.
     e. Verify consistency proof from prior c to current c (§11.4).
   Any failure ⇒ record in report.checkpoint_failures.

6. Posture-transition state continuity. For each event e whose
   EventPayload.extensions carries `trellis.custody-model-transition.v1`
   or `trellis.disclosure-profile-transition.v1` (Posture-transition registry, §6.7):
     a. Decode the extension payload per Companion Appendix A.5.1 / A.5.2.
     b. Check `from_*` state equals the state established by the most recent
        prior transition event of the same kind in the same ledger_scope, or
        equals the deployment's initial declaration if no prior transition
        exists. Mismatch ⇒ record continuity_verified = false and append
        `state_continuity_mismatch` to the outcome's failures list.
        Otherwise record continuity_verified = true.
     c. Resolve `declaration_doc_digest` under domain tag
        `trellis-posture-declaration-v1` (§9.8):
          - If the referenced declaration is absent from the export and is
            not resolvable via a referenced manifest:
              record declaration_resolved = false; continue (not fatal under
              §16's omitted-material semantics).
          - If the referenced declaration is present but its recomputed
            digest does not equal `declaration_doc_digest`:
              record declaration_resolved = false, also set
              continuity_verified = false, and append
              `declaration_digest_mismatch` to the outcome's failures
              list. Digest mismatch is tamper evidence; the fatality
              path is the continuity_verified = false conjunct in step 9.
          - Otherwise record declaration_resolved = true.
     d. Check the required attestation count (Companion §10) and verify
        each attestation's signature under domain tag
        `trellis-transition-attestation-v1` (§9.8). Any failure ⇒
        record attestations_verified = false and append
        `attestation_insufficient` to the outcome's failures list.
        Otherwise record attestations_verified = true.
     e. Emit a PostureTransitionOutcome record (below) into
        report.posture_transitions in event order.
   Localizable failures accumulate in report.posture_transitions; they do
   not short-circuit, and their presence does not by itself fail
   structure_verified. Continuity and attestation failures surface through
   integrity_verified per step 9.

6b. Erasure-evidence processing. For each event e whose
   EventPayload.extensions carries `trellis.erasure-evidence.v1` (§6.7;
   payload shape ADR 0005 §"Wire shape" / Companion §20.6.2): the verifier
   MUST execute the **10-step erasure-evidence checklist** defined
   normatively in ADR 0005 §"Verifier obligations". The checklist is
   reproduced here as an enumeration so the prose section is self-contained;
   the ADR remains the byte-authoritative source if prose drifts.
     1. Decode the payload against the ADR 0005 CDDL. Mismatch is a
        structure failure for that event (recorded in report.event_failures).
     2. Normalize `key_class` (`"wrap"` → `"subject"`) into `norm_key_class`.
        If `kid_destroyed` resolves to exactly one row in the export's
        unified `KeyEntry` registry (Core §8.7), `norm_key_class` MUST equal
        that row's `kind` — otherwise structure failure with code
        `erasure_key_class_registry_mismatch`. Pre-`KeyEntry` interop: if
        `kid_destroyed` resolves only in the legacy flat `SigningKeyEntry`
        registry, `norm_key_class` MUST be `"signing"`. Opaque-kid path:
        if `kid_destroyed` resolves in no registry snapshot, registry-bind
        is skipped (step 8 still applies for `norm_key_class ∈ {"signing",
        "subject"}`).
     3. Validate `subject_scope` cross-field by `kind` per ADR 0005
        (per-subject / per-scope / per-tenant / deployment-wide null-pattern
        rule). Other patterns are structure failures.
     4. Check `destroyed_at` ≤ host event's `authored_at` (§6.1
        `EventHeader.authored_at`). Violation is a structure failure with
        code `erasure_destroyed_at_after_host` (Companion OC-144 / TR-OP-109).
     5. Group all decoded erasure-evidence payloads by `kid_destroyed`
        (byte-equal `bstr`). Within each group, all `destroyed_at` values
        MUST be integer-equal. Mismatch is a structure failure with code
        `erasure_destroyed_at_conflict` (Companion OC-145 / TR-OP-113).
        Distinct `evidence_id` values with identical kid + identical
        `destroyed_at` are allowed (retry / completion-mode update).
     6. Check `hsm_receipt` / `hsm_receipt_kind` null-consistency (both null
        or both non-null). Mismatch is a structure failure.
     7. Verify every `attestations[*].signature` under domain tag
        `trellis-transition-attestation-v1` (§9.8) — same domain shared
        with §A.5 posture-transition attestations. Invalid signature
        flips `integrity_verified = false` for the report (parallel to
        step 6.d for posture transitions).
     8. **Chain consistency for the destroyed kid (Phase-1 scope:
        `norm_key_class ∈ {"signing", "subject"}` after step-2
        normalization).** Within each `kid_destroyed` group, all payloads
        MUST agree on `key_class` after normalization (mismatch is
        structure failure `erasure_key_class_payload_conflict`). Let
        `destroyed_at` be the single agreed value from step 5. For every
        canonical event in the chain whose `authored_at > destroyed_at`:
          - if its COSE_Sign1 protected-header `kid` equals
            `kid_destroyed`, mark `post_erasure_use` (localizable failure;
            integrity_verified = false per step 9);
          - if its `key_bag.entries` contains an entry wrapped under
            `kid_destroyed`, mark `post_erasure_wrap` (localizable failure;
            integrity_verified = false per step 9).
        For `norm_key_class ∈ {"recovery", "scope", "tenant-root", tstr}`
        the Phase-1 reference verifier does NOT apply these two checks;
        subtree obligations co-land with ADR 0006 follow-on milestones.
     9. **Cascade-scope cross-check (Phase-1 best-effort).** For each
        declared `CascadeScope`, if the export bundle contains derived
        artifacts corresponding to that scope, check those artifacts do
        NOT decode the destroyed key's material. Detection is best-effort
        in Phase-1 (the deep lint rides O-3 evolution); the verifier MAY
        emit a warning when it cannot perform the check for a given scope.
        Cascade violations surface as warnings, not as
        `integrity_verified = false`, in Phase 1 (folding deferred to a
        Phase-2 follow-on).
    10. Accumulate outcomes into a new `report.erasure_evidence` array
        parallel to `report.posture_transitions`. Each entry carries
        `evidence_id`, `kid_destroyed`, `destroyed_at`, `cascade_scopes`,
        `completion_mode`, `signature_verified`, `post_erasure_uses`
        (count), `post_erasure_wraps` (count), `cascade_violations` (array
        of scope + artifact refs), `failures` (array of localizable
        failure codes).

   `integrity_verified = false` if any erasure-evidence entry has
   `signature_verified = false`, `post_erasure_uses > 0`, or
   `post_erasure_wraps > 0`, or if steps 1–6 produced a structure failure
   for any erasure payload (CDDL decode, `erasure_key_class_registry_mismatch`,
   `erasure_key_class_payload_conflict`, subject-scope shape,
   `erasure_destroyed_at_after_host`, `erasure_destroyed_at_conflict`,
   HSM-receipt null-consistency). Cascade violations surface as warnings
   per step 9.

   **Optional manifest catalog (`trellis.export.erasure-evidence.v1`).**
   When an export contains erasure-evidence events, the manifest MAY
   include the catalog extension shaped per ADR 0005 §"Export manifest
   catalog" (binding `064-erasure-evidence.cbor`). Verifier obligations
   for the optional catalog mirror the §6.7 catalog pattern (Attachment /
   Signature-Affirmation / Intake-Handoff): verify `catalog_digest` against
   the recomputed SHA-256 of `064-erasure-evidence.cbor`; for each catalog
   entry require field-wise agreement with exactly one in-chain
   erasure-evidence event; reject duplicates by `(canonical_event_hash)`.
   Mismatch is a localizable failure with code
   `erasure_evidence_catalog_digest_mismatch`. The catalog is performance
   convenience for auditor UX; exporters who omit it are conformant.

6c. Certificate-of-completion processing. For each event e whose
   EventPayload.extensions carries `trellis.certificate-of-completion.v1`
   (§6.7; payload shape ADR 0007 §"Wire shape"): the verifier MUST execute
   the **8-step certificate-of-completion checklist** defined normatively
   in ADR 0007 §"Verifier obligations". The checklist is reproduced here
   as an enumeration so the prose section is self-contained; the ADR
   remains the byte-authoritative source if prose drifts.
     1. Decode the payload against the ADR 0007 CDDL. Mismatch is a
        structure failure for that event (recorded in report.event_failures).
     2. Validate the chain-summary invariants:
        `signer_count == len(signing_events)`,
        `len(signer_display) == len(signing_events)`, and each
        `signer_display[i].principal_ref` equals the principal on
        `signing_events[i]`. Any mismatch flips
        `integrity_verified = false` with localizable failure
        `certificate_chain_summary_mismatch`. If `covered_claims` is
        non-empty, every tag MUST be in the verifier's supported tag
        registry for this release; unknown tags flip
        `integrity_verified = false` with `certificate_covered_claim_unknown`.
        For `workflow_status` and `impact_level`, any string value not
        among the CDDL-enumerated literals MUST appear in the
        Companion / WOS append-only registry; otherwise flip
        `integrity_verified = false` with
        `certificate_enum_extension_unknown`. After decoding all
        certificate events in scope, if the same `certificate_id` labels
        two events whose canonical certificate payloads differ, flip
        `integrity_verified = false` with `certificate_id_collision`
        (fail-closed; first-seen wins is non-normative).

        **Supported registries.** The registries referenced above are
        normatively empty. The CDDL `tstr` escapes on `workflow_status`,
        `impact_level`, and the `covered_claims` array exist for
        forward-compatibility — the wire admits the slot — but the
        runtime rejects:

        | Registry | Contents | Verifier behavior |
        |---|---|---|
        | `covered_claims` supported tags | `{ }` (empty) | Any non-empty `covered_claims` value flips `certificate_covered_claim_unknown`. |
        | `workflow_status` extension strings (registered extensions to the CDDL literals `"completed"` / `"countersigned"` / `"notarized"` / `"partially-completed"`) | `{ }` (empty) | Any `workflow_status` value not equal to one of the four CDDL literals flips `certificate_enum_extension_unknown`. |
        | `impact_level` extension strings (registered extensions to the CDDL literals `"low"` / `"moderate"` / `"high"` plus `null`) | `{ }` (empty) | Any non-null `impact_level` value not equal to one of the three CDDL literals flips `certificate_enum_extension_unknown`. |

        New registry entries land via Companion / WOS append-only
        registry amendments accompanied by a matrix-row update that
        promotes the corresponding TR-CORE-147 verification surface to
        cover the extension. Verifiers MUST NOT admit extension strings
        before such a registry amendment lands.
     3. Verify every `attestations[*].signature` under domain tag
        `trellis-transition-attestation-v1` (§9.8) — same domain shared
        with §A.5 posture-transition attestations and ADR 0005 erasure
        evidence. Invalid signature flips `integrity_verified = false`
        with `attestation_insufficient` (existing code reused).
     4. Resolve `presentation_artifact.attachment_id` via the ADR 0072
        attachment-binding lineage. A conformant export that includes
        this certificate event MUST ship resolvable attachment bytes
        for that id; if resolution fails (bytes missing from the
        bundle though the binding requires them), record
        `attachment_resolved = false` and append
        `presentation_artifact_attachment_missing` to the outcome's
        failures list — distinct from a successful resolve followed by
        hash mismatch. After bytes are resolved, recompute SHA-256 over
        the artifact bytes under domain tag
        `trellis-presentation-artifact-v1` (§9.8) and confirm it equals
        `presentation_artifact.content_hash`; mismatch flips
        `integrity_verified = false` with
        `presentation_artifact_content_mismatch`.
     5. Resolve every `signing_events[i]` digest against the chain.
        Each MUST be a chain-present signing/provenance event whose
        readable payload is available to the verifier. Missing events or
        unreadable signing-event payloads flip `integrity_verified = false`
        with `signing_event_unresolved`. Consumer validators own any
        event-type-specific assertion for the signing event.
     6. Validate temporal consistency: every
        `signer_display[i].signed_at` MUST exactly equal the resolved
        `SignatureAffirmation` header's `authored_at` for
        `signing_events[i]` (timestamp exact equality, no skew
        slack). Mismatch flips `integrity_verified = false` with
        `signing_event_timestamp_mismatch`.
     7. Validate `chain_summary.response_ref` when non-null: it MUST
        equal the Formspec canonical-response-hash carried on the linked
        `SignatureAffirmation` payload / `authoredSignatures` binding
        for that ceremony — one digest, not an unconstrained search
        across authoring events. Mismatch flips
        `integrity_verified = false` with `response_ref_mismatch`.
     8. Accumulate outcomes into a new
        `report.certificates_of_completion` array parallel to
        `report.posture_transitions` and `report.erasure_evidence`.
        Each entry carries `certificate_id`, `completed_at`,
        `signer_count`, `attachment_resolved`,
        `all_signing_events_resolved`, `chain_summary_consistent`,
        `failures` (array of localizable failure codes).

   `integrity_verified = false` if any certificate-of-completion entry
   has `chain_summary_consistent = false`, `attachment_resolved = false`,
   any unresolved or wrong-type signing event, any attestation failure
   from step 3, or any step 6–7 failure. Rendering-drift checks
   (re-rendering from `template_id` + chain data) are NOT required;
   adopters that want stronger binding publish `template_id` +
   `template_hash` and rebuild at verification time as a stretch check.

   **Optional manifest catalog (`trellis.export.certificates-of-completion.v1`).**
   When an export contains certificate-of-completion events, the
   manifest MAY include the catalog extension shaped per ADR 0007
   §"Export manifest catalog" (binding `065-certificates-of-completion.cbor`).
   Verifier obligations for the optional catalog mirror the §6.7
   catalog pattern (Attachment / Signature-Affirmation / Intake-Handoff /
   Erasure-Evidence): verify `catalog_digest` against the recomputed
   bare SHA-256 of `065-certificates-of-completion.cbor` (no domain tag,
   matching the four sibling catalogs); for each catalog entry require
   field-wise agreement with exactly one in-chain certificate-of-completion
   event; reject duplicates by `canonical_event_hash`. Mismatch is a
   localizable failure with code `certificate_catalog_digest_mismatch`.
   The catalog is performance convenience for auditor UX; exporters
   who omit it are conformant.

   Traceability: **TR-CORE-146** (registered extension + domain tag),
   **TR-CORE-147** (chain-summary invariants + covered_claims registry +
   workflow_status / impact_level enum extension + certificate_id
   collision), **TR-CORE-148** (presentation_artifact attachment lineage
   + content-hash recompute), **TR-CORE-149** (signing_events resolution
   + signed_at timestamp equivalence), **TR-CORE-150** (response_ref
   canonical-response-hash equivalence), **TR-CORE-151** (optional
   `trellis.export.certificates-of-completion.v1` manifest catalog),
   **TR-CORE-175** (malformed signed-payload-digest fail-closed:
   when the linked SignatureAffirmation declares `sha-256` but
   `signedPayloadDigest` is present and unparseable, surface
   `malformed_response_digest` rather than silently skipping the
   step-7 equivalence check), **TR-CORE-176** (alias-fallback
   absence-only narrowing: WOS/Formspec record readers that admit a
   preferred field name with a legacy alias — e.g.
   `data.sourceResponseRef` / `data.formspecResponseRef` — MUST take the
   legacy fallback only when the preferred key is genuinely absent; a
   present-but-malformed preferred value MUST surface a parse failure
   rather than silently shadowing under the legacy alias).

6d. User-content-attestation processing. For each event e whose
   EventPayload.extensions carries `trellis.user-content-attestation.v1`
   (§6.7; payload shape `UserContentAttestationPayload` in §28): the
   verifier MUST execute the **9-step user-content-attestation checklist**
   defined normatively in ADR 0010 §"Verifier obligations". The checklist
   is reproduced here as an enumeration so the prose section is
   self-contained; the ADR remains the byte-authoritative source if prose
   drifts.
     1. Decode the payload against the §28 CDDL. Mismatch is a structure
        failure for that event (recorded in report.event_failures).
     2. Validate intra-payload invariants:
        `attested_at == envelope.authored_at` (timestamp exact equality, no
        skew slack); `signing_intent` is a syntactically valid URI per
        RFC 3986. Each failure flips `integrity_verified = false` with
        localizable failure `user_content_attestation_timestamp_mismatch`
        / `user_content_attestation_intent_malformed`.
     3. Resolve `attested_event_position` to a chain-present event in
        the same `ledger_scope` and confirm its `canonical_event_hash`
        equals `attested_event_hash`. Position-without-hash or
        hash-without-position attestations are rejected; both fields
        are normative and disagreement flips `integrity_verified = false`
        with `user_content_attestation_chain_position_mismatch`.
     4. Resolve `identity_attestation_ref`:
          - If null: confirm the Posture Declaration in force at
            `attested_at` declares
            `admit_unverified_user_attestations: true`. Otherwise flip
            `integrity_verified = false` with
            `user_content_attestation_identity_required`. Default
            posture is REQUIRED non-null.
          - If non-null: resolve to a chain-present event of a
            registered identity-attestation event type. Core conformance
            fixtures may continue using
            `x-trellis-test/identity-attestation/v1` under §14.6. The WOS
            composed verifier admits the canonical WOS identity-attestation
            event type `wos.assurance.identity_attestation` (§23.4) through the
            consumer-owned validation seam, not through Trellis center logic.
            Confirm its `ledger_scope` matches; confirm its
            `sequence < attested_event_position` (identity proof
            temporally precedes the attestation); confirm its payload
            subject equals `attestor`. Failure flips
            `integrity_verified = false` with
            `user_content_attestation_identity_unresolved` (no resolve)
            / `user_content_attestation_identity_subject_mismatch`
            (resolved but wrong subject) /
            `user_content_attestation_identity_temporal_inversion`
            (sequence not strictly prior).
     5. Verify `signature` over
        `dCBOR([attestation_id, attested_event_hash, attested_event_position, attestor, identity_attestation_ref, signing_intent, attested_at])`
        under domain tag `trellis-user-content-attestation-v1` (§9.8),
        using the public key resolved from `signing_kid`. Failure flips
        `integrity_verified = false` with
        `user_content_attestation_signature_invalid`.
     6. Validate key state at `attested_at`: the §8 KeyEntry for
        `signing_kid` MUST be class `signing` and lifecycle state
        `Active`, or `Rotating` inside the §8.4 rotation-grace overlap
        (`valid_from <= attested_at <= valid_to`; `valid_to = null`
        means the overlap is still open in the embedded snapshot). Wrong
        class or wrong state flips `integrity_verified = false` with
        `user_content_attestation_key_not_active`.
     7. Detect collision: after decoding all user-content-attestation
        events in scope, two events sharing `attestation_id` with
        disagreeing canonical payload flip
        `integrity_verified = false` with
        `user_content_attestation_id_collision` (fail-closed; first-seen
        wins is non-normative).
     8. Forbid operator-as-attestor: when `attestor` resolves to a
        principal class registered as `operator` (Companion §6.4), flip
        `integrity_verified = false` with
        `user_content_attestation_operator_in_user_slot`. Operator
        attestations belong in §A.5's `Attestation` shape under domain
        tag `trellis-transition-attestation-v1`, not in this primitive.
     9. Accumulate outcomes into a new
        `report.user_content_attestations` array parallel to
        `report.posture_transitions` / `report.erasure_evidence` /
        `report.certificates_of_completion`. Each entry carries
        `attestation_id`, `attested_event_hash`, `attestor`,
        `signing_intent`, `chain_position_resolved`, `identity_resolved`,
        `signature_verified`, `key_active`, `failures` (array of
        localizable failure codes).

   `integrity_verified = false` if any user-content-attestation entry
   has `chain_position_resolved = false`, `identity_resolved = false`
   (when required), `signature_verified = false`, `key_active = false`,
   or any step 7–8 failure.

   Traceability: **TR-CORE-152** (registered extension + domain tag +
   wire shape), **TR-CORE-153** (chain-position binding), **TR-CORE-154**
   (identity-attestation resolution + temporal precedence), **TR-CORE-155**
   (signature verification under
   `trellis-user-content-attestation-v1`), **TR-CORE-156** (key-state
   check at `attested_at`), **TR-CORE-157** (collision detection +
   operator-in-user-slot enforcement).

**Attachment manifest (optional, stack ADR 0072).** If `ExportManifestPayload.extensions` carries `trellis.export.attachments.v1` (§6.7), the verifier MUST:

     a. Require the archive member `061-attachments.cbor` (§18.2).
     b. Verify `SHA-256(061-attachments.cbor)` equals `attachment_manifest_digest` in the extension payload and apply `inline_attachments` per ADR 0072.
     c. For each manifest row: resolve `binding_event_hash` to exactly one exported event whose `EventPayload.extensions` carries `trellis.evidence-attachment-binding.v1`; require field-wise agreement between the row and that extension; require `payload_content_hash` equals the event's `EventPayload.content_hash`.
     d. When `inline_attachments = true`, require each referenced ciphertext file `060-payloads/<payload_content_hash>.bin` to exist and to satisfy the ciphertext-hash rule in step 4.g.
     e. For each non-null `prior_binding_hash`, require it resolve to a strict prior event in `010-events.cbor` order (array index strictly less than the binding event's index). Forward references and cycles in the binding-lineage graph MUST be recorded as localizable failures in `report.event_failures`.

**Domain validator extension members.** `trellis.export.signature-affirmations.v1`,
`trellis.export.signed-acts.v1`, `trellis.export.policy-closure.v1`, and
`trellis.export.intake-handoffs.v1`
are registered Phase-1 export extensions (§6.7). Trellis Core verifies their
manifest-level extension encoding and rejects unknown registered identifiers
according to the versioned extension rule, but it does not interpret WOS
event-type literals, WOS record shapes, or WOS/Formspec SignedAct projection
or policy-closure semantics. WOS deployments compose Core verification with the WOS-Trellis
validator specified in [`wos-trellis-verification.md`](wos-trellis-verification.md).

**Supersession graph (optional, stack ADR 0066, step 6e).** If `ExportManifestPayload.extensions` carries `trellis.export.supersession-graph.v1` (§6.7), the verifier MUST:

     a. Require the archive member `064-supersession-graph.json` (§18.2).
     b. Verify `SHA-256(064-supersession-graph.json)` equals `graph_digest`
        in the extension payload map.
     c. Decode `064-supersession-graph.json` as Trellis canonical JSON with
        the shape in §18.2. Non-canonical JSON or a malformed graph is an
        integrity failure `supersession_graph_invalid`.
     d. Check `head_chain_id` equals `manifest.scope` encoded as lowercase
        hex. Mismatch is `supersession_graph_head_mismatch`.
     e. For every exported event carrying
        `EventPayload.extensions["trellis.supersedes-chain-id.v1"]`, require a
        predecessor row with byte-equal `chain_id` and `checkpoint_hash`.
        Missing or mismatched rows are
        `supersession_graph_linkage_mismatch`.
     f. Walk `predecessors` breadth-first by `chain_id`. A repeated `chain_id`
        on one traversal path is a cycle and MUST fail with
        `supersession_graph_cycle`.
     g. If a predecessor row has non-null `bundle_path`, verify that member as
        a deterministic Trellis export package and require its head checkpoint
        digest to equal the row's `checkpoint_hash`. If the member is absent or
        the digest mismatches, record
        `supersession_predecessor_checkpoint_mismatch`.

7. For each inclusion proof ip in 020-inclusion-proofs.cbor:
     a. Recompute Merkle root per ip.audit_path, ip.leaf_hash, ip.leaf_index.
     b. Check it matches the head checkpoint's tree_head_hash.
   Any failure ⇒ record in report.proof_failures.

8. If posture declaration indicates external anchoring:
     - IF the required external material is present: verify per §16.3.
     - IF external material is declared optional: skip without failure.
     - IF required but missing: record report.anchor_unresolved (NOT a verification failure
       under Phase 1, see §16.3, unless the posture declaration itself
       claims external anchoring is required).

9. Compute:
     structure_verified =
       manifest signature valid AND every COSE/CBOR/CDDL structure decoded and signed
       AND no unknown top-level Phase 1 fields were accepted.

     integrity_verified =
       archive digests valid AND event hashes, prev_hash links, checkpoint roots,
       inclusion proofs, consistency proofs, and every available ciphertext hash valid
       AND report.omitted_payload_checks is empty
       AND no entry in report.posture_transitions has continuity_verified = false
       AND no entry in report.posture_transitions has attestations_verified = false
       AND no entry in report.erasure_evidence has signature_verified = false,
           post_erasure_uses > 0, or post_erasure_wraps > 0
       AND no entry in report.certificates_of_completion has chain_summary_consistent = false,
           attachment_resolved = false, or all_signing_events_resolved = false.

     readability_verified =
       every payload required by the export scope was decrypted and schema-validated
       under the bound registry and upstream Formspec/WOS semantics.

10. Return report with structure_verified, integrity_verified,
    readability_verified, failures, warnings, and omitted_payload_checks.
```

Implementations record attachment-manifest failures (the optional ADR 0072 step above), erasure-evidence catalog failures (the optional `trellis.export.erasure-evidence.v1` step above per ADR 0005), and certificate-of-completion catalog failures (the optional `trellis.export.certificates-of-completion.v1` step above per ADR 0007) in `report.event_failures` together with per-event failures from step 4; all such Core kinds MUST force `integrity_verified = false` under the step-9 definition whenever `report.event_failures` is non-empty. Domain validators may add parallel findings or project domain failures into a composed report, but those findings are specified outside Trellis Core.

The verifier's output is a structured report enumerating every integrity observation. The overall convenience boolean MAY be computed as all three booleans true, but implementations MUST expose the three booleans independently. A package that omits ciphertext bytes can still be structurally verified, but it cannot claim payload integrity or readability were verified offline for the omitted payloads.

Domain validators MAY wrap this Core report in a layered report with a
domain-specific findings surface and a relying-party verdict. That composed
surface MUST keep the Core report available unchanged as the substrate report.
The relying-party verdict is not a new source of authority; it is a projection
over substrate booleans plus domain findings for non-specialist readers. For
example, a WOS verifier can report `cryptographic_integrity = pass` while
`projection_integrity = fail` when `066-signed-acts.cbor` is manifest-bound but
does not byte-equal deterministic re-derivation.

```cddl
VerificationReport = {
  structure_verified:         bool,
  integrity_verified:         bool,
  readability_verified:       bool,
  event_failures:             [* VerificationFailure],
  checkpoint_failures:        [* VerificationFailure],
  proof_failures:             [* VerificationFailure],
  posture_transitions:        [* PostureTransitionOutcome],
  erasure_evidence:           [* ErasureEvidenceOutcome],
  certificates_of_completion: [* CertificateOfCompletionOutcome],
  correction_preservations:   [* CorrectionPreservationOutcome],
  omitted_payload_checks:     [* OmittedPayloadCheck],
  warnings:                   [* tstr],
}

ErasureEvidenceOutcome = {
  evidence_id:           tstr,   ; from the erasure-evidence event payload
  event_index:           uint,   ; position in the events array
  kid_destroyed:         bstr,
  destroyed_at:          timestamp,
  cascade_scopes:        [* tstr],
  completion_mode:       tstr,
  signature_verified:    bool,
  post_erasure_uses:     uint,
  post_erasure_wraps:    uint,
  cascade_violations:    [* tstr],
  failures:              [* tstr],
}

CertificateOfCompletionOutcome = {
  certificate_id:                tstr,   ; from the certificate event payload
  event_index:                   uint,   ; position in the events array
  completed_at:                  timestamp,
  signer_count:                  uint,
  attachment_resolved:           bool,
  all_signing_events_resolved:   bool,
  chain_summary_consistent:      bool,
  failures:                      [* tstr],
}

CorrectionPreservationOutcome = {
  event_index:             uint,       ; position in the events array
  correction_event_hash:   digest,     ; canonical_event_hash of the correction record
  target_event_hash:       tstr / null,
  corrected_field_set:     [* tstr],   ; JSON Pointer strings when producer supplies them
  field_values:            [* CorrectionFieldValue],
}

CorrectionFieldValue = {
  field_path:              tstr,       ; JSON Pointer string
  original_value_cbor:     bstr,       ; canonical CBOR value bytes
  corrected_value_cbor:    bstr,       ; canonical CBOR value bytes
}

VerificationFailure = {
  location: tstr,
  code:     tstr,
  detail:   tstr,
}

PostureTransitionOutcome = {
  transition_id:           tstr,   ; from the Posture-transition event payload
  kind:                    tstr,   ; Posture-transition kind: "custody-model" or "disclosure-profile"
  event_index:             uint,   ; position in the events array
  from_state:              tstr,
  to_state:                tstr,
  continuity_verified:     bool,   ; from_state matched prior-transition or initial-declaration state
  declaration_resolved:    bool,   ; declaration_doc_digest resolved to a present declaration
  attestations_verified:   bool,   ; required attestations present + signatures valid
  failures:                [* tstr], ; localized failure codes (continuity_mismatch, declaration_unresolved, attestation_insufficient, ...)
}
```

`declaration_resolved = false` on its own (declaration absent) does not fail `integrity_verified`; it is the honest reporting of omitted material. However, a declaration that IS present in the export but whose recomputed digest does not equal `declaration_doc_digest` is tamper evidence: step 6.c sets both `declaration_resolved = false` AND `continuity_verified = false` in that case, and the latter fails `integrity_verified` via the step-9 conjunction. Callers MAY tighten the absent-declaration case via posture-declaration honesty (§20).

### 19.1 Tamper evidence

When any verification boolean is false, the report identifies specifically **which** canonical bytes or payload checks do not reconcile. This is the "difficult and obvious" property: tampering that rewrites history after an export has been published is detectable by any verifier holding a prior export copy, because the tampered re-export's head will not be a consistent extension of the prior export's head (§11.4). The verifier does not require the tampering party to self-report; consistency-proof failure is the signal.

When a verifier reports a localizable or fatal failure to a human auditor or to a fixture-runner, it MUST classify the dominant failure under one of the values in the **`tamper_kind` enum** below. The enum names the §19 step where the failure was detected (per the "Failure classes" prose) and the surface that mismatched. Implementations MAY expose `tamper_kind` as a top-level field on `VerificationReport` (parallel to the three booleans) projecting the dominant `event_failures[].code`, `checkpoint_failures[].code`, or `proof_failures[].code`; conformance fixtures pin the value in `[expected.report].tamper_kind` (§27).

The table below is the Core-owned enum. Domain validator specifications MAY
register additional fixture `tamper_kind` values for composed reports without
making those values Core verifier obligations. The WOS-owned additions are
defined in [`wos-trellis-verification.md`](wos-trellis-verification.md).
Historical matrix rows TR-CORE-171 and TR-CORE-173 have been superseded by
WOS-TV-002 and WOS-TV-003 respectively; they remain named here only so existing
fixtures can migrate without implying a Core verifier dependency on WOS event
semantics.

| `tamper_kind` | §19 step | Surface that mismatched |
|---|---|---|
| `signature_invalid` | 4.b | COSE_Sign1 signature does not verify under the kid's pubkey. |
| `hash_mismatch` | 4.d / 4.e | `author_event_hash` or `canonical_event_hash` recomputation disagrees with the recorded value. |
| `prev_hash_break` | 4.h | Event's `prev_hash` does not equal the prior event's recomputed `canonical_event_hash`. |
| `event_truncation` | 4.h | A middle event of a chain is absent; subsequent `prev_hash` values do not link. |
| `event_reorder` | 4.h | Adjacent events swapped; later event's `prev_hash` no longer matches the now-earlier event. |
| `timestamp_order_violation` | 4.h (temporal) | A chain event's `authored_at` is strictly less than its predecessor's `authored_at` (ADR 0069 D-3). Hash chain and signatures are valid; only temporal order fails. |
| `legacy_timestamp_format` | 4.c (payload decode) | A timestamp field is encoded as bare `uint` instead of the required `[uint, uint .le 999999999]` array (ADR 0069 D-2.1). The verifier cannot extract the field; decode-time structural rejection. |
| `timestamp_nanos_out_of_range` | 4.c (payload decode) | A timestamp field uses the required `[seconds, nanos]` array shape but the `nanos` component exceeds `999999999` (ADR 0069 D-2.1 / Core §28 CDDL). The verifier cannot construct the timestamp; decode-time structural rejection. |
| `head_checkpoint_digest_mismatch` | 5.c / 7.b | Head checkpoint missing or its recomputed digest does not match the manifest. |
| `malformed_cose` | 4.c | COSE_Sign1 envelope is structurally invalid (wrong tag, wrong array shape, wrong protected-header type). |
| `scope_mismatch` | 4.f | `EventPayload.ledger_scope` does not equal `manifest.scope`. |
| `registry_digest_mismatch` | 3.f | A `RegistryBinding`'s `registry_digest` does not equal the SHA-256 of the corresponding `050-registries/<digest>.cbor` file. |
| `state_continuity_mismatch` | 6.b | Posture-transition event's `from_*` state does not match the most-recent prior transition's `to_*` state (or initial declaration). |
| `attestation_insufficient` | 6.d | Posture-transition event fails Companion §10 attestation-count, or an attestation signature does not verify. |
| `posture_declaration_digest_mismatch` | 6.c | Posture-declaration document is present but its recomputed digest does not equal the event's `declaration_doc_digest`. |
| `attachment_manifest_digest_mismatch` | 3.f / extensions check | `061-attachments.cbor` digest does not match the manifest's `trellis.export.attachments.v1` binding (ADR 0072). |
| `key_class_mismatch` | 4.a (key-class dispatch) | A COSE_Sign1 protected-header `kid` resolves to a `KeyEntry` whose `kind` is a reserved non-signing class (`tenant-root`, `scope`, `subject`, `recovery`, `witness`); only `signing`-class kids may sign canonical events (Core §8.7.3 step 4 / ADR 0006). |
| `key_entry_attributes_shape_mismatch` | 3 (registry decode) | A `KeyEntry` whose `kind` is a reserved non-signing class is missing its `attributes` map or carries an `attributes` value whose shape does not match the per-class CDDL group in Core §8.7.2. |
| `idempotency_key_length_invalid` | 1 / 4.c | An event's `EventPayload.idempotency_key` is missing, not a CBOR byte string, empty, or longer than 64 bytes — violates the `bstr .size (1..64)` structural bound (Core §6.1 / §17.2 / §28). |
| `idempotency_key_payload_mismatch` | 4.h (per-event-set) | Two events in scope share `(ledger_scope, idempotency_key)` but their canonical material disagrees on `content_hash`, `author_event_hash`, or `canonical_event_hash` — the §17.3 clause-3 wire-contract violation (`IdempotencyKeyPayloadMismatch` rejection from §17.5, lifted to verifier-detectable tamper). |
| `erasure_key_class_registry_mismatch` | 6b step 2 | An `ErasureEvidencePayload`'s `key_class` (after `wrap`→`subject` normalization) does not equal the registry row's `kind` for the resolved `kid_destroyed` (Core §8.7 / ADR 0006). |
| `erasure_key_class_payload_conflict` | 6b step 8 | Two `ErasureEvidencePayload` payloads naming the same `kid_destroyed` carry disagreeing `key_class` after `wrap`→`subject` normalization. |
| `erasure_destroyed_at_after_host` | 6b step 4 | An `ErasureEvidencePayload`'s `destroyed_at` strictly exceeds the hosting event's `authored_at` (Companion OC-144 / TR-OP-109). |
| `erasure_destroyed_at_conflict` | 6b step 5 | Two `ErasureEvidencePayload` payloads naming the same `kid_destroyed` carry disagreeing `destroyed_at` values (Companion OC-145 / TR-OP-113). |
| `post_erasure_use` | 6b step 8 | A canonical event with `authored_at > destroyed_at` is signed under the destroyed `kid` (within `norm_key_class ∈ {"signing", "subject"}` Phase-1 scope). |
| `post_erasure_wrap` | 6b step 8 | A canonical event with `authored_at > destroyed_at` carries a `key_bag.entries` row wrapped under the destroyed `kid` (within `norm_key_class ∈ {"signing", "subject"}` Phase-1 scope). |
| `erasure_evidence_catalog_digest_mismatch` | 6b optional catalog | `064-erasure-evidence.cbor` digest does not match the manifest's `trellis.export.erasure-evidence.v1` binding (ADR 0005 §"Export manifest catalog"). |
| `erasure_evidence_catalog_invalid` | 6b optional catalog | `064-erasure-evidence.cbor` is malformed (CBOR decode failure, missing required fields, or `entry_count` disagrees with actual rows). |
| `erasure_evidence_catalog_duplicate_event` | 6b optional catalog | Two catalog rows in `064-erasure-evidence.cbor` carry the same `canonical_event_hash`. |
| `erasure_evidence_catalog_event_unresolved` | 6b optional catalog | A catalog row's `canonical_event_hash` does not resolve to any in-chain event. |
| `erasure_evidence_catalog_event_type_mismatch` | 6b optional catalog | A catalog row's `canonical_event_hash` resolves to an in-chain event whose `event_type` is not `trellis.erasure-evidence.v1`. |
| `erasure_evidence_catalog_mismatch` | 6b optional catalog | A catalog row's per-field values do not byte-match the resolved erasure-evidence event payload (cascade_scopes, kid_destroyed, destroyed_at, completion_mode, subject_scope_kind, evidence_id). |
| `certificate_chain_summary_mismatch` | 6c step 2 | A `trellis.certificate-of-completion.v1` event's `chain_summary` violates `signer_count == len(signing_events)`, `len(signer_display) == len(signing_events)`, or per-index `signer_display[i].principal_ref == principal(signing_events[i])` (ADR 0007 §"Verifier obligations" step 2). |
| `certificate_covered_claim_unknown` | 6c step 2 | A `chain_summary.covered_claims` tag is not in the verifier's supported tag registry for this release (ADR 0007 §"Verifier obligations" step 2). |
| `certificate_enum_extension_unknown` | 6c step 2 | A `chain_summary.workflow_status` or `chain_summary.impact_level` extension string is not registered in the Companion / WOS append-only registry (ADR 0007 §"Verifier obligations" step 2). |
| `certificate_id_collision` | 6c step 2 | Two `trellis.certificate-of-completion.v1` events in scope share `certificate_id` but disagree on canonical certificate payload (ADR 0007 §"Verifier obligations" step 2; fail-closed). |
| `presentation_artifact_attachment_missing` | 6c step 4 | `presentation_artifact.attachment_id` cannot be resolved through the ADR 0072 attachment-binding lineage (bytes missing though the binding requires them). Distinct from `presentation_artifact_content_mismatch`. |
| `presentation_artifact_content_mismatch` | 6c step 4 | Resolved presentation-artifact bytes recompute under `trellis-presentation-artifact-v1` (§9.8) to a digest that does not equal `presentation_artifact.content_hash`. |
| `signing_event_unresolved` | 6c step 5 | A `signing_events[i]` digest does not resolve to a chain-present `SignatureAffirmation` event (or WOS equivalent registered in §6.7). |
| `signing_event_timestamp_mismatch` | 6c step 6 | A `signer_display[i].signed_at` does not exactly equal the resolved `SignatureAffirmation` header's `authored_at` (timestamp exact equality). |
| `response_ref_mismatch` | 6c step 7 | `chain_summary.response_ref` is non-null but does not equal the Formspec canonical-response-hash carried on the linked `SignatureAffirmation`. |
| `malformed_response_digest` | 6c step 7 | The linked `SignatureAffirmation` payload declares `signedPayloadDigestAlgorithm = "sha-256"` and carries a `signedPayloadDigest` that is not parseable as 32 bytes of hex; the consumer-domain resolver surfaces a `MalformedResponseDigest` error and Trellis Core fails closed rather than silently skipping the response-ref equivalence check. Distinct from `response_ref_mismatch` (the digest text was parseable but did not match) and from absent-digest silent-skip (the payload carried no proof at all). |
| `certificate_catalog_digest_mismatch` | 6c optional catalog | `065-certificates-of-completion.cbor` digest does not match the manifest's `trellis.export.certificates-of-completion.v1` binding (ADR 0007 §"Export manifest catalog"). |
| `certificate_catalog_invalid` | 6c optional catalog | `065-certificates-of-completion.cbor` is malformed (CBOR decode failure, missing required fields, or `entry_count` disagrees with actual rows). |
| `certificate_catalog_duplicate_event` | 6c optional catalog | Two catalog rows in `065-certificates-of-completion.cbor` carry the same `canonical_event_hash`. |
| `certificate_catalog_event_unresolved` | 6c optional catalog | A catalog row's `canonical_event_hash` does not resolve to any in-chain event. |
| `certificate_catalog_event_type_mismatch` | 6c optional catalog | A catalog row's `canonical_event_hash` resolves to an in-chain event whose `event_type` is not `trellis.certificate-of-completion.v1`. |
| `certificate_catalog_mismatch` | 6c optional catalog | A catalog row's per-field values do not byte-match the resolved certificate-of-completion event payload (certificate_id, completed_at, signer_count, media_type, attachment_id, workflow_status). |
| `user_content_attestation_timestamp_mismatch` | 6d step 2 | A `trellis.user-content-attestation.v1` payload's `attested_at` does not exactly equal the envelope's `authored_at` (timestamp exact equality; no skew slack) (ADR 0010 §"Verifier obligations" step 2). |
| `user_content_attestation_intent_malformed` | 6d step 2 | A user-content-attestation `signing_intent` is not a syntactically valid URI per RFC 3986 (ADR 0010 §"Verifier obligations" step 2). |
| `user_content_attestation_chain_position_mismatch` | 6d step 3 | `attested_event_position` resolves to a chain-present event whose `canonical_event_hash` does not equal `attested_event_hash`, OR the position resolves to no event in the same `ledger_scope` (ADR 0010 §"Verifier obligations" step 3). |
| `user_content_attestation_identity_required` | 6d step 4 | `identity_attestation_ref` is null and the Posture Declaration in force at `attested_at` does not declare `admit_unverified_user_attestations: true` (ADR 0010 §"Verifier obligations" step 4). |
| `user_content_attestation_identity_unresolved` | 6d step 4 | `identity_attestation_ref` digest does not resolve to any chain-present event of a registered identity-attestation event type (ADR 0010 §"Verifier obligations" step 4). |
| `user_content_attestation_identity_subject_mismatch` | 6d step 4 | Resolved identity-attestation event's payload subject does not equal `attestor` (ADR 0010 §"Verifier obligations" step 4). |
| `user_content_attestation_identity_temporal_inversion` | 6d step 4 | Resolved identity-attestation event's `sequence` is not strictly less than `attested_event_position` — identity proof MUST temporally precede the attestation (ADR 0010 §"Verifier obligations" step 4). |
| `user_content_attestation_signature_invalid` | 6d step 5 | `UserContentAttestationPayload.signature` does not verify under domain tag `trellis-user-content-attestation-v1` (§9.8) over the §28 preimage with the `signing_kid` public key (ADR 0010 §"Verifier obligations" step 5). |
| `user_content_attestation_key_not_active` | 6d step 6 | `signing_kid` resolves to a `KeyEntry` whose `kind` is not `signing` or whose lifecycle state at `attested_at` is neither `Active` nor `Rotating` inside the §8.4 rotation-grace overlap (ADR 0010 §"Verifier obligations" step 6). |
| `user_content_attestation_id_collision` | 6d step 7 | Two `trellis.user-content-attestation.v1` events in scope share `attestation_id` with disagreeing canonical payload (ADR 0010 §"Verifier obligations" step 7; fail-closed). |
| `user_content_attestation_operator_in_user_slot` | 6d step 8 | An `attestor` URI resolves to a principal class registered as `operator` per Companion §6.4; user-content attestations are user-actor-only, operator attestations belong in §A.5's `Attestation` shape (ADR 0010 §"Verifier obligations" step 8). |
| `interop_sidecar_phase_1_locked` | 3.f / interop check | Manifest `interop_sidecars` lists an entry under one of the Phase-1-locked kinds (`scitt-receipt`, `vc-jose-cose-event`); ADR 0008 ISC-04 / ADR 0003 lock-off. `c2pa-manifest@v1` (Wave 25) and `did-key-view@v1` (Wave 29) dispatch to per-entry verification and do NOT raise this code. |
| `interop_sidecar_content_mismatch` | 3.f / interop check | Recomputed SHA-256 over the file at `interop_sidecars[i].path` does not equal the manifest's `interop_sidecars[i].content_digest` (digest preimage under domain tag `trellis-content-v1`). ADR 0008 ISC-03 / §"Phase-1 verifier obligation" step 2. |
| `interop_sidecar_missing` | 3.f / interop check | Manifest `interop_sidecars[i].path` names a sidecar file that is absent from the export ZIP. ADR 0008 ISC-03 / §"Phase-1 verifier obligation" step 2. |
| `interop_sidecar_kind_unknown` | 3.f / interop check | A manifest-listed `interop_sidecars[i].kind` is not in the ADR 0008 closed registry (`scitt-receipt`, `vc-jose-cose-event`, `c2pa-manifest`, `did-key-view`). ADR 0008 ISC-04. |
| `interop_sidecar_unlisted_file` | 3.f / interop check | A file is present under `interop-sidecars/` in the export ZIP but is not catalogued in `manifest.interop_sidecars`. ADR 0008 ISC-03 / §"Export bundle layout". |
| `interop_sidecar_derivation_version_unknown` | 3.f / interop check | A manifest-listed `interop_sidecars[i].derivation_version` is not in the verifier's supported set for that kind. ADR 0008 ISC-06. |
| `supersession_graph_unbound` | 6e / supersession graph | `064-supersession-graph.json` is present in the export ZIP but `ExportManifestPayload.extensions["trellis.export.supersession-graph.v1"]` is absent, so the graph bytes are not manifest-bound. |
| `supersession_graph_invalid` | 6e / supersession graph | `064-supersession-graph.json` is missing when the manifest extension is present, its SHA-256 digest does not equal `graph_digest`, it is not Trellis canonical JSON, its shape is malformed, or `predecessor_count` disagrees with the row count. |
| `supersession_graph_head_mismatch` | 6e / supersession graph | `064-supersession-graph.json.head_chain_id` does not equal `manifest.scope` encoded as lowercase hex. |
| `supersession_graph_linkage_mismatch` | 6e / supersession graph | An exported event carrying `trellis.supersedes-chain-id.v1` has no graph predecessor row with byte-equal `chain_id` and `checkpoint_hash`. |
| `supersession_graph_cycle` | 6e / supersession graph | Breadth-first traversal of predecessor `chain_id` rows revisits a chain on one traversal path. |
| `supersession_predecessor_checkpoint_mismatch` | 6e / supersession graph | A non-null `predecessors[*].bundle_path` is absent, does not verify as a deterministic Trellis export ZIP, or its `head_checkpoint_digest` does not equal the row's `checkpoint_hash`. |
| `signed_acts_manifest_mismatch` | 3.h / manifest extension check | `068-signed-acts-manifest.cbor` re-derived bytes do not match the archive member bytes (domain validator check; `derivation_rule = "signed-acts-manifest-v1"`). |
| `signed_acts_manifest_extension_digest_mismatch` | 3.h / manifest extension check | `SHA-256(068-signed-acts-manifest.cbor)` does not equal `trellis.export.signed-acts.manifest.v1.manifest_digest`. |
| `signed_acts_manifest_missing_member` | 3.h / manifest extension check | Extension `trellis.export.signed-acts.manifest.v1` is declared but `068-signed-acts-manifest.cbor` is absent from the archive. |
| `signed_acts_manifest_member_unbound` | 3.h / bundle structure invariant | `068-signed-acts-manifest.cbor` is present in the archive but `trellis.export.signed-acts.manifest.v1` extension is absent; the member is unbound. |
| `signed_acts_manifest_extension_invalid` | 3.h / manifest extension check | `trellis.export.signed-acts.manifest.v1` is present but its bytes are not a structurally valid extension: the extension fails canonical-CBOR map parse, `catalog_ref` is not `"068-signed-acts-manifest.cbor"`, `derivation_rule` is not `"signed-acts-manifest-v1"`, or re-derivation from sealed source events fails before a byte-compare can run (`derivation_rule` recognized but inputs malformed). Distinct from `signed_acts_manifest_mismatch` (extension shape valid; digest+re-derive byte-compare fail) and from `signed_acts_manifest_extension_digest_mismatch` (extension shape valid; declared digest does not match member SHA-256). |
| `bundle_unbound_member` | 3.i / bundle structure invariant | An archive member is present that is not bound by the manifest (top-level digest field), any registered extension's `catalog_ref`, or the manifest's `interop_sidecars` list. |

The enum is **append-only**. New categories MUST land in this table first, with a matching `TR-CORE-*` matrix row and a fixture vector under `fixtures/vectors/tamper/`, before a verifier or a fixture references the value. Removing or renaming a value is a wire break; deprecate by adding a successor row and retaining the prior value as a synonym. Traceability: **TR-CORE-068** (matrix row) — enforced by `scripts/check-specs.py` rule R13 over the tamper corpus.

### 19.2 No network, no fallbacks

The verifier MUST NOT fetch external resources. It MUST NOT fall back to heuristic interpretation of malformed data. It MUST NOT silently skip checks that it lacks material to perform; it MUST record each skipped check in the report.

### 19.3 Time and memory

For an export with `N` events, the verifier runs in time `O(N)` for integrity (one pass over events, one pass over checkpoints) plus `O(M log N)` for the M inclusion proofs. Memory is `O(N)` in the worst case (the canonical-event-hash array to rebuild the tree), or `O(log N)` with streaming tree construction. A Phase 1 reference implementation that does not verify an N = 1,000,000 export on a laptop in under 60 seconds is not a good reference implementation; this is an engineering requirement, not a normative one.

---

## 20. Trust Posture Honesty

**Requirement class:** Fact Producer, Canonical Append Service, Export Generator.

### 20.1 Normative requirement

Implementations MUST NOT describe their trust posture more strongly than behavior supports. This is invariant #15 lifted normatively.

### 20.2 Required `PostureDeclaration`

Every export manifest (§18.3) MUST include a `PostureDeclaration` with at least the following fields:

```cddl
PostureDeclaration = {
  provider_readable:         bool,                   ; can the service operator decrypt
                                                    ; payloads in ordinary operation?
  reader_held:               bool,                   ; are decryption keys held by the subject or
                                                    ; a subject-designated reader?
  delegated_compute:         bool,                   ; is there any delegated-compute path that
                                                    ; exposes plaintext to a compute agent?
  external_anchor_required:  bool,                   ; does "tamper-evident" depend on an external
                                                    ; anchor beyond this package?
  external_anchor_name:      tstr / null,            ; if required, the name of the dependency
  recovery_without_user:     bool,                   ; can recovery occur without the user's
                                                    ; participation?
  metadata_leakage_summary:  tstr,                   ; human-readable short description of what
                                                    ; metadata remains visible
}
```

### 20.3 Honest field semantics

- `provider_readable = true` means the operator CAN decrypt payloads during ordinary operation. An implementation whose operator holds a reader-wrap copy in the `key_bag` MUST declare `true`. Declaring `false` under these circumstances is a trust-posture-honesty violation.
- `reader_held = true` means the subject or a subject-designated reader holds decryption capability, AND the operator does not hold it in ordinary operation. Both conditions are required; implementations that let the operator hold a "for emergencies" wrap MUST set `reader_held = false` unless the "emergency" is declared in `recovery_without_user` and in the Posture Declaration.
- `delegated_compute = false` means no compute agent, including AI services, is given decryption capability. An LLM-agent workflow that requires payload access to operate MUST declare `true`.
- `external_anchor_required = true` means the "tamper-evident" claim depends on the external anchor named in `external_anchor_name`. Packages that claim tamper-evidence via only the internal signed tree head MUST set `external_anchor_required = false`.
- `recovery_without_user = true` means the service can recover payload access without user participation. This is a key disclosure obligation.
- `metadata_leakage_summary` is non-normative prose; it MUST NOT be used to obscure any of the structured fields.

### 20.4 Legal claims

Cryptographic controls alone MUST NOT be described as legal admissibility. A Phase 1 export verifies integrity and provenance; legal sufficiency in any jurisdiction is governed by upstream obligations (WOS Assurance §6 and analogous regulatory regimes) and is outside the scope of this specification. An implementation MUST NOT embed in its export, its manifest prose, its README, or any accompanying documentation, a claim that the package's Phase 1 verification establishes legal admissibility.

### 20.5 Downgrade protocol

If a deployment discovers that it has overstated its posture (for example, an earlier declaration of `reader_held = true` when the operator had decryption capability), the correction is itself a canonical fact recorded in the response or case ledger, and an update to the posture-transition record. The deployment MUST NOT silently rewrite prior `PostureDeclaration` values; prior exports remain accurate as of their production time, and the correction is a forward event.

---

## 21. Posture / Custody / Conformance-Class Vocabulary

**Requirement class:** All.

### 21.1 The vocabulary problem

Three prior-draft namespaces used the letters A–E/F for three different concerns:

- the Respondent Ledger spec's Profile A/B/C (privacy × identity × integrity-anchoring posture),
- the legacy core draft's seven profiles (Core / Offline / Reader-Held / Delegated-Compute / Disclosure / User-Held / Respondent-History),
- the legacy companion draft's Profiles A–E (provider-readable / reader-held / delegated / threshold / organizational trust-custody models).

These are three orthogonal concerns and MUST NOT share a namespace.

### 21.2 Normative renames

- The Respondent Ledger spec unambiguously owns **"Profile A/B/C"** for posture axes (privacy tier × identity binding × integrity anchoring). Its definitions (Respondent Ledger §15A) are cited here; Trellis does not redefine them.
- The legacy core draft's profiles are renamed **"Conformance Classes"** (what they semantically are). This document defines them in §2.1.
- The legacy companion draft's profiles are renamed **"Custody Models"**. Their definitions move to the Operational Companion; Core only cites the identifier namespace.
- Trellis capability tiers use **phase names** — "attested-export tier" (Phase 1), "runtime-integrity tier" (Phase 2), "portable-case tier" (Phase 3), "federated tier" (Phase 4) — not letters.

### 21.3 Custody models enumerated

Phase 1 recognizes the custody-model identifiers `CM-A` through `CM-F` as values in the Custody Models registry (§26.3). Each identifier is a text string; both the identifier set and its semantics are defined normatively by Trellis Operational Companion §9 (Custody Models), §9.2 (The Six Standard Custody Models) in particular. Core does not restate those definitions: Companion §9.2 is the canonical list, and this section is a pointer.

Phase 2+ MAY register additional models via the Custody Models registry (§26.3). Registration is append-only; semantics do not change after registration.

### 21.4 Scope distinction: event / response ledger / case ledger / agency log / federation log

These are three distinct structures at three distinct scopes, not one term used three ways.

- **Event** (§1.2, §6) — atomic append.
- **Response ledger** — hash-chained sequence of events for one Formspec Response. Owned by Formspec Respondent Ledger semantics for authored meaning; owned by Trellis for envelope integrity.
- **Case ledger** — hash-chained sequence of governance events composing one or more sealed response-ledger heads with WOS governance events. Defined in §24.
- **Agency log** — operator-maintained log of case-ledger heads. Defined in §24.
- **Federation log** — log of agency-log heads witnessed by an independent operator. Phase 4, out of scope for this document.

---

## 22. Composition with Respondent Ledger

**Requirement class:** Fact Producer (Formspec-family), Verifier.

### 22.1 The seam

The Formspec Respondent Ledger specification (in-tree reference: `thoughts/formspec/specs/respondent-ledger-spec.md`; the authoritative upstream RL spec may live in a separate repo under `specs/audit/` — treat the in-tree thoughts copy as the reference for this document) defines the per-response event model, including `eventHash` and `priorEventHash` fields at §6.2 (per-event integrity chaining) and `LedgerCheckpoint` objects at §13 (per-range integrity checkpoints). Respondent Ledger §13.4 explicitly defers "specific signature suite or external anchor" to a downstream layer. Trellis is that downstream layer.

### 22.2 Per-event binding (Track E §21(a))

**When a Trellis envelope wraps a Respondent-Ledger event, Respondent Ledger §6.2 `eventHash` and `priorEventHash` are promoted from SHOULD to MUST.** These are structurally different hashes — the Respondent-Ledger `eventHash` is computed over author-defined JSON per Respondent Ledger §14, while the Trellis `canonical_event_hash` is computed over dCBOR(`CanonicalEventHashPreimage`) under a domain tag per §9.2 — so the binding is a *store-the-digest* rule, not a compute-and-check-equal rule. Concretely, when a Trellis envelope wraps the event:

- The Respondent-Ledger event, serialized per Respondent Ledger §14, MUST appear as the event's plaintext-committed authored-fact material (within the encrypted payload if `reader_held`; within the plaintext audit material if `provider_readable` per the declared posture).
- The Respondent-Ledger `eventHash` field MUST carry the value of the Trellis event's `canonical_event_hash` (§9.2). (The field stores the Trellis digest rather than an independently-computed RL digest.)
- The Respondent-Ledger `priorEventHash` field MUST carry the value of the Trellis event's `prev_hash` (§10.2).

Standalone Respondent Ledger usage without a Trellis envelope retains its own serialization and hash construction per Respondent Ledger §14. This is the integrity-chaining binding that the Respondent Ledger spec names but does not implement on its own. Trellis implements it normatively for Trellis-wrapped Respondent-Ledger events.

### 22.3 Per-range binding (Track E §21(b))

Respondent Ledger §13 `LedgerCheckpoint` and Trellis §11 `Checkpoint` are **different hashes covering different scopes**. The binding between them:

- A Respondent-Ledger `LedgerCheckpoint` (§13.2 minimum fields: `checkpointId`, `ledgerId`, `fromSequence`, `toSequence`, `batchHash`, `signedAt`) is the per-range sealing artifact from the Formspec side.
- A Trellis `Checkpoint` (§11.2) is the signed tree head from the Trellis side.
- When a Trellis envelope wraps a Respondent Ledger, the Trellis `Checkpoint.tree_head_hash` MUST cover exactly the sequence range `[fromSequence, toSequence]` declared by the Respondent Ledger `LedgerCheckpoint`. The Respondent Ledger `LedgerCheckpoint.batchHash` MUST equal the Trellis `Checkpoint.tree_head_hash` for the same `[fromSequence, toSequence]` range (i.e., the batch hash is reproducible from the canonical event hashes in that range under the construction of §11.3, and the result is the tree-head hash).

They are not the same hash, and MUST NOT be conflated; they attest to the same events at different layers (Formspec range vs. Trellis tree).

### 22.4 Case ledger as composition

The **case ledger** is defined normatively as: a Trellis-shaped hash-chained sequence of events whose admitted facts are (a) sealed response-ledger heads (one per Formspec Response associated with the case) plus (b) WOS governance events. The case-ledger event format IS the event format of §6. The composition rule: a sealed response-ledger head appears in a case ledger as an event of `event_type = "trellis.response-head"` whose payload references the sealed response head and whose `commitments` bind the response-ledger's final `tree_head_hash`. A WOS governance event appears as `event_type = "wos.*"` per the WOS-family event taxonomy.

Case-ledger head format is the head format of §11 at a version number (Phase 3) that is a strict superset of Phase 1's version 1 (§18.7).

### 22.5 Response → case composition rule

When a Formspec Response is sealed at submission:

1. The Respondent-Ledger final `LedgerCheckpoint` is produced per Respondent Ledger §13.
2. A Trellis `Checkpoint` is produced per §11 covering the same range.
3. The Trellis `Checkpoint.tree_head_hash` is bound into a new case-ledger event of type `trellis.response-head` whose payload references the Checkpoint.
4. The case ledger's `prev_hash` chain extends by one event.

This is the normative composition rule. It makes the response ledger a *named tributary* of the case ledger without redefining either.

---

## 23. Composition with WOS `custodyHook`

**Requirement class:** Fact Producer (WOS-family), Verifier.

### 23.1 The seam

WOS Kernel §10.5 names `custodyHook` as the seam through which a WOS runtime delegates cryptographic custody to a downstream layer. Trellis is that downstream layer for WOS deployments that adopt it. The seam is directional: WOS emits governance and provenance facts; Trellis admits them as canonical events. Trellis does not initiate WOS state transitions, and a WOS runtime without `custodyHook` adoption is unaffected by this section.

WOS Kernel §10.5 is explicit that the kernel itself does not define the concrete Trust-Profile object; a binding populates the seam. This section is that binding for the Trellis-as-custody-backend case. A monolithic WOS deployment that populates `custodyHook` with an in-process single posture is out of scope here and is governed by WOS Kernel §10.5 directly.

### 23.2 Binding obligations

A WOS runtime using Trellis as its custody backend — hereafter a "WOS-Trellis deployment" — MUST, for every WOS governance or provenance record (WOS Kernel §8 Facts tier and §10.4 `lifecycleHook` outputs) whose custody is routed through the hook:

1. **Envelope.** Produce the record as a Trellis `EventPayload` (§6.1) submitted to the Canonical Append Service under the `ledger_scope` chosen for the WOS case — see §23.3 on scope selection.
2. **Event type.** Populate `EventHeader.event_type` (§12.1) with a registered identifier from the `wos.*` family in the bound registry (§14); §23.4 pins both the namespace-disjointness rule and the outcome-neutrality discipline for `wos.*` identifiers.
3. **Authored payload.** Place the WOS record's authored-fact material — the serialized form WOS Kernel §8 and §10.4 prescribe for that record kind — inside the encrypted payload (`PayloadRef`, §6.4). The Trellis envelope does not restate WOS's authored-fact encoding; it wraps the bytes WOS produces.
4. **Integrity hash.** Use Trellis `canonical_event_hash` (§9.2) as the record's integrity hash wherever WOS Kernel §8 calls for one. A WOS `lifecycleHook` output that stores a hash-of-record for later reference MUST store the Trellis `canonical_event_hash` of the admitting event, not an independently recomputed digest.
5. **Chain.** Chain WOS records via Trellis `prev_hash` (§10.2) in the declared `ledger_scope`. A WOS-Trellis deployment MUST NOT maintain a parallel WOS-side linear chain over the same records; the Trellis chain is the authoritative order. This is the WOS-family analogue of the Respondent-Ledger integrity-chaining binding in §22.2.
6. **Per-range artifact.** Use Trellis `Checkpoint` (§11) as the per-range sealing artifact for any WOS range-level integrity obligation. A WOS deployment that composes case-ledger heads from multiple WOS scopes uses the case-ledger composition of §22.4.
7. **Posture.** Declare a `PostureDeclaration` (§20) covering every `ledger_scope` admitting WOS governance events, and record custody transitions that affect that posture as canonical events per §6.7 / Operational Companion §10 (Posture-Transition Auditability). Custody transitions driven by WOS governance (for example, a WOS-governance decision that alters recovery authority) are posture transitions regardless of the governance body that authored them.

### 23.3 Ledger-scope selection

`ledger_scope` for WOS-Trellis events is chosen by the Operator and MUST satisfy the §10.4 rules without exception. The recommended construction is one `ledger_scope` per WOS case (so that WOS governance events for one case form one chain), with case-ledger composition (§22.4) used when multiple response-ledger scopes must be referenced from the same case's governance chain. `ledger_scope` is signed into every event; a WOS event authored against one case MUST NOT later be replayed into another case's scope, because the domain-separated hashes (§9) would not match.

### 23.4 Event-type namespace and outcome-neutrality

The `wos.*` event-type family is registered in the bound registry (§14) with the same outcome-neutrality discipline that §12.4 pins for all Trellis `event_type` identifiers:

- **Namespace disjointness.** The `wos.*` family and the `trellis.*` family are mutually disjoint. A Trellis-authored envelope whose authored-fact material is not a WOS governance record MUST NOT use a `wos.*` identifier, and a WOS runtime MUST NOT emit a `trellis.*` identifier as its `event_type`. A Trellis processor MUST NOT admit a WOS governance record under a `trellis.*` identifier, and MUST NOT admit a non-WOS authored fact under a `wos.*` identifier.
- Registered `wos.*` identifiers name the governance-record *kind*, not its outcome. `wos.determination`, `wos.review-close`, `wos.assignment`, `wos.adjudication` are conformant shapes; `wos.determination.granted`, `wos.determination.denied`, `wos.review-close.adverse` are NON-CONFORMANT and MUST NOT be registered. WOS outcome is carried in the encrypted payload and in `EventHeader.outcome_commitment` per §12.2.
- `wos.*` identifiers MUST resolve to WOS governance semantics defined by the WOS specification at the registry-bound version (§14.2). A bound-registry entry for a `wos.*` identifier names the WOS spec version it refers to; a registry change that re-points the identifier to a different WOS semantic version is a new registry binding per §14.5.
- `wos.assurance.identity_attestation` is the canonical identity-attestation event type for ADR 0068 D-3.1 `IdentityAttestation` records. The identifier follows the WOS custody-hook taxonomy `wos.<layer>.<record_kind>`: layer `assurance`, record kind `identity_attestation`. WOS-aware user-content-attestation identity resolution (§19 step 6d) admits this event type through the consumer-owned validator, while Trellis center conformance continues to admit only `x-trellis-test/identity-attestation/v1` inside core fixtures.
- The `wos.` prefix is reserved to the WOS specification family in the bound registry. Vendors extending WOS with deployment-local governance records MUST use a registered `x-` identifier under §6.7 that does not shadow any upstream specification's reserved `x-*` prefix (cf. WOS Kernel §10.6, which reserves `x-wos-` for future WOS-normative use). A bare `wos.*` identifier MUST NOT be minted outside the WOS specification family.

### 23.5 Idempotency-key construction for WOS retries

A WOS runtime frequently retries governance submissions — a scheduler redeliver, a saga-compensation retry, a durable-execution replay. Every retry of the same WOS governance decision MUST resolve under §17.3 to the same canonical event, not to a second order position. The WOS-Trellis deployment MUST construct `idempotency_key` (§6.1, §17.2) such that:

- (a) retries of the same authored governance fact produce byte-equal keys,
- (b) distinct authoring attempts produce distinct keys, and
- (c) the construction is computable from identifiers the WOS runtime supplies per its own vocabulary — namely, a case identifier, an identifier for the governance rule or state transition being governed, and a stable per-attempt identifier that the WOS runtime preserves across network-level retries of the same authored attempt.

The recommended construction is a deterministic hash (§17.2) over the canonical encoding (§5) of the WOS-supplied identifier tuple, domain-separated per §9.1. A SHA-256 hash per §9 yields 32 bytes and therefore satisfies the `.size (1..64)` bound on `idempotency_key` in §6.1 by construction. Concrete WOS-side field names and their stability guarantees are normatively the WOS specification's to publish; Trellis does not pin WOS-vocabulary identifiers here. A UUIDv7 ([RFC 9562]) per §17.2 is conformant when the WOS runtime can guarantee one UUIDv7 per logical authored attempt.

For the **WOS-as-custody-backend** binding (Kernel §10.5 `custodyHook` into Trellis), the Operational Companion publishes the operational binding — including the WOS-authored append surface, idempotency inputs, and minimum return shape — in **§24.9**; Core defers WOS vocabulary to WOS and to that companion section rather than duplicating it here.

A WOS-Trellis deployment MUST NOT let the WOS runtime's retry/compensation machinery mint a new `idempotency_key` for the same authored governance decision; the `(ledger_scope, idempotency_key)` identity rule of §17.3 is scope-permanent regardless of WOS-layer retry semantics, and §17.5 `IdempotencyKeyPayloadMismatch` applies when a WOS-layer bug produces a different canonical payload under the same key.

### 23.6 Autonomy-cap mapping

WOS's autonomy vocabulary — `autonomous`, `supervisory`, `assistive`, `manual` (WOS AI Integration §5.2), constrained by the impact-level cap of WOS AI Integration §5.3 — remains authoritative for whether a WOS action may be taken by an AI agent. Trellis does not redefine these levels, re-rank them, or attempt to evaluate the impact-level cap.

When a WOS action is taken by an AI agent under an autonomy level other than `manual`, the corresponding Trellis admission MUST:

1. Declare the event's access class as `delegated_compute` in the Operator's access taxonomy (Operational Companion §8, §19) for every content class the agent read or authored while producing the governance record.
2. Reference a canonical Delegated-Compute Grant (Operational Companion §19.2, Appendix A.6, Appendix B.4) whose scope includes that content class and whose authority attestation (Operational Companion §19.3) names the WOS governance authority that issued the autonomy authorization.
3. Attribute the record under the actor-discriminator rule of Operational Companion §19.4 and OC-70c: `actor_agent_under_delegation` when the governance record is an agent-produced artifact, `actor_human` when a human approver confirmed an `assistive` recommendation before it became canonical.

Trellis does not evaluate whether the WOS autonomy level is conformant with the WOS impact-level cap; that evaluation is WOS's. Trellis attests to the custody and attribution facts. A WOS-conformance failure at the autonomy-cap layer is out of scope for Trellis verification but MUST NOT be masked by a Trellis attestation; see Operational Companion §19.6.

### 23.7 Non-redefinition

Trellis does not alter WOS semantic authority. A WOS runtime's case-state model, deontic ruleset, autonomy caps (WOS AI Integration §5), and governance logic remain WOS-spec bound. Trellis specifies only how the WOS record, once produced, is envelope-wrapped, integrity-bound, and posture-declared. A WOS-conformant runtime and a Trellis-conformant Canonical Append Service compose without either specification changing.

### 23.8 Delegation

When Trellis behavior depends on WOS evaluation semantics — whether a proposed WOS state transition is permitted, whether a WOS deontic check passes, whether a WOS autonomy cap admits an agent-authored attempt — Trellis MUST delegate to a WOS-conformant processor. Trellis does not evaluate WOS rules; it attests to the results WOS produces.

---

## 24. Agency Log (Phase 3 Superset Preview)

**Requirement class:** Canonical Append Service (for Phase 3 agency operators), Verifier.

### 24.1 Normative definition

An **agency log** is an operator-maintained append-only log whose entries are **case-ledger heads** plus arrival metadata and optional witness signatures. It proves that a case existed at time `T` and was not quietly deleted; it is structurally what CT logs are for certificates, applied to cases.

An agency-log entry is, **byte-for-byte, a Phase 1 Checkpoint (§11.2) structure** whose `CheckpointPayload` fields are the Phase 1 fields defined in §11.2, plus registered entries in the reserved `CheckpointPayload.extensions` container for arrival metadata and witness signatures. There are **no top-level agency-log-specific fields**; all agency-log-specific data lives inside `extensions`, under registered identifiers per §6.7. Specifically:

- `trellis.agency_log.arrival_timestamp.v1` — arrival timestamp at the witness-operator at ingest.
- `trellis.agency_log.witness_signature.v1` — optional witness signature(s) attesting to ingest observation.
- `trellis.case_ledger.composed_response_heads.v1` — digests of sealed response-ledger heads composed into this case-ledger head.
- `trellis.case_ledger.case_scope_metadata.v1` — case-scope adjudication metadata (case ID, agency, phase).

A Phase 3 agency-log **entry** is a Trellis event (§6) of `event_type = "trellis.case-head"` whose payload references the case-ledger head by digest; its own `EventPayload.extensions` may likewise carry agency-log arrival metadata. A Phase 3 agency-log **head** is a Trellis checkpoint (§11) whose `CheckpointPayload` preserves the Phase 1 shape of §11.2 unchanged and carries Phase 3 additions only under the registered identifiers in `CheckpointPayload.extensions`.

### 24.2 Phase 1 preservation obligation

Phase 1 MUST reserve head-format extension points that Phase 3 populates. The following Phase 3 fields extend the Phase 1 `CheckpointPayload` only inside `extensions`; a Phase 1 producer MUST NOT emit them, and a Phase 1 verifier MUST preserve and ignore them if encountered in a later-version head (§11.6, §18.7):

- `composed_response_heads: [* digest]` — references to sealed response-ledger heads composed into this case-ledger head.
- `case_scope_metadata: CaseScope` — arrival metadata (case ID, agency, adjudication phase).
- `witness_signatures: [* WitnessSignature]` — cosignatures by independent witnesses (Phase 4 federation).

### 24.3 Why this appears in Phase 1

The agency-log entry format is defined here, at Phase 1, because every Phase 1 checkpoint is a case-ledger-head-compatible artifact by construction. Without this normative reservation, Phase 3 agency-log adoption is a wire-format break for every Phase 1 export already in the field. By naming the reservations now, Phase 1 implementors know what Phase 3 will add and can validate their export shape against it.

### 24.4 Non-goal for Phase 1

Phase 1 does not specify agency-log gossip protocols, witness cosignature mechanics, or federation-log equivocation detection. Those belong to Phase 4. What Phase 1 guarantees is that when they arrive, they do not invalidate anything Phase 1 shipped.

---

## 25. Security and Privacy Considerations

**Requirement class:** Implementers.

### 25.1 Threat model

Trellis is designed against an adversary who controls the operating service, its database, its backup infrastructure, and its administrative console, but does **not** hold signing keys that have been distributed outside the service boundary (subject devices, independent witnesses, customer-held root keys). The goal is to make tampering by such an adversary **difficult and obvious**: difficult because it requires forging signatures, obvious because any reissued export's head is inconsistent with any prior export's head already in third-party hands.

This is not equivocation-proof. An adversary who never distributes exports externally, and who holds all signing keys, can rewrite history silently. Phase 4 transparency witnessing (out of scope for this document) raises the bar to equivocation-proof by requiring independent cosignature; Phase 1 ships the construction that makes Phase 4 additive, not reconstructive.

### 25.2 Metadata leakage

The envelope carries structural fields in plaintext (§12.2). An observer who sees envelopes without decrypting payloads learns:

- event type (limited by the outcome-neutral granularity rule, §12.4),
- timing (at `authored_at` granularity, which MAY be coarsened by the Operational Companion),
- COSE protected-header `kid` (which identifies the signer cohort but not, without correlation, the signer),
- ledger scope identifier (which may identify a case, a workflow, an agency),
- append-head position (which leaks cohort size for the scope).

Implementers MUST consult the metadata budget discipline of the Operational Companion before publishing envelopes to untrusted observers.

### 25.3 Equivocation and split-view

A service presenting different signed tree heads for the same scope to different verifiers is equivocating. Phase 1 detection is passive: verifiers holding different exports that share a scope can compare and detect divergence. Phase 4 elevates this to active detection via witness gossip. A Phase 1 deployment that does NOT distribute exports widely (for example, a single-tenant deployment) has weaker equivocation detection than one that does; this is a property of the deployment, not of the specification.

### 25.4 Side channels

Timing, access pattern, and inclusion-proof request patterns reveal information beyond what is in the envelope. Phase 1 does not mandate oblivious retrieval; deployments that require it declare so in their Posture Declaration and Operational Companion custody model.

### 25.5 Replay

`idempotency_key` (§17) prevents replay-as-duplicate. Replay-as-resubmission (a Fact Producer resubmits an event with the same key to force a retry) is handled by §17.3. Replay of an event from one ledger into another is prevented by the signed `ledger_scope`, the per-scope `prev_hash` chain, and the canonical event hash preimage (§9.2): an event hash includes the ledger scope, and the predecessor chain does not reproduce across scopes.

### 25.6 Key compromise

A compromised signing key invalidates every unrevoked signature the attacker can produce under it. Revocation (status → `Revoked`) is append-only; the compromised key MUST appear as `Revoked` in every subsequent export. Historical signatures under the key remain verifiable against the signing-key registry, but their interpretation depends on whether the compromise predates the signed event; this is a judgment the verifier cannot make from the envelope alone, and SHOULD be surfaced explicitly in the verification report (§19).

### 25.7 Post-quantum migration

Phase 1 ships Ed25519. A cryptographically-relevant quantum computer breaks Ed25519. The migration obligation (§7.3) requires that a 2045 verifier can still resolve 2026 signatures: the `suite_id` is in-band, the signing keys are in the registry, and the digest domain-separators are versioned. Migration to ML-DSA-65 or SLH-DSA-128s, or to a hybrid, registers a new `suite_id` and a new signing key; all prior records remain verifiable under their original suite by any verifier that retains Ed25519 validation code. Implementations that remove Ed25519 support after migration break their own history.

### 25.8 Crypto-shredding interaction with backups

Destroying the per-subject DEK erases plaintext locally. If the ciphertext has been backed up to off-site storage, the backup's plaintext is also erased (same DEK). This is the intended GDPR Art. 17 / FOIA-redaction behavior. An attacker with offline ciphertext and a quantum computer could theoretically recover plaintext if the AEAD succumbs to Shor or Grover; ChaCha20-Poly1305 AEAD has 256-bit key material and is believed to retain at least 128-bit post-quantum security under Grover. Against that adversary, crypto-shredding reduces to rotating the DEK class wholesale; this is a Phase 2 operational choice and does not affect Phase 1 wire format.

---

## 26. IANA Considerations

### 26.1 Content type

This specification requests registration of the media type `application/trellis-export+zip` for Phase 1 export packages. File extension: `.ztrellis` or `.zip`. Packages internally identify themselves via the `000-manifest.cbor` payload format field (`"trellis-export/1"`).

### 26.2 `suite_id` registry

A new IANA registry `Trellis Signature Suites` is requested. Registration policy: Specification Required. Initial contents per §7.2. Each registration MUST include: suite identifier, signature algorithm, digest algorithm, reference specification, status.

### 26.2.1 Retired dispatch-label registry

This sub-registry is **retired by ADR 0109**. Protected-header label `-65539` was previously used to dispatch verification plugins from the COSE protected header; ADR 0109 surface-splits dispatch into the substrate-structural axis (`artifact_type` at `-65538`, closed enum, defined inline at §7.4) and the consumer detached-signature axis (`method_uri` at `-65540`, URI-valued, owned by `integrity-cose`).

Previously allocated values are retained here as historical record only:

| Retired value | Dispatch name | Owning specification | Status |
|------------|---------|----------------------|--------|
| 1 | WOS workflow event | WOS | Retired |
| 2 | Formspec authored signature | Formspec Core §2.1.6 | Retired |

No new values may be allocated under this sub-registry. Future substrate structural roles register in the closed `artifact_type` enum at §7.4 via Trellis-owned spec amendment. Future consumer detached-signature methods register URI prefixes in their owning consumer spec; coordination at the stack level lives in `thoughts/registries/uri-prefix-coordination.md`.

### 26.3 Custody Models registry

A new IANA-style sub-registry (maintained by the Trellis maintainers until IANA registration, under the shared governance of the Formspec/WOS/Trellis working group) tracks custody-model identifiers per §21.3.

### 26.4 Domain tags

The domain-separation tags enumerated in §9.8 are Trellis-internal and do not require IANA registration; they are documented here for implementor reference.

### 26.5 CBOR tag

No new CBOR tag is requested for Phase 1. Events and checkpoints are plain dCBOR maps; their type is established by their format member (`manifest.format`, explicit `version` fields) and by their archive placement.

---

## 27. Test Vector Requirements

**Requirement class:** All (fixture authorship), Verifier (conformance demonstration).

### 27.1 Coverage minimum

A conformant Phase 1 implementation MUST pass a minimum of **50 language-neutral test vectors** distributed across the following categories, placed under `fixtures/vectors/` in the reference distribution:

| Directory | Count minimum | Purpose |
|---|---|---|
| `fixtures/vectors/append/` | 10 | Valid append flows: first event, subsequent events, multi-event chains. |
| `fixtures/vectors/verify/` | 15 | Successful verification of complete exports: small, medium, large; single-scope; reader-held; provider-readable. |
| `fixtures/vectors/export/` | 10 | Export-package determinism: same input produces byte-identical ZIP output. |
| `fixtures/vectors/tamper/` | 15 | Detection of tampering: flipped bits in events.cbor, modified signatures, rewritten checkpoints, broken prev_hash chain, unresolvable kid, registry-digest mismatch, out-of-order checkpoints, consistency-proof forgery, substituted content, stripped inclusion proofs. |

### 27.2 Per-vector requirements

Each vector MUST include:

- input: the authored facts (plaintext), the signing keys, the registry snapshot, the idempotency keys, the timestamps,
- expected output: the exact dCBOR bytes of every event, the exact bytes of the checkpoint, the exact ZIP bytes of the export,
- expected verifier verdict: the exact `verified` boolean and a reference `VerificationReport`.

### 27.3 Byte-level claim coverage

Every byte-level claim in this specification MUST correspond to at least one vector. Concretely:

- every `suite_id` value used in Phase 1 has at least one vector,
- every rejection code in §17.5 has at least one negative-case vector,
- every commitment-scheme reservation in §13.3 has at least a shape-vector (not a full scheme implementation),
- every header layer-violation case in §12.2 has at least one negative-case vector.

### 27.4 Cross-implementation byte match

The Phase 1 success criterion (§1 Status) is that a second implementation, written from this specification alone, produces byte-identical output on every `export/` vector and byte-identical verification reports on every `verify/` and `tamper/` vector. Divergence at the byte level — even one-byte divergence — is a conformance failure in one of the two implementations and MUST be diagnosed against this specification, not papered over.

---

## 28. Appendix A — Full CDDL

```cddl
; Trellis Core Phase 1 CDDL grammar
; All types encoded as dCBOR (RFC 8949 §4.2.2).

digest         = bstr .size 32  ; SHA-256
suite_id       = uint
artifact_type  = "event" / "checkpoint" / "manifest"  ; closed enum, ADR 0109
kid            = bstr .size 16
timestamp  = [uint, uint .le 999999999]  ; [seconds since Unix epoch UTC, nanos within second]
; Traceability: TR-CORE-093.

; --- Event ------------------------------------------------------------

Event = COSESign1Bytes

EventPayload = {
  version:           uint .size 1,
  ledger_scope:      bstr,
  sequence:          uint,
  prev_hash:         digest / null,
  causal_deps:       [* digest] / null,
  author_event_hash: digest,
  content_hash:      digest,
  header:            EventHeader,
  commitments:       [* Commitment] / null,
  payload_ref:       PayloadRef,
  key_bag:           KeyBag,
  idempotency_key:   bstr .size (1..64),
  extensions:        { * tstr => any } / null,
}

; Carried under EventPayload.extensions["trellis.supersedes-chain-id.v1"] (§6.7).
; Null / absent extension value means the event does not link to a superseded chain.
; Traceability: TR-CORE-169.
chain_id = bstr

SupersedesChainIdPayload = {
  chain_id:        chain_id,
  checkpoint_hash: digest,
}

EventHeader = {
  event_type:             bstr,
  authored_at:            timestamp,
  retention_tier:         uint .size 1,
  classification:         bstr,
  outcome_commitment:     digest / null,
  subject_ref_commitment: digest / null,
  tag_commitment:         digest / null,
  witness_ref:            bstr / null,
  extensions:             { * tstr => any } / null,
}

CheckpointHashPreimage = {
  version:            uint .size 1,
  scope:              bstr,
  checkpoint_payload: CheckpointPayload,
}

PayloadRef = PayloadInline / PayloadExternal

PayloadInline = {
  ref_type:   "inline",
  ciphertext: bstr,
  nonce:      bstr .size 12,
}

PayloadExternal = {
  ref_type:       "external",
  content_hash:   digest,
  availability:   AvailabilityHint,
  retrieval_hint: tstr / null,
}

AvailabilityHint = &(
  InExport:    0,
  External:    1,
  Withheld:    2,
  Unavailable: 3,
)

Commitment = {
  scheme:   uint,
  slot:     uint,
  value:    bstr,
  metadata: bstr / null,
}

KeyBag = {
  entries: [* KeyBagEntry],
}

KeyBagEntry = {
  recipient:        bstr,
  suite:            uint,
  ephemeral_pubkey: bstr .size 32,
  wrapped_dek:      bstr,
}

; --- Signature --------------------------------------------------------

; Trellis substrate envelope protected-header map (ADR 0109).
; All four labels are REQUIRED on every substrate envelope.
; Label -65539 is retired and rejected by verifiers.
; Consumer detached-signature envelopes use a separate production
; (see `integrity-cose` substrate documentation): MAP_3 with
; `-65540 => method_uri` (tstr-URI) replacing `-65538 => artifact_type`.
COSEProtectedHeaders = {
  1 => int,                       ; alg, Phase 1: -8 (EdDSA)
  4 => kid,
  -65537 => suite_id,
  -65538 => artifact_type,        ; required per ADR 0109
}

COSESign1Bytes = bstr   ; RFC 9052 COSE_Sign1 tagged CBOR value as bytes.
                       ; Substrate envelope protected headers carry alg, kid,
                       ; suite_id, artifact_type per ADR 0109. The retired
                       ; label -65539 is tombstoned; verifiers
                       ; reject envelopes that emit it.
                       ; Events, checkpoints, manifests, and key-registry
                       ; administrative entries embed payload bstrs; consumer
                       ; detached signatures (separate envelope shape) may
                       ; use payload = nil only under §7.4 payload-mode rules.

CanonicalEventHashPreimage = {
  version:       uint .size 1,
  ledger_scope:  bstr,
  event_payload: EventPayload,
}

AuthorEventHashPreimage = {
  version:         uint .size 1,
  ledger_scope:    bstr,
  sequence:        uint,
  prev_hash:       digest / null,
  causal_deps:     [* digest] / null,
  content_hash:    digest,
  header:          EventHeader,
  commitments:     [* Commitment] / null,
  payload_ref:     PayloadRef,
  key_bag:         KeyBag,
  idempotency_key: bstr .size (1..64),
  extensions:      { * tstr => any } / null,
}

; --- Append Head (post-append return artifact, §10.6) ---------------

AppendHead = {
  scope:                bstr,
  sequence:             uint,
  canonical_event_hash: digest,
}

; --- Key Registry (signing class — legacy flat shape) ----------------
; The legacy `SigningKeyEntry` shape is retained for byte-for-byte
; preservation across the Phase-1 v1.0.0 corpus. Verifiers accept both
; this flat shape and the `KeyEntry` taxonomy below; dispatch is on the
; presence of a top-level `kind` field. See §8.7 for the unified
; taxonomy and dispatch rules.

SigningKeyEntry = {
  kid:          kid,
  pubkey:       bstr,
  suite_id:     suite_id,
  status:       SigningKeyStatus,
  valid_from:   timestamp,
  valid_to:     timestamp / null,
  supersedes:   kid / null,
  attestation:  bstr / null,
}

SigningKeyStatus = &(
  Active:   0,
  Rotating: 1,
  Retired:  2,
  Revoked:  3,
)

; --- Key Registry (unified taxonomy, ADR 0006) -----------------------
; Phase-1 runtime: only `kind = "signing"` is populated. Reserved
; non-signing classes are envelope reservations; lint warns on emit.

KeyEntry = KeyEntrySigning / KeyEntryNonSigning

KeyEntrySigning = {
  kind:         "signing",
  kid:          kid,
  pubkey:       bstr,
  suite_id:     suite_id,
  status:       SigningKeyStatus,
  valid_from:   timestamp,
  valid_to:     timestamp / null,
  supersedes:   kid / null,
  attestation:  bstr / null,
}

KeyEntryNonSigning = {
  kind:         "tenant-root" / "scope" / "subject" / "recovery" / tstr,
  kid:          kid,
  suite_id:     suite_id,
  attributes:   TenantRootKeyAttributes / ScopeKeyAttributes /
                SubjectKeyAttributes / RecoveryKeyAttributes /
                { * tstr => any },
  extensions:   { * tstr => any } / null,
}

TenantRootKeyAttributes = {
  pubkey:           bstr .size 32,
  tenant_ref:       tstr,
  effective_from:   timestamp,
  supersedes:       bstr .size 16 / null,
}

ScopeKeyAttributes = {
  pubkey:              bstr .size 32,
  scope_ref:           bstr,
  parent_tenant_ref:   tstr,
  effective_from:      timestamp,
  supersedes:          bstr .size 16 / null,
}

SubjectKeyAttributes = {
  pubkey:            bstr .size 32,
  subject_ref:       tstr,
  authorized_for:    [+ bstr],
  effective_from:    timestamp,
  valid_to:          timestamp / null,
  supersedes:        bstr .size 16 / null,
}

RecoveryKeyAttributes = {
  pubkey:                  bstr .size 32,
  authorizes_recovery_for: [+ bstr .size 16],
  activation_quorum:       uint,
  activation_quorum_set:   [+ bstr .size 16] / null,
  effective_from:          timestamp,
  supersedes:              bstr .size 16 / null,
}

LedgerServiceWrapEntry = {
  ledger_id:         bstr,
  author_event_hash: digest,
  lak_version:       uint,
  ephemeral_pubkey:  bstr .size 32,
  wrapped_dek:       bstr,
  created_at:        timestamp,
  signature:         COSESign1Bytes,
}

; --- Checkpoint -------------------------------------------------------

Checkpoint = COSESign1Bytes

CheckpointPayload = {
  version:                uint .size 1,
  scope:                  bstr,
  tree_size:              uint,
  tree_head_hash:         digest,
  timestamp:              timestamp,
  anchor_ref:             bstr / null,
  prev_checkpoint_hash:   digest / null,
  extensions:             { * tstr => any } / null,
}

InclusionProof = {
  leaf_index:  uint,
  tree_size:   uint,
  leaf_hash:   digest,
  audit_path:  [* digest],
}

ConsistencyProof = {
  from_tree_size: uint,
  to_tree_size:   uint,
  proof_path:     [* digest],
}

; --- Export Manifest --------------------------------------------------

SignedExportManifest = COSESign1Bytes

ExportManifestPayload = {
  format:                      tstr,         ; "trellis-export/1"
  version:                     uint .size 1,
  generator:                   tstr,
  generated_at:                timestamp,
  scope:                       bstr,
  tree_size:                   uint,
  head_checkpoint_digest:      digest,
  registry_bindings:           [+ RegistryBinding],
  signing_key_registry_digest: digest,
  events_digest:               digest,
  checkpoints_digest:          digest,
  inclusion_proofs_digest:     digest,
  consistency_proofs_digest:   digest,
  payloads_inlined:            bool,
  external_anchors:            [* ExternalAnchor],
  posture_declaration:         PostureDeclaration,
  head_format_version:         uint,
  omitted_payload_checks:      [* OmittedPayloadCheck],
  ? interop_sidecars:            [* InteropSidecarEntry] / null,
  extensions:                  { * tstr => any } / null,
}

; Carried under
; ExportManifestPayload.extensions["trellis.export.supersession-graph.v1"] (§18.3b).
; Binds optional archive member 064-supersession-graph.json.
; Traceability: TR-CORE-170.
SupersessionGraphManifestExtension = {
  graph_digest:      digest,
  predecessor_count: uint,
}

; Carried under
; ExportManifestPayload.extensions["trellis.export.open-clocks.v1"] (§18.3c).
; Binds optional archive member open-clocks.json.
; Traceability: TR-CORE-172.
OpenClocksManifestExtension = {
  open_clocks_digest: digest,
  open_clock_count:   uint,
}

; Carried under
; ExportManifestPayload.extensions["trellis.export.witness-key-registry.v1"] (§18.3d).
; Binds optional archive member 031-witness-key-registry.cbor.
WitnessKeyRegistryManifestExtension = {
  witness_key_registry_digest: digest,
  entry_count:                 uint,
}

; Carried under
; ExportManifestPayload.extensions["trellis.export.seal-fence.v1"] (§18.3).
; Manifest-resident export identity and high-water fence.
SealFenceManifestExtension = {
  identity_rule:           "trellis-export-seal-fence-v1",
  bundle_scope:            bstr,
  export_attempt_id:       tstr,
  seal_version:            uint,
  event_count:             uint,
  high_water_sequence:     uint,
  head_checkpoint_digest:  digest,
  events_digest:           digest,
  policy_closure_digest:   digest / null,
}

; Carried under
; ExportManifestPayload.extensions["trellis.export.signed-acts.v1"] (§18.3).
; Binds optional archive member 066-signed-acts.cbor.
SignedActsManifestExtension = {
  catalog_digest: digest,
  catalog_ref:    "066-signed-acts.cbor",
  derivation_rule: tstr,
}

; Carried under
; ExportManifestPayload.extensions["trellis.export.policy-closure.v1"] (§18.3).
; Binds optional archive member 067-policy-closure.cbor.
PolicyClosureManifestExtension = {
  closure_digest:  digest,
  closure_ref:     "067-policy-closure.cbor",
  closure_version: tstr,
}

ExportManifestHashPreimage = {
  version:          uint .size 1,
  scope:            bstr,
  manifest_payload: ExportManifestPayload,
}

; Reserved under ADR 0003 discipline; producers without an active adapter
; emit null or [].
InteropSidecarEntry = {
  kind:               "scitt-receipt" /
                      "vc-jose-cose-event" /
                      "c2pa-manifest" /
                      "did-key-view" /
                      tstr,              ; extension via future ADR
  derivation_version: uint .size 1,     ; pinned per kind; bumps on wire break
  path:               tstr,              ; relative to export root;
                                         ; MUST start with "interop-sidecars/"
  content_digest:     bstr .size 32,     ; SHA-256 under domain tag trellis-content-v1
  source_ref:         tstr,              ; anchor back to canonical record derived from
  extensions:         { * tstr => any } / null,
}

OmittedPayloadCheck = {
  content_hash: digest,
  reason:       tstr,
}

RegistryBinding = {
  registry_digest:   digest,
  registry_format:   uint,
  registry_version:  tstr,
  bound_at_sequence: uint,
}

ExternalAnchor = {
  kind:         tstr,
  anchor_ref:   bstr,
  required:     bool,
  description:  tstr,
}

PostureDeclaration = {
  provider_readable:        bool,
  reader_held:              bool,
  delegated_compute:        bool,
  external_anchor_required: bool,
  external_anchor_name:     tstr / null,
  recovery_without_user:    bool,
  metadata_leakage_summary: tstr,
  ; ADR 0010 §"Field semantics" `identity_attestation_ref` clause:
  ; default REQUIRED non-null. Operators that admit unverified user
  ; attestations (notarial cases, public-comment intake without identity
  ; proof) opt in by setting this field true. Field is OPTIONAL on the
  ; wire; a verifier reading a Posture Declaration that omits the field
  ; MUST treat it as `false` (default-required posture).
  ? admit_unverified_user_attestations: bool,
}

; --- Watermark --------------------------------------------------------

Watermark = {
  scope:           bstr,
  tree_size:       uint,
  tree_head_hash:  digest,
  checkpoint_ref:  digest,
  built_at:        timestamp,
  rebuild_path:    tstr,
  ? projection_schema_id: tstr,
}

StaffViewDecisionBinding = {
  watermark:               Watermark,          ; §15.2; staff-view state seen at decision time
  staff_view_ref:          tstr / null,        ; optional RFC 3986 derived-artifact identifier
  stale_acknowledged:      bool,               ; true iff Companion §17.3 stale-view acknowledgement was recorded
  extensions:              { * tstr => any } / null,
}

; The §28 grammar mirrors the §19 prose definition byte-for-byte. When the
; prose adds an outcome slice, the appendix gains the matching field + struct
; in the same commit (mirror-discipline; ADR 0004 byte-authority).
VerificationReport = {
  structure_verified:         bool,
  integrity_verified:         bool,
  readability_verified:       bool,
  event_failures:             [* VerificationFailure],
  checkpoint_failures:        [* VerificationFailure],
  proof_failures:             [* VerificationFailure],
  posture_transitions:        [* PostureTransitionOutcome],
  erasure_evidence:           [* ErasureEvidenceOutcome],
  certificates_of_completion: [* CertificateOfCompletionOutcome],
  correction_preservations:   [* CorrectionPreservationOutcome],
  ? interop_sidecars:         [* InteropSidecarVerificationEntry],
  omitted_payload_checks:     [* OmittedPayloadCheck],
  warnings:                   [* tstr],
}

VerificationFailure = {
  location: tstr,
  code:     tstr,
  detail:   tstr,
}

; Posture-transition outcome (§19 step 6 / §A.5). Mirrors the §19 prose
; definition. `kind` (Posture-transition kind) distinguishes custody-model
; transitions from Posture disclosure-profile transitions; `failures`
; carries localized §19 codes.
PostureTransitionOutcome = {
  transition_id:           tstr,
  kind:                    tstr,   ; Posture-transition kind: "custody-model" or "disclosure-profile"
  event_index:             uint,
  from_state:              tstr,
  to_state:                tstr,
  continuity_verified:     bool,
  declaration_resolved:    bool,
  attestations_verified:   bool,
  failures:                [* tstr],
}

; Erasure-evidence outcome (§19 step 6b; ADR 0005). Mirrors the §19 prose.
ErasureEvidenceOutcome = {
  evidence_id:           tstr,
  event_index:           uint,
  kid_destroyed:         bstr,
  destroyed_at:          timestamp,
  cascade_scopes:        [* tstr],
  completion_mode:       tstr,
  signature_verified:    bool,
  post_erasure_uses:     uint,
  post_erasure_wraps:    uint,
  cascade_violations:    [* tstr],
  failures:              [* tstr],
}

; Certificate-of-completion outcome (§19 step 6c; ADR 0007). Mirrors the
; §19 prose.
CertificateOfCompletionOutcome = {
  certificate_id:                tstr,
  event_index:                   uint,
  completed_at:                  timestamp,
  signer_count:                  uint,
  attachment_resolved:           bool,
  all_signing_events_resolved:   bool,
  chain_summary_consistent:      bool,
  failures:                      [* tstr],
}

; ADR 0066 correction-preservation report evidence. This is populated when a
; readable `correctionAuthorized` / `responseCorrection` payload is present.
; It does not participate in the §19 step-9 integrity fold by itself.
CorrectionPreservationOutcome = {
  event_index:             uint,
  correction_event_hash:   digest,
  target_event_hash:       tstr / null,
  corrected_field_set:     [* tstr],
  field_values:            [* CorrectionFieldValue],
}

CorrectionFieldValue = {
  field_path:              tstr,
  original_value_cbor:     bstr,
  corrected_value_cbor:    bstr,
}

; Interop-sidecar per-entry verification outcome (§18.3a / ADR 0008).
; One entry per `interop_sidecars[i]` declared in the manifest, in
; manifest-listed order. Phase-1 verifiers populate this when at least
; one entry is dispatched (`c2pa-manifest@v1`, `did-key-view@v1`);
; empty otherwise.
InteropSidecarVerificationEntry = {
  kind:                 tstr,
  path:                 tstr,
  derivation_version:   uint .size 1,
  content_digest_ok:    bool,
  kind_registered:      bool,
  phase_1_locked:       bool,
  failures:             [* tstr],
}

; --- User-content attestation (ADR 0010) -----------------------------
; Carried under EventPayload.extensions["trellis.user-content-attestation.v1"]
; (§6.7). Signature preimage uses domain tag
; `trellis-user-content-attestation-v1` (§9.8). Verifier obligations live
; in §19 step 6d.

UserContentAttestationPayload = {
  attestation_id:           tstr,                  ; stable within ledger_scope; idempotent re-emit by hash
  attested_event_hash:      digest,                ; canonical_event_hash of the host event being attested
  attested_event_position:  uint,                  ; 0-based sequence within ledger_scope
  attestor:                 tstr,                  ; principal URI (NOT operator URI; Companion §6.4)
  identity_attestation_ref: digest / null,         ; canonical_event_hash of an identity-attestation event;
                                                   ; null only when the deployment Posture Declaration admits
                                                   ; unverified attestors (default REQUIRED non-null)
  signing_intent:           tstr,                  ; URI per RFC 3986; meaning per WOS Signature Profile registry
  attested_at:              timestamp,              ; MUST equal envelope authored_at exactly
  signature:                bstr,                  ; detached Ed25519 over dCBOR([attestation_id,
                                                   ;   attested_event_hash, attested_event_position,
                                                   ;   attestor, identity_attestation_ref, signing_intent,
                                                   ;   attested_at]) under tag trellis-user-content-attestation-v1
  signing_kid:              kid,                   ; §8 KeyEntry signing-class kid (bstr .size 16);
                                                   ; MUST be Active or Rotating within §8.4 rotation grace
                                                   ; at attested_at; per ADR 0004 byte-authority reconciled
                                                   ; against Rust types — ADR 0010 prose draft used `tstr`
                                                   ; informally but every other kid slot in the envelope is
                                                   ; the 16-byte digest of `dCBOR(suite_id) || pubkey_raw`.
  extensions:               { * tstr => any } / null,
}
```

---

## 29. Appendix B — Example Events and Exports

*This appendix is informative; the authoritative grammar is Appendix A and the authoritative bytes are the fixture vectors (§27).*

**Key-order caveat.** Example payloads in this appendix are shown with keys in a logical/reading order for human orientation. Actual dCBOR serialization MUST sort map keys in byte-wise lexicographic order of their canonical CBOR encoding per §5.1; for example, in `EventPayload` the first three keys by that ordering are `version` (`0x67 …`), `sequence` (`0x68 …`), `ledger_scope` (`0x6c …`), not `version → ledger_scope → sequence`. The authoritative bytes for every worked example live in `fixtures/vectors/append/...` and related fixture directories; where the prose below and the fixtures disagree, the fixtures are normative.

### 29.1 A minimal first event (hex-decoded dCBOR)

A Formspec `session.started` event, the first in a response ledger. Values are schematic: digest bytes truncated to `01 02 03 …` placeholders; real fixtures will use actual cryptographic outputs.

Decoded COSE payload structure:

```
EventPayload {
  version: 1,
  ledger_scope: h'7265732d303030303031',   ; "res-000001"
  sequence: 0,
  prev_hash: null,
  causal_deps: null,
  author_event_hash: h'01010101...32bytes',
  content_hash: h'02020202...32bytes',     ; SHA-256 over ciphertext
  header: {
    event_type: h'666f726d737065632e617574686f726564', ; "formspec.authored" bytes
    authored_at: 1744963200,               ; 2026-04-18T00:00:00Z
    retention_tier: 1,
    classification: h'7075626c6963',       ; "public"
    outcome_commitment: null,
    subject_ref_commitment: h'03030303...32bytes',
    tag_commitment: null,
    witness_ref: null,
    extensions: null
  },
  commitments: null,
  payload_ref: {
    ref_type: "inline",
    ciphertext: h'baadf00d...N-bytes',
    nonce: h'06060606...12bytes'
  },
  key_bag: {
    entries: [
      {
        recipient: h'7265616465722d686f6c64', ; "reader-hold"
        suite: 1,                             ; HPKE Base X25519 + HKDF-SHA256 + ChaCha20-Poly1305
        ephemeral_pubkey: h'04040404...32bytes',
        wrapped_dek: h'05050505...N-bytes'
      }
    ]
  },
  idempotency_key: h'0189b2c0...16bytes',  ; UUIDv7
  extensions: null
}
```

The wire event is a COSE_Sign1 value whose protected header includes `alg = -8`, `kid = h'deadbeef...16bytes'`, and `suite_id = 1`, and whose payload is the dCBOR bytes above.

Hex dump of the EventPayload dCBOR serialization (first bytes shown schematic):

```
aD                           ; map(13) — the EventPayload map
  67 76 65 72 73 69 6f 6e    ; "version"
  01                          ; 1
  6c 6c 65 64 67 65 72 ...    ; "ledger_scope"
  4a 72 65 73 2d ...          ; h'res-...'
  68 73 65 71 75 65 6e 63 65 ; "sequence"
  00                          ; 0
  ...                        ; remaining fields in lexicographic key order
```

(Full byte-level dump is in `fixtures/vectors/append/001-minimal-first-event.cbor.hex`.)

### 29.2 A signed checkpoint

```
CheckpointPayload {
  version: 1,
  scope: h'7265732d303030303031',          ; "res-000001"
  tree_size: 7,
  tree_head_hash: h'aabbccdd...32bytes',
  timestamp: 1744974000,
  anchor_ref: null,
  prev_checkpoint_hash: null,              ; first checkpoint of the scope
  extensions: null
}
```

The wire checkpoint is a COSE_Sign1 value over this payload with protected-header `alg`, `kid`, and `suite_id`.

### 29.3 Export manifest

```
ExportManifestPayload {
  format: "trellis-export/1",
  version: 1,
  generator: "trellis-cli/0.1.0",
  generated_at: 1744974100,
  scope: h'7265732d303030303031',
  tree_size: 7,
  head_checkpoint_digest: h'ffeeddcc...32bytes',
  registry_bindings: [
    {
      registry_digest: h'11223344...32bytes',
      registry_format: 1,
      registry_version: "2026.04",
      bound_at_sequence: 0
    }
  ],
  signing_key_registry_digest: h'...',
  events_digest: h'...',
  checkpoints_digest: h'...',
  inclusion_proofs_digest: h'...',
  consistency_proofs_digest: h'...',
  payloads_inlined: true,
  external_anchors: [],
  posture_declaration: {
    provider_readable: false,
    reader_held: true,
    delegated_compute: false,
    external_anchor_required: false,
    external_anchor_name: null,
    recovery_without_user: false,
    metadata_leakage_summary: "Envelope reveals event_type, authored_at (nanosecond granularity), retention_tier, classification, and protected-header kid. Outcome, subject, and tags are committed, not plaintext."
  },
  head_format_version: 1,
  omitted_payload_checks: [],
  extensions: null
}
```

The wire `000-manifest.cbor` member is a COSE_Sign1 value over this payload with protected-header `alg`, `kid`, and `suite_id`.

### 29.4 Worked verification trace

Given `trellis-export-res-000001-7-ffeeddcc.zip` (the export of §29.1–29.3), a verifier runs:

```
1. Open ZIP. Layout deterministic? yes.
2. Read 000-manifest.cbor. Verify COSE_Sign1 ⇒ valid.
3. Check archive digests:
     SHA-256(010-events.cbor)       = manifest.events_digest        ✓
     SHA-256(040-checkpoints.cbor)  = manifest.checkpoints_digest   ✓
     (etc.)
4. For each event e_0..e_6:
     verify signature          ✓
     recompute canonical_event_hash ✓
     recompute author_event_hash   ✓
     verify content_hash       ✓
     verify prev_hash chain    ✓
     causal_deps null          ✓ (Phase 1)
     registry binding resolves ✓
5. For the single checkpoint c_7:
     verify signature          ✓
     recompute Merkle root     ✓ = c_7.tree_head_hash
     prev_checkpoint_hash null ✓ (first checkpoint)
6. For each inclusion proof:
     recompute root            ✓
7. No external anchors declared; skip.
8. verified = true.
9. Return (true, report with 0 failures).
```

A tamper fixture `fixtures/vectors/tamper/005-flipped-byte-in-event-3.zip` modifies one byte of `events[3].payload_ref.ciphertext`. On re-run:

```
4. Event e_3: content_hash mismatch ⇒ report.event_failures[3] = content_hash_mismatch
            : author_event_hash mismatch (covers ciphertext) ⇒ report.event_failures[3] += author_event_hash_mismatch
            : signature verification fails ⇒ report.event_failures[3] += signature_invalid
5. checkpoint c_7: Merkle root mismatch ⇒ report.checkpoint_failures[0] = tree_head_hash_mismatch
   (because event e_3's canonical_event_hash changed)
8. verified = false.
```

The report localizes the tamper to sequence 3 and to the ciphertext field specifically, across three independent checks.

---

## 30. Traceability Anchors

This non-normative section anchors the traceability matrix rows that correspond to Core obligations. The prose in §§1–29 is normative; `TR-CORE-*` rows in `trellis-requirements-matrix.md` are traceability aids and must be corrected if they conflict with this document.

Core traceability rows:

- TR-CORE-001, TR-CORE-002, TR-CORE-003, TR-CORE-004, TR-CORE-005, TR-CORE-006, TR-CORE-007
- TR-CORE-010, TR-CORE-011, TR-CORE-012, TR-CORE-013, TR-CORE-014, TR-CORE-015, TR-CORE-016, TR-CORE-017
- TR-CORE-020, TR-CORE-021, TR-CORE-022, TR-CORE-023, TR-CORE-024, TR-CORE-025
- TR-CORE-030, TR-CORE-031, TR-CORE-032, TR-CORE-033, TR-CORE-034, TR-CORE-035, TR-CORE-036, TR-CORE-037, TR-CORE-038
- TR-CORE-040, TR-CORE-041, TR-CORE-042, TR-CORE-043, TR-CORE-044, TR-CORE-045, TR-CORE-046
- TR-CORE-050, TR-CORE-051, TR-CORE-052, TR-CORE-053
- TR-CORE-060, TR-CORE-061, TR-CORE-062, TR-CORE-063, TR-CORE-064, TR-CORE-065, TR-CORE-066, TR-CORE-067
- TR-CORE-070, TR-CORE-071, TR-CORE-072
- TR-CORE-080, TR-CORE-081, TR-CORE-082
- TR-CORE-090, TR-CORE-091, TR-CORE-092, TR-CORE-093
- TR-CORE-100, TR-CORE-101, TR-CORE-102, TR-CORE-103
- TR-CORE-110, TR-CORE-111, TR-CORE-112, TR-CORE-113
- TR-CORE-120, TR-CORE-121, TR-CORE-122, TR-CORE-123, TR-CORE-124, TR-CORE-125, TR-CORE-126
- TR-CORE-130, TR-CORE-131, TR-CORE-132, TR-CORE-133, TR-CORE-134
- TR-CORE-140, TR-CORE-141, TR-CORE-142, TR-CORE-143
- TR-CORE-145 (interop sidecar envelope reservation; ADR 0008)
- TR-CORE-158, TR-CORE-159, TR-CORE-160, TR-CORE-161, TR-CORE-162 (Core §17 idempotency wire-contract)
- TR-CORE-163, TR-CORE-164, TR-CORE-165, TR-CORE-166, TR-CORE-167, TR-CORE-168 (Core §18.3a interop-sidecar dispatched-verifier obligations; Waves 25/29/31 / ADR 0008)
- TR-CORE-169, TR-CORE-170 (ADR 0066 supersession linkage and export graph)
- TR-CORE-172 (ADR 0067 open statutory-clock export catalog)

## 31. References

### 31.1 Normative references

- **[RFC 2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
- **[RFC 8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.
- **[RFC 8032]** Josefsson, S., Liusvaara, I., "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017.
- **[RFC 8610]** Birkholz, H., Vigano, C., Bormann, C., "Concise Data Definition Language (CDDL)", RFC 8610, June 2019.
- **[RFC 8949]** Bormann, C., Hoffman, P., "Concise Binary Object Representation (CBOR)", STD 94, RFC 8949, December 2020.
- **[RFC 9052]** Schaad, J., "CBOR Object Signing and Encryption (COSE): Structures and Process", STD 96, RFC 9052, August 2022.
- **[RFC 9180]** Barnes, R., Bhargavan, K., Lipp, B., Wood, C., "Hybrid Public Key Encryption", RFC 9180, February 2022.
- **[RFC 9562]** Davis, K., Peabody, B., Leach, P., "Universally Unique IDentifiers (UUIDs)", RFC 9562, May 2024.
- **[RFC 6962]** Laurie, B., Langley, A., Kasper, E., "Certificate Transparency", RFC 6962, June 2013. (Merkle tree construction model.)
- **[FIPS 180-4]** NIST, "Secure Hash Standard (SHS)", FIPS PUB 180-4, August 2015.
- **[Formspec Core]** Formspec Working Group, "Formspec Core Specification v1.0".
- **[Formspec Respondent Ledger]** Formspec Working Group, "Formspec Respondent Ledger Specification v0.1" (`specs/audit/respondent-ledger-spec.md`). Cited at §§22.2–22.5 for event and checkpoint binding.
- **[WOS Kernel]** WOS Working Group, "WOS Kernel Specification v1.0". Cited at §§23.1–23.4 for `custodyHook` binding.

### 31.2 Informative references

- **[FIPS 204]** NIST, "Module-Lattice-Based Digital Signature Standard (ML-DSA)", FIPS 204, August 2024. Reserved for Phase 2+ post-quantum `suite_id`.
- **[FIPS 205]** NIST, "Stateless Hash-Based Digital Signature Standard (SLH-DSA)", FIPS 205, August 2024. Reserved for Phase 2+ post-quantum `suite_id`.
- **[WOS Assurance]** WOS Working Group, "WOS Assurance Specification". Referenced for legal-sufficiency disclosure obligations (§20.4).
- **Trellis Operational Companion (Phase 2)** — separate normative document for projection and derived-artifact discipline, metadata-budget declarations, delegated-compute honesty, posture-transition auditability, snapshot watermarks, and rebuild semantics.
