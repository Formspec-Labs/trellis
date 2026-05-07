# Trellis — COMPLETED

Historical rollup of landed Trellis work. Organized wave-by-wave.

**This file is for:** wave dispatch history, closed sprint-queue items, closed
stream items, completed critical-path steps. Anyone asking "what's been
done?" reads this.

**This file is not for:** active tactical work (→ [`TODO.md`](TODO.md)),
strategy (→ [`thoughts/product-vision.md`](thoughts/product-vision.md)),
ratification scope (→ [`ratification/ratification-checklist.md`](ratification/ratification-checklist.md)),
or implementation plans (→ [`thoughts/specs/`](thoughts/specs/)).

Prune aggressively — `git log` is the real record. Entries here capture
cross-commit wave context that a raw log cannot reconstruct.

---

## Wave-by-wave dispatch history

### Wave 47 (2026-05-07) — TODO #11 ResponseCorrection coordination

- Closed the remaining Trellis ADR 0066 coordination row by landing the
  Formspec `ResponseCorrection` producer shape that Trellis correction-
  preservation reports were waiting on.
- Formspec Respondent Ledger now defines `response.correction-recorded` with
  `recordKind = "responseCorrection"` and a `data` payload carrying the
  correction target event hash, corrected field subset, original/corrected
  field values, correction reason, and authorization event hash.
- Synced parent `PLANNING.md` PLN-0050 and `TODO-STACK.md`; WOS
  `CorrectionAuthorized` remains the sibling governance authorization record,
  while Trellis can report both readable `correctionAuthorized` and
  `responseCorrection` payloads.

Verification:
- `uv run --with pytest --with jsonschema python -m pytest tests/conformance/schemas/test_respondent_ledger_schema.py -q`.

### Wave 46 (2026-05-07) — TODO #14 stack security disclosure policy

- Added root `SECURITY.md` with private vulnerability-reporting intake,
  stack-wide scope, out-of-scope cases, response expectations, and coordinated
  disclosure posture.
- Included Trellis envelope, append, verify, export, COSE, HPKE, key registry,
  store, and conformance-vector behavior in the in-scope surface.
- Synced root `README.md`, `STACK.md`, parent `PLANNING.md` PLN-0308, parent
  `TODO-STACK.md`, and Trellis `TODO.md`.

Verification:
- Docs-only change; reviewed linked paths and `rg` security-policy references.

### Wave 45 (2026-05-07) — TODO #21 cadence subtype fixture breadth

- Added non-height snapshot-cadence projection fixtures:
  `projection/006-cadence-positive-time` and
  `projection/007-cadence-event-gap`.
- Extended the cadence generator so the same deterministic chain can emit
  height-based, time-driven, and event-driven cadence reports while preserving
  the existing required-tree-size runner contract.
- Rust and Python conformance now replay 138 committed vectors.

Verification:
- `cargo test -p trellis-conformance`.
- `PYTHONPATH=trellis-py/src uv run --with cbor2 --with cryptography python -m trellis_py.conformance --vectors fixtures/vectors`.
- `uv run --with cbor2 --with cryptography python scripts/check-specs.py`.

### Wave 44 (2026-05-07) — TODO #5 Respondent Ledger hash-pair schema closure

- Tightened the Formspec Respondent Ledger event schema so `eventHash` and
  `priorEventHash` are structurally paired: an event may omit both for a
  non-chained ledger, but cannot carry only one half of the integrity-chain
  seam.
- Added conformance coverage proving half-chained events are rejected while the
  first Trellis-wrapped event may still use `priorEventHash: null`.
- Synced the schema copy used by the Formspec MCP package.

Verification:
- `uv run --with pytest --with jsonschema python -m pytest tests/conformance/schemas/test_respondent_ledger_schema.py -q`.

### Wave 43 (2026-05-07) — TODO #1 PLN-0379..0398 drift audit

- Audited the live parent stack-closure rows PLN-0379..0398 against the
  accepted WOS custody-hook companion and Trellis Core custody/composition
  surfaces.
- Confirmed the phantom `tag` / `payload` / `prior_event_hash` /
  `producer_signature` seam is confined to PLN-0385's historical correction
  text and explanatory downstream notes that explicitly reject it.
- Confirmed the sibling rows already point at the accepted four-field WOS
  append input (`caseId` / `recordId` / `eventType` / `record`), Trellis
  `prev_hash`, and envelope COSE_Sign1 boundaries where those details are
  material. No parent-row semantic correction was required.

Verification:
- `rg` audit over parent `PLANNING.md`, WOS custody-hook companion, WOS TODOs,
  and Trellis Core custody sections.

### Wave 42 (2026-05-07) — TODO #15 Python WOS verifier carve-out

- `trellis_py.verify` no longer executes WOS-domain rescission, catalog,
  intake/case-created, or clock-calendar semantics as part of Core integrity
  verification.
- Added `trellis_py.verify_wos` as the Python WOS-domain composition layer,
  mirroring the Rust `trellis-verify` + `trellis-verify-wos` split.
- Python conformance now routes WOS-coupled vector expectations through the
  composed WOS verifier while keeping Core-only vectors on the Core report.

Verification:
- `PYTHONPATH=trellis-py/src uv run --with cbor2 --with cryptography --with pytest python -m pytest trellis-py/tests`.
- `PYTHONPATH=trellis-py/src uv run --with cbor2 --with cryptography python -m trellis_py.conformance --vectors fixtures/vectors`.

### Wave 41 (2026-05-07) — TODO #15 Rust WOS verifier extraction

- `trellis-verify` now exposes a domain-validator seam and keeps WOS record
  semantics out of the Core verifier.
- Added sibling adapter crate `trellis-verify-wos` for WOS event-type literals,
  record parsing, rescission terminality, clock-calendar checks, and
  signature/intake catalog field matching.
- `trellis-conformance` routes WOS-coupled fixture expectations through the
  composed WOS verifier while integrity-only vectors remain on `trellis-verify`.
- Core §16/§19 and §6.7 now distinguish Core byte-integrity obligations from
  consumer-owned domain validation; WOS-domain obligations live in
  `specs/wos-trellis-verification.md`.
- `wos-server` had no live code dependency to migrate in this checkout. The
  Python verifier carve-out closed in Wave 42.

Verification:
- `cargo check -p trellis-verify -p trellis-verify-wos`.
- `cargo test -p trellis-verify --lib`.
- `cargo test -p trellis-verify-wos --lib`.
- `cargo test -p trellis-conformance`.
- `cargo nextest run -p trellis-verify -p trellis-verify-wos -p trellis-conformance`.
- `uv run --with cbor2 --with cryptography python scripts/check-specs.py`.

### Wave 40 (2026-05-07) — TODO #11 correction-preservation report output

- `trellis-verify` now adds `correction_preservations[]` to
  `VerificationReport` for readable ADR 0066 correction records.
- The report entry surfaces the correction event hash, target event hash,
  corrected field set, and optional original/corrected field value pairs as
  canonical CBOR bytes when upstream producers include them.
- Current WOS `correctionAuthorized` records carry target hash and field-set
  evidence; Formspec `ResponseCorrection` and WOS runtime emission remain
  producer-owned work in sibling TODOs.
- Existing supersession graph verifier coverage already closes the byte-equal
  predecessor-checkpoint linkage half of ADR 0066 D-3.

Verification:
- `cargo test -p trellis-verify`.
- `cargo test -p trellis-conformance`.
- `uv run --with cbor2 --with cryptography python scripts/check-specs.py`
  passed with the existing non-signing key reservation warnings.
- `cargo fmt --check --manifest-path Cargo.toml -p trellis-verify`.
- `git diff --check`.

### Wave 39 (2026-05-07) — TODO #12 ADR 0067 statutory clocks

- Rust and Python export verifiers now walk clock records in chain order,
  tracking active and paused segments by `clockId`.
- A resumed `clockStarted` after `clockResolved(resolution="paused")` must keep
  the paused segment's `clockKind` and `calendarRef`; mismatch is localized as
  `clock_calendar_mismatch`.
- Core §19.1, the requirements matrix, and `scripts/check-specs.py` now include
  the `clock_calendar_mismatch` failure kind.
- Added generator `fixtures/vectors/_generator/gen_adr0067_clocks.py`.
- Added active append fixtures `append/043-clock-started`,
  `append/044-clock-satisfied`, `append/045-clock-elapsed`, and
  `append/046-clock-paused-resumed`.
- Added `verify/018-export-043-open-clocks`, which manifest-binds
  `open-clocks.json` through `trellis.export.open-clocks.v1` and covers
  TR-CORE-172.
- Added `tamper/051-clock-calendar-mismatch`, which proves ADR 0067 D-4 refusal
  on a validly signed pause/resume chain that changes `calendarRef`.
- WOS `TODO.md` now points at the active Trellis fixture IDs instead of the
  stale `014–018` range.

Verification:
- `cargo fmt --check`.
- `python -m py_compile trellis-py/src/trellis_py/verify.py
  fixtures/vectors/_generator/gen_adr0067_clocks.py`.
- `cargo test -p trellis-verify`.
- `cargo test -p trellis-conformance`.
- `PYTHONPATH=trellis-py/src uv run --with cbor2 --with cryptography python
  -m trellis_py.conformance --vectors fixtures/vectors`.
- `uv run --with cbor2 --with cryptography python scripts/check-specs.py`.
- `git diff --check`.

### Wave 38 (2026-05-07) — TODO #11 supersession graph export contract

- Core §6.7 now registers
  `ExportManifestPayload.extensions["trellis.export.supersession-graph.v1"]`
  as the ADR 0066 manifest hook for cross-chain supersession traversal.
- Core §18 adds optional root member `064-supersession-graph.json`, encoded as
  Trellis canonical JSON and bound by the extension's `graph_digest`.
- Core §19 adds supersession graph validation: head-chain equality,
  per-event `trellis.supersedes-chain-id.v1` row matching, breadth-first
  predecessor traversal, cycle failure, and optional embedded predecessor
  package checkpoint matching.
- Core §18 reserves `070-predecessors/` for optional embedded predecessor
  export ZIPs named by `064-supersession-graph.json` `bundle_path` entries.
- Requirements matrix TR-CORE-170 anchors the graph contract as
  `spec-cross-ref`. Runtime verifier implementation and fixtures remain open
  under TODO #11.
- Verification: `uv run --with cbor2 --with cryptography python
  scripts/check-specs.py`; `git diff --check`.

### Wave 37 (2026-05-07) — TODO #11 ADR 0066 append vectors

- Added generator `fixtures/vectors/_generator/gen_append_011_to_015.py` for
  ADR 0066's five accepted modes.
- Added active append fixtures:
  `append/011-correction`, `append/012-amendment`,
  `append/013-rescission`, `append/014-reinstatement`, and
  `append/015-supersession`.
- The first four vectors are ordinary same-chain WOS governance appends; the
  supersession vector is a new-chain genesis event carrying
  `EventPayload.extensions["trellis.supersedes-chain-id.v1"]` as
  `SupersedesChainIdPayload { chain_id, checkpoint_hash }`.
- Requirements matrix TR-CORE-169 is now fixture-backed by
  `append/015-supersession`; TODO #11's single-chain and supersession-extension
  fixture checkboxes are closed. Verifier D-3 semantics and
  `supersession-graph.json` export composition remain open.
- Verification: `cargo test -p trellis-conformance`;
  `PYTHONPATH=trellis-py/src uv run --with cbor2 --with cryptography python
  -m trellis_py.conformance --vectors fixtures/vectors`;
  `uv run --with cbor2 --with cryptography python scripts/check-specs.py`;
  `git diff --check`.

### Wave 36 (2026-05-07) — TODO #11/#12 append-ID reservation

- Trellis TODO now reserves ADR 0066 amendment / rescission / reinstatement /
  supersession vectors as the contiguous open range `append/011` …
  `append/015`.
- ADR 0067 clock vectors move out of that range to the next open append
  namespace, `append/043-clock-started` … `append/046-clock-paused-resumed`.
- No landed vector is renumbered: `append/018-attachment-bound`,
  `append/019-wos-signature-affirmation`, `append/041-aead-retry-determinism`,
  and `append/042-idempotency-retry-noop` remain stable.
- Parent ADR / WOS TODO references still need their own sync because those
  files are outside this Trellis-owned checkpoint and are currently dirty in
  the parent workspace.
- Verification: fixture namespace inspected with `find fixtures/vectors/append
  -maxdepth 1 -type d`; `uv run --with cbor2 --with cryptography python
  scripts/check-specs.py`; `git diff --check`.

### Wave 35 (2026-05-07) — TODO #11 supersedes-chain CDDL pin

- Core §6.7 now names `SupersedesChainIdPayload` for
  `EventPayload.extensions["trellis.supersedes-chain-id.v1"]` instead of
  leaving ADR 0066's `{ chain_id, checkpoint_hash }` linkage as prose only.
- Core §28 CDDL defines `chain_id = bstr` and
  `SupersedesChainIdPayload { chain_id, checkpoint_hash }`, with null /
  absent extension value meaning the event does not link to a superseded chain.
- Requirements matrix TR-CORE-169 anchors the reject-if-unknown-at-version and
  canonical hash-binding obligation as `spec-cross-ref` coverage; supersession
  vector coverage remains open under TODO #11 until the append-ID collision is
  resolved.
- Verification: `uv run --with cbor2 --with cryptography python
  scripts/check-specs.py`; `git diff --check`.

### Wave 34 (2026-05-07) — TODO #9 timestamp encoding closeout

Closes Trellis TODO item #9 after ADR 0069 D-2.1 blessed Trellis's existing
`[seconds, nanos]` CBOR timestamp shape instead of a single `uint64`
nanosecond counter. The closeout keeps the byte-protocol stable while adding
the missing negative that proves array-shaped timestamps still enforce the
nanosecond component bound.

Train:
- Core §19.1, the requirements matrix, Rust verifier taxonomy, Python verifier
  taxonomy, and `scripts/check-specs.py` now include
  `timestamp_nanos_out_of_range`.
- `trellis-verify` maps timestamp nanos values above `999999999` to that
  typed structural failure, with unit coverage for the decoder bridge.
- Fixture corpus gains `tamper/045-timestamp-nanos-out-of-range`, generated
  from `append/001` and re-signed so signatures verify before timestamp decode
  rejects the malformed `[1745000000, 1000000000]` value.
- TODO #9 is marked closed; leap-second parser coverage is explicitly left to
  JSON-string stack surfaces because Trellis CBOR timestamps are numeric.

Verification:
- `cargo test -p trellis-verify` passed (103 tests).
- `cargo test -p trellis-conformance` passed (11 tests across unit + store parity).
- `uv run --with cbor2 --with cryptography --with pytest python -m pytest trellis-py/tests -q` passed (70 tests).
- `PYTHONPATH=trellis-py/src uv run --with cbor2 --with cryptography python -m trellis_py.conformance --vectors fixtures/vectors` passed (119 vectors, 0 failures).
- `uv run --with cbor2 --with cryptography python scripts/check-specs.py` passed with the existing non-signing key reservation warnings.

### Wave 33 (2026-05-07) — Python parity for TODO #30 sidecar taxonomy

Closes the remaining Python G-5 parity residue for the TODO #30 interop
sidecar missing-vs-mismatch split. The Rust/spec/fixture train had already
separated absent manifest-listed sidecars (`interop_sidecar_missing`) from
present-but-mutated sidecars (`interop_sidecar_content_mismatch`); the Python
verifier still used the older digest-mismatch bucket and, under current
`cbor2`, rejected COSE_Sign1 bodies decoded as tuples before reaching the
sidecar classifier.

Train:
- `trellis_py.verify` accepts tuple-backed COSE_Sign1 arrays and frozen empty
  unprotected maps emitted by current `cbor2`.
- Python sidecar verification now checks listed-file presence before digest
  recomputation and emits `interop_sidecar_missing` for `tamper/044`.
- `trellis_py.conformance` accepts tuple-backed COSE_Sign1 bodies when reading
  fixture payloads.
- `trellis-py/tests/test_tamper_vectors.py` pins the `tamper/044` taxonomy so
  the Python verifier cannot collapse the two failure modes again.

Verification: `uv run --with cbor2 --with cryptography --with pytest python -m
pytest trellis-py/tests/test_tamper_vectors.py
trellis-py/tests/test_interop_c2pa_byte_oracle.py -q` passed (5 tests), and
`PYTHONPATH=trellis-py/src uv run --with cbor2 --with cryptography python -m
trellis_py.conformance --vectors fixtures/vectors` passed (118 vectors, 0
failures).

### Wave 32 (2026-05-06) — TODO #2/#3 verify-engine hygiene closeout

Closes Trellis TODO items #2 and #3 as a docs-only evidence sweep. The
implementation had already landed across the recent verify-engine refactor
train; the live TODO rows still showed as open despite every subtask being
checked off.

Evidence:
- #2 dedup: `trellis-types` now owns CBOR map helpers, `decode_cbor_value`,
  `checkpoint_digest`, `sha256_bytes`, and the idempotency-key bound helper;
  CDDL, verify, conformance, stores, and interop crates consume those helpers.
  `VerifyErrorKind` / `VerificationFailureKind` replace stringly typed public
  error discriminants, and parity tests lock their wire strings.
- #2 API shape: `VerifyEventSetOptions` replaced the broad
  `verify_event_set_with_classes` parameter list.
- #3 allocation / decode hygiene: the main verify pass stores decoded
  `EventDetails`, finalizers consume lookup pools instead of re-decoding the
  same events, extension payload collectors move values where practical, and
  `VerificationReport::integrity_verified_from_parts` centralizes the integrity
  fold.
- #3 conformance diagnostics: vector failures now include fixture-local
  context instead of bare unwrap panics.

Verification: docs-only closeout after the Wave 31 validation batch; no code
changed in this wave.

### Wave 31 (2026-05-06) — TODO #30 interop sidecar missing-vs-mismatch split

Closes Trellis TODO item #30 by separating sidecar packaging omission from
sidecar byte mutation in the Phase-1 dispatched verifier.

Train:
- `trellis-verify::verify_interop_sidecars` now returns
  `interop_sidecar_missing` when `manifest.interop_sidecars[i].path` is absent
  from the export ZIP, before digest recomputation. Present bytes with a
  disagreeing digest still return `interop_sidecar_content_mismatch`.
- `VerificationFailureKind` gains the append-only wire value
  `interop_sidecar_missing`; unit coverage pins the direct verifier path.
- Core §18.3a / §19.1, ADR 0008, and the requirements matrix add TR-CORE-168
  for the listed-file presence gate while narrowing TR-CORE-163 to digest-only
  mismatch.
- Fixture corpus gains `tamper/044-interop-sidecar-missing`, generated from the
  same Wave 25 interop-sidecar reproducibility script as `tamper/037..040`.

Verification: `cargo test -p trellis-verify`, `cargo test -p
trellis-conformance`, and `uv run --with cbor2 --with cryptography python
scripts/check-specs.py` passed.

### Wave 30 (2026-05-06) — TODO #6 key-rotation grace-window semantics

Closes Trellis TODO item #6 by ratifying the `Rotating` signing-key
overlap as a bounded signing-time authority, not an indefinite second
active state.

Train:
- Core §8.4 pins the predicate: `Rotating` admits new signatures only
  when `valid_from <= signature_time <= valid_to`; `valid_to = null`
  means the overlap is still open in the embedded registry snapshot.
- Core §19 step 6d step 6 and Core §28 UCA CDDL comments now admit
  user-content attestations under `Active` or in-overlap `Rotating`
  signing keys; `Retired`, `Revoked`, and out-of-overlap `Rotating`
  still surface `user_content_attestation_key_not_active`.
- Companion §20.8 OC-147 records the operator obligation to publish
  the overlap in the registry row and not represent indefinite
  dual-active issuance as a completed rotation. Matrix rows updated:
  TR-CORE-156 and new TR-OP-133.
- `trellis-verify` captures `SigningKeyEntry.valid_from`, applies the
  rotation predicate in UCA finalization, and adds unit coverage for
  in-overlap acceptance plus after-`valid_to` rejection.
- Fixture corpus gains `tamper/043-uca-rotating-after-valid-to`.
  `tamper/034-uca-key-not-active` wording was refreshed so the
  Retired-key negative remains correct after rotation grace ratification.

Verification: targeted `cargo test -p trellis-verify rotating_key`
passed before the final validation batch.

### Wave 29 (2026-05-05) — TODO #5 `did-key-view` adapter activation

Closes Trellis TODO item #5 by activating ADR 0008's `did-key-view@v1`
sidecar kind under the same digest-binding discipline as
`c2pa-manifest@v1`.

Train:
- New `trellis-interop-did` crate parses legacy `SigningKeyEntry` and
  ADR 0006 `KeyEntrySigning` registry rows, skips non-signing entries,
  rejects duplicate signing `kid` values and non-Ed25519 suites, and
  emits compact deterministic JSON sorted by `kid`.
- `trellis-verify` admits manifest-listed `did-key-view@v1` through
  the existing interop-sidecar path-(b) digest-binding verifier. It
  does not parse DID JSON, resolve network identifiers, or change
  canonical event verification behavior.
- Core, matrix, and ADR 0008 update the active sidecar set from
  `c2pa-manifest@v1` only to `c2pa-manifest@v1` plus
  `did-key-view@v1`.

Verification: committed in `b10b89f`.

### Wave 28 (2026-05-05) — TODO #1 panic-safety fixes

Closes Trellis TODO item #1 by resolving three potential panic sites in the
verifier and CDDL parser. While guarded by prior checks in the reference
impl, these `.expect()` and `.unwrap()` calls on untrusted input paths
posed a crash risk for the verifier.

Train:
- `trellis-cddl` — `parse_canonical_event` replaces `.expect()` on 32-byte
  conversion with `.map_err()`.
- `trellis-verify` — `verify_tampered_ledger` replaces `.unwrap()` on
  `error.kind()` with a safe `if let Some(kind)` binding.
- `trellis-verify` — `verify_export_zip` replaces `.expect("bound registry
  exists")` with a match returning `VerificationReport::fatal`.

Verified by `cargo nextest run --workspace` (152 tests passed).

### Wave 27 (2026-04-29) — TODO #23 close-out: PLN-0385 wire-shape drift discovery + Fork-B resolution

Closes Trellis TODO item #23 (`custody-hook-encoding.md` v1.0 +
cross-stack ingestion fixture) by discovering that the work the TODO
described was speculative-against-a-phantom-spec, and the actual gap
was 3 lines of prose drift across two repos plus a status pin.

A cross-stack-scout dispatch (agent `ac9045864e6973fec`) ran three
pre-flight audits before scoping the train and stopped on a tripwire:
the four-field append wire surface cited by parent PLN-0385 + this
TODO item + `wos-server/TODO.md` lines 19/116 (`tag`, `payload`,
`prior_event_hash`, `producer_signature`) does NOT match the four-
field surface pinned by ADR-0061 §2.3 + `custody-hook-encoding.md`
§1.3 (`caseId`, `recordId`, `eventType`, `record`). The token
`producer_signature` exists in zero specs / zero crates / zero
schemas / zero fixtures across the entire stack — it was a planning-
layer hallucination propagated through PLN-0385.

Diagnosis (Fork B, ratified): PLN-0385 was authored from a wos-server-
centric mental model where Trellis-envelope-level fields
(`prior_event_hash` is Core §10.2; producer signing is COSE_Sign1
around the envelope) got conflated with the WOS-authored-record
surface (the seam input). ADR-0061 had drawn the layering line
correctly; PLN-0385 prose erased it.

Resolution path (Fork A, executed): the cross-stack ingestion fixture
the TODO asked for ALREADY existed as
`append/010-wos-custody-hook-state-transition` (and siblings
`append/019-022`). The verifier round-trip ALREADY existed as the
trellis-conformance replay. The companion file at
`work-spec/specs/kernel/custody-hook-encoding.md` was at
`1.0.0-draft.1`/`draft` — ratifying it to `1.0.0`/`accepted` plus
adding two paragraphs binding §3.4/§3.5 to the existing fixture
corpus, plus correcting the PLN-0385 four-field reference in three
places (parent PLANNING.md + 2 cross-references in
wos-server/TODO.md), closes the work cleanly.

Train (1 work-spec commit + 1 trellis commit + 1 parent commit):

- work-spec `3497a1b` — `docs: ratify custody-hook-encoding.md v1.0;
  correct PLN-0385 wire-shape drift`. Companion frontmatter +
  body header: `1.0.0-draft.1`/`draft` → `1.0.0`/`accepted`.
  §3.4 paragraph binds the cross-stack ingestion fixture corpus
  (`append/010` + siblings `019-022`). §3.5 paragraph binds the
  Trellis verifier round-trip (`cargo test -p trellis-conformance`).
  `crates/wos-server/TODO.md` lines 19 + 116 corrected.
- trellis `<commit-2-sha>` — `docs: close TODO #23 + Wave 27
  COMPLETED entry`. TODO renumber #23 removed; #24 → #23, #25 → #24.
  Cross-reference in §"Signature-stack cluster" updated; phantom
  `producer_signature` removed from cluster prose. "Items 5-10 +
  17-25" → "Items 5-10 + 17-24". "Depends on item #24" → "Depends
  on item #23".
- parent `<commit-3-sha>` — submodule bump (work-spec + trellis) +
  PLANNING.md PLN-0385 four-field reference correction +
  `producer_signature` phantom removed.

No fixtures changed; no Rust changed; no tests changed. The corpus
this companion binds to was authored against the correct surface
from the start — only the prose pointing AT it had drifted.

Anti-monkeypatching wins:

1. **Pre-flight tripwire prevented a phantom-spec authoring train.**
   The original TODO scope would have authored a NEW cross-stack
   fixture against the phantom four-field surface, supeseding ADR-
   0061 silently and creating a duplicate of `append/010` under a
   new name. Pre-flight caught it before any fixture touched disk.
2. **Drift correction over speculation.** The honest work was three
   lines of prose, not a multi-commit fixture train. Reclassifying
   the scope from "S" to "drift cleanup" preserves the user-economic-
   model rule (don't manufacture work).
3. **Question-excess rule applied.** When the user asked whether
   `producer_signature` would add value if it WERE intentional, the
   answer (analyzed against existing signing surfaces — envelope
   COSE_Sign1, ADR 0010 user-content-attestation events, payload-
   internal sigs in `record`) was: pure duplication. ADR-0061's
   choice to keep the four fields identity-shaped (not signature-
   shaped) was the architecturally clean call; PLN-0385's drift
   reached for an "every record needs a signature" intuition that
   was already covered three different ways at adjacent layers.
4. **Submodule WIP isolation.** work-spec submodule had ~120 files
   of unrelated WIP from prior sessions. Stash-and-replay landed
   only the Wave 27 prose edits in commit `3497a1b`; pre-existing
   WIP preserved untouched in working tree.

Findings closed: PLN-0385 wire-shape drift; companion v1.0
ratification status; cross-stack fixture corpus binding; Trellis
verifier round-trip binding.

Findings deferred: wider parent-PLANNING.md PLN-0379..0398 cluster
audit (other rows in the cluster may carry similar drift; not in
scope for this train).

### Wave 26 (2026-04-28) — Wave 25 review close-out: canonical dCBOR ordering + cross-impl byte oracle

Closes a semi-formal Wave 25 code review (`46cfc72..6e09dc0` + parent
`fb5b9ff3`). One BLOCKER (FINDING 1, real correctness bug) plus two
trailing alignments shipped; three lesser findings (4/5/6) deferred
to backlog with explicit rationale.

Train (3 trellis commits + 1 parent submodule bump):

- `b522f89` — `fix(c2pa): canonical dCBOR ordering in
  emit_c2pa_manifest_for_certificate`. Pre-fix, the Rust emitter
  inserted the five assertion fields in byte-lex order of the decoded
  UTF-8 string (`canonical_event_hash, certificate_id, cose_sign1_ref,
  kid, presentation_artifact.content_hash`). RFC 8949 §4.2.2 (per
  Core §5.1 dCBOR profile) requires lex order on the **encoded
  `tstr` bytes**, which prefixes a length byte — for the five field
  lengths spanning 11..42 bytes, canonical order is
  `kid (11) → certificate_id (22) → cose_sign1_ref (22) →
  canonical_event_hash (28) → presentation_artifact.content_hash (42)`.
  Two fields share length 22, falsifying the prior comment's "no two
  strings share a length" claim (FINDING 3 fixed in the same commit).
  Replaced the insertion-order `vec![]` with an encoded-tstr-keyed
  sort via a new `encode_tstr_key` helper (RFC 8949 §3.1 major type 3
  short + 1-byte length-head forms). Path-(b) verifier was unaffected
  because it digest-binds the on-disk file, and the on-disk fixture
  was always cbor2-canonical — only the Rust emitter was wrong.
  trellis-interop-c2pa: 7/0 → 10/0 tests (added byte-equality oracle
  against the on-disk fixture, name-locked canonical-key-order test,
  encode_tstr_key encoding test).
- `175b630` — `test(c2pa): cross-implementation byte-equality oracle
  (cbor2 path)`. Wave 25 README claimed "byte-exact under any
  conforming dCBOR encoder" with no test; the FINDING 1 bug shipped
  under that aspirational claim. Wave 26 audited adding `c2pa-rs` as
  a `[dev-dependencies]` for a third oracle (C2PA-tooling round-trip):
  the probe `cargo tree --edges normal,build,dev` measured **285
  unique transitive crates** plus tokio + reqwest + hyper +
  hyper-rustls + vendored OpenSSL — above the brief's ~150 threshold
  and pulling explicitly-flagged heavy stack for an offline
  assertion-only oracle. Skipped Phase 2b per the tripwire; landed
  Phase 2a alone — `trellis-py/tests/test_interop_c2pa_byte_oracle.py`
  asserts cbor2(canonical=True) re-encoding of the declared logical
  input is byte-equal to the on-disk fixture. Together with the Rust
  fixture-byte test from `b522f89`, two independent encoders
  (`ciborium` + `cbor2`) meet at the same canonical fixture; any
  drift in either localizes to that side. README rewritten:
  byte-exactness claim is now **verified** with both enforcement
  paths cited; audit findings + dev-dep decision documented in-crate.
  trellis-py: 64/0 → 67/0 tests; G-5 unchanged (114/0).
- `<this commit>` — `fix(adr+spec): align ADR 0008 dispatch order
  with Rust + close Wave 26`. ADR 0008 §"Phase-1 verifier obligation"
  prose listed dispatch as `kind → derivation_version → path →
  content_digest → unlisted_file → phase_1_locked`; Rust authoritative
  implementation in `trellis-verify::verify_interop_sidecars` runs
  `kind → derivation_version → path → phase_1_locked → content_digest
  → unlisted_file` (with `phase_1_locked` ahead of digest so a
  fixture mis-listing kind+path under a still-locked kind surfaces
  the dominant `phase_1_locked` failure rather than a digest
  mismatch). Per ADR 0004, Rust is byte authority — prose updated to
  match (FINDING 2). The realignment also annotates the rationale
  for lock-off-before-digest order so the next reader sees why.

ISC-02 status. **Promoted from aspirational to verified** in Wave 26.
The two-sided cbor2-↔-fixture-↔-ciborium oracle is the new
ADR 0008 path-(b) byte-determinism enforcement mechanism.

ISC-05 status. Held throughout. The audited c2pa-rs dev-dep was NOT
added; `trellis-verify` / `trellis-types` continue to take zero
ecosystem deps. `deny.toml` `c2pa` wrapper allowlist unchanged.

Counts (Wave 26 deltas vs. Wave 25 close):

| gate | Wave 25 | Wave 26 | delta |
|-----|--------|--------|-------|
| `cargo test --workspace` | 56 suites green | 56 suites green | clean |
| `trellis-interop-c2pa` unit tests | 7/0 | 10/0 | +3 (fixture-byte oracle, key-order lock, tstr-encoding) |
| `trellis-py` pytest | 64/0 | 67/0 | +3 (cbor2 byte oracle) |
| G-5 conformance corpus | 114/0 | 114/0 | clean (no fixture changes) |
| `check-specs.py` | clean | clean | clean |

Findings closed: **1** (canonical dCBOR ordering — root correctness
bug, was producing non-canonical bytes against the spec); **2** (ADR
0008 prose dispatch order disagreed with Rust; Rust wins per ADR
0004); **3** (false comment claim about field-name length uniqueness,
empirically falsified by `certificate_id` and `cose_sign1_ref` both
being 22 bytes).

Findings deferred to backlog (acceptable — none on the critical path,
each surfaces a future cleanup target with non-trivial scope):

- **FINDING 4** — `interop_sidecar_content_mismatch` failure-code
  conflation. The Rust verifier raises `content_mismatch` for both
  *missing file* and *digest divergence*. A finer-grained
  `interop_sidecar_missing` code would localize "manifest promised
  bytes that aren't in the ZIP" vs. "bytes are present but mutated".
  Worth doing; not on Wave-26's surgical-fix track.
- **FINDING 5** — `is_interop_sidecar_path_valid` predicate has no
  Python-side unit test. The Rust unit test `interop_sidecar_path_prefix_invariant`
  covers TR-CORE-167; the Python equivalent in `trellis-py` is
  fixture-driven only. Low-value to add unless `trellis-py` is
  consumed standalone by an adopter.
- **FINDING 6** — brittle version-gating in
  `verify_interop_sidecars` (`if !supported_versions.contains(...)
  && kind == INTEROP_SIDECAR_KIND_C2PA_MANIFEST`). The double
  conjunction is correct today but reads fragile; will get a cleaner
  match-on-kind-then-version rewrite when a second kind unlocks
  (Wave N+, when `scitt-receipt` or another kind activates and the
  current shape stops fitting).

Anti-monkeypatching wins:

1. **Review-driven, not speculative.** FINDING 1 was a real
   correctness bug uncovered by review; the fix realigns Rust with
   the spec (ADR 0004 byte-authority discipline). Findings 2 and 3
   are alignment cleanups in the same train, not invented scope.
2. **Audit before adopting.** Adding `c2pa-rs` as a dev-dep was
   plausible-sounding but failed the empirical cost check (285
   transitive crates + tokio + openssl). Phase 2a alone delivers the
   ISC-02 cross-impl claim without taking the cost. Future adopter
   that *needs* the C2PA-tooling oracle pays the cost in their own
   `trellis-interop-c2pa-tooling` crate, not the workspace base.
3. **Findings 4/5/6 deferred with explicit rationale**, not
   silently fixed under the guise of "while we're here". The
   surgical-fix train stayed surgical.
4. **README claim flipped from aspirational to verified.** A claim
   without a test was the Wave-25 rough edge that let FINDING 1
   ship; Wave 26 closes that gap permanently. Two encoder paths
   meeting at the same fixture makes future regressions obvious.

### Wave 25 (2026-04-28) — `c2pa-manifest@v1` adapter activation + dispatched verifier (item #1)

Closes the original TODO item #1 — the `c2pa-manifest` interop-sidecar
adapter. ADR 0008's reservation-with-lockoff posture flips for the
first kind: `c2pa-manifest@v1` now dispatches to per-entry verification
under the **path-(b) digest-binds only** discipline; the three other
registered kinds (`scitt-receipt`, `vc-jose-cose-event`, `did-key-view`)
remain Phase-1 locked-off pending their per-kind triggers.

Train (`46cfc72..75f0884`, 5 commits):

- `3eda94d` — Spec deltas. Core §18.3a narrows the lock-off ("all
  kinds except `c2pa-manifest@v1`"), §19.1 gains 5 new tamper-kind
  rows (`interop_sidecar_content_mismatch`,
  `interop_sidecar_kind_unknown`, `interop_sidecar_unlisted_file`,
  `interop_sidecar_derivation_version_unknown`,
  `interop_sidecar_path_invalid`). §28 CDDL backfilled mirror-discipline
  (ADR 0004 byte-authority): adds `posture_transitions`,
  `erasure_evidence`, `certificates_of_completion`, and
  `interop_sidecars` fields to `VerificationReport` plus four outcome
  struct definitions (the §19 prose had them; §28 didn't). ADR 0008:
  c2pa-manifest status Phase-1-locked → Phase-2-active; Open Q3
  resolved (vendor-prefix label
  `org.formspec.trellis.certificate-of-completion.v1`); Open Q5 adds
  `source_ref` resolution semantics deferred. Matrix: TR-CORE-163..167
  (4 fixture-bearing + 1 unit-test-only). check-specs.py
  `TAMPER_KIND_ENUM` mirror updated. ADR 0008 fixture-plan slot
  reassignment 028..031 → 037..040 (Wave 23 UCA fixtures absorbed
  the original slots).
- `bfd7fc9` — `trellis-verify` dispatched verifier. Replaces the
  broad lock-off block with `verify_interop_sidecars`; adds
  `InteropSidecarVerificationEntry` struct mirroring Core §28 CDDL
  byte-for-byte; threads `interop_sidecars` into `VerificationReport`
  with the integrity-fold extension. Failure dispatch order: kind →
  derivation_version → path-prefix → lock-off (3 kinds) → digest →
  unlisted-file. Unit test `interop_sidecar_path_prefix_invariant`
  covers the byte-prefix predicate (TR-CORE-167). ISC-05 holds —
  `trellis-verify` does NOT take a `c2pa-rs` dep.
- `8a1e76f` — `trellis-interop-c2pa` adapter. Three public surfaces:
  `emit_c2pa_manifest_for_certificate`, `extract_trellis_assertion`,
  `TrellisAssertion::verify_against_canonical_chain`. Uses **hand-
  rolled CBOR** rather than `c2pa-rs` — the `c2pa` crate brings 328
  transitive deps (image parsers, ASN.1 decoders, RDF infra,
  network-capable certificate validation), inappropriate as a workspace
  base dep. The Trellis assertion itself is a 5-field dCBOR map; the
  C2PA-tooling consumer (read manifest from PDF/JPEG, decode
  assertion, run cross-check) is documented as the operator's
  responsibility in `crates/trellis-interop-c2pa/README.md`.
- `75f0884` — Fixture corpus. 1 positive (`export/014-interop-sidecar-c2pa-manifest`)
  + 4 negatives (`tamper/037..040`). Built via
  `gen_interop_sidecar_c2pa_037_to_040.py` mutating
  `export/012-interop-sidecars-empty-list` as the base, re-signing
  the manifest under `_keys/issuer-001.cose_key`. Synthetic
  five-field Trellis-assertion sidecar bytes mirror the
  `trellis-interop-c2pa` shape so the fixture and the adapter
  exercise the same byte format.
- `<commit-5>` — Python parity + this entry + TODO renumber. Wave 25
  closes G-5 at 114/0 (+5 vectors from 109/0). `_verify_interop_sidecars`
  in `trellis-py/src/trellis_py/verify.py` mirrors the Rust dispatch
  byte-for-byte. README documents the **C2PA-tooling-path is not
  ported** — that path lives in `trellis-interop-c2pa` Rust only;
  porting to Python would force every G-5 oracle deployment to ship
  a C2PA SDK, which the path-(b) discipline sidesteps.

Counts: G-4 clean (cargo test --workspace 100%; trellis-verify 88/0
tests + new path-prefix unit test; trellis-interop-c2pa 7/0 tests;
trellis-conformance 9/0 model-checks + corpus replay). G-5 109 → **114**.
pytest 64 / 0. `check-specs.py` clean.

Anti-monkeypatching wins (the discipline showed up):

1. **Spec rows landed BEFORE fixtures + Rust references.** Commit 1
   (spec deltas + matrix rows + check-specs enum mirror) wired the
   normative surface; commit 2 (Rust verifier) and commit 4 (fixtures)
   could only land because the failure codes existed in
   `TAMPER_KIND_ENUM`. Vector-coverage rule was kept happy via the
   transit allowlist (`fixtures/vectors/_pending-invariants.toml`)
   and cleared at commit 4. Lockstep held.
2. **§28 mirror discipline backfilled, not deferred.** §19 prose had
   gained `posture_transitions` / `erasure_evidence` /
   `certificates_of_completion` over Waves 21-23, but §28 still
   carried the old 8-field `VerificationReport`. Wave 25 is when the
   drift was visible (the Rust Report struct reaches 12 fields with
   `interop_sidecars`); the cleanup landed in commit 1 alongside the
   new field. ADR 0004 byte-authority preserved.
3. **Vendor-prefix label decision rather than C2PA coalition gating.**
   Open Q3 had been deferred behind "may need C2PA coalition step";
   Wave 25 used the C2PA assertion-naming convention for vendor
   assertions (`org.formspec.trellis.certificate-of-completion.v1`)
   to ship without that gate, and documented the rationale in ADR
   0008 + crate README. A coalition-membership ADR remains an
   optional follow-on bumping `derivation_version` per ISC-06.
4. **`source_ref` resolution semantics explicitly deferred** rather
   than stubbed. Open Q5 names the deferral as "this is a separable
   design question that benefits from being decided once across all
   four kinds" — the Phase-1 verifier validates `source_ref` for
   presence only. No speculative resolution code; no dead-code
   constants for the still-locked kinds.
5. **Hand-rolled CBOR for the assertion**, not a `c2pa-rs` dep at
   the workspace base. The 328-crate dep tree would have crossed
   ISC-05 hygiene boundaries the moment a workspace `cargo check`
   touched it. The C2PA-tooling consumer's PDF/JPEG embedding lives
   outside the workspace center.
6. **Fixture-slot relocation 028..031 → 037..040.** The pre-flight
   tripwire surfaced that the original ADR 0008 fixture plan
   collided with the Wave 23 UCA corpus (slots 028..034). Resolved
   with kind-agnostic names (no `c2pa` substring in the slug) so
   future kinds reuse the same negative scaffolding without slot
   churn.

Findings flagged but not fixed (out-of-scope per the brief):

- C2PA-tooling-path Python parity is intentionally absent. The Rust
  adapter's `extract_trellis_assertion` + `verify_against_canonical_chain`
  exist; the Python equivalent would force a C2PA SDK into the G-5
  oracle's dep tree, which path-(b) discipline sidesteps. If a future
  adopter needs a Python-side consumer, it lands as `trellis-py-c2pa`
  beside `trellis-py`, not folded into `trellis-py` itself.
- Formal C2PA-registry registration of the assertion label is
  deferred behind a future coalition-membership ADR. The vendor-prefix
  label is interop-equivalent for path-(a) consumers.
- `trellis-cli` does not yet expose a sidecar-emit subcommand. The
  emitter is library-tier; a CLI wrapper would land with the first
  reference deployment that ships the assertion to a real PDF
  pipeline.

### Wave 24 (2026-04-28) — Core §17 `idempotency_key` Rust + Python + fixtures (item #2)

Closes the seven sub-tasks of TODO item #2 — the wire-contract idempotency
catch-up. Spec already pinned `bstr .size (1..64)` and `(ledger_scope,
idempotency_key)` identity in §6.1 / §17 / §28; Wave 24 paid down the Rust
runtime, the verifier, the stores, the fixture corpus, the Python G-5 oracle,
and the spec/lint/matrix discipline around them.

Train (`9a32ad6..b88c73c`, 2 commits):

- `885a96b` — Rust + fixtures + spec lockstep. `trellis-cddl::ParsedAuthoredEvent` /
  `ParsedCanonicalEvent` carry `idempotency_key`; both parsers length-validate
  via the new typed `CddlErrorKind::IdempotencyKeyLengthInvalid`. `StoredEvent`
  threads the key through `with_idempotency_key`. `trellis-store-postgres`
  partial-unique index `trellis_events_scope_idempotency_uidx` enforces
  §17.3 at SQL; `trellis-store-memory` matches via `append_event_in_tx`.
  `trellis-verify::verify_event_set_with_classes` adds an offline
  `idempotency_index` BTreeMap detecting §17.3 clause-3 divergence with
  `tamper_kind = idempotency_key_payload_mismatch` (Core §16: no service
  state required). `decode_event_details` length-checks the wire bytes.
  Three new fixtures (`append/042-idempotency-retry-noop`,
  `tamper/035-idempotency-key-payload-mismatch`, `tamper/036-idempotency-key-too-long`)
  with byte-exact generators. Spec: §17.2 / §17.3 / §17.4 traceability anchors;
  §19.1 enum gains two rows (`idempotency_key_length_invalid`,
  `idempotency_key_payload_mismatch`); `check-specs.py` `TAMPER_KIND_ENUM`
  mirrors. Matrix: TR-CORE-158..162 (the rows themselves were already
  authored; this commit added their prose anchors and lint coverage).
- `b88c73c` — `trellis-py` G-5 parity. `EventDetails` carries
  `idempotency_key`; `_decode_event_details` length-validates with
  `VerifyError(kind="idempotency_key_length_invalid")`; `_verify_event_set`
  builds the same `(scope, key) → canonical_event_hash` index as the Rust
  side, surfacing `idempotency_key_payload_mismatch` event-failures.

Counts: G-4 clean (cargo test --workspace 100%); G-5 109 → **109** (the
two new tamper vectors went from 2 / 2 failed to 0 / 0); pytest 64 / 0;
`check-specs.py` clean.

Spec posture verified: the byte-level question "does `idempotency_key`
join the canonical hash preimage?" — yes. §28 CDDL pins the field as the
twelfth entry in both `AuthorEventHashPreimage` and `EventPayload`; §9.5
and §9.2 hash both preimages. The existing Phase-1 v1.0.0 fixture corpus
already encoded the field byte-exact (witness map prefix `0xac` authored
/ `0xad` canonical) — Rust simply was not parsing or threading it. The
runtime change is therefore strictly additive at the byte path; no
existing fixture's `canonical_event_hash` re-derived.

Sub-task status:

1. Fixtures first — `append/042` + `tamper/035` + `tamper/036` (DONE).
2. `trellis-cddl` / `trellis-types` parse + length-validate (DONE).
3. `trellis-core` + stores `(scope, key)` uniqueness (DONE; partial unique
   index in Postgres, in-memory map in `trellis-store-memory`).
4. `trellis-verify` reject duplicate identity with divergent canonical
   material per §17.5 (DONE).
5. `trellis-conformance` + `trellis-cli` drive updated vectors (DONE; the
   conformance crate already carried the model-check at TR-CORE-050; the
   new fixture corpus is consumed by the Wave-24-existing replay path).
6. `trellis-py` G-5 parity (DONE — `b88c73c`).
7. Hygiene — `trellis-verify` dev-dep on `trellis-cddl`: KEEP. The dep is
   genuinely used (`trellis-verify/src/lib.rs:6090` consumes
   `parse_ed25519_cose_key` in tests). The SKILL "Findings since last
   sync" entry was stale; refreshed in this wave.

WOS `custodyHook` binding (parent ADR 0061 §2.4 — `(caseId, recordId)` →
`SHA-256(len_prefix("trellis-wos-idempotency-v1") || dCBOR(...))`): the
Rust `(scope, key)` enforcement composes cleanly. Parent runtime wiring
tracks separately at `work-spec/TODO.md`.

Findings flagged but not fixed (out-of-scope per the brief):

- Retired Respondent Ledger naming downstream — out of scope (Wave 24
  did not touch that surface).
- Companion §6.4 user-vs-operator distinction — Wave 23 residue, untouched.
- WOS-side `custodyHook` runtime wiring — parent's job.

### Wave 23 (2026-04-28) — ADR 0010 user-content-attestation primitive (item #1) — closes PLN-0379

Sequenced sibling to ADR 0007 (Wave 22). Lands the byte-level primitive
`trellis.user-content-attestation.v1` — the cryptographic anchor a user
(non-operator) signs to attest to in-chain content with a declared
`signing_intent` URI. Distinct from Companion §A.5 operator-actor Attestation
(distinct domain tag `trellis-user-content-attestation-v1`). WOS-side
meaning ratifies in parallel via PLN-0380 (`work-spec` SHAs `d7d6845..026eac8`).

Train (`b1b23ce..74cd52d`, 6 commits):
- ADR 0010 (~265 lines) authored with 11-vector fixture plan + 9-step
  verifier obligations.
- Spec amendments — Core §6.7 registration, §9.8 domain tag, §19 step 6d,
  §28 CDDL append, matrix TR-CORE-152..157, Companion §6.4 user-vs-operator
  reminder.
- Rust verifier extension — `UserContentAttestationDetails` + `Outcome`,
  decode + finalize (steps 3-9), `decode_identity_attestation_subject`
  via `EventPayload.extensions[event_type]["subject"]`.
- Positive `append/036..039` (minimal / multi-attestor / without-identity /
  stand-alone). `_generator/gen_append_036_to_039.py`.
- Negative `tamper/028..034` (sig-invalid / chain-position-mismatch /
  identity-unresolved / identity-subject-mismatch / identity-temporal-
  inversion / intent-malformed / key-not-active).
- Python parity (`trellis-py/src/trellis_py/verify.py`, 478 lines added).
- Matrix TR-CORE-152..156 promoted `prose → test-vector`; TR-CORE-157
  stays `prose` (idempotency-collision + operator-as-attestor lint-only).

Counts: G-4 clean; G-5 95 → **106**; pytest 57 (no new cases — corpus
serves as integration test); check-specs clean.

Two design fixes during the train (the craftsman dispatch hit a usage
limit mid-train; pickup audit caught both):

1. **Step-2 deferred-failure pattern.** ADR 0010 step 2 (intra-payload
   invariants — `intent_malformed` / `timestamp_mismatch`) flips
   `integrity_verified = false` only — NOT a structure failure. The
   decoder previously bubbled `Err(VerifyError::with_kind(...))` and
   the fatal-decode path flipped `readability_verified = false`,
   contradicting the ADR. Refactored to a `step_2_failure: Option<&'static str>`
   marker on `UserContentAttestationDetails`; finalize raises it as an
   `event_failure` and skips remaining per-event checks. Manifest at
   `tamper/033-uca-intent-malformed` + generator updated to match.
2. **De-monkeypatching.** Phase-1 fixture corpus minted bare
   `trellis.user-identity-attestation.v1` for identity events — unregistered
   in Core §6.7 and lint-warned by check-specs. Renamed to
   `x-trellis-test/identity-attestation/v1` (the §6.7 + §10.6 reserved
   test prefix). Dropped the dead-code `PLN_0381_CANDIDATE_IDENTITY_EVENT_TYPE`
   constant + admit branch (speculative admission of unratified
   `wos.identity.attested.v1`). Matrix TR-CORE-154 prose updated.

Residue: TR-CORE-157 (idempotency-collision + operator-as-attestor)
follow-on tampers if a corpus gap surfaces. Rotation-grace `Rotating`
admission is now closed by Wave 30. PLN-0381 ratification adds canonical
`wos.identity.*` branch in a single edit to
`is_identity_attestation_event_type`. Open finding flagged but out-of-scope:
`is_operator_uri` hardcodes `urn:{trellis,wos}:operator:` prefixes — works
today, would land properly via a Companion §6.4 amendment naming the
convention.

---

### Wave 22 (2026-04-28) — ADR 0007 certificate-of-completion close (item #4)

Closes the corpus + downstream surfaces for `trellis.certificate-of-completion.v1`
— the integrity artifact for ESIGN/UETA. Spec deltas + Rust verifier landed
Waves 18-21; Wave 22 closes vectors, Python parity, CLI, reference template.

Train (`c84dd52..7052427`, 8 commits):
- Positive `append/028..030` (PDF-minimal / dual-signer-with-template /
  HTML-template-bound). `_generator/gen_append_028_to_030.py`.
- Ledger tampers `021/023/025/026` (signer-count / attestation-truncation /
  HTML-missing-template-hash / id-collision).
- Verifier fix `c9f46cc`: `cert_events` keyed by global `event_index`
  (Vec→BTreeMap). Single-event tests had masked the bug.
- Export `export/010-certificate-of-completion-inline` + `065` catalog +
  tampers `020/022/024` (content-hash / signing-event-unresolved /
  response-ref-mismatch).
- Python parity (`trellis-py/src/trellis_py/verify.py` + 23 pytest cases).
- `trellis-cli seal-completion --help` stub (mirrors `erase-key`).
- Reference HTML template at `reference/certificate-of-completion/template-v1/`.
- Matrix: TR-CORE-146..151 → `test-vector`; TR-OP-131 stays `prose`; TR-OP-132
  stays `declaration-doc-check`.

Counts: G-4 clean; G-5 84 → **95**; pytest 34 → 57; check-specs clean.

Pushback worth keeping: `tamper/021` and `tamper/025` surface as
`structure_verified = false` (CDDL decode rejects via
`VerificationReport::fatal`, not the typical structure-true/integrity-false
shape). `tamper/023` uses signature *truncation* (64→63 bytes), not byte-flip
— Phase-1 verifier is structural-only.

Residue: c2pa-manifest binding tracks at TODO item #2 (post-resort);
TR-OP-131 vector-promotion gates on an operator-emit-side fixture.

---

### Wave 21 (2026-04-28) — ADR 0005 erasure-evidence Stages 2-5 close (item #3) — closes PLN-0312

Closes the verifier + fixture + CLI + matrix deltas for ADR 0005
*Cryptographic erasure evidence*. **Closes parent `PLN-0312` entirely.**

Stage history: Stage 1 spec deltas Wave 18 (`9b3d3e4`); Stages 2-3 + 4-A
(Rust 10-step verifier, Python parity, `append/023..027`) Wave 19
(`586de5e..dd408b6`); Stages 4-B / 4-C / 5 + follow-on Wave 21 (9-commit
train).

Wave 21 train highlights:
- Slot collision: `export/009-intake-handoffs-...` renumbered to
  `export/013-...` so ADR 0005 Stage 4-C takes `export/009-erasure-
  evidence-inline`. R16 deprecated tombstone preserves the prefix; both
  conformance harnesses skip `status = "deprecated"`.
- Rust verifier: `parse_erasure_evidence_export_extension` +
  `verify_erasure_evidence_catalog`; step-8 chain-walk for `signing` +
  `subject` key classes (`post_erasure_use` / `post_erasure_wrap` typed
  failures).
- Python parity at G-5 84/0/0.
- Tampers `017/018/019` (post-use / post-wrap / catalog-digest mismatch).
- Export `export/009-erasure-evidence-inline` + 432-line generator.
- `trellis-cli erase-key --help` ADR 0005 flag contract.
- Companion §27.1 verifier-surface paragraph.
- Matrix: TR-OP-105 + TR-OP-107 → `test-vector`. TR-OP-106 / 108 / 109 /
  113 stay `prose` / `declaration-doc-check` per ADR 0005 *Fixture plan*.

Counts: cargo workspace clean; G-5 84/0/0; pytest scripts 162/0;
trellis-py 34/0; check-specs clean (incl. `TRELLIS_CHECK_RENUMBERING=1`).

Residue: ADR 0005 *Open questions* (LAK rotation, `hsm_receipt_kind`,
legal-hold-coupled erasure lint, multi-operator quorum) tracked at
TODO #15.

---

### Wave 20 (2026-04-27) — Interop sidecar reservation (item #18)

Closes item #18 from the TODO. Lands Phase-1 reservation of the interop
sidecar slot in the export manifest under ADR 0008 ISC-01..ISC-05 discipline.

- Core 18.3a gains interop_sidecars field with InteropSidecarEntry
  CDDL; Phase-1 lock-off prose anchors TR-CORE-145.

- trellis-verify rejects non-empty interop_sidecars with
  interop_sidecar_phase_1_locked fatal failure.

- Fixtures: export/011-interop-sidecars-absent (canonical positive,
  absent field), export/012-interop-sidecars-empty-list (canonical
  positive, empty array), tamper/027-interop-sidecar-populated-phase-1
  (verifier rejects populated entry). scripts/check-specs.py
  TAMPER_KIND_ENUM extended.

- Scaffolding: empty crates trellis-interop-scitt, trellis-interop-vc,
  trellis-interop-c2pa, trellis-interop-did; parent workspace Cargo.toml
  updated; deny.toml cargo-deny config with ecosystem-lib ban list.

Verification:
- cargo test --workspace clean (0 failures).
- python3 scripts/check-specs.py clean.
- python3 -m pytest scripts/test_check_specs.py clean (155).

NEEDS_CONTEXT: none. tamper/028-031 require Phase-2+ adapter logic and
are deferred to per-kind activation waves.

---

### Wave 19 (2026-04-27) — AEAD nonce determinism (item #37)

Closes item #37 from the TODO. Lands deterministic ChaCha20-Poly1305 nonce
derivation for PayloadInline so that structurally identical retries with
the same idempotency_key produce byte-identical ciphertext.

- Core #9.4 pins the Phase-1 derivation:
  nonce = HKDF-SHA256(salt = dCBOR(idempotency_key), ikm =
  SHA-256(plaintext_payload), info = "trellis-payload-nonce-v1",
  length = 12). #9.4 prose binds the nonce to both idempotency identity
  (cross-key collision prevention) and exact payload content (same-key
  different-payload silent divergence prevention).

- Core #17.3 no-op retry clause updated to reference
  "post-dCBOR task canonicalization and post-#9.4 deterministic AEAD nonce".

- Rust helper trellis-types::derive_payload_nonce implements the #9.4
  construction with hkdf crate; 2 unit tests (determinism + perturbation).
  Payload_NONCE_DOMAIN duplicate removed; Payload_NONCE_INFO is the
  single source of truth. encode_uint direct unit test restored.

  - trellis-conformance vector_dirs tightened to skip directories with
  manifest.toml - safely handles incomplete WIP tamper trees.

  - Fixture append/041-aead-retry-determinism with real 
  ChaCha20-Poly1305 + HPKE suite-1 wrap; generator script + key material.

  - TR-CORE-144 matrix row added (wording corrected post-review to match
  #9.4 salt/ikm/info construction, not an earlier draft's 
  AuthorEventHashPreimage-based wording).

  - TODO.md reindexed PLN mappings (0347->0368), added signature-stack
  cluster paragraph, expanded items #4/#10, added backlog items #36-#40,
  marked #37 CLOSED Wave 19.

Verification:
- cargo test --workspace clean (0 failures).
- cargo clippy -p trellis-types --tests -D warnings clean.
- python3 scripts/check-specs.py clean.
- trellis-py G-5: 34 passed.

NEEDS_CONTEXT: none. The construction is self-contained; no callee crates 
consume derive_payload_nonce yet - the helper lands ahead of full 
append-path wiring.

---

### Wave 18 (2026-04-27) — Crypto-erasure evidence Stage 1 spec deltas (item #3 partial)

Lands the spec-side foundation of ADR 0005 (cryptographic-erasure
evidence) into the ratified Phase-1 surface. Stages 2-5 (Rust verifier,
Python parity, vectors, CLI, §27 tests) remain open under item #3 —
this is an intentional partial closure per the Wave 18 scout-strategy
directive (M-L scope, sibling-coordination chaos, foundation-first
landing pattern).

- **Item #3 Stage 1 — Companion §20.6 + Core §6.7 + Core §6.9 + Core
  §19 step 6b + Core §19.1 enum + matrix rows.** Single commit
  `9b3d3e4` lands:
  - **Companion §20.6** retitled "Documentation and Evidence";
    OC-78 promoted from conditional to "every cryptographic erasure MUST
    be accompanied by a canonical `trellis.erasure-evidence.v1` event";
    §20.6.1 promoted from "ReasonCode Reservation" to "ReasonCode Table"
    (codes 1-5 + 255 landed); §20.6.2 cites ADR 0005 §"Wire shape" as
    byte-authoritative for the `ErasureEvidencePayload` CDDL plus reuses
    the §A.5 `Attestation` rule under
    `trellis-transition-attestation-v1`; §20.6.3 carries six new MUSTs +
    one SHOULD: OC-141 (`cascade_scopes` registry), OC-142 (post-erasure
    sign/wrap forbidden — Phase-1 scope `signing` + `subject` per ADR
    0005 step-8 bound), OC-143 (SHOULD dual attestation for
    `reason_code ∈ {3, 5}` or `subject_scope.kind ∈ {per-tenant,
    deployment-wide}`), OC-144 (`destroyed_at` ≤ host event
    `authored_at`), OC-145 (single `destroyed_at` per `kid_destroyed`),
    OC-146 (`key_class` registry-bind under ADR 0006 `KeyEntry`;
    `wrap`→`subject` normalization reused from Wave 17).

  - **Core §6.7** registers `trellis.erasure-evidence.v1` in the
    `EventPayload.extensions` table (Phase 1, reject-if-unknown-at-version).
  - **Core §6.9** retargets the Erasure-Evidence row from
    "ADR 0005 §Reason codes (Companion §20 once promoted)" to
    "Companion §20.6.1 (mirrored in ADR 0005)".
  - **Core §19** new step 6b enumerates the 10-step erasure-evidence
    verifier checklist verbatim (anchored on ADR 0005 §"Verifier
    obligations" as byte-authoritative); Phase-1 chain-walk scope (step
    8) is `norm_key_class ∈ {"signing", "subject"}`; other classes
    co-land with ADR 0006 follow-ons. Optional manifest catalog
    pattern (`trellis.export.erasure-evidence.v1` binding
    `064-erasure-evidence.cbor`) mirrors the §6.7 catalog discipline.
  - **Core §19.1 `tamper_kind` enum** appended with seven
    erasure-evidence rows (`erasure_key_class_registry_mismatch`,
    `erasure_key_class_payload_conflict`,
    `erasure_destroyed_at_after_host`, `erasure_destroyed_at_conflict`,
    `post_erasure_use`, `post_erasure_wrap`,
    `erasure_evidence_catalog_digest_mismatch`). Mirrored in
    `scripts/check-specs.py` `TAMPER_KIND_ENUM`. Per §19.1's existing
    rule the enum is allowed to be a superset of the tamper corpus, so
    reserving these without immediate fixtures is conformant — corpus
    lands with Stage 4.
  - **Matrix §2.11**: TR-OP-104 retargeted (table now in Companion
    §20.6.1, not "reserved"); seven new rows TR-OP-105..109 +
    TR-OP-113 + TR-OP-114 bind each Companion OC-141..146 + the
    §20.6.2 schema-conformance rule. All rows carry
    `Verification = prose` (or `declaration-doc-check` for the
    SHOULD-grade OC-143) until the corpus + Rust verifier land — Notes
    column flags the test-vector promotion path. ULCOMP-R-159..168
    legacy mapping row updated to include the new TR-OP rows.

- **TDD discipline note.** Stage 1 is spec-only; the §19 step 6b
  10-step checklist is normative prose backed by ADR 0005's existing
  byte-authoritative §"Verifier obligations". The `tamper_kind` enum
  values are pre-declared (allowed by R13 corpus-subset rule) so that
  Stage 4 vectors can reference them without further enum amendments
  in the same change train. Lint (`scripts/check-specs.py`) and pytest
  (`scripts/test_check_specs.py`) both clean post-commit.

- **Stages 2-5 escalated as open work in item #3.** Detailed sub-bullet
  list lives under [`TODO.md`](TODO.md) item #3 with explicit handles
  for: Rust verifier 10-step checklist (`crates/trellis-core/` +
  `crates/trellis-verify/`), Python parity (`trellis-py/`), nine
  fixture vectors (`append/023..027` + `tamper/017..019` +
  `export/009-erasure-evidence-inline` + manifest catalog
  `064-erasure-evidence.cbor`), CLI (`trellis-cli erase-key`),
  Companion §27.3 / §27.7 test extensions, and the matrix-row
  promotion lockstep. **Numbering note (escalated):** the existing
  `export/009-intake-handoffs-public-create-empty-outputs` occupies
  vector slot `export/009`; Stage 4 renumbers the intake-handoff
  vector forward or selects the next free slot, gated by the
  pre-merge renumbering guard.

- **Sibling-coordination friction.** Wave 18 ran six scouts in
  parallel, three of which (items #29, #30, #34) shared
  `specs/trellis-operational-companion.md` and
  `specs/trellis-requirements-matrix.md` with this item. The race
  protocol (commit logical chunks; rebase before push) held — Stage
  1's commit landed without conflict despite repeated index-wipe
  events from concurrent commits. Stages 2-5 should land in a quieter
  wave or with explicit serialization to avoid recurring the
  pattern.

Verification (Stage 1 only):

- `python3 scripts/check-specs.py` clean (heading-label discipline +
  TR-OP-* coverage + R13 tamper-kind corpus-subset all green).
- `python3 -m pytest scripts/test_check_specs.py -q` clean (155).
- `cargo check --workspace` clean.
- `cd trellis-py && python3 -m pytest -q` clean (4).

NEEDS_CONTEXT: none for Stage 1; Stages 2-5 carry the explicit handles
under item #3 with no architectural ambiguity. The primary cost is
mechanical breadth (generators × 9 vectors + parallel runtimes) rather
than design uncertainty.

### Wave 18 (2026-04-27) — `trellis-store-postgres` review follow-ups (item #32)

Closes item #32 from the post-Wave-17 TODO. Lands the three
SUGGESTION-tier follow-ups from the Wave 16 store-postgres review
(commits `4fe787a` / `00570c3` / `8bb61fb` / `351dfb8` —
approve-with-suggestions) before wos-server composes the adapter.

- **`MemoryTransaction::commit` returns `Result<(), Infallible>`**
  (`db4ad29`). Was `()`; cross-store generic test bodies could not
  share `tx.commit()?` against both adapters because postgres-side
  returns `Result<(), postgres::Error>`. Tightened to
  `Result<(), Infallible>` so the `?`-chain shape is identical.
  Pinned by `commit_supports_question_mark_chaining` driving a
  generic `Result<(), Infallible>`-returning body. The sole external
  caller in this submodule (`trellis-conformance/tests/store_parity.rs`)
  targets the postgres-side commit and was unaffected; the only
  memory-side caller updated was the internal test at `lib.rs:213`.

- **Loopback DSN classifier edge cases + bracketed-IPv6 parser fix**
  (`c33c91c`). Four new unit tests: comma-separated host list rejected
  conservatively (false-negative is the safe direction; production
  multi-host setups must use `connect_with_tls`); empty-string `host=`
  accepts (libpq local-socket fallback); relative-path "socket" hosts
  rejected (libpq requires absolute paths; the gate enforces "no
  cleartext on a wire" first); IPv6 `[::1]` accepts in both kv and
  URI forms. **Real-bug surfaced:** the IPv6-URI test fired a defect in
  `extract_dsn_host` where `rsplit_once(':')` sliced bracketed IPv6
  literals internally (e.g. `[::1]` produced host=`[:`, port=`1]`).
  The classifier was fail-closed (rejecting valid loopback DSNs with
  a confusing "host `:`" error) — safe direction but operator-hostile.
  Fixed inline: when `host_port` starts with `[`, the bracketed slice
  IS the host; port (if any) comes after `]:`. Mismatched brackets
  fall through to the loopback classifier which rejects anything
  non-trivial.

- **Migration runner refuse-on-future-version guard** (`6684b23`).
  "Append-only migrations" was convention only — `BTreeSet::contains`
  let an old binary connect to a forward-rolled schema (botched
  rollback / partial deployment) and silently no-op. The guard
  compares `applied.iter().max()` against
  `MIGRATIONS.iter().map(|(v,_)| *v).max()` inside the same
  advisory-lock-bracketed transaction; if the database is ahead,
  returns `MigrationFailed` with a "schema ahead of binary" message
  naming both versions so the operator rolls forward (deploy newer
  binary) or rolls back (database state) rather than running on
  lying schema awareness. Pinned by
  `migrations_refuse_when_schema_ahead_of_binary`, which forges a
  `version=999` row on a fresh cluster and asserts
  `PostgresStore::connect` refuses with `MigrationFailed` and the
  expected message fragments.

Verification: `cargo test -p trellis-store-memory` clean (5/5);
`cargo test -p trellis-store-postgres` clean (21/21);
`cargo test -p trellis-conformance --test store_parity` clean (2/2);
`cargo test --workspace` clean (48 result buckets, 0 failures);
`cargo tree -p trellis-verify | grep -E '(postgres|r2d2|tokio-postgres|native-tls)'`
empty (Core §16 verifier-isolation invariant intact).

NEEDS_CONTEXT: none. The IPv6-URI parser fix went in the same commit
as the surfacing test on the rationale that the new test demonstrates
the defect AND validates the fix; splitting them produces a
deliberately-red commit which is worse history.

### Wave 18 (2026-04-27) — R15 temporal-in-force enforcement (item #30)

Closes item #30 from the post-Wave-17 TODO. Wave 15 review surfaced
that R15 enforces only the acyclic half of Companion §A.6 rule 15
("supersedes chain is acyclic AND each linked declaration was in force
at the time of the successor's `effective_from`"); OC-70e + TR-OP-048
silently dropped the temporal half. With one declaration in the corpus
today the gap is latent; closing it prevents an out-of-order
`effective_from` from passing silently the moment a second declaration
lands.

- **RED tests** (`2d559e5`). Six new R15 cases: valid temporal chain;
  successor `effective_from` BEFORE predecessor's (out-of-order);
  successor `effective_from` AFTER predecessor's `scope.time_bound`
  (window closed); two half-open boundary positives (equal lower bound
  is in; equal upper bound is out — pin comparator semantics so a
  GREEN regression cannot drift the bounds); real-reference
  declaration via `shutil.copytree` of `fixtures/declarations/ssdi-intake-triage/`
  + synthetic successor with out-of-order `effective_from` (Wave 15
  review F3 follow-up — removes the synthetic-vs-real seam).

- **GREEN extension** (`3ea9849`). Extends
  `check_declaration_supersedes_acyclic` to capture top-level
  `effective_from` and nested `scope.time_bound` per declaration during
  the existing single-pass walk; after cycle / dangling / duplicate
  detection, iterates supersedes edges and asserts the predecessor's
  half-open in-force window `[effective_from, scope.time_bound)`
  covered the successor's `effective_from`. Edges with non-UTC-datetime
  endpoints are skipped (R11 separately enforces shape; double-firing
  would be noise). External lint contract unchanged: same diagnostic
  class, same exit code, same call site. Cycle detection switched from
  recursive DFS to iterative explicit-stack while-loop with
  WHITE/GRAY/BLACK coloring preserved (Wave 15 review F6 nit closed —
  Python's 1000-frame default would have panicked on long single-parent
  chains; theoretical today, footgun removed cheaply).

- **Prose restoration** (`3575a10` + sibling `abaef36`). OC-70e prose
  restored to state both clauses ("acyclic, resolvable, AND
  temporal-in-force per Appendix A.6 rule 15") and now explicitly
  pins §A.6 rule 15 as the single-source-of-truth contract. Matrix
  TR-OP-048 was extended in flight by sibling-scout #32's commit
  `abaef36` (commit subject misnamed — message says store-postgres but
  the file diff is the matrix only; content is correct).

Wave 18 sibling-coordination note: five parallel scouts (#29 reason-code
reconciliation, #30 R15 temporal, #31 HPKE hardening, #32
store-postgres, #34 reason-code parity lint, plus ongoing #3 ADR 0005
crypto-erasure work) raced repeatedly on
`scripts/check-specs.py`, `scripts/test_check_specs.py`,
`specs/trellis-operational-companion.md`,
`specs/trellis-requirements-matrix.md`. Race protocol per the dispatch
brief: `git pull --rebase` before push. TR-OP-048 prose drift between
sibling commits resolved by accepting the sibling-committed matrix line
(content correct) and committing OC-70e under the right
docs(spec)-prefixed message in this scout's chain.

Verification: `python3 -m pytest scripts/test_check_specs.py -q` →
143 passed within R15 + adjacent territory (137 prior + 6 new R15
temporal); two pre-existing sibling-scout #34 failures
(`TestReasonCodeCorpusParity`) gate on item #29 (Wave 15 BLOCKER) and
are out of scope for this entry. `cargo test --workspace` clean.

NEEDS_CONTEXT: none.

### Wave 18 (2026-04-27) — Reason-code parity lint (item #34)

Closes item #34 from the post-Wave-17 TODO. Generalizes Wave 15's R13
`tamper_kind` corpus-vs-table parity discipline to the three Phase-1
ReasonCode families: Companion §A.5.1 (Custody-Model Transition),
Companion §A.5.2 (Disclosure-Profile Transition), and ADR 0005
§"Reason codes" (Erasure-Evidence; Companion §20.6.1 once promoted).
Closes the gap that let item #29's Wave-15 BLOCKER drift land
undetected — every `(family, code, name)` triple in fixture
derivations and generators now has to agree with its family's
registered table or the lint fires loud.

- **R19 `check_reason_code_corpus_parity` in `scripts/check-specs.py`.**
  Parses each table from spec markdown into `{family: {code: name}}`,
  walks every `derivation.md` under `fixtures/vectors/` and every
  `gen_*.py` under `fixtures/vectors/_generator/`, detects family
  by the first canonical marker (`CustodyModelTransitionPayload` /
  `DisclosureProfileTransitionPayload` / `ErasureEvidencePayload` and
  their event-type tags), and reports each disagreement with file +
  family + (annotated, registered) triple. Three annotation forms
  caught: derivation table-row (`| ` + "`reason_code`" + ` | ` + "`<int>`" + ` (<name>) |`),
  derivation body-prose form (`reason_code = <int>` (`<name>` ...)),
  generator comment (`REASON_CODE = <int>  # <name>`).

- **Family-ambiguous diagnostic.** A file annotating reason codes
  without naming any registered family marker is also rejected — the
  drift surface Core §6.9 cares about includes "author wrote a code
  without anchoring which family it belongs to."

- **TDD evidence.** `scripts/test_check_specs.py::TestReasonCodeCorpusParity`
  adds 12 cases: 3 table-parser smoke tests, 8 synthetic-injection
  cases (positive aligned, drift, unregistered code, family-ambiguous,
  body-prose form, generator-comment form, code-255-Other-floor OK +
  fail, files-without-reason-code-skipped), 1 live-corpus parity
  (`test_real_corpus_parity_via_table_authority`, mirroring R13's
  `test_real_corpus_is_clean`). All synthetic tests use stub tables
  via the `tables=` kwarg so test bodies do not depend on the live
  corpus state.

- **Matrix discipline.** TR-CORE-069 (Core §6.9 ReasonCode Registry,
  added Wave 15) Notes column updated to register R19 enforcement and
  cite the corpus-vs-table parity surface. `Verification = spec-cross-ref`
  unchanged — the lint is a meta-check across the corpus, not per-vector
  evidence; per-vector `tr_core` declarations would be a manifest-touch
  cascade (every transition + erasure fixture). Mirrors the R13 ↔
  TR-CORE-068 pattern (R13 lint cited in Notes, fixtures carry the
  TR-OP claims).

- **Sibling-coordination.** Lean-(b) per the brief: waited for
  item #29's §A.5.2 renumber to land before committing, so R19's
  `test_real_corpus_parity_via_table_authority` is GREEN at landing
  rather than a brief CI-red window. The lint detected exactly four
  drift sites pre-#29 (`append/008/derivation.md`,
  `tamper/016/derivation.md`, `gen_append_008.py`, `gen_tamper_016.py`);
  post-#29 the corpus is clean.

Verification: `cargo test --workspace` clean (0 failures across all
crates); `python3 scripts/test_check_specs.py` clean (155 prior + 12
new = 167 covered); `python3 scripts/check-specs.py` clean
(`Trellis spec checks passed.`).

NEEDS_CONTEXT: none.

### Wave 18 (2026-04-27) — Companion §A.5.2 reason-code renumber (Wave 15 BLOCKER, item #29)

Reconciles the Wave 15 BLOCKER where Companion §A.5.2 seeded
`code 4 = audience-scope-change` but four committed disclosure-profile
fixture artifacts (`append/008-disclosure-profile-transition-a-to-b`,
`tamper/016-disclosure-profile-from-mismatch`, plus their two generators)
emit `reason_code = 4` annotated `governance-policy-change`. Per the
seed's own kill-criterion ("freezes at first runtime use") and the
no-runtime-users state, owner picked path (a): renumber A.5.2 to mirror
A.5.1, fixtures byte-stable, prose locks. Co-lands with sibling-scout
#34's R19 corpus-vs-table parity lint above (sibling-#34 entry's
`Trellis spec checks passed.` referenced this entry's pre-state via
"two pre-existing sibling-scout #34 failures gate on item #29" — this
entry closes that gate).

- **§A.5.2 renumbered to mirror A.5.1.** New table:
  `1 = initial-deployment-correction` (= A.5.1),
  `2 = audience-scope-change` (disclosure-only — A.5.1 code 2 is
  custody-only),
  `3 = disclosure-policy-realignment` (disclosure-only — A.5.1 code 3 is
  custody-only),
  `4 = governance-policy-change` (= A.5.1; matches the four fixtures),
  `5 = legal-order-compelling-transition` (= A.5.1),
  `255 = Other` (cross-family invariant, Core §6.9). Codes whose meaning
  is shared across families now share their numeric value (1, 4, 5);
  disclosure-only codes (2, 3) fill A.5.1's custody-specific slots so
  cross-family numeric collisions never carry a meaning-equivalent
  reinterpretation.

- **Pin note added.** §A.5.2 trailing paragraph closes with: "this seed
  table locks at first runtime use per Core §6 (Event Format) §6.9
  ReasonCode Registry governance — once a Phase-1 producer emits a
  registered code on the wire, the (code, meaning) binding is
  append-only; renumbering after first runtime use is a wire break."
  Future seeders cannot reuse the "still pre-runtime" loophole.

- **Fixture corpus byte-stable.** No fixture or generator was edited.
  The four annotated artifacts already emitted `reason_code = 4`
  annotated `governance-policy-change`; the renumbered table now agrees.
  `append/008` and `tamper/016` byte hashes unchanged.

- **TDD evidence — sibling #34's R19 parity lint transitions RED→GREEN.**
  Sibling-scout #34 (Wave 18 parity-lint, entry above) authored R19
  expecting it to fail at HEAD until this BLOCKER lands. Pre-renumber:
  R19 fired on the four §A.5.2 disclosure-profile artifacts (the two
  failures sibling #30 noted as out-of-scope and sibling #34's own
  Verification block recorded). Post-renumber (this commit): R19
  passes (`scripts/check-specs.py` exit 0, "Trellis spec checks
  passed.") Canonical Red-Green-Refactor: parity oracle and spec
  reconciliation land as one wave.

- **Matrix discipline.** TR-OP-046 prose names neither specific codes
  nor specific (code, meaning) pairs — it is a meta-rule about
  per-family registry mechanics under Core §6.9. No matrix update
  required.

Verification: `cargo test --workspace` clean (0 failures);
`cd trellis-py && python3 -m pytest -q` clean (4);
`python3 -m trellis_py.conformance` clean (71 vectors, 0 failures);
`python3 -m unittest scripts.test_check_specs` clean (155);
`python3 scripts/check-specs.py` clean (`Trellis spec checks passed.`).

NEEDS_CONTEXT: none.

### Wave 18 (2026-04-27) — HPKE crate hardening (item #31)

Closes item #31 from the post-Wave-17 TODO. Lands the four follow-ups
from the Wave 16 HPKE review (commit `0c1573d`, approve-with-suggestions)
as one change train. Architecture sound; this train closes the
dep-pin / production-footgun / verifier-isolation drift in one wave so
the HPKE substrate is a stable foundation for ADR 0005 (item #3, Wave
18+) and the Phase-2+ adapters in TODO items #19-#22.

- **Pin all crypto deps exact** (`0ac4261`). Byte-exact reproducibility
  for `append/004-hpke-wrapped-inline` flows through `chacha20poly1305`,
  `hkdf`, `x25519-dalek`, `sha2`, and `rand_core` directly; caret-ranges
  left those crates free to drift on the next `cargo update`. `=`-pin
  all five at the resolved versions (`Cargo.lock`):
  `chacha20poly1305 = 0.10.1`, `hkdf = 0.12.4`, `x25519-dalek = 2.0.1`,
  `sha2 = 0.10.9`, `rand_core = 0.9.5`. The existing `hpke = 0.13.0`
  pin stays unchanged. `Cargo.toml` gains a `# DO NOT BUMP without
  re-verifying:` block adjacent to the pins; (1) names the
  `#[doc(hidden)]`-but-`pub` `hpke::kdf::{labeled_extract,
  extract_and_expand, LabeledExpand}` symbols
  `wrap_dek_with_pinned_ephemeral` leans on (any minor-version bump may
  make these private and silently break the carve-out); (2) names the
  four other crates whose under-specified version-level behavior (AEAD
  nonce schedules, KDF chaining, X25519 scalar clamping) drives the
  byte oracle; (3) pins ADR 0009 §Lifecycle promote-on-bump as the
  doc-trigger.

- **`test-vectors` Cargo feature gate** (`1c87dc3`).
  `wrap_dek_with_pinned_ephemeral` (the Core §9.4 test-vector carve-out
  path) now sits behind a `test-vectors` Cargo feature, default off.
  `derive_base_key_and_nonce`, the `chacha20poly1305` /
  `hpke::kdf::{labeled_extract, extract_and_expand, LabeledExpand}` /
  `x25519_dalek` imports, the `KEM_SUITE_ID` and `HPKE_SUITE_ID` consts,
  the `pinned_ephemeral_wrap_round_trips` unit test, and
  `tests/append_004_byte_match.rs` (whole file) all gate to the same
  feature. A binary built without `--features test-vectors` does not
  have the symbol to link — production crate-graphs cannot link the
  carve-out path even by mistake. Production code (`wrap_dek`,
  `unwrap_dek`, `WrapResult`, `HpkeError`, `HPKE_SUITE1_INFO`,
  `HPKE_SUITE1_AAD`, the `wrap_then_unwrap_round_trip` smoke test)
  unchanged. Smoke test switched its recipient-pubkey derivation from
  `x25519_dalek::PublicKey::from(&X25519Static::from(seed))` to the
  `hpke` crate's own `Kem::sk_to_pk` so it stays compilable when the
  `x25519-dalek` import is gated off. Makefile `test-rust` now runs
  both passes (`cargo test --workspace` + `cargo test -p trellis-hpke
  --features test-vectors`); CI exercises the byte oracle.

- **Spike → ADR 0009 promotion** (`0576ccd`). The 2026-04-24 spike's
  own §Lifecycle pinned promote-on-bump as the trigger; closing this
  debt proactively gives normative HPKE crate-selection authority a
  stable doc id. New
  [`thoughts/adr/0009-hpke-crate-selection.md`](thoughts/adr/0009-hpke-crate-selection.md)
  covers crate selection + rejected options, the sibling-crate posture
  (`trellis-hpke` peer-of `trellis-cose`, not embedded — same
  architectural pattern as ADR 0008 §ISC-05), the six pinned versions,
  the `wrap_dek_with_pinned_ephemeral` carve-out path's reliance on
  `#[doc(hidden)]`-but-`pub` symbols, the verifier-isolation invariant,
  the §Lifecycle clause (any of the six bumps triggers re-read +
  Decision-log entry; byte oracle is the load-bearing canary), and a
  Decision log with entries for 2026-04-24 (selection), Wave 16
  (execution), Wave 18 (this hardening). Spike header rewritten to
  declare **Superseded — non-normative archive** and point at ADR
  0009; spike body preserved as historical context.

- **Verifier-isolation CI assertion** (`4d18b40`). The sibling-crate
  architecture rests on Core §16 (Verification Independence): the
  offline verifier path MUST NOT pull HPKE / X25519 / AEAD / HKDF
  crypto crates. Until now, that property was prose-only. A future
  `trellis-cose` change adding `trellis-hpke` as a dep would silently
  breach the invariant — every consumer of `trellis-cose` (including
  `trellis-verify`) would inherit HPKE.
  `scripts/check-verifier-isolation.sh` is the loud-fail gate:
  `cargo tree -p trellis-verify` MUST NOT mention `hpke`,
  `x25519-dalek`, `chacha20poly1305`, or `hkdf`. Wired three ways:
  `make check-verifier-isolation` (fast iteration), `make test` (CI
  runs this target), `.PHONY` + help text. Negative-case verified by
  injecting `hpke = "=0.13.0"` as a `trellis-verify` dep; the script
  flagged all four crates with diagnose hint and exited 1.

Verification: `cargo test --workspace` clean (workspace still resolves
to the same `Cargo.lock` entries; no consumer's resolved version
moves); `cargo test -p trellis-hpke --features test-vectors` green
(2 unit tests + 3 byte-oracle integration tests; `append/004`
produces `34e42d4af5ef94a07a3a84201b889d4cd1a743cb27b11b6a10438a8feb8e5847`
for the ephemeral pubkey and the committed wrapped-DEK bytes);
`cargo test -p trellis-hpke` (feature off) — 1 unit test, 0
integration tests (gated symbols cannot be referenced even by accident);
`cargo tree -p trellis-verify | grep -E 'hpke|x25519-dalek|chacha20poly1305|hkdf'`
empty; `make check-verifier-isolation` → `OK: trellis-verify is
HPKE-clean.`; `python3 scripts/check-specs.py` clean (warnings-only
on Phase-1 non-signing key-class fixtures, no errors); G-5 stranger
cross-check (`trellis-py`) clean across all 71 vectors.

NEEDS_CONTEXT: none. Five-sibling parallel wave produced concurrent-
staging churn on TODO.md / COMPLETED.md / spec files; Cargo.toml /
lib.rs / Makefile changes were committed atomically with `git commit
-o <path>` to dodge index races (the parent submodule is shared on
disk between sibling agents).

### Wave 17 (2026-04-27) — Key-class taxonomy execution (ADR 0006)

Closes item #1 from the post-Wave-15 TODO. Lands the unified `KeyEntry`
taxonomy end-to-end: Core §8.7 prose, CDDL, `trellis-verify` registry
dispatch, `trellis-py` parity, vectors `append/031..035` (five reservation
positives) + `tamper/023..025` (three class-dispatch negatives), matrix
rows TR-CORE-039 / TR-CORE-047 / TR-CORE-048, and the ADR 0005 `key_class`
reconciliation (`wrap`→`subject` normalization is executed on both runtimes).
Reconciles the dropped-without-replacement five-key-class gap surfaced in
`specs/archive/cross-reference-map-coverage-analysis.md` §8 inside the
Phase-1 envelope (no wire break for the legacy flat `SigningKeyEntry`
shape; verifiers dispatch on presence of a top-level `kind` field).

- **Item #1 — Key-class taxonomy.** Pre-existing Wave-17 work had already
  landed Core §8.7 (taxonomy + CDDL + verifier-dispatch prose), the
  matrix rows, vectors `append/031..035`, the Rust + Python
  `parse_key_registry` dispatch, and the `scripts/check-specs.py`
  Phase-1 non-signing warning. Three gaps remained: (a) the empty
  `tamper/023..025/` directories were panicking the conformance
  harness with no `manifest.toml`; (b) registry-shape failures bubbled
  as untyped `VerifyError` instead of surfacing as a typed
  `tamper_kind = "key_entry_attributes_shape_mismatch"`; (c) TR-CORE-049
  (unknown-`kind`) was tagged `Verification = test-vector` but ADR 0006
  *Fixture plan* defers unknown-`kind` to a follow-on row.

- **Tamper vectors landed.**
  - `tamper/023-key-class-mismatch-signing-as-recovery` — recovery-class
    kid in COSE_Sign1 protected header; `tamper_kind =
    "key_class_mismatch"` per Core §8.7.3 step 4.
  - `tamper/024-key-entry-attributes-shape-mismatch` — `subject`-kind
    row missing required `attributes` map; `tamper_kind =
    "key_entry_attributes_shape_mismatch"` per Core §8.7.1 / §8.7.3
    step 3.
  - `tamper/025-subject-key-wrap-after-valid-to` — subject-class kid in
    COSE_Sign1 protected header; `subject` row carries explicit
    `valid_to` so the wire bytes also exercise the Phase-2+
    `subject_wrap_after_valid_to` enforcement seam (captured today as
    `NonSigningKeyEntry.subject_valid_to`; runtime enforcement defers
    to ADR 0006 *Phase-1 runtime discipline* "lifts the Wrap-entry
    recipient reference to a registered `subject` kid"). Phase-1
    detection mode: `tamper_kind = "key_class_mismatch"`. The
    deferred-runtime caveat is documented in the vector's
    `derivation.md`.

  All three generated by
  `fixtures/vectors/_generator/gen_tamper_023_to_025.py`; non-signing
  kids are byte-equal to the corresponding ones in
  `append/032..035` so cross-vector reasoning holds.

- **Verifier plumbing.** `VerifyError` extended with an optional
  `kind: &'static str` tag; `parse_key_registry` uses
  `VerifyError::with_kind("key_entry_attributes_shape_mismatch", ...)`
  when the §8.7.1 shape gate fails. `verify_export_zip` and
  `verify_tampered_ledger` map the kind tag onto
  `VerificationReport::fatal(kind, ...)` so the structural-failure code
  flows into the report's `tamper_kind` field. Subject-class
  `valid_to` captured into `NonSigningKeyEntry.subject_valid_to` for
  Phase-2+ enforcement readiness; `#[allow(dead_code)]` until the
  Phase-2+ recipient-as-kid path activates. Mirrored in
  `trellis-py/src/trellis_py/verify.py` (`VerifyError.kind`,
  `NonSigningKeyEntry.subject_valid_to`, both call sites).

- **Matrix discipline.** TR-CORE-049 (unknown-`kind` /
  `unknown_key_class`) demoted from `Verification = test-vector` to
  `Verification = prose` because ADR 0006 *Fixture plan* explicitly
  defers unknown-`kind` and `tstr` class-injection vectors to a
  follow-on row beyond `tamper/023..025`. Promote back to test-vector
  when that follow-on lands. TR-CORE-039 / TR-CORE-047 / TR-CORE-048
  covered by the new vectors.

- **ADR 0005 reconciliation.** `wrap`→`subject` normalization is now
  executed on both runtimes; the ADR 0005 status note records the
  cross-reference is in-tree.

Verification: `cargo test --workspace` clean (140+/component); `cd
trellis-py && python3 -m pytest -q` clean (4); `python3 -m
trellis_py.conformance` clean (71 vectors, 0 failures); `python3
scripts/check-specs.py` clean (warnings: Phase-1 non-signing
reservations from the seven `KeyEntry` vectors are intended per ADR
0006 §"Phase-1 lint discipline"; final line "Trellis spec checks
passed."). Renumbering of items #3..#29 deferred to Wave 17's final
landing pass per the prior wave entry.

NEEDS_CONTEXT: none.

### Wave 17 (2026-04-27) — HPKE duplicate-ephemeral detection lint

Closes the §9.4 producer-side ephemeral-uniqueness MUST that was deferred
by design until Rust HPKE existed (Wave 16). Targets item #2 from the
post-Wave-16 TODO (renumber from #3 → #2 already landed in
`bfedfad`).

- **Item #2 — HPKE duplicate-ephemeral detection lint.** New
  `scripts/check-specs.py` rule **R17 — `check_hpke_ephemeral_uniqueness`** —
  walks `vector_event_payloads()`, groups artifacts by vector dir
  (collapsing the multiple-CBOR-view duplicates that
  `vector_event_payloads()` yields), and rejects (a) duplicate
  `ephemeral_pubkey` inside a single `KeyBag.entries` (Core §9.4 "N
  recipients require N distinct values") and (b) any `ephemeral_pubkey`
  byte-equality across distinct vector dirs (Core §9.4 reuse "across
  events in the same ledger scope, or across ledger scopes" — the
  persisted `ephemeral_pubkey` IS the encapsulated key derived from the
  single-shot private scalar, so byte equality across wraps proves
  scalar reuse). Within-event vs cross-vector failures emit distinct
  diagnostics so the §9.4 clause being violated is unambiguous.

- **Placement decision: corpus-time lint, not runtime enforcement.**
  Core §9.4 phrases the obligation as a producer-side MUST ("Every
  `KeyBagEntry` ... MUST use a fresh X25519 ephemeral keypair"; reuse
  "is a non-conformance"), not a verifier obligation. Corroboration:
  §19.1's `tamper_kind` enum has no `ephemeral_reuse` category and §16
  pins verifier statelessness across events ("Verifiers MUST NOT depend
  on derived artifacts, workflow runtime, or mutable DBs"). A verifier
  holding only one event has no prior-state to compare against; runtime
  detection in `trellis-verify` would require violating §16. Production
  freshness rests on `OsRng` in `trellis-hpke::wrap_dek` (Wave 16
  byte-oracle); the §9.4 test-vector carve-out is the gap this lint
  closes — fixture-pinned ephemerals committed under
  `fixtures/vectors/_keys/` give a copy-paste path that would otherwise
  silently reuse an ephemeral across vectors. Lives in
  `scripts/check-specs.py` (alongside R13/R14/R15 and other corpus
  contracts), not in `trellis-hpke` (the `setup_sender` path already
  uses fresh randomness; the lint is for the
  `wrap_dek_with_pinned_ephemeral` carve-out plus any hand-rolled
  fixture that did not flow through `wrap_dek` at all) and not in
  `trellis-verify` (Core §16 verification independence).

- **TDD-RED → GREEN.** 8 unit tests in
  `scripts/test_check_specs.py::TestHpkeEphemeralUniqueness` covering:
  distinct ephemerals across vectors pass; same-vector multiple
  CBOR-view duplicates collapse (not reuse); cross-vector reuse in
  same scope fails with diagnostic citing both vector dirs; cross-scope
  reuse fails (the encapsulated key value alone is the reuse witness);
  within-event recipient-list duplicates fail with §9.4 N-recipients
  clause cited; `key_bag` absent / empty-entries skipped; real corpus
  is clean. RED state confirmed before lint landed (8 failures with
  `AttributeError: module 'check_specs' has no attribute
  'check_hpke_ephemeral_uniqueness'`).

- **Spec + matrix + fixture in same change train.** New row
  **TR-CORE-033** anchored in Core §9.4 carve-out paragraph + §30
  traceability list; `append/004-hpke-wrapped-inline` claims
  TR-CORE-033 in `coverage.tr_core`. (The TR-CORE-033 anchor + §30
  list edits + matrix row landed in commit `3327cbe` alongside the
  sibling key-class scout's pre-commit sweep; the lint code + tests +
  manifest claim land here in the Wave 17 commit train.)

Verification: `python3 scripts/check-specs.py` clean, 137 lint tests
green (was 129; +8 new R17 tests), `cargo test --workspace` clean,
`cd trellis-py && python3 -m pytest -q` clean (G-5 cross-check, 4
vectors).

NEEDS_CONTEXT note: the existing corpus has only one HPKE-wrapped
vector (`append/004`), so the cross-vector branch of the lint is
exercised only by synthetic-injection unit tests today. When item #1
(key-class taxonomy) lands `append/031..035` and ADR 0005 lands
`append/023..027`, additional HPKE-wrapped vectors will exercise the
cross-vector path against the real corpus.

### Wave 16 (2026-04-27) — Rust HPKE wrap/unwrap; `trellis-store-postgres` production hardening

Foundational crypto execution begins. Targets items #2 (HPKE wrap/unwrap
in Rust) and #31 (`trellis-store-postgres` production hardening) from
the post-Wave-15 TODO. Run in parallel — no file overlap (HPKE in
`crates/trellis-hpke/`, store hardening in `crates/trellis-store-postgres/`).

- **Item #2 — Rust HPKE wrap/unwrap, byte-matching `append/004`.**
  New `trellis-hpke` sibling crate (NOT folded into `trellis-cose`) so
  HPKE deps do not leak into `trellis-verify` via the existing
  `trellis-verify -> trellis-cose` chain — Core §16 verification
  independence preserved (`cargo tree -p trellis-verify` confirms zero
  HPKE crates pulled). Three call shapes: `wrap_dek` (production seal,
  `OsRng` ephemeral, through `hpke::single_shot_seal_in_place_detached`),
  `wrap_dek_with_pinned_ephemeral` (fixture-only carve-out per Core §9.4
  test-vector clause — bypasses `hpke::setup_sender`'s mandatory
  DeriveKeyPair-on-fresh-randomness path and uses the lower-level
  public KDF helpers `labeled_extract` / `extract_and_expand` plus
  `x25519-dalek` + `chacha20poly1305` directly), and `unwrap_dek`
  (production / verifier, `setup_receiver` + `AeadCtxR::open`). Pinned
  to `hpke =0.13.0`; the `0.14.0-pre.2` pre-release pulls a broken
  `sha3 0.11.0-rc.7`. **G-5 strengthens** from "vectors match" to
  "Rust independently derives the same `ephemeral_pubkey` (`34e42d4af5...`)
  and `wrapped_dek` (`9f89d135c1...`) bytes as `gen_append_004.py`"
  — `tests/append_004_byte_match.rs` is the byte oracle and includes a
  cross-check that decrypts the `wrapped_dek` pulled directly out of
  the committed `expected-event-payload.cbor`. Spike doc
  (`thoughts/specs/2026-04-24-hpke-crate-spike.md`) updated to
  Status = Executed with implementation notes.

- **Item #31 — `trellis-store-postgres` production hardening — canonical-side of composed `EventStore`.**
  Six sub-bullets landed (TLS / transaction-composition / idempotency-key uniqueness /
  versioned migrations / parity tests / connection pool); supersedes the canonical-side
  scope of parent `work-spec/crates/wos-server/TODO.md` **WS-020** + **WS-090** (two-port
  `Storage` + `AuditSink` split that VISION.md §VIII rejects) — wos-server-side reconciliation
  is a follow-up handle for the wos-server-spec owner.
  + **TLS wiring.** `connect` now refuses non-loopback DSNs (`UnsafeDsn` error class);
    `connect_with_tls(dsn, native_tls::TlsConnector)` accepts any DSN. Loopback gating
    parses both libpq KV and `postgres://` URI forms; recognizes IPv4/IPv6 loopback,
    `localhost`, Unix-socket directories. `postgres-native-tls = "0.5"` chosen over
    `postgres-rustls` for native-platform-trust integration; pinned via lockfile.
  + **Transaction-composition surface.** New `append_event_in_tx(&mut Transaction, &StoredEvent, Option<&[u8]>) -> Result<(), PostgresStoreError>`
    free function — wos-server's `EventStore` opens its own transaction on its own
    `postgres::Client`, calls this for the canonical row, writes its `projections`
    rows on the same `tx`, and commits. The load-bearing single-transaction-per-write
    invariant the rejection of dual-write rests on (VISION.md §VIII). `LedgerStore::append_event`
    keeps its existing seam, now implemented as a one-shot tx wrapper. Memory-store parity
    via `MemoryStore::begin` + `MemoryTransaction` + `trellis_store_memory::append_event_in_tx`
    (buffer-on-commit, drop-on-rollback) — same shape so cross-store parity tests share a
    single body.
  + **Idempotency-key uniqueness.** Schema-level only per scope note in TODO #31:
    column `idempotency_key BYTEA NULL`, partial unique index
    `trellis_events_scope_idempotency_uidx ON (scope, idempotency_key) WHERE idempotency_key IS NOT NULL`,
    plus a `CHECK (octet_length BETWEEN 1 AND 64)` matching Core §6.1 / §17.2.
    `append_event_in_tx` rejects collisions with `IdempotencyKeyPayloadMismatch` —
    Postgres surface for Core §17.5. Phase-1 callers pass `None` until item #24
    threads the field through `trellis-cddl` / `trellis-types` / `trellis-core` /
    `trellis-verify` / conformance / cli / py.
  + **Versioned migrations.** New `trellis-store-postgres::migrations` module —
    `trellis_schema_migrations(version, applied_at)` ledger, advisory-lock-bracketed
    apply (`pg_advisory_xact_lock(0x7472656c6c697300)` = "trellis\0" so two
    replicas connecting at startup don't race), append-only migration list. v1 = initial
    table; v2 = idempotency-key column + partial unique index + length CHECK. Hand-rolled
    over `refinery` to keep deps lean and the migration list readable inline.
    `migrations_apply_idempotently_across_reconnects` test verifies re-apply is a no-op.
  + **Parity tests + Postgres CI.** New `crates/trellis-conformance/tests/store_parity.rs`
    runs every fixture under `fixtures/vectors/append/` against both `MemoryStore` AND
    `PostgresStore` and asserts byte-identical canonical + signed bytes round-trip out
    of Postgres (`TRUNCATE` between fixtures because the corpus reuses scopes). Second
    integration test `transaction_composition_atomic_with_caller_projections` exercises
    the load-bearing rollback-with-projection-write semantic. `make test-postgres`
    target documents the dependency surface (Postgres `initdb`/`pg_ctl` on PATH);
    `cargo test --workspace` already runs both. Test cluster harness (initdb +
    pg_ctl + ephemeral port + temp dir) duplicated into `tests/common/mod.rs` rather
    than promoting to public API in `trellis-store-postgres`.
  + **Connection pool.** `PostgresStorePool::builder` / `builder_with_tls` →
    `PoolBuilder::{max_size, connection_timeout}.build() -> PostgresStorePool` with
    `r2d2 = "0.8"` + `r2d2_postgres = "0.18"`; `checkout()` returns a `PooledClient`
    enum that derefs to `postgres::Client`. `deadpool-postgres` rejected as the brief's
    "lean" guidance — `deadpool-postgres` is async-only and would force a tokio runtime
    into Trellis (load-bearing architectural shift Trellis has not adopted); `r2d2_postgres`
    is the sync-native equivalent and matches `postgres = "0.19"`. Inner pool is a runtime
    enum (`InnerPool::{NoTls, NativeTls}`) — `r2d2_postgres::PostgresConnectionManager<T>`
    is generic over a single TLS type per pool, and a custom-enum `MakeTlsConnect` impl
    hits a `tokio::io` sealed-trait wall. Sizing guidance pinned in the crate doc-comment.

Cross-cutting: 16 unit + integration tests in `trellis-store-postgres` (was 1); 4 in
`trellis-store-memory` (was 0); 2 in `trellis-conformance/tests/store_parity.rs` (new).
`PostgresStoreError` gained a stable `kind: PostgresStoreErrorKind` taxonomy (callers
match on enum, not message strings) covering `ConnectionFailed` / `UnsafeDsn` /
`MigrationFailed` / `QueryFailed` / `IdempotencyKeyPayloadMismatch` / `DomainViolation` /
`IdempotencyKeyTooLong` / `PoolFailed`. Verification-independence contract preserved —
`trellis-verify` deps unchanged; `cargo tree -p trellis-verify` shows no `postgres`,
no `r2d2`, no `native-tls`.

NEEDS_CONTEXT note: wos-server-side reconciliation of WS-020 + WS-090 (the two-port
`Storage` + `AuditSink` split that VISION.md §VIII rejects) is the wos-server-spec
owner's call. This item lands the canonical-side; the wos-server-side `EventStore`
that composes `trellis-store-postgres + projections schema + single tx` per VISION.md
§III + §V is wos-server-spec follow-up.

### Wave 15 (2026-04-27) — small-stuff sweep before HPKE / Postgres

Cleared the four XS/S items at the top of TODO before tackling the
foundational crypto + production-hardening work. All four close
de-facto contracts that prose was leaving informal:

- **Item #1 — `tamper_kind` enum normative in Core §19.1.** Promoted
  the de-facto fixture-author convention from `tamper/001`'s
  derivation.md (proposed 13 values) to a normative §19.1 enum table
  matching the 15 categories actually in the corpus (caught the drift:
  corpus had renamed `wrong_scope` → `scope_mismatch`,
  `registry_snapshot_swap` → `registry_digest_mismatch`, plus three
  catalog-digest-mismatch values absent from the original proposal).
  Authority placement: §19.1 (verifier output), not §17.5 (CAS
  rejection codes — different concept). Enforced by check-specs R13.
  TR-CORE-068 row + tamper/001 coverage update.
- **Item #2 — ReasonCode registry per-family under Core §6.9.**
  Decision: per-family namespace, `255 = Other` is the only shared
  cross-family invariant. Code `3` already meant
  `operator-boundary-change` in custody-model and
  `legal-order-compelling-erasure` in erasure-evidence; merging the
  namespaces would silently reinterpret. Companion §A.5.1 +
  §A.5.2 (NEW reason-code table — was a gap; A.5.2 had `reason_code:
  uint` with no inline registry) + §20.6.1 (NEW erasure reservation)
  + ADR 0005 all cite Core §6.9. Three matrix rows: TR-CORE-069 +
  TR-OP-046 + TR-OP-104.
- **Items #3 + #4 — O-4 lint rules 14 + 15 + renumbering CI guard.**
  Batched; all three live in `scripts/check-specs.py`.
  + R14 = signing-key structural validation (no crypto): alg in the
    Phase-1 set, signer_kid non-empty, cose_sign1_b64 base64-shaped.
    Anchored at Companion §19.9 OC-70d, TR-OP-047.
  + R15 = `supersedes` chain acyclicity: walks declaration corpus,
    builds DFS graph, rejects cycles / dangling refs / duplicate ids.
    Anchored at Companion §19.9 OC-70e, TR-OP-048.
  + R16 = wrapper around the existing `check-vector-renumbering.py`
    (which had unit-test coverage but was unwired from
    `check-specs.py`). Opt-in via `TRELLIS_CHECK_RENUMBERING=1`
    so local dev branches without an `origin/main` to compare to
    don't trip; CI / `make check-specs-strict` sets it.

Verification: 129 lint tests (was 106; +23), 7 renumbering-script
tests, full cargo workspace, and `make check-specs-strict` all green.

NEEDS_CONTEXT note: Companion §A.5.2's seeded reason codes (1-5) are
best-effort interpretations of disclosure-side reasons by analogy to
A.5.1's custody-side codes — first SBA PoC vector that exercises a
disclosure-profile transition pins them. Codes 1-5 freeze at first
runtime use; 255 stays as catch-all and codes 6-onwards register
cleanly under append-only.

### Wave 14 (2026-04-24) — ADR 0006/0007, HPKE + anchor spikes, shared-bundle design

Rounded out the decision-document set that the 2026-04-23 audit sweep
surfaced as gaps, plus landed the DI-first anchor-substrate stance.

- **ADR 0006 — Key-class taxonomy.** Core §8's `SigningKeyEntry` generalized
  to a tagged-union `KeyEntry` with five variants: `signing`, `tenant-root`,
  `scope`, `subject`, `recovery`. Phase-1 CDDL lands all five as envelope-
  reserved; Phase-1 runtime restricts emission to `signing` only. Unblocks
  ADR 0005 `key_class` enum alignment and Phase-2+ custody models CM-D /
  CM-F. Lands at `thoughts/adr/0006-key-class-taxonomy.md`.
- **ADR 0007 — Certificate-of-completion composition.** `trellis.certificate-
  of-completion.v1` canonical event binds a human-readable PDF/HTML artifact
  to a signing-workflow completion event via ADR 0072 attachment path +
  chain-derived `ChainSummary` the verifier cross-checks. PDF rendering NOT
  normatively pinned; gross PDF-vs-chain divergence is detectable. Nine-step
  implementation arc; seven-vector fixture plan. Closes the DocuSign-
  replacement pitch in engineering terms. Lands at
  `thoughts/adr/0007-certificate-of-completion-composition.md`.
- **HPKE crate selection spike.** Picks `hpke` (rozbb/rust-hpke) for the
  Rust wrap/unwrap path. Pure Rust, single-shot API matches per-KeyBagEntry
  usage, PQ-suite migration path via KEM-generic traits. Interface sketch
  + verification approach pinned for sequence item #6. Lands at
  `thoughts/specs/2026-04-24-hpke-crate-spike.md`.
- **Anchor substrate spike — DI-first.** Does NOT pick OpenTimestamps vs
  Rekor vs Trillian. Declares an `AnchorAdapter` trait + enumerates three
  first-class candidate adapters. Adopters pick per-deployment; multi-
  adapter deployments are native via ADR 0002's list-form `external_anchors`.
  Keeps ε (vision-model anchor-substrate uncertainty) formally open at
  the center while giving adopters a stable trait contract. Lands at
  `thoughts/specs/2026-04-24-anchor-substrate-spike.md`.

Parent-repo landing same session:

- **Shared cross-seam fixture bundle design.** Parent monorepo hosts
  `fixtures/stack-integration/` with per-scenario bundles combining
  Formspec canonical response + WOS provenance events + Trellis export
  bundle + pinned expected cross-layer verifier report. Full-stack
  analogue of Trellis G-5. Three Phase-1 bundles planned (WOS-T4
  signature-complete, ADR 0073 public-create, ADR 0073 workflow-attach).
  Lands at `formspec/thoughts/specs/2026-04-24-shared-cross-seam-fixture-
  bundle-design.md`.

### Wave 13 (2026-04-24) — TODO structural flattening

Collapsed Trellis TODO from ten numbered streams plus separate Deferred
and Sustaining sections into one sequenced list of 22 open items, each
carrying its prerequisite inline. Removed redundant `Phase 1` tags on
open-work items (all Phase-1 by default); kept Phase-2/3/4 tags where
they differentiate. Stripped landed-status narrative from the
WOS-T4 and ADR-0073 Stream bodies — COMPLETED.md holds that history.
Parent TODO + cross-refs updated. No content lost; structure flatter.

### Wave 12 (2026-04-23) — audit sweep + ADR 0005 + G-O-5 re-close

Closed out the 2026-04-23 design-doc audit sweep in three phases:

- **O-5 disclosure-profile verifier gap closed.** Rust `trellis-verify`
  and Python stranger both extended to decode
  `trellis.disclosure-profile-transition.v1` in addition to the custody-
  model axis. `tamper/016-disclosure-profile-from-mismatch` is the
  negative oracle. G-O-5 was retroactively reopened in the ratification
  checklist on 2026-04-23 after the audit surfaced the gap, then
  re-closed the same day once the Rust + Python + vector arrived.
  Verified by `cargo test -p trellis-conformance` +
  `python3 -m trellis_py.conformance` (63 vectors, 0 failures).
- **ADR 0005 — Crypto-erasure evidence.** Adopts explicit
  `trellis.erasure-evidence.v1` event over the absence-is-evidence
  alternative. Extension-slot wire shape, chain-cross-check verifier
  obligation, Companion §20 rewrite (OC-78 promotion + new OC-79/80/81),
  optional export catalog. Closes the DocuSign-replacement positioning
  claim around provable crypto-shredding. Lands at
  `thoughts/adr/0005-crypto-erasure-evidence.md`. Execution arc is
  Trellis TODO sequence item #8.
- **Audit execution.** Archived nine landed design briefs from
  `thoughts/specs/` (six in Group A clean archive + two in Group B
  needing citation migration + one cross-cutting doc); promoted the
  Phase-1 ADR 0001-0004 set + the new ADR 0005 from `thoughts/specs/`
  into a new Trellis-local `thoughts/adr/` tree; updated citations in
  Trellis TODO / CLAUDE.md / product-vision.md and parent
  vision-model.md; deleted the stale auto-memory file that duplicated
  the ADR content. §8.6 HPKE wording tightened to match §9.4 semantics.
  `thoughts/specs/` emptied; new design work lands there before
  promotion or archive.

### Wave 11 (working tree) — ADR 0072 attachment export closure

Closed the Trellis-side Phase-1 evidence-integrity export batch:

- Added deterministic fixture generation for `export/005-attachments-inline`,
  `verify/013-export-005-missing-attachment-body`, and
  `tamper/013-attachment-manifest-digest-mismatch`.
- Landed `061-attachments.cbor` fixture coverage bound through
  `ExportManifestPayload.extensions["trellis.export.attachments.v1"]`, with
  inline attachment ciphertext under `060-payloads/`.
- Extended the Rust verifier to check the attachment-manifest digest, resolve
  each `binding_event_hash` to an event carrying
  `trellis.evidence-attachment-binding.v1`, compare manifest fields to the
  chain-authored binding, and reject missing inline attachment bodies.
- Reconciled TODO / executable-dispatch state so ADR 0072 has no remaining
  Trellis-side task in the current Phase-1 batch.

### Wave 10 (working tree) — G-5 close and 1.0.0 ratification

Closed ratification after the clean-room stranger pass landed:

- Bound the `trellis-py/` evidence bundle into
  `ratification/ratification-checklist.md` and flipped G-5 to closed.
- Reissued `specs/trellis-core.md` and
  `specs/trellis-operational-companion.md` as `1.0.0`.
- Updated repo-facing status text so active docs no longer describe the
  ratified surface as draft-only.
- Cut the first Trellis release tag for the ratified 1.0.0 surface.

### Wave 9 (working tree) — G-2 traceability cleanup

Closed the remaining local ratification bookkeeping before G-5:

- Added explicit `Core §N` / `Companion §N` anchors to every
  `spec-cross-ref` matrix row that lacked one.
- Flipped G-2 in `ratification/ratification-checklist.md` after
  byte-vector, model-check, declaration-doc, projection-drill, and
  spec-cross-ref evidence all had live checks or fixtures.
- Reconciled `TODO.md` and the executable dispatch doc: O-3/O-4/O-5 are
  closed, the G-5 commission brief exists, and ratification close-out is
  blocked on the independent G-5 implementation only.
- Packaged the tracked G-5 allowed read set under `ratification/g5-package/`
  with per-file and archive SHA-256 checksums. The package excludes forbidden
  paths and untracked workspace files.
- Accepted the Trellis-side custodyHook wire-format note and regenerated
  `append/010-wos-custody-hook-state-transition` on the accepted ADR-0061
  shape: dCBOR authored WOS bytes, TypeID-shaped `caseId` / `recordId`, and
  the two-field `trellis-wos-idempotency-v1` idempotency construction.

### Wave 8 (4 commits `ee57780..b0f114d`) — Wave 6 tail closure

Closed out the Wave 6 tail that had been sitting in the working tree. Four
slices in dependency order:

- `ee57780` — Core amendments: §9.4 HPKE freshness (per-`KeyBagEntry`
  ephemeral uniqueness + fixture test-vector carve-out), §6.4
  ChaCha20-Poly1305 AEAD pin, §6.7 `trellis.staff-view-decision-binding.v1`
  extension-registry row, §19 step 4.k verifier obligation, §28 Appendix A
  CDDL additions (`StaffViewDecisionBinding` + optional
  `projection_schema_id` on `Watermark`). Retroactively satisfies
  `projection/005`'s §6.7 + §28 Appendix A citations.
- `fd54232` — `tamper/004` `tamper_kind` reconciled to canonical
  `posture_declaration_digest_mismatch` per `tamper/001`'s enum.
- `4cc9fe8` — `append/004-hpke-wrapped-inline` vector + 2 pinned X25519 keys
  (`recipient-004-ledger-service`, `ephemeral-004-recipient-001`) under
  `_keys/`. Depends on `ee57780`. Claims TR-CORE-031 + TR-CORE-038.
- `b0f114d` — Lint R9/R10/R11 + 122 new pytest lines + SSDI event-registry
  stub (`fixtures/declarations/ssdi-intake-triage/event-registry.stub.md`).
  Closes Wave 1 lint-refactor plan commits 5-6.

Net state: 25 vectors (up from 24); all six Wave-1 lint rules live; Core
§§6.4/6.7/9.4/19/28 amendments landed. check-specs.py green; pytest 92/92;
renumbering guard green.

### Wave 7 (6 commits `964716c..dd0d1da`) — residue batch + review-fix

5 new fixtures + semi-formal-review-fix pass + TODO refresh.

- `964716c` — residue-batch: `append/009-signing-key-revocation`
  (TR-CORE-037 + TR-CORE-070; §8 Active→Revoked + §14.3 RegistryBinding
  digest; discharges the last `pending_invariants` entries),
  `projection/005-watermark-staff-view-decision-binding` (TR-OP-006;
  staff-view §15.2 Watermark + §28 Appendix A StaffViewDecisionBinding;
  closes final O-3 breadth item), `tamper/006-event-reorder` (TR-CORE-020;
  step 4.h swap).
- `8ba1f59` — TODO refresh for the residue batch.
- `4ae9d3c` — semi-formal-review fix pass (verdict REQUEST CHANGES on
  `964716c`; 1 blocker + 2 warnings fixed in-patch): `§29.3 → §28 Appendix
  A` citation drift (8 places across projection/005
  manifest/derivation/generator), stale `tamper/006` forward-reference
  removed, TR-CORE-023 added to `tamper/006`.
- `f69f9e4` — symmetric TR-CORE-023 claim on `tamper/005-chain-truncation`.
- `914f032` — `tamper/007-hash-mismatch` (§19 step 4.d; re-signed tampered
  `author_event_hash`; TR-CORE-020+023+061).
- `dd0d1da` — `tamper/008-malformed-cose` (§19 structural-identification;
  CBOR tag-flip 18→17; TR-CORE-035+060+061; closes TR-CORE-060 from the
  allowlist).

Net allowlist state: `pending_invariants = []`; `pending_matrix_rows` drops
TR-CORE-037 / TR-CORE-070 / TR-CORE-060 / TR-OP-006 (and TR-OP-006 also
drops from `_pending-projection-drills.toml`). 92/92 pytest, check-specs
green (warnings only), renumbering guard green (23 base prefixes). Corpus:
24 vectors.

### Wave 6 (2 commits `992fbc1..6b20ef3`)

4 parallel in-tree agents (no worktrees). Landed `tamper/005-chain-truncation`
(TR-CORE-020, Core §19 step 4.h pin; first expanded-tamper case, `992fbc1`)
and §9.4 HPKE-freshness decision memo recommending Option (a) amendment
(`6b20ef3`, `thoughts/specs/2026-04-19-trellis-hpke-freshness-decision.md`).
Stream D O-5 semi-formal review completed (verdict REQUEST CHANGES, 1
blocking-style finding + 1 nit + 6 notes; Finding 1 is the `tamper_kind`
enum-name drift between `tamper/001` and `tamper/004`). `projection/005`
authoring agent halted cleanly on a Phase-1 extension-registry spec blocker.
3 new spec-amendment tasks surfaced: `tamper_kind` reconcile, register
`trellis.staff-view-decision-binding.v1`, land Core §9.4 HPKE amendment.
89/89 pytest; check-specs + renumbering guard green (18 base prefixes).

### Wave 5 (9 commits `334bb75..552c142`)

4 parallel code-scout agents + working-tree commit-split. Landed:
`shred/002-backup-refusal` (`334bb75`), lint commit 4 R6+R8 including new
`_pending-model-checks.toml` scaffolding (`d9f228a`), Stream D O-5 bundle
`append/006..008` + `tamper/002..004` (`dbdfe0a` + `814b2fe`),
`append/002-rotation-signing-key` rebased from worktree (`4585646`), lint
commit 3 R4-R5/R7 fixture corpora + pre-merge renumbering guard
(`0fcee6f`), Companion A.6 ambiguity amendment (`65090f8`), Wave 5 fixture
batch `append/003` + `projection/002-004` + `tamper/001` (`905668b`),
TODO refresh (`552c142`). Allowlist 2 invariants + 54 rows + 5
projection-drill + 8 model-check; 89/89 pytest; `check-specs.py` +
`check-vector-renumbering.py --base-ref HEAD` green.

### Wave 4 (6 commits `248781f..00042c4`)

`append/005-prior-head-chain` vector (closes #10/#13, TR-CORE-020/023/050/080);
SSDI intake-triage reference O-4 declaration at `fixtures/declarations/`;
first O-3 projection + shred fixtures (Test 1 watermark + Test 4
purge-cascade); Wave 1 lint refactor commits 1-2 (shared plumbing + R1
fixture-naming guard + R3 projection-drills loader, 30→52 pytest); 10
WOS-binding review findings applied.

### Wave 3 (5 commits + 1 review)

`append/005` brainstorm (corrected TODO invariant mislabels; pinned serial
order 005→003→004→002→tamper); Wave 1 lint-refactor plan (6 S-commits
phased); WOS custodyHook ↔ Trellis binding (Core §23 4→8 subsections +
Companion §24 OC-113a/b/c/d/e + Appendix B.2 extensions); G-4 Rust workspace
plan (10 crates, 5 layers, M1 six sub-milestones); F6 deprecation-field
lint + F1/F2/F5/F8 review-nits cleanup.

### Wave 2 spec edits (`cfd587b..1233e02`)

Core §§6.5/6.7/9.8/15.2/15.3/19 (Posture-transition registry,
`trellis-posture-declaration-v1` + `trellis-transition-attestation-v1`
domain tags, `projection_schema_id` reconciliation, dCBOR rebuild encoding,
verification algorithm step 5.5 + `PostureTransitionOutcome`); Companion
§§10.3/16.2/19.9/20.5 + Appendix A.5 (shared `Attestation` rule + A.5.1 /
A.5.2 / A.5.3) + A.6 (Delegated-Compute Declaration + OC-70a mandates) +
A.7 (Cascade-scope enum); Matrix TR-OP-008/042..045 + TR-OP-005/006 flipped;
allowlist promotes #11/#14/#15 to hybrid. Validated through 3 opus-model
`/semi-formal-code-review` cycles; 15 blockers+warnings closed in-patch.

### Wave 1 (done)

4 parallel design-brief agents landed Streams A/B/C/D briefs; consolidated
in `thoughts/specs/2026-04-18-trellis-wave1-consolidation-plan.md`.

---

## Closed sprint-queue items

### Lint / fixture infrastructure — Wave 1 refactor plan (all 6 commits + renumbering guard)

Wave 1 lint-refactor plan: [`thoughts/specs/2026-04-18-trellis-wave1-lint-extension-plan.md`](thoughts/specs/2026-04-18-trellis-wave1-lint-extension-plan.md).

- **Lint-refactor commits 1-2** — shared plumbing + R1 fixture-naming guard
  + R3 projection-drills loader. Landed Wave 4 (30→52 pytest).
- **Lint-refactor commit 3** — R4-R5: projection/shred op dispatch +
  `tr_op` / `companion_sections` coverage lint. Landed Wave 5 working tree
  (`0fcee6f`).
- **Lint-refactor commit 4** — R6-R8: G-2 non-byte verification channels.
  R7 landed Wave 5; R6 spec-cross-ref (warning-not-error on uncited rows;
  non-resolving cites remain hard errors) + R8 model-check evidence (new
  `_pending-model-checks.toml` + `thoughts/model-checks/evidence.toml` path
  convention) landed in `d9f228a`.
- **Lint-refactor commit 5** — R9-R10: O-5 extension registry check + CDDL
  cross-ref. Landed Wave 8 (`b0f114d`).
- **Lint-refactor commit 6** — R11: O-4 declaration-doc Phase 1 static
  validator (frontmatter/schema, posture ref, authorized actions,
  event-registry stub, actor discriminator, runtime enclave, UTC bounds,
  signature table; ledger-replay checks deferred to G-4 Rust). Landed
  Wave 8 (`b0f114d`) with SSDI event-registry stub.
- **Pre-merge renumbering guard** — F6 amendment's complementary rule at
  merge time: `scripts/check-specs.py` enforces lifecycle fields, and
  `scripts/check-vector-renumbering.py` compares the current tree to a
  ratification/base ref to reject deleted or renumbered `<op>/NNN-*` vector
  prefixes. Landed Wave 5 working tree with CLI/git-path tests.
- **R12 verify-report consistency check** — Cross-checks failure-kind
  tokens in verify/* manifests against `[expected.report]` booleans per
  Core §19. Landed `d3af6a8`.
- **Generator `_lib/` extraction** — Shared byte-level plumbing
  centralized in
  [`fixtures/vectors/_generator/_lib/byte_utils.py`](fixtures/vectors/_generator/_lib/byte_utils.py).
  Renamed `gen_verify_002_003.py` → `gen_verify_negative_export_001.py`.
  Landed `b3cb833`.
- **Verify vectors 008 + 009** — Closed Core §19 step 5.d
  (`prev_checkpoint_hash` mismatch) and step 5.e (consistency-proof
  mismatch) with
  [`verify/008-export-001-prev-checkpoint-hash-mismatch`](fixtures/vectors/verify/008-export-001-prev-checkpoint-hash-mismatch)
  and
  [`verify/009-export-001-consistency-proof-mismatch`](fixtures/vectors/verify/009-export-001-consistency-proof-mismatch).
  Extended `gen_verify_negative_export_001.py`; lint + Trellis
  conformance replay pass.
- **Residual V3 breadth closure** — Landed the remaining G-3 fixture batch
  on 2026-04-21: `export/002-revoked-key-history`,
  `export/003-three-event-transition-chain`,
  `export/004-external-payload-optional-anchor`,
  `verify/010-export-002-revoked-key-after-valid-to`,
  `verify/011-export-003-transition-chain`,
  `verify/012-export-004-optional-anchor`,
  `tamper/009-prev-hash-break`, `tamper/010-missing-head`,
  `tamper/011-wrong-scope`, and `tamper/012-registry-snapshot-swap`.
  Also landed the Core §19 revocation-language pin, `trellis-verify`
  support for bundled `PayloadExternal` export members, and distinct
  `prev_hash_break` tamper classification. `python3 scripts/check-specs.py`,
  `cargo test -p trellis-verify`, and
  `cargo test -p trellis-conformance committed_vectors_match_the_rust_runtime`
  all pass, and ratification gate G-3 is now checked.

### First vector batch (G-3) — all 5 landed

Per [`thoughts/specs/2026-04-18-trellis-g3-first-batch-brainstorm.md`](thoughts/specs/2026-04-18-trellis-g3-first-batch-brainstorm.md).
Brainstorm corrected TODO's prior invariant mislabels. Serial order:
005 → 003 → 004 → 002 → tamper/001 (from 005, not 001).

- **`append/005-prior-head-chain`** — invariants #5, #10, #13;
  TR-CORE-020/023/050/080. Landed (`060a547`).
- **`append/003-external-payload-ref`** — invariants #4 + #8 partial + #13.
  `PayloadExternal` variant. Claims TR-CORE-031, -071. Landed (`905668b`).
- **`append/004-hpke-wrapped-inline`** — invariants #4 real + #8 populated
  + #11 latent. Real ChaCha20-Poly1305 payload encryption + HPKE suite-1
  DEK wrap with pinned X25519 recipient/ephemeral keys under `_keys/`.
  Landed Wave 8 (`4cc9fe8`) depending on Core amendments in `ee57780` (§9.4
  HPKE freshness + §6.4 AEAD pin + §9.4 test-vector carve-out). Claims
  TR-CORE-031, -038.
- **`append/002-rotation-signing-key`** — invariant #7 (key-bag immutable
  under rotation; not "key rotation" writ large). Claims TR-CORE-036, -038.
  Landed (`4585646`, rebased onto main from worktree).
- **`tamper/001-signature-flip`** (derived from `append/005`, not 001) —
  verification side; claims TR-CORE-061. Landed (`905668b`).

### `append/` residue batch (critical-path step 2)

Closed by Wave 7 `append/009-signing-key-revocation` (TR-CORE-037 +
TR-CORE-070). `pending_invariants = []` achieved.

### G-2 model-check flush

Closed 2026-04-21. `trellis-conformance` now carries a real model-check
suite at [`crates/trellis-conformance/src/model_checks.rs`](crates/trellis-conformance/src/model_checks.rs)
covering TR-CORE-001 / 020 / 023 / 025 / 046 / 050 and TR-OP-061 / 111.
`thoughts/model-checks/evidence.toml` and the row-specific evidence briefs
under `thoughts/model-checks/` are live, and
[`fixtures/vectors/_pending-model-checks.toml`](fixtures/vectors/_pending-model-checks.toml)
is empty.

### G-4 reference implementation

Closed 2026-04-21. The Rust workspace under `crates/` now provides real
`append`, `verify`, and `export` behavior, a real Postgres backend, and a
conformance harness that replays the committed `append`, `export`, `verify`,
`tamper`, `projection`, and `shred` corpora byte-for-byte. Ratification gate
G-4 is now checked in
[`ratification/ratification-checklist.md`](ratification/ratification-checklist.md).

---

## Closed stream items

### Stream B — O-3 projection discipline

- **`projection/002-rebuild-equivalence-minimal`** — Test 2 / TR-OP-005;
  first fixture exercising Core §15.3's new dCBOR rebuild pin. Landed
  (`905668b`).
- **`projection/003-cadence-positive-height` + `004-cadence-gap`** —
  Test 3 / TR-OP-008. Landed (`905668b`).
- **`shred/002-backup-refusal`** — Test 4 backup variant. Landed
  (`334bb75`).
- **`projection/005-watermark-staff-view-decision-binding`** — TR-OP-006 +
  §17.4 Staff-View. Final O-3 breadth item landed Wave 7.

### Stream C — O-4 delegated-compute honesty

- **Companion A.6 amendment to pin ambiguities** — Pinned
  key-absence-as-null for TOML nullable fields,
  `[signature] = {cose_sign1_b64, signer_kid, alg}` shape, and optional
  `audit.registry_ref`. Landed Wave 5 (`65090f8`).

### Stream D — O-5 posture-transition audit

- **Author O-5 fixtures** — All 6 cases landed: `append/006` CM-B→CM-A
  (TR-OP-042/045), `append/007` CM-C narrowing, `append/008`
  disclosure-profile A→B (TR-OP-043/045 + invariant #11), `tamper/002`
  from-state mismatch (TR-OP-044), `tamper/003` missing dual-attestation,
  `tamper/004` declaration-digest mismatch. Commits `dbdfe0a` + `814b2fe`.
  Semi-formal review (Wave 6) returned REQUEST CHANGES — minor, single
  blocking finding.
- **Reconcile `tamper_kind` enum naming** — Landed Wave 8 (`fd54232`):
  `tamper/004` uses canonical `posture_declaration_digest_mismatch`;
  Core §19 `failures[]` remains `declaration_digest_mismatch` (different
  layer).

### Stream E — Track E cross-cutting bindings

- **WOS `custodyHook` ↔ Trellis binding** (vision item 22). Core §23
  (4→8 subsections) + Companion §24 (OC-113a/b/c/d/e) + Appendix B.2
  extensions landed Wave 3C + Wave 4E (10 opus-review findings applied).
  Committed as `248781f`.

### Stream A — G-2 non-byte-testable invariant audit

Design at [`thoughts/specs/2026-04-18-trellis-g2-invariant-audit-paths.md`](thoughts/specs/2026-04-18-trellis-g2-invariant-audit-paths.md).
Hybrid classification; 11 byte-testable, 4 non-byte-only, 5 hybrid
invariants. No authoring tasks — Stream A closes when G-2 audit sign-off
lands.

---

## Earlier closed items (pre-Wave 1)

- Core clarifications from T10 — §6.1 (`idempotency_key` uniqueness scope +
  UUIDv7 construction), §7.4 (COSE_Sign1 embedded payload, verifier MUST
  reject `payload == nil`), §9.1 (length-prefix form applies uniformly
  including single-component).
- Allowlist rollout — `TRELLIS_SKIP_COVERAGE=1` bypass removed;
  `_pending-invariants.toml` allowlist drives batched vector coverage
  (F5). `check_vector_manifest_paths` lint rule added (F7). 20/20 pytest
  green.
- Vector-lifecycle policy (F6) — renumbering-forbidden, `status =
  "deprecated"` tombstones, overlap-encouraged-as-boolean. Landed as F6
  amendment in
  `thoughts/specs/2026-04-18-trellis-g3-fixture-system-design.md` under
  "Vector lifecycle" + "Manifest schema"; lint enforcement deferred to the
  separate `check-specs.py` follow-on plan.
- Matrix drift for Core §6.8 / §10.6 / §14.6 closed; `append/001` coverage
  updated (`475b064`, `a1eb41f`).
- Working norms encoded in the handoff prompt (`c346313`).
- Ratification-evidence removed; normalization handoff archived (`617f9ae`,
  `28f551c`).
- G-3 scaffold plan (12 tasks, `880ebdd..18c72c8`), Core amendments B1..S5
  (`6ad24ab..e1895ae`), first reference vector (`e1ab065`).
