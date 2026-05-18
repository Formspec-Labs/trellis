---
title: Canonical CBOR §4.2.2 Profile
status: normative
authority: Rust per Trellis ADR 0004; conformance oracle is `integrity-stack/crates/integrity-cbor/src/lib.rs::encode_canonical_cbor_value`
fixture_corpus: trellis/fixtures/vectors/
matrix_row: TR-CORE-179 (see trellis-requirements-matrix.md)
related_spec: trellis-core.md §5.1
---

# Canonical CBOR §4.2.2 Profile

## 1. Purpose and scope

This profile defines the canonical CBOR encoding for every byte the Trellis substrate produces or verifies. Every conformant runtime — Rust (today), Python (Task A2), and any future Go / WASM-Rust / Swift / .NET implementation — emits byte-identical output for byte-identical input under this profile.

The contract is the bytes. Runtimes are interchangeable. A regulator agency implementing a Trellis verifier in their language of choice implements this profile; they do not need to read the Rust source to produce conformant output. The Rust source (`integrity-stack/crates/integrity-cbor/src/lib.rs::encode_canonical_cbor_value`) is the conformance oracle when rules and behavior diverge; this document names what the oracle enforces.

The profile covers: integer encoding width, definite-length discipline, map-key sort order, duplicate-key rejection, float validity, float-width compaction, and tag restrictions. It does not cover COSE envelope framing, hash preimage construction, or ZIP packaging — those are in `trellis-core.md §7`, `§9`, and `§18` respectively, each of which calls into this profile for their encoding steps.

---

## 2. Normative rules

A canonical CBOR encoder under this profile MUST satisfy rules R1–R7. Each rule names the Rust enforcement location (file:line) and notes whether the rule is fully enforced today or is a forward-compatibility commitment that is currently inert in Trellis substrate (no production preimage shape exercises it yet).

### R1 — Integer encoding: smallest form

Unsigned and negative integers MUST use the smallest valid major-type encoding. Values 0–23 encode in the initial byte only. Values 24–255 use a 1-byte argument. Values 256–65535 use a 2-byte argument. Values 65536–4294967295 use a 4-byte argument. Larger values use an 8-byte argument. Encoders MUST NOT pad to a larger argument size.

**Rust enforcement.** `encode_major_len` at `integrity-stack/crates/integrity-cbor/src/lib.rs:655` dispatches on value range (`:658–675`) and always emits the smallest encoding. `ciborium::into_writer`, called by `encode_cbor_value` at `:211`, uses the same compact-encoding convention for integers stored in `ciborium::Value::Integer`.

**Status.** Fully enforced. Every integer in every Trellis preimage (suite IDs, sequence numbers, map lengths) goes through this path.

### R2 — Definite-length encoding only

Byte strings, text strings, arrays, and maps MUST use definite-length encoding (initial byte encodes the exact item count or byte count). Indefinite-length encoding (additional info `0x1f` / tag `31`) is forbidden in emitter output.

Decoders MAY accept indefinite-length input for defense-in-depth compatibility with external CBOR producers, but emitters MUST NOT produce it. A Trellis verifier that re-encodes a decoded value before comparing digests MUST go through the canonical encoder; it MUST NOT pass indefinite-length through to a digest comparison.

**Rust enforcement.** `ciborium::into_writer` (called at `:211`) always emits definite-length encoding for all types. There is no explicit reject path for indefinite-length _input_ in `canonicalize_cbor_value`; the rule is satisfied by construction on emission. A parse-side reject path for indefinite-length input is a conformant defense-in-depth addition; it is not currently present in `integrity-cbor` but is permitted.

**Status.** Emission-side fully enforced by construction. Parse-side indefinite-length rejection is not currently implemented; conformant implementations may add it as defense-in-depth per the above.

### R3 — Map key sort: bytewise on canonical-encoded key bytes (§4.2.2, not §4.2.1)

For every map, encode each key under this profile recursively, then sort entries by lexicographic byte comparison of the canonical-encoded key bytes. This is the RFC 8949 §4.2.2 rule — sort on encoded key bytes — not §4.2.1 (sort by length first, then bytewise). The distinction matters for mixed-type keysets and is the reason `cbor2.dumps(canonical=True)` (which implements §4.2.1) is not conformant for emission.

Concretely: an integer key `0` encodes as `0x00`; a text key `""` (empty string) encodes as `0x60`. Bytewise: `0x00` < `0x60`, so the integer key sorts first. Under §4.2.1 (length-first) the integer key also encodes in 1 byte and the empty text key encodes in 1 byte — same length, so tie-break is bytewise anyway. For text-only keysets the two profiles frequently produce the same sort order by coincidence (both sort by the encoding's first byte, which for CBOR text strings encodes the length). The divergence appears in mixed-type maps and in cases where the length byte and the following content bytes produce a different total comparison than the length-first rule.

**Rust enforcement.** `canonicalize_cbor_value` at `:158` recursively encodes each key via `encoded_cbor_key_bytes` at `:172` (which calls `encode_cbor_value` at `:421`), then sorts by `left.0.cmp(&right.0)` at `:176`. This is a direct bytewise comparison of the encoded key bytes — §4.2.2 exactly.

**Status.** Fully enforced.

### R4 — No duplicate keys

Maps MUST NOT contain duplicate keys, where "duplicate" means byte-identical canonical-encoded key bytes after R3 sort. Encoders MUST reject input containing duplicate keys. Decoders MUST reject input bytes whose CBOR map carries duplicate keys at any nesting depth.

**Rust enforcement (encoder side).** After sorting, `canonicalize_cbor_value` at `:177–186` walks adjacent pairs via `entries.windows(2)` and returns `CborHelperError("duplicate canonical CBOR map key `<hex>`")` if any two adjacent sorted entries share the same encoded key.

**Rust enforcement (decoder side).** `integrity-cbor` does not currently implement a standalone parse-side duplicate-key byte-walker. The emission-side check in `canonicalize_cbor_value` catches duplicates when re-encoding decoded values. A full parse-side guard (checking for duplicates before any `cbor2.loads` / `ciborium::from_reader` call, at every nesting depth) is a conformant defense-in-depth addition.

**Status.** Encoder-side fully enforced. Decoder-side parse-time rejection (before decode) is not currently in `integrity-cbor`; it is a forward-compatibility addition under development (Task A2b in the closeout plan).

### R5 — Finite floats only; negative zero rejected

NaN, positive infinity (`+Inf`), and negative infinity (`-Inf`) MUST be rejected at the canonical emission boundary. Negative zero (`-0.0`) MUST be rejected. The canonical representation of zero is `+0.0`.

**Rust enforcement.** `canonicalize_cbor_value` at `:194–199` handles two cases. Non-finite floats (NaN, ±Inf) match `Value::Float(float) if !float.is_finite()` at `:194` and return `CborHelperError("CBOR float must be finite for canonical encoding")`. Negative zero matches `Value::Float(float) if *float == 0.0 && float.to_bits() != 0.0_f64.to_bits()` at `:197` and returns `CborHelperError("CBOR float must use canonical +0, not -0")`. The `to_bits()` check is the correct way to distinguish IEEE-754 negative zero from positive zero (they compare equal under `==` but have distinct bit representations).

**Status.** Fully enforced. Note: no Trellis substrate preimage shape currently carries a float field. The enforcement is load-bearing for future preimage shapes and for any third-party use of `encode_canonical_cbor_value`.

### R6 — Float compaction: smallest width (forward-compatibility commitment; currently inert)

A float value whose exact IEEE-754 representation fits in a smaller width MUST be emitted in the smallest width. A value exactly representable as f16 MUST be emitted as a 2-byte CBOR float (major type 7, additional info 25). A value exactly representable as f32 but not f16 MUST be emitted as a 4-byte CBOR float (additional info 26). Only values requiring the full f64 range MUST be emitted as 8-byte (additional info 27).

**Rust enforcement.** This rule is NOT currently enforced by `canonicalize_cbor_value` or `encode_cbor_value`. The `canonicalize_cbor_value` function passes the `Value::Float` variant through to `ciborium::into_writer` (`:211`) after only the R5 checks. `ciborium` encodes `f64` values using 8-byte representation without compaction. No Trellis substrate preimage shape currently carries a float field, so this gap does not affect any byte in the current fixture corpus.

**Forward-compatibility commitment.** Any future Trellis preimage shape that introduces a float field MUST implement R6 before that preimage lands in production. Implementing R6 as a future change to `canonicalize_cbor_value` (before `ciborium::into_writer`) or as a post-write compaction step does not change the spec contract; the spec contract is: conformant emitters produce the smallest width.

**Status.** Inert — not currently enforced, no float-bearing Trellis preimage exists. Third-party implementations of this profile MUST implement R6 regardless; they cannot rely on the current Rust behavior as the specification for float width.

### R7 — Tags: only explicitly registered (forward-compatibility commitment; currently inert for generic tags)

Tagged items (CBOR major type 6) are forbidden in canonical preimage output except where a specific Trellis spec section explicitly names a tag by number and purpose. Registering a use of a tag requires a normative spec section name and number; generic or opaque tags are not part of this profile.

Currently registered tags in Trellis substrate:
- **Tag 18** (`COSE_Sign1`): `trellis-core.md §7`. Used in every event envelope and checkpoint. Tag 18 is produced by COSE encoding, not by `encode_canonical_cbor_value`.
- No other tags are currently registered for canonical CBOR preimages produced by `encode_canonical_cbor_value`.

**Rust enforcement.** `canonicalize_cbor_value` at `:200` passes `Value::Tag` through recursively: `Value::Tag(tag, item) => Ok(Value::Tag(*tag, Box::new(canonicalize_cbor_value(item)?)))`. Generic tags are not rejected; the rule is enforced by the fact that no Trellis preimage shape introduces a generic tag as input to `encode_canonical_cbor_value`. Tag 18 COSE envelopes are produced by a separate code path outside `encode_canonical_cbor_value`.

**Forward-compatibility commitment.** Any future preimage shape that uses a CBOR tag MUST register it in a normative spec section. The `encode_canonical_cbor_value` function will need an explicit allowlist check if a future preimage accidentally introduces an unregistered tag. Implementations of this profile for other runtimes SHOULD implement a tag allowlist; the absence of a tag allowlist in the current Rust source is a property of the current preimage shapes, not a permission to use arbitrary tags.

**Status.** Inert for generic tags — no generic tagged items appear in any Trellis preimage. Tag 18 handling is in the COSE layer, not in `encode_canonical_cbor_value`.

---

## 3. Conformance oracle

**Rust source, per Trellis ADR 0004.** The byte authority is `encode_canonical_cbor_value` at `integrity-stack/crates/integrity-cbor/src/lib.rs:220`, which calls `canonicalize_cbor_value` (`:158`) then `encode_cbor_value` (`:209`). When rules in this document and behavior of the Rust source disagree, the Rust source is the conformance contract; this profile document is updated to match. When Rust is updated (bug fix, performance improvement, new rule enforcement), the profile document is updated in the same commit train.

**Fixture corpus.** `trellis/fixtures/vectors/` is the regression evidence. Every fixture that exercises a canonical encoding step (every append, verify, and export fixture) implicitly validates the encoding rules via byte-exact reproduction. If the Rust source produces different bytes than a committed fixture, that is a Rust regression.

**Cross-runtime parity matrix.** The cross-runtime parity gate is a permanent CI invariant covering every R1–R7 case in the corpus at [`trellis/fixtures/vectors/canonical-cbor/`](../fixtures/vectors/canonical-cbor/) and every preimage shape in the broader fixture corpus. The Rust oracle is the byte authority; the Python in-tree runtime (`trellis-py/_cbor_canonical.py`) is the second runtime that exercises the profile without reading Rust source. The `trellis/scripts/check_signed_acts_projection_parity.py` script enforces Python-generator → Rust-verifier parity for the SignedAct projection corpus, which implicitly exercises R1 (integer width), R3 (key sort), and R4 (dup-key rejection). The per-rule generic-CBOR gate over the §5 corpus is added by Task A2 of the substrate-externalization preflight plan. A new runtime joins the parity matrix by implementing the adapter contract in [`thoughts/specs/2026-05-18-canonical-cbor-runtime-port.md`](../../thoughts/specs/2026-05-18-canonical-cbor-runtime-port.md) §3 and producing byte-identical output for every encode-kind case (and matching reject codes for every reject-kind case) in the corpus.

---

## 4. Conformance test corpus

A runtime claims §4.2.2 profile conformance by:

1. Passing every case in the corpus at [`trellis/fixtures/vectors/canonical-cbor/`](../fixtures/vectors/canonical-cbor/) — encode each `kind=encode` case under this profile, assert `output_hex` matches `expected_output_hex` exactly; for each `kind=reject` case surface the matching normalized `reject_code` from the closed set.
2. Producing byte-identical output to the Rust authority for every preimage shape in `trellis/fixtures/vectors/`. The signed-acts parity script at `trellis/scripts/check_signed_acts_projection_parity.py` exercises this comparison for the SignedAct projection corpus; the per-rule generic-CBOR parity gate (Task A2 of the substrate-externalization preflight plan) extends it to the §5 corpus.
3. Correctly rejecting the non-conformant inputs in §6 — duplicate keys, non-finite floats, negative zero. The corpus carries the byte-exact reject cases; the §6 examples are illustrative.

A runtime that produces byte-identical output for text-only-key maps but diverges on mixed-type maps is not conformant; R3's §4.2.2 sort applies to all map key types.

---

## 5. Test vectors

The canonical regression corpus lives at [`trellis/fixtures/vectors/canonical-cbor/`](../fixtures/vectors/canonical-cbor/). Each case is a JSON file under `cases/`; the [`manifest.json`](../fixtures/vectors/canonical-cbor/manifest.json) indexes them. The corpus is authored against the Rust oracle (`encode_canonical_cbor_value`) and regenerated by [`trellis/fixtures/vectors/_generator/gen_canonical_cbor_profile.py`](../fixtures/vectors/_generator/gen_canonical_cbor_profile.py), which invokes the Rust adapter at [`trellis/crates/trellis-conformance/examples/canonical_cbor_emit.rs`](../crates/trellis-conformance/examples/canonical_cbor_emit.rs). A conformant runtime passes every encode-kind case (byte-identical `expected_output_hex`) and every reject-kind case (matching `expected_reject_code` from the closed set in [`thoughts/specs/2026-05-18-canonical-cbor-runtime-port.md`](../../thoughts/specs/2026-05-18-canonical-cbor-runtime-port.md) §4).

Forward-compatibility cases (R6 float compaction, R7 generic-tag allowlist, R2 parse-side indefinite-length rejection, and the R5/R6-coupled positive-zero width case) are present in the corpus with `forward_compatibility: true`. The Rust oracle currently emits `result=unimplemented` for these; external implementers SHOULD implement the rule per the profile and surface the rule-correct output / reject code. The parity gate accepts both `unimplemented` (from the Rust oracle) and the rule-correct result (from a runtime that has implemented the rule).

The single most load-bearing case — the §4.2.2 / §4.2.1 distinguishing case (Example 3 below) — is pinned inline here for emphasis:

| # | Description | Input | Expected hex | Rule |
|---|---|---|---|---|
| V10 | Mixed-type map sorted bytewise on encoded keys: int key `100` (`18 64`) sorts before empty tstr key (`60`) | `{100: "a", "": "b"}` | `a2 18 64 61 61 60 61 62` | R3 (§4.2.2 wins) |

**V10 note — §4.2.2 vs §4.2.1 distinction.** V10 is the canonical example demonstrating where §4.2.2 and §4.2.1 diverge for mixed-type keys. Under §4.2.2 (bytewise on encoded key bytes), the integer key `100` encodes as `18 64` (2 bytes) and the empty text key encodes as `60` (1 byte); the first-byte comparison `0x18 < 0x60` places the integer key first. Under §4.2.1 (length-first), the empty tstr is shorter and sorts first — producing `a2 60 61 62 18 64 61 61`, the OPPOSITE order and **non-conformant** under this profile. For text-only-key maps (the common Trellis case) §4.2.1 and §4.2.2 frequently produce the same sort order by coincidence, because all text keys share the same major-type prefix byte and the length nibble participates in the bytewise sort. The §4.2.2 requirement is the normative contract; the coincidental §4.2.1 agreement for text-only maps is not a license to implement §4.2.1. The corpus case is `R3-mixed-key-disagreement` at [`cases/R3-mixed-key-disagreement.json`](../fixtures/vectors/canonical-cbor/cases/R3-mixed-key-disagreement.json).

---

## 6. Compliance examples

### Conformant

**Example 1: text-key map with bytewise sort (text-only — both profiles agree by coincidence).**

Input: `{"b": 2, "aa": 1}`. Key `"b"` encodes as `61 62` (major-type-tstr byte `0x61`, then `'b'` = `0x62`). Key `"aa"` encodes as `62 61 61` (major-type-tstr byte `0x62`, then `'a' 'a'`). Bytewise compare first bytes: `0x61` < `0x62`, so `"b"` sorts first.

Output: `a2 61 62 02 62 61 61 01` — `"b": 2, "aa": 1`.

Under §4.2.1 (length-first): `"b"` (1-byte content) before `"aa"` (2-byte content) — same order. For text-only keysets the two profiles often produce the same sort by coincidence, because the major-type-byte's lower nibble encodes string length and participates in the bytewise comparison. **This example does not distinguish §4.2.2 from §4.2.1.** Example 3 below uses a mixed-type keyset where they diverge.

**Example 2: integer smallest-form encoding.**

Input: integer `255`. Encoded as `18 ff` (2 bytes: major type 0, additional info 24, argument `0xff`). NOT as `19 00 ff` (3 bytes with 2-byte argument) which would be non-canonical padding.

**Example 3: mixed-type keyset where §4.2.2 and §4.2.1 diverge (load-bearing distinguishing case).**

Input: `{100: "a", "": "b"}`. Key `100` encodes as `18 64` (major-type-uint, additional-info 24, argument `0x64` = 2 bytes total). Key `""` encodes as `60` (major-type-tstr length 0 — 1 byte total).

- §4.2.2 bytewise on encoded keys: compare `18 64` vs `60` — first byte `0x18` < `0x60`, so int key `100` sorts first. Output: `a2 18 64 61 61 60 61 62` — `100: "a", "": "b"`.
- §4.2.1 length-first: 1-byte key (`""`) before 2-byte key (`100`) — opposite order. Output: `a2 60 61 62 18 64 61 61` — `"": "b", 100: "a"`. **Non-conformant under this profile.**

This is the test case implementations MUST run to confirm §4.2.2 conformance — text-only-key maps will pass under either profile.

### Non-conformant

**Example 4: §4.2.1 length-first sort applied to the mixed-type case from Example 3.**

Output: `a2 60 61 62 18 64 61 61`. This is what `cbor2.dumps(canonical=True)` in Python produces for the input above. It is NOT conformant under this profile.

**Example 5: indefinite-length array.**

`9f 01 02 ff` (indefinite-length array `[1, 2]`). Non-conformant on the emission side. A conformant emitter produces `82 01 02` (definite-length 2-element array).

**Example 6: NaN float.**

Any encoding of IEEE-754 NaN is non-conformant. `encode_canonical_cbor_value` returns an error before producing output.

---

## 7. Cross-runtime implementation notes

A runtime implementing this profile:

- Uses §4.2.2 bytewise key sort (encoded-key bytes, not length-first). Do not use `cbor2.dumps(canonical=True)` for emission — it implements §4.2.1.
- Rejects NaN, ±Inf, and -0.0 at the emission boundary, before calling any underlying serializer.
- Implements R6 float compaction (smallest width) even though the current Rust oracle does not. Third-party implementations should implement R6 now; the Rust oracle will be updated when the first float-bearing preimage lands.
- Joins the cross-runtime parity matrix by producing byte-identical output for every vector in §5 and every preimage shape in `trellis/fixtures/vectors/`.
- Does not rely on coincidental §4.2.1 / §4.2.2 agreement for text-only-key maps. Run V10 (mixed-type map) to confirm §4.2.2 sort is implemented correctly.

### How to join the runtime matrix

The runtime-port adapter contract is defined in the stack-level decision doc `formspec-stack/thoughts/specs/2026-05-18-canonical-cbor-runtime-port.md`. A new runtime joins the parity matrix by:

1. Implementing R1–R7 against this profile (R6/R7 are forward-compatibility commitments — implement them, but the gate accepts `result=unimplemented` while the Rust oracle is also inert on them).
2. Exposing a sub-process adapter command that consumes the parity-gate manifest (`trellis/fixtures/vectors/canonical-cbor/manifest.json`) and emits results matching the adapter output schema (`runtime`, `library_version`, `command`, `result`, `output_hex` | `reject_code`, optional `mismatch_path`, optional `stderr_excerpt`).
3. Emitting **normalized reject codes** from the closed set (`duplicate_map_key`, `non_finite_float`, `negative_zero_float`, `indefinite_length_input`, `generic_tag_disallowed`). Provider-specific exception text is for diagnostics only; the gate never asserts on it.
4. Producing byte-identical `output_hex` for every encode-kind case in the manifest and matching `reject_code` for every reject-kind case.

The current in-tree runtimes are Rust (`integrity-cbor`, byte authority per Trellis ADR 0004) and Python (`trellis-py` with the custom `_cbor_canonical` emitter). Go / .NET / Swift / WASM-Rust harnesses are documented external candidates; the runtime-port decision doc records the classification.
