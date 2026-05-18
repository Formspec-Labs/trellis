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

**Cross-runtime parity matrix (pending).** The end-state cross-runtime parity gate is planned as a permanent CI invariant covering every R1–R7 vector and every preimage shape in the conformance corpus. Today, `trellis/scripts/check_signed_acts_projection_parity.py` enforces Python-generator → Rust-verifier parity for the SignedAct projection corpus, which implicitly exercises R1 (integer width), R3 (key sort), and R4 (dup-key rejection). Broadening the gate to assert byte-identical output between Rust and Python encoders for every vector in §5 below is tracked in the end-state substrate closeout plan (Task A9). Until that gate lands, the §5 vectors are the today-current conformance contract — pinned against the Rust oracle. A runtime joins the parity matrix by implementing this profile and producing byte-identical output for every vector in §5.

---

## 4. Conformance test corpus

A runtime claims §4.2.2 profile conformance by:

1. Passing every test vector in §5 — decode the input, encode under this profile, assert the hex output matches exactly.
2. Producing byte-identical output to the Rust authority for every preimage shape in `trellis/fixtures/vectors/`. The signed-acts parity script at `trellis/scripts/check_signed_acts_projection_parity.py` exercises this comparison for the SignedAct projection corpus today; the broader generic-CBOR parity gate is planned (Task A9) and will assert the byte-identity contract for every vector in §5.
3. Correctly rejecting the non-conformant inputs in §6 — duplicate keys, non-finite floats, negative zero.

A runtime that produces byte-identical output for text-only-key maps but diverges on mixed-type maps is not conformant; R3's §4.2.2 sort applies to all map key types.

---

## 5. Test vectors

Vectors are `(input description, expected output hex)` pairs. Encode the described input under this profile; assert output matches the hex. The expected output was produced by the Rust oracle (`encode_canonical_cbor_value`).

Full fixture corpus vectors live in `trellis/fixtures/vectors/canonical-cbor/` (to be populated when the corpus generator lands, per Task A6 of the closeout plan). The representative vectors below pin the corner cases that distinguish this profile from §4.2.1:

| # | Description | Input | Expected hex | Rule |
|---|---|---|---|---|
| V1 | Unsigned 0 | `0` | `00` | R1 |
| V2 | Unsigned 23 (1-byte boundary) | `23` | `17` | R1 |
| V3 | Unsigned 24 (2-byte boundary) | `24` | `18 18` | R1 |
| V4 | Unsigned 256 (3-byte boundary) | `256` | `19 01 00` | R1 |
| V5 | Negative -1 | `-1` | `20` | R1 |
| V6 | Negative -25 (2-byte boundary) | `-25` | `38 18` | R1 |
| V7 | Empty map | `{}` | `a0` | R2, R3 |
| V8 | Empty array | `[]` | `80` | R2 |
| V9 | Single-entry text-key map | `{"a": 1}` | `a1 61 61 01` | R3 |
| V10 | Map sorted bytewise — integer before text (same 1-byte encoding length) | `{"": 2, 0: 1}` | `a2 00 01 60 02` | R3 (int key `0x00` sorts before empty-tstr `0x60`) |
| V11 | Dup-key rejection | `{"a": 1, "a": 2}` | error: "duplicate canonical CBOR map key" | R4 |
| V12 | NaN rejection | `float NaN` | error: "CBOR float must be finite" | R5 |
| V13 | Negative zero rejection | `-0.0` | error: "CBOR float must use canonical +0, not -0" | R5 |
| V14 | Nested map, inner keys sorted | `{"outer": {"z": 1, "a": 2}}` | `a1 65 6f 75 74 65 72 a2 61 61 02 61 7a 01` | R3 (inner map: "a" sorts before "z") |

**V10 note — §4.2.2 vs §4.2.1 distinction.** V10 is the canonical example demonstrating where §4.2.2 and §4.2.1 diverge for mixed-type keys. Under §4.2.1 (length-first), integer `0` (encoded 1 byte as `0x00`) and empty text string (encoded 1 byte as `0x60`) have equal length; tie-break is then bytewise, giving `0x00 < 0x60` — same result as §4.2.2. For mixed major types where the length-byte comparison would invert the bytewise-on-encoded-bytes comparison, the profiles diverge. In practice, for text-only-key maps (the common Trellis case) §4.2.1 and §4.2.2 produce the same sort order, because all text keys share the same major-type prefix byte and the length nibble participates in the bytewise sort. The §4.2.2 requirement is the normative contract; the coincidental §4.2.1 agreement for text-only maps is not a license to implement §4.2.1.

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
