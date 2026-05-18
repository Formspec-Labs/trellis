# Canonical CBOR §4.2.2 Profile — Conformance Corpus

Machine-readable regression corpus for the canonical CBOR profile at
[`trellis/specs/canonical-cbor-profile.md`](../../../specs/canonical-cbor-profile.md). Every case targets one profile rule (R1–R7). The corpus is the per-rule conformance contract; the parity gate (Task A2) and external runtime implementers consume it directly.

## Authority

The byte authority is the Rust oracle at
`integrity-stack/crates/integrity-cbor/src/lib.rs::encode_canonical_cbor_value`
(Trellis ADR 0004). When the oracle changes, the corpus is regenerated; when
spec prose and Rust disagree, Rust wins and the spec is updated.

The runtime-port adapter contract is in
[`thoughts/specs/2026-05-18-canonical-cbor-runtime-port.md`](../../../../thoughts/specs/2026-05-18-canonical-cbor-runtime-port.md) §3.
The closed reject-code set lives in §4 of that same doc and is mirrored in
[`manifest.json`](manifest.json) under `reject_code_set`.

## Layout

```
canonical-cbor/
├── README.md             — this file
├── manifest.json         — case index; the parity gate's entry point
└── cases/                — one JSON file per case
    ├── R1-uint-0.json
    ├── R2-empty-map.json
    ├── R3-mixed-key-disagreement.json   ← load-bearing §4.2.2 vs §4.2.1 case
    └── …
```

## Case schema

Each `cases/<case_id>.json` is:

```json
{
  "case_id":               "R3-mixed-key-disagreement",
  "rule":                  "R3",
  "kind":                  "encode" | "reject",
  "summary":               "one-sentence purpose",
  "input":                 <input value>,
  "expected_output_hex":   "a218646161606162",   // iff kind=encode
  "expected_reject_code":  "duplicate_map_key",  // iff kind=reject
  "forward_compatibility": false,
  "notes":                 "optional"
}
```

### Input value representation

A closed set of structured value shapes. Adapters construct their library's
CBOR value type from these:

| Shape                                                                                  | Means                                                            |
|----------------------------------------------------------------------------------------|------------------------------------------------------------------|
| `{ "uint": N }`                                                                        | CBOR unsigned integer.                                           |
| `{ "nint": -N }`                                                                       | CBOR negative integer (JSON-negative form for human readability).|
| `{ "tstr": "…" }`                                                                      | UTF-8 text string.                                               |
| `{ "bstr_hex": "deadbeef" }`                                                           | Byte string from hex.                                            |
| `{ "bool": true }`                                                                     | Boolean.                                                         |
| `{ "null": null }`                                                                     | CBOR null.                                                       |
| `{ "float": 1.5 }`                                                                     | Float (admissible, finite, not -0).                              |
| `{ "float_special": "nan" \| "+inf" \| "-inf" \| "negative_zero" }`                    | Special float values for R5 reject testing.                      |
| `{ "array": [ <value>, ... ] }`                                                        | Definite-length array; element order preserved.                  |
| `{ "map": [ { "key": <value>, "value": <value> }, ... ] }`                             | Map preimage in **author-provided order**; emitter re-sorts per R3. |
| `{ "tag": { "number": N, "value": <value> } }`                                         | CBOR tag wrapping a value.                                       |
| `{ "bytes_hex": "9f0102ff" }`                                                          | Pre-encoded CBOR bytes — adapter decodes then re-encodes (used for R2 parse-side cases). |

The `map` shape uses an ordered array of `{key, value}` records (not a JSON
object) because (a) JSON objects do not preserve insertion order portably and
(b) the R3 sort is the load-bearing test — the corpus expresses the
unsorted preimage and the emitter MUST re-sort.

### Reject codes (closed set)

Mirror of the runtime-port decision doc §4:

- `duplicate_map_key` — R4.
- `non_finite_float` — R5 (NaN, ±Inf).
- `negative_zero_float` — R5 (-0.0).
- `indefinite_length_input` — R2 parse-side; forward-compatibility (Rust oracle does not enforce today).
- `generic_tag_disallowed` — R7 parse-side; forward-compatibility (Rust oracle does not enforce today).

### Forward-compatibility cases

`forward_compatibility: true` marks a case where the Rust oracle does NOT yet
enforce the rule. The Rust adapter emits `result=unimplemented` for these.
A conformant external runtime that DOES enforce the rule emits the rule's
expected output / reject code; the parity gate accepts both
`result=unimplemented` and the rule-correct result.

Today's forward-compatibility cases:

- `R5-positive-zero` — Rust emits f64; an R6-conformant runtime emits f16.
- `R6-float-f16-representable` — R6 float compaction not implemented in Rust.
- `R7-generic-tag-disallowed` — R7 generic-tag allowlist not implemented in Rust.
- `R2-indefinite-length-input` — R2 parse-side reject not implemented in Rust.

## One-command verification

From the trellis repo root:

```sh
python3 fixtures/vectors/_generator/gen_canonical_cbor_profile.py
```

This invokes the Rust regenerator
(`trellis/crates/trellis-conformance/examples/canonical_cbor_emit.rs`) for
every case in [`manifest.json`](manifest.json), compares the emitted bytes /
reject codes against the committed `expected_*` fields, and aborts non-zero
on mismatch. For an intentional regeneration after a Rust authority change:

```sh
python3 fixtures/vectors/_generator/gen_canonical_cbor_profile.py --write
```

`--write` updates the committed `expected_*` fields in place; review the diff
and commit only when the change is intentional.

## Adding a case

1. Write `cases/<case_id>.json` (case_id format: `<rule>-<short-id>`).
2. Add a matching entry to `manifest.json` `cases[]`.
3. Run the regenerator (no `--write`) — it will fail with the expected output
   the Rust oracle produced. Either copy that into the case file and re-run
   (now passing), or, for an intentional regeneration, re-run with `--write`.
4. Spec-side: if the case exercises a rule that profile §5 does not yet
   demonstrate, link it in the §5 paragraph that references this corpus.

## What this corpus does NOT cover

- COSE envelope framing — covered by the COSE-Sign1 fixture series (out of
  scope for §4.2.2; the COSE preimage uses §4.2.2 internally but the corpus
  here tests §4.2.2 alone).
- Hash preimages — domain separation tags and digest construction live in
  Core §9 and have their own vectors.
- ZIP packaging — Core §18 fixtures.
- Real-Trellis preimage shapes — those live under `trellis/fixtures/vectors/append/`, `export/`, etc., and exercise §4.2.2 transitively. The corpus here is the per-rule unit-level conformance contract; the application-level fixtures are the integration-level conformance contract.
