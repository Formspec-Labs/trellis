# Trellis Core Prose Surgery Audit - 2026-05-13

Scope: `specs/trellis-core.md` sections 5, 7, 9.1, and 18.

## Classification

| Section | Rule family | Classification | Substrate authority | Trellis-owned remainder |
|---|---|---|---|---|
| §5 | Deterministic CBOR encoding profile | Keep as composition prose | `integrity-cbor` owns primitive CBOR encoding helpers and deterministic value decoding | Trellis still names which artifacts are dCBOR and which fixture members must byte-match |
| §7 | COSE_Sign1 protected headers and signature structure | Keep only Trellis profile pins | `integrity-cose` owns COSE_Sign1 parsing, protected-header construction, Sig_structure, and Ed25519 verification | Trellis owns `suite_id = 1`, `artifact_type = -65538`, retired label `-65539`, artifact-type names, and migration/resolution discipline |
| §9.1 | Length-prefixed domain separation | Keep skeleton plus tag namespace | `integrity-canonical` owns length-prefixed digest framing and SHA helpers | Trellis owns the `trellis-*` domain tags and which components enter each preimage |
| §18 | Deterministic ZIP mechanics | Keep archive composition | `integrity-bundle` / `trellis-export` own deterministic ZIP byte mechanics | Trellis owns member names, lexicographic member order, manifest digest bindings, optional catalog semantics, and verifier obligations |

## Edits Applied

- Added `trellis.export.witness-key-registry.v1` as a manifest extension binding for `031-witness-key-registry.cbor`.
- Registered `kind = "witness"` as a reserved non-signing `KeyEntry` class and documented that witness keys cannot sign Trellis events, checkpoints, manifests, or signing-key-registry administrative entries.
- Registered `031-witness-key-registry.cbor` in the archive layout and verifier digest algorithm.

No broad prose deletion was made in this pass because the current `trellis-core.md` already marks the relevant substrate authority at the top of §§5, 7, 9.1, and 18. The remaining prose is profile composition and verifier obligation text, not a standalone duplicate byte implementation.
