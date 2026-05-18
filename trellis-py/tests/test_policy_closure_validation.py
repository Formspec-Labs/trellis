"""FP6 regression — duplicate-map-key guard on policy-closure validation.

`_validate_policy_closure_member` runs two layers of defence against
duplicate canonical-CBOR map keys in `067-policy-closure.cbor`:

  Layer 1 — parse-side walker `reject_duplicate_canonical_map_keys`
            (trellis_py/_cbor_strict.py) detects dup keys at any nesting
            depth BEFORE `cbor2.loads`. cbor2 would otherwise silently
            collapse duplicates into a single dict entry.

  Layer 2 — decode-then-canonical-re-encode. The bytes round-trip through
            `cbor2.loads` → `encode_canonical_cbor_value` and must equal
            the input. This catches non-canonical inputs (ordering, float
            width, generic tags) that the walker permits.

The guard has shipped since FP6 but lacked a direct regression test wired
through the validator. This file fixes that by feeding hand-crafted CBOR
bytes (not `cbor2.dumps(..., canonical=True)`, which would canonicalise
the inputs) through `_validate_policy_closure_member` and asserting the
resulting `VerifyError`.

Layer-2 dup-key reachability note: the `R4` raise in
`_emit_map_from_pairs` (trellis_py/_cbor_canonical.py:182) is unreachable
from `_validate_policy_closure_member` for dup-key inputs. Layer 1 always
fires first; even if it did not, `cbor2.loads` collapses duplicates into
a Python `dict`, so the re-encoder never sees them as pairs. Layer 2 is
exercised here for the non-dup-key non-canonical case (R3 ordering) so
both arms of the validator have explicit coverage.
"""

from __future__ import annotations

import cbor2
import pytest

from trellis_py import verify as core
from trellis_py import verify_wos


def _h(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.replace(" ", ""))


# ---------------------------------------------------------------------------
# Layer 1 — parse-side walker rejects duplicate keys at parse time.
# ---------------------------------------------------------------------------


def test_layer1_rejects_duplicate_root_keys_before_decode() -> None:
    # Hand-crafted CBOR map with TWO entries both keyed "a":
    #   a2          map(2)
    #     61 61     tstr("a")
    #     01        uint(1)
    #     61 61     tstr("a")
    #     02        uint(2)
    # cbor2.loads collapses this to {"a": 2}; the walker must reject first.
    dup_bytes = _h("a2 61 61 01 61 61 02")

    with pytest.raises(
        core.VerifyError, match=r"duplicate canonical CBOR map key `6161`"
    ):
        verify_wos._validate_policy_closure_member(  # noqa: SLF001
            dup_bytes, expected_version="policy-closure-test-v1"
        )


def test_layer1_rejects_duplicate_keys_at_nested_depth() -> None:
    # Outer map {"outer": <inner>} where <inner> is a map with two "x" keys:
    #   a1                                  map(1)
    #     65 6f 75 74 65 72                 tstr("outer")
    #     a2                                map(2)
    #       61 78  f5                       tstr("x") true
    #       61 78  f4                       tstr("x") false
    # Layer 1 must walk into <inner> and detect the dup key there.
    dup_bytes = _h("a1 65 6f 75 74 65 72 a2 61 78 f5 61 78 f4")

    with pytest.raises(
        core.VerifyError, match=r"duplicate canonical CBOR map key `6178`"
    ):
        verify_wos._validate_policy_closure_member(  # noqa: SLF001
            dup_bytes, expected_version="policy-closure-test-v1"
        )


# ---------------------------------------------------------------------------
# Layer 2 — canonical re-encode disagreement catches non-canonical bytes
# that Layer 1 permits (ordering, float width, generic tags). Dup keys
# never reach this layer in the validator path, so the non-canonical-order
# case is the load-bearing reachable check.
# ---------------------------------------------------------------------------


def test_layer2_rejects_noncanonical_map_key_order() -> None:
    # `cbor2.dumps({...}, canonical=False)` may emit keys in insertion
    # order rather than §4.2.2 bytewise-sorted order. The walker permits
    # this (no dups), but the re-encode under §4.2.2 will disagree and
    # raise the "not canonical CBOR" verdict.
    noncanonical = cbor2.dumps(
        {
            # Insertion order intentionally violates §4.2.2 (which would
            # sort by encoded key bytes: closure_schema_version,
            # closure_version, verifier_boundary, artifacts).
            "verifier_boundary": {},
            "closure_version": "policy-closure-test-v1",
            "closure_schema_version": 1,
            "artifacts": [],
        },
        canonical=False,
    )

    with pytest.raises(core.VerifyError, match=r"not canonical CBOR"):
        verify_wos._validate_policy_closure_member(  # noqa: SLF001
            noncanonical, expected_version="policy-closure-test-v1"
        )
