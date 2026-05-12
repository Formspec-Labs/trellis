"""Parametrized G-5 tamper vectors for ADR 0010 user-content-attestation.

Corpus-wide parity remains `python -m trellis_py.conformance`; these tests
pin a small UCA subset so regressions surface under pytest without running
the full stranger gate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trellis_py.conformance import _assert_tamper, _load_manifest
from trellis_py import verify_wos
from trellis_py.verify import _is_identity_attestation_event_type


def _vectors_root() -> Path:
    # trellis/trellis-py/tests/this_file.py → trellis/
    return Path(__file__).resolve().parents[2] / "fixtures" / "vectors"


def _uca_tamper_dirs() -> list[Path]:
    root = _vectors_root() / "tamper"
    if not root.is_dir():
        return []
    return sorted(p for p in root.iterdir() if p.is_dir() and "-uca-" in p.name)


@pytest.mark.parametrize("vector_dir", _uca_tamper_dirs(), ids=lambda p: p.name)
def test_uca_tamper_vectors_match_manifest(vector_dir: Path) -> None:
    manifest = _load_manifest(vector_dir)
    _assert_tamper(vector_dir, manifest)


def test_core_identity_attestation_event_type_is_fixture_only() -> None:
    assert not _is_identity_attestation_event_type(
        "wos.assurance.identity_attestation"
    )
    assert _is_identity_attestation_event_type("x-trellis-test/identity-attestation/v1")
    assert not _is_identity_attestation_event_type("wos.identity.authentication_method")


def test_wos_identity_attestation_event_type_is_adapter_owned() -> None:
    assert verify_wos._is_wos_identity_attestation_event_type(  # noqa: SLF001
        "wos.assurance.identity_attestation"
    )
    assert not verify_wos._is_wos_identity_attestation_event_type(  # noqa: SLF001
        "wos.identity.identity_attestation"
    )
    assert not verify_wos._is_wos_identity_attestation_event_type(  # noqa: SLF001
        "wos.identity.authentication_method"
    )
