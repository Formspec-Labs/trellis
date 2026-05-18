"""Core §19 step 3.i ``bundle_unbound_member`` sweep — Python mirror.

Mirror of Rust unit tests at
``integrity-stack/crates/integrity-verify/src/trellis/export.rs``
(commit b15f53f, Task 2.a). Pins the same two cases:

1. A stray archive member not in the §18.2 admitted set, not named by
   any manifest top-level digest / registry binding / event content_hash
   / ``interop_sidecars[].path`` / registered manifest extension MUST
   surface ``bundle_unbound_member`` and MUST drive
   ``integrity_verified`` to false. TR-CORE-181.

2. Both-fire rule: when a member is unbound BOTH per a per-extension
   ``*_unbound`` finding (here ``supersession_graph_unbound``, fired
   when ``064-supersession-graph.json`` is present without
   ``trellis.export.supersession-graph.v1``) AND per the generic sweep,
   BOTH findings MUST appear; the per-extension finding MUST NOT
   suppress the generic sweep (trellis-core.md §19 step 3.i, lines
   1774-1783, Task 1.a load-bearing decision).
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from trellis_py.verify import verify_export_zip


FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "vectors"
SOURCE_EXPORT = FIXTURES / "export" / "001-two-event-chain" / "expected-export.zip"


def _inject_stray_member(zip_bytes: bytes, stray_path: str, stray_bytes: bytes) -> bytes:
    """Rebuild the export ZIP with an extra stray member living under the
    same export-root directory. Mirror of Rust ``inject_stray_member``
    at ``export.rs`` (commit b15f53f). Uses ZIP_STORED to match the
    fixture's compression discipline and ``parse_export_zip``'s
    one-export-root invariant.
    """
    source = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")
    try:
        infos = source.infolist()
        # Recover the export-root directory (e.g.
        # ``trellis-export-test-response-ledger-2-280d3354/``) from any
        # existing entry so the stray member lives under the same root —
        # ``parse_export_zip`` requires exactly one root.
        root = None
        for info in infos:
            if "/" in info.filename:
                root = info.filename.split("/", 1)[0]
                break
        assert root is not None, "fixture export must have a root directory"

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as dest:
            for info in infos:
                with source.open(info) as fh:
                    dest.writestr(info.filename, fh.read())
            dest.writestr(f"{root}/{stray_path}", stray_bytes)
    finally:
        source.close()
    return buffer.getvalue()


def test_verify_export_zip_flags_stray_archive_member_as_bundle_unbound_member() -> None:
    """Core §19 step 3.i — a stray member that is not in the §18.2
    admitted set, not named by a manifest top-level digest, not bound
    by a registry binding, not bound by an event content_hash, not
    listed under ``interop_sidecars[].path``, and not bound by any
    registered manifest extension MUST surface ``bundle_unbound_member``
    and MUST drive ``integrity_verified`` to false. TR-CORE-181.

    Mirror of Rust
    ``verify_export_zip_flags_stray_archive_member_as_bundle_unbound_member``.
    """
    zip_bytes = SOURCE_EXPORT.read_bytes()
    stray_member_path = "999-stray.bin"
    tampered = _inject_stray_member(zip_bytes, stray_member_path, b"stray bytes")

    report = verify_export_zip(tampered)

    assert report.structure_verified, (
        f"stray-member injection should not break structure: {report!r}"
    )
    stray_failures = [
        f
        for f in report.event_failures
        if f.kind == "bundle_unbound_member"
    ]
    assert stray_failures, (
        f"expected bundle_unbound_member finding for stray member: "
        f"{report.event_failures!r}"
    )
    assert stray_failures[0].location == stray_member_path, (
        "bundle_unbound_member should locate the stray member path"
    )
    assert not report.integrity_verified, (
        f"integrity_verified must be false when a member is unbound: {report!r}"
    )


def test_verify_export_zip_fires_both_supersession_unbound_and_bundle_unbound_member() -> None:
    """Core §19 step 3.i both-fire rule (Task 1.a, trellis-core.md lines
    1774-1783). When a member is unbound both per a per-extension
    ``*_unbound`` rule (here: ``supersession_graph_unbound``, fired
    when ``064-supersession-graph.json`` is present without
    ``trellis.export.supersession-graph.v1``) AND per the generic
    sweep, BOTH findings MUST appear; the per-extension finding MUST
    NOT suppress the generic sweep. TR-CORE-181.

    Mirror of Rust
    ``verify_export_zip_fires_both_supersession_unbound_and_bundle_unbound_member``.
    """
    zip_bytes = SOURCE_EXPORT.read_bytes()
    # Fixture 001 does not bind a supersession-graph member; inject
    # 064-supersession-graph.json without the manifest extension.
    tampered = _inject_stray_member(
        zip_bytes, "064-supersession-graph.json", b"{}\n"
    )

    report = verify_export_zip(tampered)

    supersession_unbound = any(
        f.kind == "supersession_graph_unbound"
        for f in report.event_failures
    )
    bundle_unbound = any(
        f.kind == "bundle_unbound_member"
        and f.location == "064-supersession-graph.json"
        for f in report.event_failures
    )
    assert supersession_unbound, (
        f"supersession_graph_unbound MUST fire: {report.event_failures!r}"
    )
    assert bundle_unbound, (
        f"bundle_unbound_member MUST also fire (no suppression): "
        f"{report.event_failures!r}"
    )
    assert not report.integrity_verified, (
        f"integrity_verified must be false: {report!r}"
    )
