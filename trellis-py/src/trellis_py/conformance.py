"""Walk the committed Trellis vector corpus (fixtures/vectors contract)."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
from pathlib import Path
from typing import Any

import cbor2
from cbor2 import CBORTag

from trellis_py.append import append_event
from trellis_py.codec import domain_separated_sha256, encode_bstr, encode_tstr, encode_uint
from trellis_py.constants import CHECKPOINT_DOMAIN, EVENT_DOMAIN
from trellis_py.export_zip import ExportEntry, export_to_zip_bytes
from trellis_py.verify import (
    VerificationReport,
    verify_export_zip,
    verify_tampered_ledger,
)
from trellis_py import verify_wos


WOS_TAMPER_KINDS = {
    "case_created_event_type_mismatch",
    "case_created_event_unresolved",
    "case_created_handoff_mismatch",
    "case_created_payload_invalid",
    "case_created_payload_unreadable",
    "clock_calendar_mismatch",
    "intake_event_type_mismatch",
    "intake_event_unresolved",
    "intake_handoff_catalog_digest_mismatch",
    "intake_handoff_catalog_duplicate_event",
    "intake_handoff_catalog_invalid",
    "intake_handoff_mismatch",
    "intake_payload_invalid",
    "intake_payload_unreadable",
    "intake_response_hash_mismatch",
    "missing_intake_handoff_catalog",
    "missing_signature_catalog",
    "rescission_terminality_violation",
    "response_ref_mismatch",
    "signature_affirmation_payload_invalid",
    "signature_affirmation_payload_unreadable",
    "signature_catalog_digest_mismatch",
    "signature_catalog_duplicate_event",
    "signature_catalog_event_type_mismatch",
    "signature_catalog_event_unresolved",
    "signature_catalog_invalid",
    "signature_catalog_mismatch",
}


def _load_manifest(vector_dir: Path) -> dict[str, Any]:
    return tomllib.loads((vector_dir / "manifest.toml").read_text("utf-8"))


def _sign1_payload_value(value: Any) -> Any:
    if isinstance(value, CBORTag) and value.tag == 18:
        body = value.value
        if isinstance(body, (list, tuple)) and len(body) >= 3:
            return body[2]
    raise ValueError("expected tag-18 COSE_Sign1")


def _sign1_payload_bytes(cose_bytes: bytes) -> bytes:
    v = cbor2.loads(cose_bytes)
    inner = _sign1_payload_value(v)
    if not isinstance(inner, bytes):
        raise ValueError("payload not bytes")
    return inner


def _encode_cbor_canonical(value: Any) -> bytes:
    return cbor2.dumps(value, canonical=True)


def _checkpoint_digest(scope: bytes, payload_bytes: bytes) -> bytes:
    preimage = bytearray()
    preimage.append(0xA3)
    preimage.extend(encode_tstr("scope"))
    preimage.extend(encode_bstr(scope))
    preimage.extend(encode_tstr("version"))
    preimage.extend(encode_uint(1))
    preimage.extend(encode_tstr("checkpoint_payload"))
    preimage.extend(payload_bytes)
    return domain_separated_sha256(CHECKPOINT_DOMAIN, bytes(preimage))


def _canonical_event_hash_preimage(scope: bytes, canonical_event: bytes) -> bytes:
    b = bytearray()
    b.append(0xA3)
    b.extend(encode_tstr("version"))
    b.extend(encode_uint(1))
    b.extend(encode_tstr("ledger_scope"))
    b.extend(encode_bstr(scope))
    b.extend(encode_tstr("event_payload"))
    b.extend(canonical_event)
    return bytes(b)


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _assert_append(root: Path, manifest: dict[str, Any]) -> None:
    from trellis_py.append import AppendError

    inputs = manifest["inputs"]
    authored = (root / inputs["authored_event"]).read_bytes()
    exp_author = (root / "author-event-hash.bin").read_bytes()
    exp_canonical = (root / "expected-event-payload.cbor").read_bytes()
    exp_sig = (root / "sig-structure.bin").read_bytes()
    exp_signed = (root / "expected-event.cbor").read_bytes()
    exp_head = (root / "expected-append-head.cbor").read_bytes()
    sk_path = inputs.get("signing_key") or inputs.get("signing_key_b")
    if not sk_path:
        raise AssertionError("append manifest must name a signing key")
    signing_key = (root / sk_path).read_bytes()
    try:
        art = append_event(signing_key, authored)
    except AppendError as exc:
        raise AssertionError(f"append failed: {exc}") from exc
    assert art.author_event_hash == exp_author
    assert art.canonical_event == exp_canonical
    assert art.sig_structure == exp_sig
    assert art.signed_event == exp_signed
    assert art.append_head == exp_head


def _assert_export(root: Path, manifest: dict[str, Any]) -> None:
    inputs = manifest["inputs"]
    expected = manifest["expected"]
    ledger_state = cbor2.loads((root / inputs["ledger_state"]).read_bytes())
    root_dir = ledger_state["root_dir"]
    members = ledger_state["members"]
    entries = [
        ExportEntry(path=f"{root_dir}/{name}", bytes=(root / name).read_bytes()) for name in members
    ]
    actual = export_to_zip_bytes(entries)
    expected_zip = (root / expected["zip"]).read_bytes()
    assert actual == expected_zip


def _assert_verify(root: Path, manifest: dict[str, Any]) -> None:
    inputs = manifest["inputs"]
    expected_report = manifest["expected"]["report"]
    wos_report = verify_wos.verify_export_zip((root / inputs["export_zip"]).read_bytes())
    expected_kind = expected_report.get("first_failure_kind")
    if expected_kind in WOS_TAMPER_KINDS:
        _assert_wos_report(root, expected_report, wos_report, expected_kind)
        return
    report = wos_report.trellis
    assert report.structure_verified == expected_report["structure_verified"]
    assert wos_report.integrity_verified == expected_report["integrity_verified"]
    assert report.readability_verified == expected_report["readability_verified"]
    if "posture_transition_count" in expected_report:
        assert len(report.posture_transitions) == expected_report["posture_transition_count"]
    if "first_failure_kind" in expected_report:
        ff = _first_failure(report)
        assert ff is not None
        assert ff.kind == expected_report["first_failure_kind"]
    if "failing_event_id" in expected_report:
        ff = _first_failure(report)
        assert ff is not None
        assert ff.location == expected_report["failing_event_id"]


def _first_failure(report: VerificationReport):
    if report.event_failures:
        return report.event_failures[0]
    if report.checkpoint_failures:
        return report.checkpoint_failures[0]
    if report.proof_failures:
        return report.proof_failures[0]
    return None


def _first_wos_failure(report: verify_wos.WosVerificationReport):
    for finding in report.wos_findings:
        if finding.severity == "failure":
            return finding
    return None


def _assert_wos_report(
    root: Path,
    expected_report: dict[str, Any],
    report: verify_wos.WosVerificationReport,
    expected_kind: str,
) -> None:
    assert report.trellis.structure_verified == expected_report["structure_verified"]
    assert report.integrity_verified == expected_report["integrity_verified"]
    assert report.trellis.readability_verified == expected_report["readability_verified"]
    # First check `wos_findings` (DomainFinding emitted from WOS validators);
    # fall back to Trellis-Core `event_failures` when the kind is a
    # Core-emitted failure routed through the WOS path because the
    # resolution required a WOS resolver (e.g. `response_ref_mismatch`).
    ff = _first_wos_failure(report)
    if ff is not None:
        assert ff.kind == expected_kind
        if "failing_event_id" in expected_report:
            assert ff.event_hash is not None
            assert ff.event_hash.hex() == expected_report["failing_event_id"]
        return
    trellis_failure = _first_failure(report.trellis)
    assert trellis_failure is not None
    assert trellis_failure.kind == expected_kind
    if "failing_event_id" in expected_report:
        assert trellis_failure.location == expected_report["failing_event_id"]


def _assert_tamper(root: Path, manifest: dict[str, Any]) -> None:
    inputs = manifest["inputs"]
    expected_report = manifest["expected"]["report"]
    expected_kind = expected_report.get("tamper_kind")
    if expected_kind in WOS_TAMPER_KINDS:
        if "export_zip" in inputs:
            wos_report = verify_wos.verify_export_zip((root / inputs["export_zip"]).read_bytes())
        else:
            init_pd = (
                (root / p).read_bytes() if (p := inputs.get("initial_posture_declaration")) else None
            )
            pd = (root / p).read_bytes() if (p := inputs.get("posture_declaration")) else None
            wos_report = verify_wos.verify_tampered_ledger(
                (root / inputs["signing_key_registry"]).read_bytes(),
                (root / inputs["ledger"]).read_bytes(),
                init_pd,
                pd,
            )
        _assert_wos_report(root, expected_report, wos_report, expected_kind)
        return
    if "export_zip" in inputs:
        report = verify_export_zip((root / inputs["export_zip"]).read_bytes())
    else:
        init_pd = (
            (root / p).read_bytes() if (p := inputs.get("initial_posture_declaration")) else None
        )
        pd = (root / p).read_bytes() if (p := inputs.get("posture_declaration")) else None
        report = verify_tampered_ledger(
            (root / inputs["signing_key_registry"]).read_bytes(),
            (root / inputs["ledger"]).read_bytes(),
            init_pd,
            pd,
        )
    assert report.structure_verified == expected_report["structure_verified"]
    assert report.integrity_verified == expected_report["integrity_verified"]
    assert report.readability_verified == expected_report["readability_verified"]
    if "tamper_kind" in expected_report:
        ff = _first_failure(report)
        assert ff is not None
        assert ff.kind == expected_report["tamper_kind"]
    if "failing_event_id" in expected_report:
        ff = _first_failure(report)
        assert ff is not None
        assert ff.location == expected_report["failing_event_id"]


def _assert_projection(root: Path, manifest: dict[str, Any]) -> None:
    inputs = manifest["inputs"]
    expected = manifest["expected"]
    if "watermark" in expected:
        view = cbor2.loads((root / inputs["view"]).read_bytes())
        wm = view["watermark"]
        wm_bytes = _encode_cbor_canonical(wm)
        assert wm_bytes == (root / expected["watermark"]).read_bytes()
        checkpoint_payload = _sign1_payload_bytes((root / inputs["checkpoint"]).read_bytes())
        cp_val = cbor2.loads(checkpoint_payload)
        checkpoint_scope = cp_val["scope"]
        checkpoint_digest = _checkpoint_digest(checkpoint_scope, checkpoint_payload)
        assert wm["checkpoint_ref"] == checkpoint_digest
        if "staff_view_decision_binding" in expected:
            fields = manifest["staff_view_decision_binding_fields"]
            ext = fields.get("extensions")
            if ext == "null":
                ext_val = None
            else:
                raise AssertionError("unexpected extensions field")
            binding = {
                "watermark": wm,
                "extensions": ext_val,
                "staff_view_ref": fields["staff_view_ref"],
                "stale_acknowledged": fields["stale_acknowledged"],
            }
            assert _encode_cbor_canonical(binding) == (
                root / expected["staff_view_decision_binding"]
            ).read_bytes()
    if "view_rebuilt" in expected:
        chain_bytes = (root / inputs["chain"]).read_bytes()
        chain = cbor2.loads(chain_bytes)
        events = chain
        last = events[-1]
        last_cose_bytes = cbor2.dumps(last, canonical=True)
        inner_payload = _sign1_payload_bytes(last_cose_bytes)
        last_payload = cbor2.loads(inner_payload)
        scope = last_payload["ledger_scope"]
        preimage = _canonical_event_hash_preimage(scope, inner_payload)
        canonical_hash = domain_separated_sha256(EVENT_DOMAIN, preimage)
        rebuilt = {
            "event_count": len(events),
            "last_canonical_event_hash": canonical_hash,
        }
        rebuilt_bytes = _encode_cbor_canonical(rebuilt)
        assert rebuilt_bytes == (root / expected["view_rebuilt"]).read_bytes()
        assert rebuilt_bytes == (root / inputs["view"]).read_bytes()
    if "cadence_report" in expected:
        cadence = manifest["cadence"]
        sizes = []
        for path in inputs["checkpoints"]:
            payload = _sign1_payload_bytes((root / path).read_bytes())
            sizes.append(cbor2.loads(payload)["tree_size"])
        required = cadence["required_tree_sizes"]
        missing = [v for v in required if v not in sizes]
        report = {
            "interval": cadence["interval"],
            "cadence_kind": cadence["kind"],
            "failure_code": cadence.get("failure_code"),
            "cadence_satisfied": not cadence["expect_failure"],
            "missing_tree_sizes": missing,
            "expected_tree_sizes": required,
            "observed_tree_sizes": sizes,
        }
        assert _encode_cbor_canonical(report) == (root / expected["cadence_report"]).read_bytes()


def _assert_shred(root: Path, manifest: dict[str, Any]) -> None:
    inputs = manifest["inputs"]
    expected = manifest["expected"]
    procedure = manifest["procedure"]
    chain = cbor2.loads((root / inputs["chain"]).read_bytes())
    events = chain
    first_bytes = cbor2.dumps(events[0], canonical=True)
    target_payload = cbor2.loads(_sign1_payload_bytes(first_bytes))
    target_content_hash = target_payload["content_hash"]
    declared_scope = procedure["cascade_scope"]
    report_entries: list[tuple[str, Any]] = [("declared_scope", declared_scope)]
    if "backup_snapshot" in inputs:
        snap = (root / inputs["backup_snapshot"]).read_bytes()
        report_entries.append(("backup_snapshot_ref", _sha256(snap)))
    post_states = {}
    for scope in declared_scope:
        if "backup_snapshot" in inputs:
            post_states[scope] = {
                "rationale": f"{scope}-backup-restore-refused-per-§16.5",
                "backup_resurrection_refused": True,
                "invalidated_or_plaintext_absent": True,
            }
        else:
            post_states[scope] = {
                "rationale": f"{scope}-in-declared-cascade-scope",
                "invalidated_or_plaintext_absent": True,
            }
    report_entries.append(("expected_post_state", post_states))
    report_entries.append(("target_content_hash", target_content_hash))
    report = dict(report_entries)
    assert _encode_cbor_canonical(report) == (root / expected["cascade_report"]).read_bytes()


def _vector_dirs(vectors_root: Path, op: str) -> list[Path]:
    base = vectors_root / op
    if not base.is_dir():
        return []
    dirs = [p for p in base.iterdir() if p.is_dir() and not p.name.startswith("_")]
    return sorted(dirs, key=lambda p: p.name)


def run_all(vectors_root: Path) -> tuple[int, int, list[str]]:
    failures: list[str] = []
    total = 0
    for op in ("append", "export", "verify", "tamper", "projection", "shred"):
        for d in _vector_dirs(vectors_root, op):
            # F6 — deprecated tombstones preserve the `<op>/NNN` prefix for the
            # R16 pre-merge guard but carry no replayable bytes; skip them.
            try:
                manifest = _load_manifest(d)
            except FileNotFoundError:
                continue
            if manifest.get("status") == "deprecated":
                continue
            total += 1
            try:
                mop = manifest.get("op")
                if mop != op:
                    failures.append(f"{d}: manifest op {mop!r} != dir op {op!r}")
                    continue
                if op == "append":
                    _assert_append(d, manifest)
                elif op == "export":
                    _assert_export(d, manifest)
                elif op == "verify":
                    _assert_verify(d, manifest)
                elif op == "tamper":
                    _assert_tamper(d, manifest)
                elif op == "projection":
                    _assert_projection(d, manifest)
                elif op == "shred":
                    _assert_shred(d, manifest)
            except AssertionError as exc:
                failures.append(f"{d}: {exc}")
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{d}: {type(exc).__name__}: {exc}")
    return total, len(failures), failures


def main() -> None:
    p = argparse.ArgumentParser(description="Trellis G-5 vector conformance (trellis-py)")
    p.add_argument(
        "--vectors",
        type=Path,
        default=None,
        help="Path to fixtures/vectors (default: <repo>/trellis/fixtures/vectors)",
    )
    p.add_argument("--write-report", type=Path, default=None, help="Write JSON report to this path")
    args = p.parse_args()
    vectors = args.vectors
    if vectors is None:
        here = Path(__file__).resolve()
        vectors = here.parents[3] / "fixtures" / "vectors"
    if not vectors.is_dir():
        print(f"vectors root not found: {vectors}", file=sys.stderr)
        sys.exit(2)
    total, nfail, failures = run_all(vectors)
    report = {
        "vectors_root": str(vectors),
        "total_vectors": total,
        "failed": nfail,
        "failures": failures,
    }
    text = json.dumps(report, indent=2)
    if args.write_report:
        args.write_report.write_text(text, encoding="utf-8")
    print(text)
    sys.exit(1 if nfail else 0)


if __name__ == "__main__":
    main()
