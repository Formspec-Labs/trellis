#!/usr/bin/env python3
"""Cross-runtime parity gate. Permanent CI invariant.

Runs three named gates in sequence and reports a structured failure block
on disagreement. The gates cover the substrate's three byte-identity surfaces:

1. `generic-cbor-profile` — every R1–R7 case in
   `fixtures/vectors/canonical-cbor/manifest.json` agrees with the Rust oracle
   (`integrity-cbor::encode_canonical_cbor_value`) via the
   `canonical_cbor_emit` cargo example. Drives the
   `gen_canonical_cbor_profile.py` orchestrator in verify-only mode.
2. `signed-acts-projection` — the Python WOS/Formspec signature export
   generator regenerates every signed-acts vector into a temp tree, and
   each generated binary is byte-compared against the committed corpus.
   The Python WOS verifier then runs over the signed-acts positive and
   negative vectors; failure kinds and verdicts MUST match. Rust consumes
   the same corpus through `cargo nextest run -p trellis-verify-wos`.
3. `seal-fence` — Python `verify_seal_fence_extension` (Task C2) produces
   the same outcome as Rust `verify_seal_fence_extension`
   (`integrity-stack/crates/integrity-verify/src/trellis/export.rs:996`)
   across every committed export fixture, against synthetic seal-fence
   extensions built from each fixture's archive members, including every
   Rust `SealFenceTamper` variant (`export.rs:1153`).

Failure output names: gate, case id / vector id, rule (R1–R7 when
applicable), runtime + library, expected hex / reject code, actual,
and the exact shell command to reproduce.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "trellis-py" / "src"))

GENERATOR = ROOT / "fixtures" / "vectors" / "_generator" / "gen_signature_export_006.py"
VECTORS = ROOT / "fixtures" / "vectors"
CANONICAL_CBOR_GENERATOR = (
    ROOT / "fixtures" / "vectors" / "_generator" / "gen_canonical_cbor_profile.py"
)
AUTHORING_FILES = {"manifest.toml", "derivation.md"}
GENERATED_DIRS = [
    ("export", "006-signature-affirmations-inline"),
    ("export", "007-signature-admission-failed-inline"),
    ("export", "008-signed-acts-fallback-act-id"),
    ("export", "009-signed-acts-manifest-only"),
    ("verify", "014-export-006-signature-row-mismatch"),
    ("verify", "019-export-006-signed-acts-render-drift"),
    ("verify", "020-export-006-signed-acts-unsupported-rule"),
    ("verify", "021-signed-acts-manifest-tamper"),
    ("verify", "022-066-render-drift-tampered-only"),
    ("tamper", "014-signature-catalog-digest-mismatch"),
    ("tamper", "055-signed-acts-catalog-digest-mismatch"),
    ("tamper", "056-policy-closure-digest-mismatch"),
]


def tree_bytes(base: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(base).as_posix()
        if rel in AUTHORING_FILES:
            continue
        files[rel] = path.read_bytes()
    return files


def load_generator():
    spec = importlib.util.spec_from_file_location("gen_signature_export_006", GENERATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load generator at {GENERATOR}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_generator(tmp: Path) -> None:
    module = load_generator()
    module.OUT_EXPORT_006 = tmp / "export" / "006-signature-affirmations-inline"
    module.OUT_EXPORT_007 = tmp / "export" / "007-signature-admission-failed-inline"
    module.OUT_EXPORT_008 = tmp / "export" / "008-signed-acts-fallback-act-id"
    module.OUT_EXPORT_009 = tmp / "export" / "009-signed-acts-manifest-only"
    module.OUT_VERIFY_014 = tmp / "verify" / "014-export-006-signature-row-mismatch"
    module.OUT_VERIFY_019 = tmp / "verify" / "019-export-006-signed-acts-render-drift"
    module.OUT_VERIFY_020 = tmp / "verify" / "020-export-006-signed-acts-unsupported-rule"
    module.OUT_VERIFY_021 = tmp / "verify" / "021-signed-acts-manifest-tamper"
    module.OUT_VERIFY_022 = tmp / "verify" / "022-066-render-drift-tampered-only"
    module.OUT_TAMPER_014 = tmp / "tamper" / "014-signature-catalog-digest-mismatch"
    module.OUT_TAMPER_055 = tmp / "tamper" / "055-signed-acts-catalog-digest-mismatch"
    module.OUT_TAMPER_056 = tmp / "tamper" / "056-policy-closure-digest-mismatch"
    module.main()


def compare_generated_tree(tmp: Path) -> bool:
    ok = True
    for op, name in GENERATED_DIRS:
        rel = Path(op) / name
        if not (VECTORS / rel).is_dir():
            print(f"committed vector directory missing: {rel}", file=sys.stderr)
            ok = False
            continue
        if not (tmp / rel).is_dir():
            print(f"generator did not emit vector directory: {rel}", file=sys.stderr)
            ok = False
            continue
        expected = tree_bytes(VECTORS / rel)
        actual = tree_bytes(tmp / rel)
        if actual.keys() != expected.keys():
            only_expected = sorted(expected.keys() - actual.keys())
            only_actual = sorted(actual.keys() - expected.keys())
            print(
                f"Generated file set differs for {rel}:\n"
                f"  only in committed corpus: {only_expected}\n"
                f"  only in generated tree: {only_actual}",
                file=sys.stderr,
            )
            ok = False
            continue
        for child in sorted(actual):
            if actual[child] != expected[child]:
                print(f"bytes differ: {rel / child}", file=sys.stderr)
                ok = False
    return ok


def assert_no_wos_failures(verify_wos, export_zip: Path) -> None:
    report = verify_wos.verify_export_zip(export_zip.read_bytes())
    failures = [finding.kind for finding in report.wos_findings if finding.severity == "failure"]
    if failures:
        raise AssertionError(f"{export_zip} emitted WOS failures: {failures}")
    if report.verdict.projection_integrity != "pass":
        raise AssertionError(
            f"{export_zip} projection_integrity={report.verdict.projection_integrity}"
        )


def assert_wos_failure(
    verify_wos,
    export_zip: Path,
    expected_failures: set[str],
    *,
    projection_integrity: str,
    blocking_reasons: list[str],
    domain_admissibility: str = "pass",
) -> None:
    report = verify_wos.verify_export_zip(export_zip.read_bytes())
    if not report.trellis.structure_verified:
        raise AssertionError(f"{export_zip} did not preserve substrate structure")
    if not report.trellis.integrity_verified:
        raise AssertionError(f"{export_zip} did not preserve substrate integrity")
    if not report.trellis.readability_verified:
        raise AssertionError(f"{export_zip} did not preserve substrate readability")
    if report.integrity_verified:
        raise AssertionError(f"{export_zip} unexpectedly passed composed integrity")
    if report.verdict.cryptographic_integrity != "pass":
        raise AssertionError(
            f"{export_zip} cryptographic_integrity={report.verdict.cryptographic_integrity}"
        )
    if report.verdict.projection_integrity != projection_integrity:
        raise AssertionError(
            f"{export_zip} projection_integrity={report.verdict.projection_integrity}"
        )
    if report.verdict.relying_party_result != "invalid":
        raise AssertionError(
            f"{export_zip} relying_party_result={report.verdict.relying_party_result}"
        )
    if report.verdict.domain_admissibility != domain_admissibility:
        raise AssertionError(
            f"{export_zip} domain_admissibility={report.verdict.domain_admissibility}"
        )
    if report.verdict.blocking_reasons != blocking_reasons:
        raise AssertionError(
            f"{export_zip} blocking_reasons={report.verdict.blocking_reasons}"
        )
    failures = {
        finding.kind for finding in report.wos_findings if finding.severity == "failure"
    }
    if failures != expected_failures:
        raise AssertionError(
            f"{export_zip} failures {sorted(failures)}, expected {sorted(expected_failures)}"
        )


def check_python_verifier_vectors() -> None:
    from trellis_py import verify_wos

    assert_no_wos_failures(
        verify_wos,
        VECTORS / "export/006-signature-affirmations-inline/expected-export.zip"
    )
    assert_no_wos_failures(
        verify_wos,
        VECTORS / "export/007-signature-admission-failed-inline/expected-export.zip"
    )
    assert_no_wos_failures(
        verify_wos,
        VECTORS / "export/008-signed-acts-fallback-act-id/expected-export.zip"
    )
    assert_no_wos_failures(
        verify_wos,
        VECTORS / "export/009-signed-acts-manifest-only/expected-export.zip"
    )
    # verify/019 + verify/022: 066 render-drift advisories — verdict stays
    # valid (the substrate-anchored 068 manifest is the load-bearing proof).
    assert_no_wos_failures(
        verify_wos,
        VECTORS / "verify/019-export-006-signed-acts-render-drift/input-export.zip"
    )
    assert_no_wos_failures(
        verify_wos,
        VECTORS / "verify/022-066-render-drift-tampered-only/input-export.zip"
    )
    # `signed_acts_catalog_invalid` is a structural-shape kind → routes to
    # `projection_mismatch` blocking-reason per Rust
    # `RelyingPartyVerdict::from_parts` at
    # `integrity-stack/crates/integrity-verify/src/trellis/validator.rs:115-133`.
    assert_wos_failure(
        verify_wos,
        VECTORS / "verify/020-export-006-signed-acts-unsupported-rule/input-export.zip",
        {"signed_acts_catalog_invalid"},
        projection_integrity="fail",
        blocking_reasons=["projection_mismatch"],
    )
    # verify/021 (068 manifest tamper): cross-runtime parity guard that
    # Python's verdict for the tampered 068 member matches Rust's
    # (`cargo nextest run -p trellis-conformance` exercises the same fixture).
    # The five `signed_acts_manifest_*` kinds signal substrate damage /
    # declaration violation of the substrate-anchored signed-acts proof, so
    # they surface under `domain_admissibility` (not the projection bucket) —
    # see Rust `is_projection_finding` at
    # `integrity-stack/crates/integrity-verify/src/trellis/validator.rs:288-297`.
    assert_wos_failure(
        verify_wos,
        VECTORS / "verify/021-signed-acts-manifest-tamper/input-export.zip",
        {"signed_acts_manifest_extension_digest_mismatch"},
        projection_integrity="pass",
        domain_admissibility="fail",
        blocking_reasons=["domain_admissibility"],
    )
    # `signed_acts_catalog_digest_mismatch` is a structural-shape kind →
    # `projection_mismatch` per Rust validator.rs:115-133.
    assert_wos_failure(
        verify_wos,
        VECTORS / "tamper/055-signed-acts-catalog-digest-mismatch/input-export.zip",
        {"signed_acts_catalog_digest_mismatch"},
        projection_integrity="fail",
        blocking_reasons=["projection_mismatch"],
    )


def check_cross_runtime_manifest_byte_identity() -> None:
    """Assert Python `encode_signed_acts_manifest_v1` output is byte-identical
    to the committed Rust-emitted `068-signed-acts-manifest.cbor` member across
    every export fixture that ships a 068 member.

    The committed bytes ARE the Rust output (the fixture corpus is generated
    by the Rust writer pipeline). Re-deriving the manifest from the same
    `010-events.cbor` source events on the Python side and byte-comparing
    against the archive member is the canonical cross-runtime parity check
    this script promotes to a permanent invariant (Task A9).
    """
    from trellis_py import verify as core
    from trellis_py import verify_wos

    export_fixtures = [
        "export/006-signature-affirmations-inline",
        "export/007-signature-admission-failed-inline",
        "export/008-signed-acts-fallback-act-id",
        "export/009-signed-acts-manifest-only",
    ]
    for fixture in export_fixtures:
        export_zip_path = VECTORS / fixture / "expected-export.zip"
        archive = core.parse_export_zip(export_zip_path.read_bytes())
        committed_member_bytes = archive.get(
            verify_wos.SIGNED_ACTS_MANIFEST_MEMBER
        )
        if committed_member_bytes is None:
            raise AssertionError(
                f"{fixture} is registered for 068 byte-identity but archive "
                f"is missing {verify_wos.SIGNED_ACTS_MANIFEST_MEMBER}"
            )
        events_bytes = archive.get("010-events.cbor")
        if events_bytes is None:
            raise AssertionError(f"{fixture} archive is missing 010-events.cbor")
        events = core._parse_sign1_array(events_bytes)  # noqa: SLF001
        decoded: list[core.EventDetails] = []
        for event in events:
            try:
                decoded.append(core._decode_event_details(event))  # noqa: SLF001
            except core.VerifyError as exc:
                raise AssertionError(
                    f"{fixture}: cannot decode event for re-derivation: {exc}"
                ) from exc
        manifest = verify_wos.derive_signed_acts_manifest_v1(decoded)
        python_bytes = verify_wos.encode_signed_acts_manifest_v1(manifest)
        if python_bytes != committed_member_bytes:
            raise AssertionError(
                f"{fixture}: Python-derived 068 bytes "
                f"({python_bytes.hex()[:64]}...) do not match committed Rust "
                f"output ({committed_member_bytes.hex()[:64]}...)"
            )


def check_cross_runtime_seal_fence_parity() -> None:
    """Assert Python `verify_seal_fence_extension` (Task C2) produces the
    same outcome as Rust `verify_seal_fence_extension`
    (`integrity-stack/crates/integrity-verify/src/trellis/export.rs:996`)
    across every committed export fixture, on a synthetic seal-fence
    extension built from each fixture's archive members.

    The export-fixture corpus does not yet ship the
    `trellis.export.seal-fence.v1` extension (the Rust unit tests at
    `export.rs:1162` construct one on the fly via `sealed_export_package`).
    This parity gate replicates that pattern in Python so the Python
    verifier is exercised against the full committed corpus AND against
    every Rust `SealFenceTamper` variant at `export.rs:1153`.

    Cross-runtime parity follows from the primitives being byte-identical:
    canonical-CBOR §4.2.2 (Task A2 byte oracle), `domain_separated_sha256`
    (Task A2 byte oracle), and SHA-256(member-bytes). If any of those drift,
    `check_cross_runtime_manifest_byte_identity` and this gate both
    surface the divergence.
    """
    from trellis_py import verify as core
    from trellis_py.verify_export import (
        SEAL_FENCE_EXPORT_EXTENSION,
        SEAL_FENCE_IDENTITY_RULE,
        export_attempt_id,
        verify_seal_fence_extension,
    )

    export_fixtures = [
        "export/006-signature-affirmations-inline",
        "export/007-signature-admission-failed-inline",
        "export/008-signed-acts-fallback-act-id",
        "export/009-signed-acts-manifest-only",
        "export/009-erasure-evidence-inline",
    ]

    # Mirror of Rust `SealFenceTamper` variants at `export.rs:1153`. Each
    # tuple is (mutator, expected Python finding kind). Rust treats every
    # variant as fatal `ManifestPayloadInvalid`; Python's typed kinds
    # localize the diagnostic. Both runtimes surface the same five
    # categories of mismatch.
    tampers: list[tuple[str, callable, str]] = [
        ("IdentityRule",
         lambda sf: sf.__setitem__("identity_rule", "trellis-export-seal-fence-test"),
         "seal_fence_identity_rule_mismatch"),
        ("ExportAttemptId",
         lambda sf: sf.__setitem__("export_attempt_id", "sha256:wrong"),
         "seal_fence_export_attempt_id_mismatch"),
        ("EventsDigest",
         lambda sf: sf.__setitem__("events_digest", b"\xaa" * 32),
         "seal_fence_events_digest_recompute_mismatch"),
        ("HeadCheckpointDigest",
         lambda sf: sf.__setitem__("head_checkpoint_digest", b"\xbb" * 32),
         "seal_fence_head_checkpoint_digest_recompute_mismatch"),
        ("PolicyClosureDigest",
         lambda sf: sf.__setitem__("policy_closure_digest", b"\xcc" * 32),
         "seal_fence_policy_closure_digest_recompute_mismatch"),
    ]

    import copy as _copy
    import cbor2 as _cbor2

    for fixture in export_fixtures:
        export_zip_path = VECTORS / fixture / "expected-export.zip"
        if not export_zip_path.is_file():
            raise AssertionError(f"{fixture} expected-export.zip is missing")
        archive = core.parse_export_zip(export_zip_path.read_bytes())
        manifest_sign1 = core._parse_sign1_bytes(archive["000-manifest.cbor"])  # noqa: SLF001
        manifest_map = _cbor2.loads(manifest_sign1.payload)
        events = core._parse_sign1_array(archive["010-events.cbor"])  # noqa: SLF001
        if not events:
            raise AssertionError(f"{fixture} has no events; cannot build seal-fence")
        hw = core._decode_event_details(events[-1])  # noqa: SLF001
        scope = bytes(core._map_lookup_bytes(manifest_map, "scope"))  # noqa: SLF001
        events_digest = core._map_lookup_fixed_bytes(  # noqa: SLF001
            manifest_map, "events_digest", 32
        )
        head_ck_digest = core._map_lookup_fixed_bytes(  # noqa: SLF001
            manifest_map, "head_checkpoint_digest", 32
        )
        closure_bytes = archive.get("067-policy-closure.cbor")
        closure_digest = (
            core._sha256(closure_bytes) if closure_bytes is not None else None  # noqa: SLF001
        )
        seal_version = len(events)
        attempt = export_attempt_id(
            scope, seal_version, hw.sequence, hw.canonical_event_hash
        )
        seal_fence = {
            "identity_rule": SEAL_FENCE_IDENTITY_RULE,
            "bundle_scope": scope,
            "export_attempt_id": attempt,
            "seal_version": seal_version,
            "event_count": len(events),
            "high_water_sequence": hw.sequence,
            "high_water_event_hash": hw.canonical_event_hash,
            "head_checkpoint_digest": head_ck_digest,
            "events_digest": events_digest,
            "policy_closure_digest": closure_digest,
        }
        base_extensions = _copy.deepcopy(manifest_map.get("extensions", {}) or {})
        base_extensions[SEAL_FENCE_EXPORT_EXTENSION] = seal_fence
        manifest_map_sealed = dict(manifest_map)
        manifest_map_sealed["extensions"] = base_extensions

        # Happy path: synthetic seal-fence over unmodified members.
        findings = verify_seal_fence_extension(archive, manifest_map_sealed)
        if findings:
            raise AssertionError(
                f"{fixture} synthetic seal-fence happy path emitted findings: "
                f"{[(f.kind, f.detail) for f in findings]}"
            )

        # Every tamper variant: at least one finding of the expected kind.
        for tamper_name, mutate, expected_kind in tampers:
            tampered_ext = _copy.deepcopy(base_extensions)
            mutate(tampered_ext[SEAL_FENCE_EXPORT_EXTENSION])
            tampered_manifest = dict(manifest_map)
            tampered_manifest["extensions"] = tampered_ext
            findings = verify_seal_fence_extension(archive, tampered_manifest)
            kinds = [f.kind for f in findings]
            if expected_kind not in kinds:
                raise AssertionError(
                    f"{fixture} tamper {tamper_name} expected finding "
                    f"{expected_kind!r}, got {kinds}"
                )


# --------------------------------------------------------------------------
# Gate runner — structured failure output
# --------------------------------------------------------------------------

GATES_ORDER = ("generic-cbor-profile", "signed-acts-projection", "seal-fence")


def _print_gate_header(gate: str) -> None:
    print(f"[{gate}] running…", file=sys.stderr)


def _print_gate_pass(gate: str, detail: str) -> None:
    print(f"[{gate}] PASS — {detail}", file=sys.stderr)


def _print_failure_block(
    *,
    gate: str,
    case_id: str,
    rule: str | None,
    runtime: str,
    expected: str,
    actual: str,
    command: str,
    note: str | None = None,
) -> None:
    """Structured failure block. Mirrors the failure framing required by the
    A2 task: gate, case id / vector id, rule (R1–R7 when applicable), runtime
    + version, expected hex / reject code, actual hex / reject code, and the
    exact shell command for human reproduction.
    """
    print(f"[{gate}] FAIL", file=sys.stderr)
    print(f"  case_id:  {case_id}", file=sys.stderr)
    if rule:
        print(f"  rule:     {rule}", file=sys.stderr)
    print(f"  runtime:  {runtime}", file=sys.stderr)
    print(f"  expected: {expected}", file=sys.stderr)
    print(f"  actual:   {actual}", file=sys.stderr)
    print(f"  command:  {command}", file=sys.stderr)
    if note:
        print(f"  note:     {note}", file=sys.stderr)
    print(file=sys.stderr)


# --------------------------------------------------------------------------
# Gate 1: generic-cbor-profile
# --------------------------------------------------------------------------

def run_generic_cbor_profile_gate() -> bool:
    """Drive `gen_canonical_cbor_profile.py` in verify-only mode (no
    `--write`) — it shells into the Rust adapter
    (`cargo run -q --example canonical_cbor_emit -- --manifest …`),
    diffs every case against the committed `expected_output_hex` /
    `expected_reject_code`, and exits non-zero on disagreement.

    Forward-compatibility cases (`forward_compatibility: true` in the
    manifest) are handled by the orchestrator: it accepts
    `result=unimplemented` from the Rust oracle. A runtime that has
    implemented the rule emits the rule-correct output and the
    orchestrator falls through to the same byte / reject-code check.

    Structured failure output from the orchestrator already names case_id,
    expected, actual, and the reproducer command. This wrapper preserves
    that block under the gate banner and adds the runtime tag.
    """
    _print_gate_header("generic-cbor-profile")

    if not CANONICAL_CBOR_GENERATOR.is_file():
        print(
            f"[generic-cbor-profile] FAIL — generator missing at {CANONICAL_CBOR_GENERATOR}",
            file=sys.stderr,
        )
        return False

    command = [sys.executable, str(CANONICAL_CBOR_GENERATOR)]
    result = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode == 0:
        # The orchestrator already prints a concise pass line; just tag the gate.
        if result.stdout.strip():
            print(result.stdout.rstrip(), file=sys.stderr)
        _print_gate_pass(
            "generic-cbor-profile",
            "manifest.json cases agree with Rust oracle (integrity-cbor)",
        )
        return True

    # The orchestrator's own failure block already carries case_id /
    # expected / actual / reproducer command (see
    # `_generator/gen_canonical_cbor_profile.py`). Surface it under the
    # gate banner so the framing is uniform with the other gates.
    if result.stdout.strip():
        print(result.stdout.rstrip(), file=sys.stderr)
    if result.stderr.strip():
        print(result.stderr.rstrip(), file=sys.stderr)
    print(
        f"[generic-cbor-profile] FAIL — runtime=Rust integrity-cbor (oracle); "
        f"reproduce: (cd {ROOT}; python3 fixtures/vectors/_generator/gen_canonical_cbor_profile.py)",
        file=sys.stderr,
    )
    return False


# --------------------------------------------------------------------------
# Gate 2: signed-acts-projection
# --------------------------------------------------------------------------

def run_signed_acts_projection_gate() -> bool:
    """Preserves the pre-rename behavior byte-for-byte: regenerate the
    signature-export corpus into a temp tree, byte-compare against the
    committed corpus, then run the Python WOS verifier over the
    signed-acts positive and negative vectors and assert the
    cross-runtime 068 byte-identity invariant.
    """
    _print_gate_header("signed-acts-projection")
    runtime = "Python trellis-py (Signed-Act generator + verifier)"

    if not GENERATOR.is_file():
        _print_failure_block(
            gate="signed-acts-projection",
            case_id="<harness>",
            rule=None,
            runtime=runtime,
            expected="generator present",
            actual=f"missing at {GENERATOR}",
            command=f"ls {GENERATOR}",
        )
        return False

    try:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            run_generator(tmp)
            if not compare_generated_tree(tmp):
                _print_failure_block(
                    gate="signed-acts-projection",
                    case_id="<corpus byte-identity>",
                    rule=None,
                    runtime=runtime,
                    expected="generated tree matches committed corpus",
                    actual="bytes differ (see preceding diagnostics)",
                    command=(
                        f"(cd {ROOT} && "
                        f"python3 scripts/check_cross_runtime_parity.py)"
                    ),
                    note=(
                        "Python signature-export generator output diverged from "
                        "the committed signed-acts vectors. Either the generator "
                        "regressed or the corpus needs regeneration."
                    ),
                )
                return False
    except Exception as exc:  # noqa: BLE001
        _print_failure_block(
            gate="signed-acts-projection",
            case_id="<harness>",
            rule=None,
            runtime=runtime,
            expected="generator runs cleanly",
            actual=f"exception: {exc!r}",
            command=(
                f"(cd {ROOT} && "
                f"python3 scripts/check_cross_runtime_parity.py)"
            ),
        )
        return False

    try:
        check_python_verifier_vectors()
    except AssertionError as exc:
        _print_failure_block(
            gate="signed-acts-projection",
            case_id="<python-verifier-vector>",
            rule=None,
            runtime=runtime,
            expected="Python verifier verdict matches expected per-vector verdict",
            actual=str(exc),
            command=(
                f"(cd {ROOT}/trellis-py && "
                f"python3 -c 'from trellis_py import verify_wos; "
                f"print(verify_wos.verify_export_zip(open(VECTOR, \"rb\").read()))')"
            ),
            note="See assertion text for the offending fixture path.",
        )
        return False

    try:
        check_cross_runtime_manifest_byte_identity()
    except AssertionError as exc:
        _print_failure_block(
            gate="signed-acts-projection",
            case_id="<068-signed-acts-manifest.cbor cross-runtime>",
            rule="R1+R3+R4 (canonical CBOR, applied to signed-acts manifest)",
            runtime="Python trellis_py.verify_wos.encode_signed_acts_manifest_v1 vs "
                    "Rust trellis-export-writer (committed bytes)",
            expected="Python-derived 068 bytes byte-identical to committed Rust output",
            actual=str(exc),
            command=(
                f"(cd {ROOT} && "
                f"python3 scripts/check_cross_runtime_parity.py)"
            ),
            note="Drift here implies canonical-CBOR profile divergence between "
                 "trellis-py._cbor_canonical and integrity-cbor.",
        )
        return False

    _print_gate_pass(
        "signed-acts-projection",
        "generator bytes, Python verifier verdicts, and 068 cross-runtime byte-identity all match",
    )
    return True


# --------------------------------------------------------------------------
# Gate 3: seal-fence
# --------------------------------------------------------------------------

def run_seal_fence_gate() -> bool:
    """Preserves the pre-rename `check_cross_runtime_seal_fence_parity`
    behavior byte-for-byte: synthesize a seal-fence extension from each
    committed export fixture's archive members, exercise every Rust
    `SealFenceTamper` variant, and assert the Python verifier surfaces
    the expected finding kind for each tamper.
    """
    _print_gate_header("seal-fence")
    runtime = "Python trellis_py.verify_export.verify_seal_fence_extension vs " \
              "Rust integrity-verify::trellis::export::verify_seal_fence_extension"

    try:
        check_cross_runtime_seal_fence_parity()
    except AssertionError as exc:
        _print_failure_block(
            gate="seal-fence",
            case_id="<seal-fence tamper variant>",
            rule="seal-fence extension parity (Trellis Core §6.7 / export.rs:1153)",
            runtime=runtime,
            expected="Python finding kinds match Rust SealFenceTamper variants",
            actual=str(exc),
            command=(
                f"(cd {ROOT} && "
                f"python3 scripts/check_cross_runtime_parity.py)"
            ),
            note="Assertion text names the fixture and tamper variant that diverged.",
        )
        return False

    _print_gate_pass(
        "seal-fence",
        "Python verifier matches Rust SealFenceTamper coverage across every export fixture",
    )
    return True


# --------------------------------------------------------------------------
# Orchestrator
# --------------------------------------------------------------------------

def main() -> int:
    try:
        import cbor2  # noqa: F401
        import cryptography  # noqa: F401
    except ImportError:
        print(
            "Missing generator deps (cbor2, cryptography). Install with:\n"
            "  pip install -e ./trellis-py",
            file=sys.stderr,
        )
        return 2

    gates: list[tuple[str, callable]] = [
        ("generic-cbor-profile", run_generic_cbor_profile_gate),
        ("signed-acts-projection", run_signed_acts_projection_gate),
        ("seal-fence", run_seal_fence_gate),
    ]

    failures: list[str] = []
    for name, runner in gates:
        ok = runner()
        if not ok:
            failures.append(name)

    print(file=sys.stderr)
    if failures:
        print(
            f"cross-runtime parity: {len(failures)} gate(s) failed: {failures}",
            file=sys.stderr,
        )
        return 1

    print(
        "cross-runtime parity: all three gates pass "
        "(generic-cbor-profile, signed-acts-projection, seal-fence)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
