"""Lint test harness for check-specs.py fixture-coverage rules.

Each test invokes check-specs.py as a subprocess with TRELLIS_LINT_ROOT
pointing at a synthetic scenario under check-specs-fixtures/.  Tests assert
on exit code and stderr content.

This is the RED-phase foundation for Tasks 5–7, which implement the actual
coverage rules.  All three tests are expected to fail until Task 4 wires up
TRELLIS_LINT_ROOT in check-specs.py.
"""

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINT = ROOT / "scripts" / "check-specs.py"
FIX = Path(__file__).resolve().parent / "check-specs-fixtures"


def _load_check_specs_module():
    """Import check-specs.py as a module for direct helper-level tests.

    The hyphenated filename prevents a normal `import check_specs`, so we
    load via importlib. The module's ROOT defaults to the real repo when
    TRELLIS_LINT_ROOT is unset, which is what helper tests want.
    """
    spec = importlib.util.spec_from_file_location("check_specs", LINT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_lint(scenario: str) -> subprocess.CompletedProcess:
    return run_lint_root(FIX / scenario)


def run_lint_root(root: Path) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.pop("TRELLIS_SKIP_COVERAGE", None)
    env["TRELLIS_LINT_ROOT"] = str(root)
    return subprocess.run(
        [sys.executable, str(LINT)],
        env=env,
        capture_output=True,
        text=True,
    )


class TestCoverageLint(unittest.TestCase):
    def test_minimal_valid_scenario_passes(self):
        result = run_lint("minimal-valid")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_testable_row_without_vector_fails(self):
        result = run_lint("missing-coverage")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no vector covers", result.stderr.lower())

    def test_forbidden_generator_import_fails(self):
        result = run_lint("forbidden-import")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("forbidden import", result.stderr.lower())

    # I3 — relative imports in _generator/ must be rejected
    def test_relative_generator_import_fails(self):
        result = run_lint("forbidden-import")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relative imports forbidden", result.stderr.lower())

    # I4 — stdlib modules beyond the original six must be accepted
    def test_stdlib_base64_import_passes(self):
        result = run_lint("stdlib-base64")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    # C1 / M6 — invariant-gap: hash-prefixed and multi-value cells are parsed correctly
    def test_invariant_gap_fails(self):
        result = run_lint("invariant-gap")
        self.assertNotEqual(result.returncode, 0)
        # Invariants #1 and #4 (from '#1, #4' in TR-CORE-006) are uncovered;
        # invariant #5 (from '#5' in TR-CORE-005) is covered by the vector.
        self.assertIn("#1", result.stderr)
        self.assertIn("#4", result.stderr)
        # #5 must NOT appear as an uncovered invariant
        self.assertNotIn("invariant #5 has no", result.stderr)

    # F1 / M6 — declared-vs-derived invariant mismatch is a WARNING, not an error.
    # Matrix rows with Invariant=— make bidirectional enforcement incoherent;
    # invariants declaration is commentary-only per amended design.
    def test_declared_invariants_mismatch_warns(self):
        result = run_lint("declared-mismatch")
        self.assertEqual(result.returncode, 0, msg=f"stderr={result.stderr!r}")
        self.assertIn("warning:", result.stderr.lower())
        self.assertIn("declared invariants", result.stderr.lower())
        self.assertIn("commentary only", result.stderr.lower())


class TestManifestPathsLint(unittest.TestCase):
    """A/F7 — check_vector_manifest_paths verifies every [inputs]/[expected]
    string value resolves to a real file."""

    def test_missing_sibling_input_fails(self):
        # Manifest references input-authored-event.cbor that does not exist.
        result = run_lint("manifest-missing-sibling")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("input-authored-event.cbor", result.stderr)
        self.assertIn("does not exist", result.stderr.lower())

    def test_missing_keys_relative_fails(self):
        # Manifest references ../../_keys/issuer-xyz.cose_key which is absent.
        result = run_lint("manifest-missing-keys-ref")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("issuer-xyz.cose_key", result.stderr)

    def test_all_manifest_paths_resolve_passes(self):
        # Manifest references sibling + ../../_keys/ + ../../_inputs/ files, all present.
        result = run_lint("manifest-all-present")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_zip_sha256_is_not_treated_as_path(self):
        # Export manifest has a zip_sha256 hex digest in [expected]; it must NOT
        # be resolved as a path.
        result = run_lint("manifest-zip-sha256")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_boolean_in_expected_report_is_skipped(self):
        # [expected.report] has booleans like structure_verified = true — nested
        # non-string values must be ignored by the path-resolution check.
        result = run_lint("manifest-boolean-expected")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    # F1 — lists of path strings must be recursed into, not silently skipped.
    def test_list_of_paths_with_missing_element_fails(self):
        result = run_lint("manifest-list-missing-element")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing-payload.bin", result.stderr)
        self.assertIn("does not exist", result.stderr.lower())

    # F2 — absolute paths bypass the vector_dir sandbox and must be rejected.
    def test_absolute_path_is_rejected(self):
        result = run_lint("manifest-absolute-path")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("/etc/passwd", result.stderr)
        self.assertIn("absolute", result.stderr.lower())

    # F2 — empty-string paths resolve to vector_dir itself and must be rejected.
    def test_empty_path_is_rejected(self):
        result = run_lint("manifest-empty-path")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("empty", result.stderr.lower())


class TestPendingInvariantsAllowlist(unittest.TestCase):
    """F5 — fixtures/vectors/_pending-invariants.toml replaces
    TRELLIS_SKIP_COVERAGE=1 blanket bypass."""

    def test_skip_coverage_env_has_no_effect(self):
        # TRELLIS_SKIP_COVERAGE=1 must NOT silence an uncovered testable row.
        env = os.environ.copy()
        env["TRELLIS_SKIP_COVERAGE"] = "1"
        env["TRELLIS_LINT_ROOT"] = str(FIX / "missing-coverage")
        result = subprocess.run(
            [sys.executable, str(LINT)], env=env, capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no vector covers", result.stderr.lower())

    def test_tr_row_listed_pending_and_uncovered_passes(self):
        # pending_matrix_rows lists TR-CORE-001; no vector references it → OK.
        result = run_lint("allowlist-tr-pending-ok")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_tr_row_listed_pending_but_now_covered_fails(self):
        # pending_matrix_rows lists TR-CORE-001 but a vector covers it → must fail,
        # forcing cleanup of the allowlist.
        result = run_lint("allowlist-tr-listed-but-covered")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TR-CORE-001", result.stderr)
        self.assertIn("pending", result.stderr.lower())

    def test_tr_row_uncovered_and_not_listed_fails(self):
        # TR-CORE-001 uncovered and not in pending_matrix_rows → must fail.
        result = run_lint("allowlist-tr-uncovered-not-listed")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no vector covers", result.stderr.lower())
        self.assertIn("TR-CORE-001", result.stderr)

    # F8 — allowlist entry that isn't a real matrix row ID must error out.
    def test_tr_row_unknown_id_fails(self):
        result = run_lint("allowlist-tr-unknown-id")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TR-CORE-999", result.stderr)
        self.assertIn("not a matrix row", result.stderr.lower())

    # F8 — non-integer in pending_invariants must produce a clean lint error,
    # not a raw Python ValueError traceback.
    def test_invariant_bad_type_reports_clean_error(self):
        result = run_lint("allowlist-inv-bad-type")
        self.assertNotEqual(result.returncode, 0)
        # Must NOT expose a Python traceback.
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("ValueError", result.stderr)
        # Must reference the offending file and offending value.
        self.assertIn("_pending-invariants.toml", result.stderr)
        self.assertIn("three", result.stderr)

    def test_invariant_pending_and_uncovered_passes(self):
        # pending_invariants = [6]; no vector for invariant 6 → OK.
        result = run_lint("allowlist-inv-pending-ok")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_invariant_listed_but_now_covered_fails(self):
        # pending_invariants = [6] but a vector covers TR-CORE tied to inv 6 → fail.
        result = run_lint("allowlist-inv-listed-but-covered")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invariant", result.stderr.lower())
        self.assertIn("6", result.stderr)

    def test_missing_allowlist_file_behaves_as_empty(self):
        # Scenario has uncovered rows and no _pending-invariants.toml → must
        # fail as if the allowlist were empty.
        result = run_lint("allowlist-absent-file")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no vector covers", result.stderr.lower())

    def test_malformed_allowlist_toml_errors(self):
        # A malformed _pending-invariants.toml must yield a clear lint error,
        # not a Python traceback or silent skip.
        result = run_lint("allowlist-malformed-toml")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("_pending-invariants.toml", result.stderr)


class TestVectorLifecycleFields(unittest.TestCase):
    """F6 — manifest-level status / deprecated_at lifecycle fields.

    status is optional and defaults to 'active'. When status = 'deprecated',
    deprecated_at is required and must be a 'YYYY-MM-DD' ISO-8601 date string.
    Deprecated vectors are excluded from byte-testable coverage audits.
    """

    def test_status_active_without_deprecated_at_passes(self):
        result = run_lint("lifecycle-status-active")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_deprecated_vector_does_not_count_toward_coverage(self):
        # The only vector is deprecated and covers TR-CORE-001..015; the audit
        # must treat those rows as uncovered.
        result = run_lint("lifecycle-status-deprecated-excluded")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no vector covers", result.stderr.lower())
        self.assertIn("TR-CORE-001", result.stderr)

    def test_deprecated_without_deprecated_at_fails(self):
        result = run_lint("lifecycle-deprecated-missing-date")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("deprecated_at", result.stderr)

    def test_deprecated_with_malformed_date_fails(self):
        result = run_lint("lifecycle-deprecated-malformed-date")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("deprecated_at", result.stderr)
        self.assertIn("yesterday", result.stderr)

    def test_unknown_status_value_fails(self):
        result = run_lint("lifecycle-status-unknown")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("status", result.stderr.lower())
        self.assertIn("foo", result.stderr)


class TestVectorNaming(unittest.TestCase):
    """R1 — fixture-naming guard: every child of fixtures/vectors/<op>/ MUST
    match `^NNN-slug$` where NNN is three digits and slug is dash-separated
    lowercase alphanumeric segments."""

    def test_valid_naming_passes(self):
        result = run_lint("naming-valid")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_missing_nnn_prefix_fails(self):
        # append/abc has no numeric prefix at all.
        result = run_lint("naming-missing-nnn")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("abc", result.stderr)
        self.assertIn("naming", result.stderr.lower())

    def test_no_dash_between_nnn_and_slug_fails(self):
        # append/001abc is missing the dash.
        result = run_lint("naming-no-dash")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("001abc", result.stderr)

    def test_uppercase_slug_fails(self):
        # append/001-Cap-Case has uppercase letters in the slug.
        result = run_lint("naming-uppercase-slug")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cap-Case", result.stderr)

    def test_trailing_dash_fails(self):
        # append/001-foo- ends with a dash.
        result = run_lint("naming-trailing-dash")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("001-foo-", result.stderr)

    def test_two_digit_nnn_fails(self):
        # append/01-foo has only two digits.
        result = run_lint("naming-short-nnn")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("01-foo", result.stderr)

    def test_numeric_only_slug_passes(self):
        # append/002-123 is numeric-only-slug; digits are valid in [a-z0-9].
        result = run_lint("naming-numeric-slug")
        self.assertEqual(result.returncode, 0, msg=result.stderr)


class TestVectorManifestIdentityAndCoverageIds(unittest.TestCase):
    """Manifest identity and coverage claims must match the matrix/directory."""

    def test_unknown_tr_op_coverage_id_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            scenario = Path(tmp) / "tr-op-unknown-id"
            shutil.copytree(FIX / "tr-op-covered", scenario)
            manifest = (
                scenario
                / "fixtures/vectors/projection/001-example/manifest.toml"
            )
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    "TR-OP-042", "TR-OP-999"
                ),
                encoding="utf-8",
            )

            result = run_lint_root(scenario)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("coverage.tr_op", result.stderr)
        self.assertIn("TR-OP-999", result.stderr)
        self.assertIn("not a known TR-OP", result.stderr)

    def test_manifest_op_must_match_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            scenario = Path(tmp) / "projection-drill-misplaced-op"
            shutil.copytree(FIX / "projection-drill-covered", scenario)
            source = scenario / "fixtures/vectors/projection/001-example"
            target = scenario / "fixtures/vectors/append/001-example"
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source), str(target))

            result = run_lint_root(scenario)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest op", result.stderr)
        self.assertIn("directory op='append'", result.stderr)
        self.assertIn("no projection rebuild drill covers", result.stderr.lower())


class TestPendingProjectionDrillsLoader(unittest.TestCase):
    """R3 — _pending-projection-drills.toml loader. File parallels
    _pending-invariants.toml but covers projection-rebuild-drill rows. No
    rule consumes the loader yet (R7 lands it); these tests pin the
    load-side behavior only."""

    @classmethod
    def setUpClass(cls):
        cls.cs = _load_check_specs_module()

    def test_missing_file_returns_empty_set(self):
        # Point the loader at a path that does not exist; no error, empty set.
        errors: list[str] = []
        result = self.cs.load_pending_projection_drills(
            errors,
            path=Path("/tmp/does-not-exist-projection-drills.toml"),
        )
        self.assertEqual(result, set())
        self.assertEqual(errors, [])

    def test_malformed_toml_errors(self):
        tmp = Path(os.environ.get("TMPDIR", "/tmp")) / "trellis-pd-bad.toml"
        tmp.write_text("pending_matrix_rows = [not valid\n", encoding="utf-8")
        errors: list[str] = []
        self.cs.load_pending_projection_drills(errors, path=tmp)
        self.assertTrue(any("malformed TOML" in e for e in errors), errors)
        tmp.unlink()

    def test_valid_rows_load(self):
        tmp = Path(os.environ.get("TMPDIR", "/tmp")) / "trellis-pd-ok.toml"
        tmp.write_text(
            'pending_matrix_rows = ["TR-OP-008", "TR-OP-042"]\n',
            encoding="utf-8",
        )
        errors: list[str] = []
        result = self.cs.load_pending_projection_drills(errors, path=tmp)
        self.assertEqual(result, {"TR-OP-008", "TR-OP-042"})
        self.assertEqual(errors, [])
        tmp.unlink()


class TestSharedPlumbing(unittest.TestCase):
    """Commit-1 helpers: op dispatch widening, Companion section resolution,
    split matrix-id helpers, generic allowlist loader, Core §6.7 event-type
    registry, Companion CDDL-block extraction.

    These helpers are dead code wired in commit 1; they do not fire any rule
    in main() until commit 2+. Tests exercise them directly against the real
    repo specs.
    """

    @classmethod
    def setUpClass(cls):
        cls.cs = _load_check_specs_module()

    def test_vector_ops_includes_projection_and_shred(self):
        # Op dispatch must accept the two Wave-1 ops alongside the existing four.
        self.assertIn("projection", self.cs.VECTOR_OPS)
        self.assertIn("shred", self.cs.VECTOR_OPS)
        for op in ("append", "verify", "export", "tamper"):
            self.assertIn(op, self.cs.VECTOR_OPS)

    def test_companion_headings_extracts_part_I_section_numbers(self):
        # Companion §§5..29 are the top-level `## N. Title` headings today
        # (Part I starts at §5 because Part 0 consumes §§1..4 as front-matter
        # sections without ## numbering of their own).
        headings = self.cs.companion_headings()
        self.assertIn(5, headings)
        self.assertIn(29, headings)
        self.assertEqual(headings[10], "Posture-Transition Auditability")
        self.assertEqual(headings[19], "Delegated-Compute Honesty")
        # ≥25 sections expected; guard against regex breakage.
        self.assertGreaterEqual(len(headings), 25)

    def test_tr_op_ids_splits_matrix_ids(self):
        op_ids = self.cs.tr_op_ids()
        # Every id must be a TR-OP-NNN string; none may be TR-CORE-*.
        self.assertTrue(op_ids, "expected ≥1 TR-OP-* row in the matrix")
        for row_id in op_ids:
            self.assertTrue(row_id.startswith("TR-OP-"), row_id)

    def test_tr_core_ids_splits_matrix_ids(self):
        core_ids = self.cs.tr_core_ids()
        self.assertTrue(core_ids)
        for row_id in core_ids:
            self.assertTrue(row_id.startswith("TR-CORE-"), row_id)

    def test_derived_companion_sections_for_tr_op_resolves_anchor(self):
        # Pick a TR-OP row that has a prose anchor in the Companion and check
        # the derived section number lines up with its containing `## N.` heading.
        op_ids = self.cs.tr_op_ids()
        self.assertIn("TR-OP-042", op_ids)
        derived = self.cs.derived_companion_sections_for_tr_op(["TR-OP-042"])
        # TR-OP-042 anchors under Companion §A.5.1 → Appendix A → grandparent
        # `## A. Appendix A` or under the nearest `## N.` heading above it;
        # what we require is that a non-empty set is returned for a known row.
        self.assertTrue(derived, f"expected a section for TR-OP-042, got {derived}")
        # The Traceability Anchors appendix (§C) lists every TR-OP row by ID.
        # The appendix-strip MUST remove it before scanning, otherwise every
        # row would resolve to §C and drown out its real prose anchor.
        self.assertNotIn("§C", derived)

    def test_derived_companion_sections_tolerates_drifted_appendix_title(self):
        # If the Traceability Anchors appendix title drifts (e.g. someone
        # renames it to "Traceability Anchor Index"), the appendix-strip must
        # still fire — otherwise every declared companion_sections set would
        # spuriously include §C. We match on the `## <letter>. Traceability`
        # prefix, so any title that keeps that prefix is fine.
        fake_companion = (
            "# Trellis Operational Companion\n\n"
            "## 10. Posture-Transition Auditability\n\n"
            "Row TR-OP-042 lives here in the real prose.\n\n"
            "## C. Traceability Anchor Index\n\n"
            "- TR-OP-042 → §10\n"
        )
        derived = self.cs.derived_companion_sections_for_tr_op(
            ["TR-OP-042"], text=fake_companion
        )
        self.assertEqual(derived, {"§10"})
        self.assertNotIn("§C", derived)

    def test_load_allowlist_with_int_field_parses_list(self):
        cs = self.cs
        tmp = Path(os.environ.get("TMPDIR", "/tmp")) / "trellis-load-allowlist-int.toml"
        tmp.write_text("pending_invariants = [3, 6, 7]\n", encoding="utf-8")
        errors: list[str] = []
        data = cs.load_allowlist(tmp, errors, int_field="pending_invariants")
        self.assertEqual(data["pending_invariants"], {3, 6, 7})
        self.assertEqual(errors, [])
        tmp.unlink()

    def test_load_allowlist_with_str_field_parses_list(self):
        cs = self.cs
        tmp = Path(os.environ.get("TMPDIR", "/tmp")) / "trellis-load-allowlist-str.toml"
        tmp.write_text('pending_matrix_rows = ["TR-CORE-001"]\n', encoding="utf-8")
        errors: list[str] = []
        data = cs.load_allowlist(tmp, errors, str_field="pending_matrix_rows")
        self.assertEqual(data["pending_matrix_rows"], {"TR-CORE-001"})
        self.assertEqual(errors, [])
        tmp.unlink()

    def test_load_allowlist_missing_file_returns_empty_without_errors(self):
        cs = self.cs
        missing = Path("/tmp/does-not-exist-check-specs-allowlist.toml")
        errors: list[str] = []
        data = cs.load_allowlist(missing, errors, int_field="pending_invariants")
        self.assertEqual(data["pending_invariants"], set())
        self.assertEqual(errors, [])

    def test_load_allowlist_malformed_toml_reports_error(self):
        cs = self.cs
        tmp = Path(os.environ.get("TMPDIR", "/tmp")) / "trellis-load-allowlist-bad.toml"
        tmp.write_text("pending_invariants = [not valid toml\n", encoding="utf-8")
        errors: list[str] = []
        cs.load_allowlist(tmp, errors, int_field="pending_invariants")
        self.assertTrue(any("malformed TOML" in e for e in errors), errors)
        tmp.unlink()

    def test_load_allowlist_rejects_wrong_element_type(self):
        cs = self.cs
        tmp = Path(os.environ.get("TMPDIR", "/tmp")) / "trellis-load-allowlist-bad-type.toml"
        tmp.write_text('pending_invariants = ["three"]\n', encoding="utf-8")
        errors: list[str] = []
        cs.load_allowlist(tmp, errors, int_field="pending_invariants")
        self.assertTrue(any("not an integer" in e for e in errors), errors)
        tmp.unlink()

    def test_core_event_type_registry_returns_registered_identifiers(self):
        registry = self.cs.core_event_type_registry()
        # Per Core §6.7 table — the two reject-if-unknown-at-version Phase-1
        # transition identifiers MUST both be present.
        self.assertIn("trellis.custody-model-transition.v1", registry)
        self.assertIn("trellis.disclosure-profile-transition.v1", registry)
        # Each entry exposes container / phase / purpose fields.
        entry = registry["trellis.custody-model-transition.v1"]
        self.assertEqual(entry["container"], "EventPayload.extensions")
        self.assertEqual(entry["phase"], "1")
        self.assertIn("Custody-model", entry["purpose"])

    def test_companion_cddl_blocks_extracts_named_rules(self):
        blocks = self.cs.companion_cddl_blocks()
        # Keys are (appendix_id, rule_name) tuples.
        keys = set(blocks.keys())
        self.assertIn(("A.5", "Attestation"), keys)
        self.assertIn(("A.5.1", "CustodyModelTransitionPayload"), keys)
        self.assertIn(("A.5.2", "DisclosureProfileTransitionPayload"), keys)
        # Block text includes the declaration opener.
        custody = blocks[("A.5.1", "CustodyModelTransitionPayload")]
        self.assertIn("transition_id", custody)

    def test_event_type_registry_check_accepts_real_vectors(self):
        errors: list[str] = []
        self.cs.check_event_type_registry(errors)
        self.assertEqual(errors, [])

    def test_event_type_registry_check_rejects_unregistered_transition(self):
        original = self.cs.core_event_type_registry
        try:
            self.cs.core_event_type_registry = lambda: {}
            errors: list[str] = []
            self.cs.check_event_type_registry(errors)
        finally:
            self.cs.core_event_type_registry = original
        self.assertTrue(
            any("trellis.custody-model-transition.v1" in e for e in errors),
            errors,
        )

    def test_transition_cddl_cross_refs_accept_real_vectors(self):
        errors: list[str] = []
        self.cs.check_transition_cddl_cross_refs(errors)
        self.assertEqual(errors, [])

    def test_transition_cddl_cross_refs_reject_missing_block(self):
        original = self.cs.companion_cddl_blocks
        try:
            self.cs.companion_cddl_blocks = lambda: {}
            errors: list[str] = []
            self.cs.check_transition_cddl_cross_refs(errors)
        finally:
            self.cs.companion_cddl_blocks = original
        self.assertTrue(
            any("missing A.5.1 CDDL block" in e for e in errors),
            errors,
        )

    def test_row_with_dual_verification_respects_both_gates(self):
        # TR-OP-005 and TR-OP-006 carry BOTH `test-vector` and
        # `projection-rebuild-drill` in their Verification column, so they
        # must land in both the R5 (testable) and R7 (drill) id sets. This
        # pins the behavior so a future split of the two helpers can't
        # silently drop one side.
        testable = self.cs.testable_row_ids()
        drills = self.cs.projection_rebuild_drill_row_ids()
        for row_id in ("TR-OP-005", "TR-OP-006"):
            self.assertIn(row_id, testable, row_id)
            self.assertIn(row_id, drills, row_id)


class TestProjectionShredOpDispatch(unittest.TestCase):
    """R4 — projection/shred op walker. vector_manifests() must enumerate
    every manifest under fixtures/vectors/projection/ and fixtures/vectors/shred/
    in the real repo, and the coverage rules must honor their `coverage.tr_op`
    claims."""

    @classmethod
    def setUpClass(cls):
        cls.cs = _load_check_specs_module()

    def test_vector_manifests_includes_projection_and_shred(self):
        # Real-repo walk — confirm projection/001-* and shred/001-* manifests
        # land in the list once op dispatch is wired.
        manifests = self.cs.vector_manifests()
        ops = {m[1].get("op") for m in manifests}
        self.assertIn("projection", ops)
        self.assertIn("shred", ops)

    def test_tr_op_coverage_gate_respects_verification_column(self):
        # TR-OP-001 has Verification=projection-rebuild-drill (not test-vector),
        # so it must NOT appear in the testable set even though the production
        # projection manifest claims it in coverage.tr_op.
        testable = self.cs.testable_row_ids()
        self.assertNotIn("TR-OP-001", testable)
        self.assertNotIn("TR-OP-002", testable)

    def test_projection_manifest_walked_scenario_passes(self):
        # The synthetic scenario has a projection manifest whose
        # coverage.tr_op covers the only test-vector TR-OP row in the matrix.
        result = run_lint("tr-op-covered")
        self.assertEqual(result.returncode, 0, msg=result.stderr)


class TestTrOpCoverage(unittest.TestCase):
    """R5 — check_tr_op_coverage mirrors check_vector_coverage for
    `TR-OP-*` rows with `Verification=test-vector`. Coverage is satisfied
    when any manifest lists the row in `coverage.tr_op`; pending entries
    may sit in _pending-invariants.toml's `pending_matrix_rows`."""

    def test_tr_op_uncovered_not_listed_fails(self):
        result = run_lint("tr-op-uncovered-not-listed")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TR-OP-042", result.stderr)
        self.assertIn("no vector covers", result.stderr.lower())

    def test_tr_op_covered_passes(self):
        result = run_lint("tr-op-covered")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_tr_op_listed_but_covered_fails(self):
        # TR-OP-042 is covered AND still in pending_matrix_rows → must fail,
        # forcing cleanup.
        result = run_lint("tr-op-listed-but-covered")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TR-OP-042", result.stderr)
        self.assertIn("pending", result.stderr.lower())

    def test_tr_op_invariant_listed_but_covered_fails(self):
        # Invariant coverage must count coverage.tr_op, not only
        # coverage.tr_core, or a covered operational invariant can remain in
        # pending_invariants forever.
        result = run_lint("tr-op-invariant-listed-but-covered")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invariant #14", result.stderr)
        self.assertIn("pending_invariants", result.stderr)


class TestProjectionRebuildDrillCoverage(unittest.TestCase):
    """R7 — TR-OP rows with Verification=projection-rebuild-drill are
    covered by projection/shred manifests listing the row in coverage.tr_op,
    with _pending-projection-drills.toml as the narrow escape hatch."""

    def test_projection_drill_uncovered_not_listed_fails(self):
        result = run_lint("projection-drill-uncovered-not-listed")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TR-OP-042", result.stderr)
        self.assertIn("projection rebuild drill", result.stderr.lower())

    def test_projection_drill_covered_passes(self):
        result = run_lint("projection-drill-covered")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_projection_drill_pending_ok_passes(self):
        result = run_lint("projection-drill-pending-ok")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_projection_drill_listed_but_covered_fails(self):
        result = run_lint("projection-drill-listed-but-covered")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TR-OP-042", result.stderr)
        self.assertIn("_pending-projection-drills.toml", result.stderr)


class TestCompanionSectionsDeclaredCoverage(unittest.TestCase):
    """R5 — when a manifest declares `companion_sections`, it MUST equal the
    set derived from its `coverage.tr_op` rows via
    derived_companion_sections_for_tr_op()."""

    def test_companion_sections_declared_match_passes(self):
        result = run_lint("companion-sections-declared-match")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_companion_sections_declared_mismatch_fails(self):
        result = run_lint("companion-sections-declared-mismatch")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("companion_sections", result.stderr)


class TestCoveragePrefixDiscipline(unittest.TestCase):
    """R8 — coverage.tr_core entries MUST start with TR-CORE-; coverage.tr_op
    entries MUST start with TR-OP-. Without this rule, a misfiled ID is
    silently dropped by the R4/R5 bucket audits."""

    def test_coverage_prefix_mismatch_fails(self):
        result = run_lint("coverage-prefix-mismatch")
        self.assertNotEqual(result.returncode, 0)
        # Both mis-prefixed IDs must be named in the diagnostic, each tied
        # to its (wrong) bucket.
        self.assertIn("coverage.tr_core entry 'TR-OP-042'", result.stderr)
        self.assertIn("coverage.tr_op entry 'TR-CORE-020'", result.stderr)


class TestSpecCrossRefRows(unittest.TestCase):
    """R6 — matrix rows with Verification=spec-cross-ref must cite resolvable
    `Core §N` / `Companion §N` headings in Requirement/Rationale/Notes. A
    non-resolving cite is a hard error; a missing cite is a warning (to keep
    the current uncited rows tolerable while flagging the gap)."""

    def test_spec_cross_ref_resolves_passes(self):
        result = run_lint("spec-cross-ref-resolves")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_spec_cross_ref_missing_section_fails(self):
        result = run_lint("spec-cross-ref-missing-section")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TR-CORE-001", result.stderr)
        self.assertIn("Core §99", result.stderr)
        self.assertIn("no matching heading", result.stderr.lower())

    def test_spec_cross_ref_missing_cite_warns(self):
        result = run_lint("spec-cross-ref-missing-cite")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("warning:", result.stderr.lower())
        self.assertIn("TR-CORE-001", result.stderr)
        self.assertIn("spec-cross-ref", result.stderr)

    def test_real_repo_spec_cross_ref_rows_cite_resolvable_sections(self):
        # Every matrix row with Verification=spec-cross-ref that DOES carry a
        # Core §N / Companion §N citation in Requirement/Rationale/Notes must
        # resolve to a real heading — protects against a §-number drifting in
        # the spec without the matrix catching up.
        cs = _load_check_specs_module()
        errors: list[str] = []
        warnings: list[str] = []
        cs.check_spec_cross_ref_rows(errors, warnings)
        # Warnings about uncited rows are tolerable (see test above); hard
        # errors about non-resolving cites are not.
        self.assertEqual(errors, [])


class TestModelCheckEvidence(unittest.TestCase):
    """R8 — matrix rows with Verification=model-check must either name an
    evidence artifact in thoughts/model-checks/evidence.toml (whose path
    resolves) or appear in _pending-model-checks.toml's pending_matrix_rows
    allowlist. Both at once is a drift error."""

    def test_evidence_present_passes(self):
        result = run_lint("model-check-evidence-present")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_evidence_missing_fails(self):
        result = run_lint("model-check-evidence-missing")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TR-CORE-001", result.stderr)
        self.assertIn("no model-check evidence", result.stderr.lower())

    def test_evidence_path_gone_fails(self):
        result = run_lint("model-check-evidence-path-gone")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TR-CORE-001", result.stderr)
        self.assertIn("evidence path", result.stderr.lower())
        self.assertIn("does not exist", result.stderr.lower())

    def test_pending_row_passes_without_evidence(self):
        result = run_lint("model-check-evidence-pending-ok")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_listed_but_covered_fails(self):
        result = run_lint("model-check-evidence-listed-but-covered")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("_pending-model-checks.toml", result.stderr)
        self.assertIn("TR-CORE-001", result.stderr)


class TestDeclarationDocs(unittest.TestCase):
    """R11 — O-4 declaration-doc Phase 1 static checks."""

    @classmethod
    def setUpClass(cls):
        cls.cs = _load_check_specs_module()

    def test_real_reference_declaration_passes(self):
        errors: list[str] = []
        self.cs.check_declaration_docs(errors)
        self.assertEqual(errors, [])

    def test_decide_action_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "declarations"
            shutil.copytree(ROOT / "fixtures/declarations/ssdi-intake-triage", root / "ssdi")
            declaration = root / "ssdi/declaration.md"
            declaration.write_text(
                declaration.read_text(encoding="utf-8").replace(
                    'authorized_actions      = ["read", "propose"]',
                    'authorized_actions      = ["read", "decide"]',
                ),
                encoding="utf-8",
            )
            errors: list[str] = []
            self.cs.check_declaration_docs(errors, root=root)
        self.assertTrue(any("non-Phase-1 values" in e for e in errors), errors)

    def test_time_bound_required_without_open_ended_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "declarations"
            shutil.copytree(ROOT / "fixtures/declarations/ssdi-intake-triage", root / "ssdi")
            declaration = root / "ssdi/declaration.md"
            declaration.write_text(
                declaration.read_text(encoding="utf-8").replace(
                    "time_bound              = 2027-01-01T00:00:00Z\n",
                    "",
                ),
                encoding="utf-8",
            )
            errors: list[str] = []
            self.cs.check_declaration_docs(errors, root=root)
        self.assertTrue(any("scope.time_bound is required" in e for e in errors), errors)

    def test_actor_discriminator_rule_must_match_literal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "declarations"
            shutil.copytree(ROOT / "fixtures/declarations/ssdi-intake-triage", root / "ssdi")
            declaration = root / "ssdi/declaration.md"
            declaration.write_text(
                declaration.read_text(encoding="utf-8").replace(
                    'actor_discriminator_rule        = "exactly_one_of(actor_human, actor_agent_under_delegation)"',
                    'actor_discriminator_rule        = "actor_human_or_agent"',
                ),
                encoding="utf-8",
            )
            errors: list[str] = []
            self.cs.check_declaration_docs(errors, root=root)
        self.assertTrue(any("actor_discriminator_rule" in e for e in errors), errors)

    def test_runtime_enclave_must_match_posture_stub(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "declarations"
            shutil.copytree(ROOT / "fixtures/declarations/ssdi-intake-triage", root / "ssdi")
            declaration = root / "ssdi/declaration.md"
            declaration.write_text(
                declaration.read_text(encoding="utf-8").replace(
                    'runtime_enclave  = "isolated_enclave"',
                    'runtime_enclave  = "provider_operated"',
                ),
                encoding="utf-8",
            )
            errors: list[str] = []
            self.cs.check_declaration_docs(errors, root=root)
        self.assertTrue(any("delegated_compute_exposure" in e for e in errors), errors)

    def test_audit_event_types_need_registry_stub(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "declarations"
            shutil.copytree(ROOT / "fixtures/declarations/ssdi-intake-triage", root / "ssdi")
            (root / "ssdi/event-registry.stub.md").unlink()
            errors: list[str] = []
            self.cs.check_declaration_docs(errors, root=root)
        self.assertTrue(any("event-registry.stub.md" in e for e in errors), errors)


class TestPendingModelChecksLoader(unittest.TestCase):
    """Loader-level tests for the third allowlist file (R8). Parallels the
    _pending-projection-drills.toml tests — missing file is not an error,
    malformed TOML is, typed values round-trip."""

    @classmethod
    def setUpClass(cls):
        cls.cs = _load_check_specs_module()

    def test_missing_file_returns_empty_set(self):
        errors: list[str] = []
        result = self.cs.load_pending_model_checks(
            errors,
            path=Path("/tmp/does-not-exist-model-checks.toml"),
        )
        self.assertEqual(result, set())
        self.assertEqual(errors, [])

    def test_malformed_toml_errors(self):
        tmp = Path(os.environ.get("TMPDIR", "/tmp")) / "trellis-mc-bad.toml"
        tmp.write_text("pending_matrix_rows = [not valid\n", encoding="utf-8")
        errors: list[str] = []
        self.cs.load_pending_model_checks(errors, path=tmp)
        self.assertTrue(any("malformed TOML" in e for e in errors), errors)
        tmp.unlink()

    def test_valid_rows_load(self):
        tmp = Path(os.environ.get("TMPDIR", "/tmp")) / "trellis-mc-ok.toml"
        tmp.write_text(
            'pending_matrix_rows = ["TR-CORE-020", "TR-CORE-050"]\n',
            encoding="utf-8",
        )
        errors: list[str] = []
        result = self.cs.load_pending_model_checks(errors, path=tmp)
        self.assertEqual(result, {"TR-CORE-020", "TR-CORE-050"})
        self.assertEqual(errors, [])
        tmp.unlink()


class TestGeneratorLibAllowlist(unittest.TestCase):
    """check_generator_imports permits `_lib` imports iff
    fixtures/vectors/_generator/_lib/ exists; otherwise the existing
    allowlist applies unchanged. Exercised against a throwaway synthetic
    root so the real corpus is not mutated."""

    @classmethod
    def setUpClass(cls):
        cls.cs = _load_check_specs_module()

    def _build_root(self, *, with_lib: bool, gen_source: str) -> Path:
        root = Path(tempfile.mkdtemp(prefix="trellis-gen-lib-"))
        gen_dir = root / "fixtures" / "vectors" / "_generator"
        gen_dir.mkdir(parents=True)
        (gen_dir / "gen_thing.py").write_text(gen_source, encoding="utf-8")
        if with_lib:
            lib_dir = gen_dir / "_lib"
            lib_dir.mkdir()
            (lib_dir / "__init__.py").write_text("", encoding="utf-8")
            (lib_dir / "byte_utils.py").write_text(
                "CONSTANT = 1\n", encoding="utf-8",
            )
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        return root

    def _run_only_import_check(self, root: Path) -> list[str]:
        # Monkey-patch module globals for the duration of this check.
        original_fixtures = self.cs.FIXTURES
        original_root = self.cs.ROOT
        try:
            self.cs.ROOT = root
            self.cs.FIXTURES = root / "fixtures" / "vectors"
            errors: list[str] = []
            self.cs.check_generator_imports(errors)
            return errors
        finally:
            self.cs.FIXTURES = original_fixtures
            self.cs.ROOT = original_root

    def test_lib_import_is_allowed_when_lib_present(self):
        source = "from _lib.byte_utils import CONSTANT\n"
        errors = self._run_only_import_check(
            self._build_root(with_lib=True, gen_source=source)
        )
        self.assertEqual(errors, [])

    def test_lib_import_is_forbidden_when_lib_absent(self):
        source = "from _lib.byte_utils import CONSTANT\n"
        errors = self._run_only_import_check(
            self._build_root(with_lib=False, gen_source=source)
        )
        self.assertTrue(errors)
        self.assertIn("_lib", errors[0])
        self.assertIn("forbidden", errors[0].lower())

    def test_other_forbidden_imports_still_rejected(self):
        source = "import requests\n"
        errors = self._run_only_import_check(
            self._build_root(with_lib=True, gen_source=source)
        )
        self.assertTrue(errors)
        self.assertIn("requests", errors[0])


class TestVerifyReportConsistency(unittest.TestCase):
    """R12 — verify manifests whose description tokens (`fatal` / `localizable`)
    contradict the declared `[expected.report]` booleans are rejected.

    Uses the `manifests` test hook on check_verify_report_consistency so each
    scenario is a single synthetic (path, dict) tuple — no TRELLIS_LINT_ROOT
    tree required.
    """

    @classmethod
    def setUpClass(cls):
        cls.cs = _load_check_specs_module()

    def _run(self, manifest: dict) -> list[str]:
        errors: list[str] = []
        self.cs.check_verify_report_consistency(
            errors,
            manifests=[(Path("verify/xxx-test/manifest.toml"), manifest)],
        )
        return errors

    def test_non_verify_op_is_skipped(self):
        # Append manifests are not R12's concern even if they mention "fatal".
        errors = self._run({
            "op": "append",
            "description": "Fatal failure during something.",
        })
        self.assertEqual(errors, [])

    def test_happy_path_no_tokens_passes(self):
        errors = self._run({
            "op": "verify",
            "description": "Happy-path verification.",
            "expected": {"report": {
                "structure_verified": True,
                "integrity_verified": True,
                "readability_verified": True,
            }},
        })
        self.assertEqual(errors, [])

    def test_fatal_with_all_false_passes(self):
        errors = self._run({
            "op": "verify",
            "description": "Negative: step 2.c fatal failure.",
            "expected": {"report": {
                "structure_verified": False,
                "integrity_verified": False,
                "readability_verified": False,
            }},
        })
        self.assertEqual(errors, [])

    def test_fatal_with_structure_true_fails(self):
        errors = self._run({
            "op": "verify",
            "description": "Negative: step 2.c fatal failure.",
            "expected": {"report": {
                "structure_verified": True,
                "integrity_verified": False,
                "readability_verified": False,
            }},
        })
        self.assertTrue(errors)
        self.assertIn("fatal failure", errors[0])

    def test_localizable_with_structure_true_integrity_false_passes(self):
        errors = self._run({
            "op": "verify",
            "description": "Negative: step 5.c localizable failure.",
            "expected": {"report": {
                "structure_verified": True,
                "integrity_verified": False,
                "readability_verified": True,
            }},
        })
        self.assertEqual(errors, [])

    def test_localizable_with_integrity_true_fails(self):
        errors = self._run({
            "op": "verify",
            "description": "Negative: step 5.c localizable failure.",
            "expected": {"report": {
                "structure_verified": True,
                "integrity_verified": True,
                "readability_verified": True,
            }},
        })
        self.assertTrue(errors)
        self.assertIn("localizable failure", errors[0])

    def test_localizable_with_structure_false_fails(self):
        errors = self._run({
            "op": "verify",
            "description": "Negative: step 7.b localizable failure.",
            "expected": {"report": {
                "structure_verified": False,
                "integrity_verified": False,
                "readability_verified": False,
            }},
        })
        self.assertTrue(errors)
        self.assertIn("localizable failure", errors[0])

    def test_both_tokens_fails(self):
        errors = self._run({
            "op": "verify",
            "description": "This is a fatal and localizable failure.",
            "expected": {"report": {
                "structure_verified": False,
                "integrity_verified": False,
                "readability_verified": False,
            }},
        })
        self.assertTrue(errors)
        self.assertIn("both 'fatal' and 'localizable'", errors[0])

    def test_fatal_without_expected_report_fails(self):
        errors = self._run({
            "op": "verify",
            "description": "Negative: step 2.a fatal failure.",
        })
        self.assertTrue(errors)
        self.assertIn("[expected.report]", errors[0])

    def test_localizable_without_expected_report_fails(self):
        errors = self._run({
            "op": "verify",
            "description": "Negative: step 5.c localizable failure.",
        })
        self.assertTrue(errors)
        self.assertIn("[expected.report]", errors[0])
        self.assertIn("localizable", errors[0])

    def test_real_corpus_is_clean(self):
        # Guard against regressions in the committed verify/* vectors: the
        # real fixtures MUST pass R12 so the lint stays green.
        errors: list[str] = []
        self.cs.check_verify_report_consistency(errors)
        self.assertEqual(errors, [], msg=f"R12 found errors: {errors}")




class TestDeclarationSignatureStructural(unittest.TestCase):
    """R14 — O-4 declaration `[signature]` field structural validation
    (no crypto). The reference declaration is a passing baseline; mutate
    individual signature-block fields to confirm each fail-loud branch.
    """

    @classmethod
    def setUpClass(cls):
        cls.cs = _load_check_specs_module()

    def _mutate_and_run(self, replacement: tuple[str, str]) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "declarations"
            shutil.copytree(
                ROOT / "fixtures/declarations/ssdi-intake-triage",
                root / "ssdi",
            )
            declaration = root / "ssdi/declaration.md"
            declaration.write_text(
                declaration.read_text(encoding="utf-8").replace(
                    replacement[0], replacement[1]
                ),
                encoding="utf-8",
            )
            errors: list[str] = []
            self.cs.check_declaration_docs(errors, root=root)
        return errors

    def test_unknown_alg_is_rejected(self):
        errors = self._mutate_and_run((
            'alg            = "EdDSA"',
            'alg            = "RS256"',
        ))
        self.assertTrue(any("alg" in e and "Phase-1" in e for e in errors), errors)

    def test_empty_signer_kid_is_rejected(self):
        errors = self._mutate_and_run((
            'signer_kid     = "urn:example:operator/ssa-example-adjudication-unit#key-2026-05"',
            'signer_kid     = ""',
        ))
        self.assertTrue(any("signer_kid" in e for e in errors), errors)

    def test_empty_cose_b64_is_rejected(self):
        errors = self._mutate_and_run((
            'cose_sign1_b64 = "AAAA-placeholder-signature-for-reference-purposes-only-AAAA"',
            'cose_sign1_b64 = ""',
        ))
        self.assertTrue(any("cose_sign1_b64" in e for e in errors), errors)

    def test_non_b64_cose_value_is_rejected(self):
        errors = self._mutate_and_run((
            'cose_sign1_b64 = "AAAA-placeholder-signature-for-reference-purposes-only-AAAA"',
            'cose_sign1_b64 = "not base64 has spaces!"',
        ))
        self.assertTrue(
            any("base64 alphabet" in e for e in errors),
            errors,
        )


class TestDeclarationSupersedesAcyclic(unittest.TestCase):
    """R15 — declaration `supersedes` chains MUST be acyclic and
    resolvable. The reference corpus has one root declaration with no
    `supersedes`; tests build synthetic multi-doc corpora to exercise
    cycles and dangling refs.
    """

    @classmethod
    def setUpClass(cls):
        cls.cs = _load_check_specs_module()

    def _scaffold(self, tmp: Path, decls: list[tuple[str, str | None]]) -> Path:
        """Create N synthetic declaration.md files with given (id, supersedes).

        Each declaration is a minimal-frontmatter stub — the supersedes
        check parses frontmatter and ignores fields it does not need.
        """
        root = tmp / "declarations"
        root.mkdir(parents=True)
        for i, (decl_id, supersedes) in enumerate(decls):
            d = root / f"slug-{i}"
            d.mkdir()
            lines = [
                "---",
                f'declaration_id          = "{decl_id}"',
            ]
            if supersedes is not None:
                lines.append(f'supersedes              = "{supersedes}"')
            lines.append("---")
            lines.append("")
            lines.append("# stub")
            (d / "declaration.md").write_text("\n".join(lines), encoding="utf-8")
        return root

    def test_real_reference_corpus_has_no_cycles(self):
        errors: list[str] = []
        self.cs.check_declaration_supersedes_acyclic(errors)
        self.assertEqual(errors, [])

    def test_simple_chain_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._scaffold(Path(tmp), [
                ("urn:test:v1", None),
                ("urn:test:v2", "urn:test:v1"),
                ("urn:test:v3", "urn:test:v2"),
            ])
            errors: list[str] = []
            self.cs.check_declaration_supersedes_acyclic(errors, root=root)
        self.assertEqual(errors, [])

    def test_two_node_cycle_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._scaffold(Path(tmp), [
                ("urn:test:a", "urn:test:b"),
                ("urn:test:b", "urn:test:a"),
            ])
            errors: list[str] = []
            self.cs.check_declaration_supersedes_acyclic(errors, root=root)
        self.assertTrue(
            any("cycle" in e.lower() for e in errors),
            errors,
        )

    def test_three_node_cycle_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._scaffold(Path(tmp), [
                ("urn:test:a", "urn:test:b"),
                ("urn:test:b", "urn:test:c"),
                ("urn:test:c", "urn:test:a"),
            ])
            errors: list[str] = []
            self.cs.check_declaration_supersedes_acyclic(errors, root=root)
        self.assertTrue(
            any("cycle" in e.lower() for e in errors),
            errors,
        )

    def test_dangling_supersedes_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._scaffold(Path(tmp), [
                ("urn:test:v1", "urn:nonexistent"),
            ])
            errors: list[str] = []
            self.cs.check_declaration_supersedes_acyclic(errors, root=root)
        self.assertTrue(
            any("does not resolve" in e for e in errors),
            errors,
        )

    def test_duplicate_declaration_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._scaffold(Path(tmp), [
                ("urn:test:dup", None),
                ("urn:test:dup", None),
            ])
            errors: list[str] = []
            self.cs.check_declaration_supersedes_acyclic(errors, root=root)
        self.assertTrue(
            any("MUST be unique" in e for e in errors),
            errors,
        )

    def test_self_loop_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._scaffold(Path(tmp), [
                ("urn:test:self", "urn:test:self"),
            ])
            errors: list[str] = []
            self.cs.check_declaration_supersedes_acyclic(errors, root=root)
        self.assertTrue(
            any("cycle" in e.lower() for e in errors),
            errors,
        )

    def test_empty_supersedes_treated_as_root(self):
        # Empty-string supersedes is the A.6 convention for "no predecessor".
        with tempfile.TemporaryDirectory() as tmp:
            root = self._scaffold(Path(tmp), [
                ("urn:test:root", ""),
            ])
            errors: list[str] = []
            self.cs.check_declaration_supersedes_acyclic(errors, root=root)
        # Empty-string supersedes is treated as None — should not flag dangling.
        self.assertEqual(errors, [], errors)


class TestDeclarationSupersedesTemporalInForce(unittest.TestCase):
    """R15 (temporal-in-force half) — for every supersedes edge
    `successor -> predecessor`, the predecessor MUST have been in force
    at `successor.effective_from`. A declaration's in-force window is
    `[effective_from, scope.time_bound)`; absent `scope.time_bound` is
    open-ended. Companion §A.6 rule 15 ("supersedes chain is acyclic
    AND each linked declaration was in force at the time of the
    successor's `effective_from`"). Wave 18 closes the temporal half
    that Wave 15 silently dropped.
    """

    @classmethod
    def setUpClass(cls):
        cls.cs = _load_check_specs_module()

    def _scaffold_temporal(
        self,
        tmp: Path,
        decls: list[tuple[str, str | None, str, str | None]],
    ) -> Path:
        """Create N declarations with (id, supersedes, effective_from, time_bound).

        `effective_from` is required (RFC 3339 UTC); `time_bound` is the
        nested `scope.time_bound` close-of-window, encoded by key absence
        when None per the A.6 nullable-field convention.
        """
        root = tmp / "declarations"
        root.mkdir(parents=True)
        for i, (decl_id, supersedes, eff_from, time_bound) in enumerate(decls):
            d = root / f"slug-{i}"
            d.mkdir()
            lines = [
                "---",
                f'declaration_id          = "{decl_id}"',
                f"effective_from          = {eff_from}",
            ]
            if supersedes is not None:
                lines.append(f'supersedes              = "{supersedes}"')
            if time_bound is not None:
                lines.append("[scope]")
                lines.append(f"time_bound              = {time_bound}")
            lines.append("---")
            lines.append("")
            lines.append("# stub")
            (d / "declaration.md").write_text(
                "\n".join(lines), encoding="utf-8"
            )
        return root

    def test_temporal_in_force_chain_passes(self):
        # v1 takes effect 2026-01-01 with no time_bound; v2 takes effect
        # 2026-06-01 (well within v1's open-ended window). In force at
        # successor's effective_from -> passes.
        with tempfile.TemporaryDirectory() as tmp:
            root = self._scaffold_temporal(Path(tmp), [
                ("urn:test:v1", None, "2026-01-01T00:00:00Z", None),
                ("urn:test:v2", "urn:test:v1", "2026-06-01T00:00:00Z", None),
            ])
            errors: list[str] = []
            self.cs.check_declaration_supersedes_acyclic(errors, root=root)
        self.assertEqual(errors, [], errors)

    def test_successor_effective_from_before_predecessor_is_rejected(self):
        # Out-of-order: v2's effective_from (2025-12-01) precedes v1's
        # effective_from (2026-01-01). Predecessor was not yet in force
        # at successor's effective_from -> reject.
        with tempfile.TemporaryDirectory() as tmp:
            root = self._scaffold_temporal(Path(tmp), [
                ("urn:test:v1", None, "2026-01-01T00:00:00Z", None),
                ("urn:test:v2", "urn:test:v1", "2025-12-01T00:00:00Z", None),
            ])
            errors: list[str] = []
            self.cs.check_declaration_supersedes_acyclic(errors, root=root)
        self.assertTrue(
            any("in force" in e.lower() for e in errors),
            errors,
        )

    def test_successor_effective_from_after_predecessor_time_bound_is_rejected(self):
        # v1 closes its window at 2026-05-01 (scope.time_bound). v2's
        # effective_from is 2026-06-01 — predecessor's window had
        # already closed -> reject.
        with tempfile.TemporaryDirectory() as tmp:
            root = self._scaffold_temporal(Path(tmp), [
                (
                    "urn:test:v1",
                    None,
                    "2026-01-01T00:00:00Z",
                    "2026-05-01T00:00:00Z",
                ),
                ("urn:test:v2", "urn:test:v1", "2026-06-01T00:00:00Z", None),
            ])
            errors: list[str] = []
            self.cs.check_declaration_supersedes_acyclic(errors, root=root)
        self.assertTrue(
            any("in force" in e.lower() for e in errors),
            errors,
        )

    def test_successor_effective_from_equals_predecessor_effective_from_passes(self):
        # Boundary: equal effective_from is in force per the half-open
        # window `[effective_from, time_bound)`. Documents the inclusive
        # lower bound so a future regression cannot flip the comparison.
        with tempfile.TemporaryDirectory() as tmp:
            root = self._scaffold_temporal(Path(tmp), [
                ("urn:test:v1", None, "2026-01-01T00:00:00Z", None),
                ("urn:test:v2", "urn:test:v1", "2026-01-01T00:00:00Z", None),
            ])
            errors: list[str] = []
            self.cs.check_declaration_supersedes_acyclic(errors, root=root)
        self.assertEqual(errors, [], errors)

    def test_successor_effective_from_equals_predecessor_time_bound_is_rejected(self):
        # Boundary: equal to the half-open upper bound is OUT of the
        # window per `[effective_from, time_bound)`. Documents the
        # exclusive upper bound.
        with tempfile.TemporaryDirectory() as tmp:
            root = self._scaffold_temporal(Path(tmp), [
                (
                    "urn:test:v1",
                    None,
                    "2026-01-01T00:00:00Z",
                    "2026-05-01T00:00:00Z",
                ),
                ("urn:test:v2", "urn:test:v1", "2026-05-01T00:00:00Z", None),
            ])
            errors: list[str] = []
            self.cs.check_declaration_supersedes_acyclic(errors, root=root)
        self.assertTrue(
            any("in force" in e.lower() for e in errors),
            errors,
        )

    def test_real_reference_declaration_temporal_violation(self):
        # Wave 15 review F3 follow-up: copy the real reference
        # declaration via shutil.copytree and mutate it to introduce a
        # temporal-in-force violation. Removes the synthetic-vs-real seam
        # so a runtime regression touching real-declaration parsing
        # cannot pass under synthetic stubs alone.
        #
        # Strategy: keep ssdi-intake-triage as the predecessor (real
        # bytes, real effective_from = 2026-05-01); add a synthetic
        # successor that supersedes it with an out-of-order
        # effective_from = 2026-04-01 (one month BEFORE the predecessor
        # took effect).
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "declarations"
            root.mkdir(parents=True)
            shutil.copytree(
                ROOT / "fixtures/declarations/ssdi-intake-triage",
                root / "ssdi-intake-triage",
            )
            successor_dir = root / "ssdi-intake-triage-v2"
            successor_dir.mkdir()
            (successor_dir / "declaration.md").write_text(
                """---
declaration_id          = "urn:example:ssdi-intake-triage/declaration/v2"
effective_from          = 2026-04-01T00:00:00Z
supersedes              = "urn:example:ssdi-intake-triage/declaration/v1"
---

# successor stub for temporal-violation test
""",
                encoding="utf-8",
            )
            errors: list[str] = []
            self.cs.check_declaration_supersedes_acyclic(errors, root=root)
        self.assertTrue(
            any("in force" in e.lower() for e in errors),
            errors,
        )



class TestVectorRenumberingWrapper(unittest.TestCase):
    """R16 — `scripts/check-specs.py` opt-in wrapper around
    `check-vector-renumbering.py`.

    The wrapper is OFF by default (local dev) and ON via
    `TRELLIS_CHECK_RENUMBERING=1` (CI / Makefile strict target).
    """

    @classmethod
    def setUpClass(cls):
        cls.cs = _load_check_specs_module()

    def test_off_by_default(self):
        os_env = os.environ.copy()
        os_env.pop("TRELLIS_CHECK_RENUMBERING", None)
        # Direct call: the wrapper reads the live os.environ; mutate within
        # a controlled scope.
        had = os.environ.pop("TRELLIS_CHECK_RENUMBERING", None)
        try:
            errors: list[str] = []
            self.cs.check_vector_renumbering(errors)
            # No env var set: the rule is a no-op.
            self.assertEqual(errors, [])
        finally:
            if had is not None:
                os.environ["TRELLIS_CHECK_RENUMBERING"] = had

    def test_on_with_real_repo_passes(self):
        # When the env var is set and the live repo is consistent with
        # origin/main (or whatever TRELLIS_RATIFICATION_REF resolves to),
        # the rule passes. We do not assert hard pass here because the
        # local repo may have un-pushed renumbers; we just assert the
        # rule runs without infrastructure errors.
        had = os.environ.get("TRELLIS_CHECK_RENUMBERING")
        os.environ["TRELLIS_CHECK_RENUMBERING"] = "1"
        try:
            errors: list[str] = []
            self.cs.check_vector_renumbering(errors)
            # Errors are acceptable here (real repo state); we only assert
            # the wrapper invoked the script without infrastructure
            # failures (i.e. the script existed and ran).
            for error in errors:
                self.assertNotIn("is missing", error)
        finally:
            if had is None:
                os.environ.pop("TRELLIS_CHECK_RENUMBERING", None)
            else:
                os.environ["TRELLIS_CHECK_RENUMBERING"] = had

    def test_on_with_unresolvable_base_ref_fails_loud(self):
        # An impossible base ref forces the underlying script to exit 2
        # (could-not-read fixtures); our wrapper escalates to a lint
        # failure when the env opt-in is set.
        had_check = os.environ.get("TRELLIS_CHECK_RENUMBERING")
        had_ref = os.environ.get("TRELLIS_RATIFICATION_REF")
        os.environ["TRELLIS_CHECK_RENUMBERING"] = "1"
        os.environ["TRELLIS_RATIFICATION_REF"] = "definitely-not-a-real-ref"
        try:
            errors: list[str] = []
            self.cs.check_vector_renumbering(errors)
            self.assertTrue(errors, "expected wrapper to surface base-ref failure")
        finally:
            if had_check is None:
                os.environ.pop("TRELLIS_CHECK_RENUMBERING", None)
            else:
                os.environ["TRELLIS_CHECK_RENUMBERING"] = had_check
            if had_ref is None:
                os.environ.pop("TRELLIS_RATIFICATION_REF", None)
            else:
                os.environ["TRELLIS_RATIFICATION_REF"] = had_ref


class TestTamperKindEnum(unittest.TestCase):
    """R13 — every tamper manifest's `[expected.report].tamper_kind` is in
    the Core §19.1 enum. Drift outside the enum fails loud."""

    @classmethod
    def setUpClass(cls):
        cls.cs = _load_check_specs_module()

    def _run(self, manifest: dict) -> list[str]:
        errors: list[str] = []
        self.cs.check_tamper_kind_enum(
            errors,
            manifests=[(Path("tamper/xxx-test/manifest.toml"), manifest)],
        )
        return errors

    def test_non_tamper_op_is_skipped(self):
        errors = self._run({
            "op": "verify",
            "expected": {"report": {"tamper_kind": "not_a_real_value"}},
        })
        self.assertEqual(errors, [])

    def test_known_kind_passes(self):
        errors = self._run({
            "op": "tamper",
            "expected": {"report": {"tamper_kind": "signature_invalid"}},
        })
        self.assertEqual(errors, [])

    def test_unknown_kind_fails(self):
        errors = self._run({
            "op": "tamper",
            "expected": {"report": {"tamper_kind": "made_up_value"}},
        })
        self.assertTrue(errors)
        self.assertIn("not in the Core §19.1 enum", errors[0])
        self.assertIn("made_up_value", errors[0])

    def test_missing_tamper_kind_fails(self):
        errors = self._run({
            "op": "tamper",
            "expected": {"report": {"structure_verified": True}},
        })
        self.assertTrue(errors)
        self.assertIn("missing required", errors[0])

    def test_missing_expected_report_fails(self):
        errors = self._run({"op": "tamper"})
        self.assertTrue(errors)
        self.assertIn("missing [expected.report]", errors[0])

    def test_non_string_kind_fails(self):
        errors = self._run({
            "op": "tamper",
            "expected": {"report": {"tamper_kind": 123}},
        })
        self.assertTrue(errors)
        self.assertIn("must be a string", errors[0])

    def test_real_corpus_is_clean(self):
        # Every committed tamper/* vector MUST satisfy R13 — drift detection.
        errors: list[str] = []
        self.cs.check_tamper_kind_enum(errors)
        self.assertEqual(errors, [], msg=f"R13 found errors: {errors}")

    def test_enum_matches_corpus(self):
        # Belt-and-braces: the enum should exactly match the set of
        # tamper_kind values currently in the corpus, so a future drop of a
        # tamper category from the enum without removing the vector trips
        # this test before reaching CI.
        cs = self.cs
        corpus_kinds: set[str] = set()
        for _path, manifest in cs.vector_manifests():
            if manifest.get("op") != "tamper":
                continue
            report = manifest.get("expected", {}).get("report", {})
            kind = report.get("tamper_kind")
            if isinstance(kind, str):
                corpus_kinds.add(kind)
        # Enum is allowed to be a superset (reserved values for upcoming
        # vectors), but every corpus kind MUST be in the enum.
        self.assertTrue(
            corpus_kinds.issubset(cs.TAMPER_KIND_ENUM),
            msg=(
                f"corpus uses tamper_kinds outside the enum: "
                f"{sorted(corpus_kinds - cs.TAMPER_KIND_ENUM)}"
            ),
        )


class TestHpkeEphemeralUniqueness(unittest.TestCase):
    """R17 — every HPKE wrap MUST use a unique X25519 ephemeral_pubkey within
    its containing ledger scope (Core §9.4). Catches weak-RNG / fixture-
    authoring drift; failure mode is otherwise silent."""

    @classmethod
    def setUpClass(cls):
        cls.cs = _load_check_specs_module()

    def _payload(self, scope: bytes, ephemerals: list[bytes], event_type: str = "x-trellis-test/append") -> dict:
        return {
            "header": {"event_type": event_type},
            "ledger_scope": scope,
            "key_bag": {
                "entries": [
                    {"recipient": f"r{i}".encode(), "suite": 1, "ephemeral_pubkey": ep, "wrapped_dek": b"\x00"}
                    for i, ep in enumerate(ephemerals)
                ],
            },
        }

    def _run(self, items: list[tuple[Path, dict]]) -> list[str]:
        errors: list[str] = []
        self.cs.check_hpke_ephemeral_uniqueness(errors, payloads=items)
        return errors

    def test_distinct_ephemerals_across_vectors_pass(self):
        ep_a = b"\xaa" * 32
        ep_b = b"\xbb" * 32
        items = [
            (Path("fixtures/vectors/append/100-a/expected-event.cbor"), self._payload(b"scope-X", [ep_a])),
            (Path("fixtures/vectors/append/101-b/expected-event.cbor"), self._payload(b"scope-X", [ep_b])),
        ]
        self.assertEqual(self._run(items), [])

    def test_same_vector_repeated_artifacts_pass(self):
        # vector_event_payloads yields the same logical event multiple times
        # (one per CBOR artifact view); identical (scope, ephemeral) pairs
        # within a single vector dir are NOT reuse — they are byte-identical
        # re-encodings of the same wrap.
        ep = b"\xcc" * 32
        items = [
            (Path("fixtures/vectors/append/200-x/input-author-event-hash-preimage.cbor"), self._payload(b"scope-Y", [ep])),
            (Path("fixtures/vectors/append/200-x/expected-event-payload.cbor"), self._payload(b"scope-Y", [ep])),
            (Path("fixtures/vectors/append/200-x/expected-event.cbor"), self._payload(b"scope-Y", [ep])),
        ]
        self.assertEqual(self._run(items), [])

    def test_cross_vector_reuse_in_same_scope_fails(self):
        ep = b"\xdd" * 32
        items = [
            (Path("fixtures/vectors/append/300-first/expected-event.cbor"), self._payload(b"scope-Z", [ep])),
            (Path("fixtures/vectors/append/301-second/expected-event.cbor"), self._payload(b"scope-Z", [ep])),
        ]
        errors = self._run(items)
        self.assertTrue(errors)
        self.assertTrue(any("ephemeral_pubkey" in e for e in errors))
        self.assertTrue(any("Core §9.4" in e for e in errors))
        self.assertTrue(any("300-first" in e and "301-second" in e for e in errors))

    def test_cross_scope_reuse_also_fails(self):
        # §9.4: "Reusing an ephemeral private key ... across ledger scopes,
        # is a non-conformance." The persisted ephemeral_pubkey IS the
        # encapsulated key; same value across scopes is the same reuse.
        ep = b"\xee" * 32
        items = [
            (Path("fixtures/vectors/append/400-a/expected-event.cbor"), self._payload(b"scope-P", [ep])),
            (Path("fixtures/vectors/append/401-b/expected-event.cbor"), self._payload(b"scope-Q", [ep])),
        ]
        errors = self._run(items)
        self.assertTrue(errors)
        self.assertTrue(any("ephemeral_pubkey" in e for e in errors))

    def test_within_event_duplicate_recipients_fails(self):
        # §9.4: "in an event with N recipients the key_bag contains N
        # KeyBagEntry rows with N distinct ephemeral_pubkey values"
        ep = b"\x11" * 32
        items = [
            (Path("fixtures/vectors/append/500-multi/expected-event.cbor"), self._payload(b"scope-R", [ep, ep])),
        ]
        errors = self._run(items)
        self.assertTrue(errors)
        self.assertTrue(any("within a single key_bag" in e or "within event" in e for e in errors))

    def test_no_keybag_skipped(self):
        items = [
            (Path("fixtures/vectors/append/600-no-keybag/expected-event.cbor"),
             {"header": {"event_type": "x-trellis-test/no-keybag"}, "ledger_scope": b"s"}),
        ]
        self.assertEqual(self._run(items), [])

    def test_empty_keybag_skipped(self):
        items = [
            (Path("fixtures/vectors/append/700-empty/expected-event.cbor"),
             {"header": {"event_type": "x-trellis-test/empty"}, "ledger_scope": b"s",
              "key_bag": {"entries": []}}),
        ]
        self.assertEqual(self._run(items), [])

    def test_real_corpus_is_clean(self):
        errors: list[str] = []
        self.cs.check_hpke_ephemeral_uniqueness(errors)
        self.assertEqual(errors, [], msg=f"R17 found errors: {errors}")


class TestReasonCodeCorpusParity(unittest.TestCase):
    """R19 — ReasonCode corpus-vs-table parity per family.

    Mirrors R13's ``test_enum_matches_corpus`` discipline: the spec table is
    the source of truth, fixture annotations are dependent corpus, drift
    between them is a lint failure naming the file + family + (code,
    annotated, registered) triple. Closes the gap that let TODO item #29
    (Wave 15 BLOCKER — §A.5.2 codes vs. fixture annotations) land
    undetected.
    """

    @classmethod
    def setUpClass(cls):
        cls.cs = _load_check_specs_module()

    # --- table-parser smoke tests ------------------------------------------------

    def test_table_parser_returns_three_families(self):
        tables = self.cs.reason_code_tables()
        self.assertEqual(set(tables), {"custody-model", "disclosure-profile", "erasure-evidence"})
        # Every family registers code 255 = Other (Core §6.9 cross-family floor).
        for family, table in tables.items():
            self.assertIn(255, table, msg=f"{family} missing 255 = Other floor")
            self.assertEqual(table[255].lower(), "other", msg=f"{family} 255 != Other")

    def test_table_parser_custody_model_codes_1_to_5(self):
        tables = self.cs.reason_code_tables()
        # Companion §A.5.1 — Phase-1 seeded codes; values 1-5 + 255.
        cm = tables["custody-model"]
        self.assertEqual(cm[1], "initial-deployment-correction")
        self.assertEqual(cm[2], "key-custody-change")
        self.assertEqual(cm[3], "operator-boundary-change")
        self.assertEqual(cm[4], "governance-policy-change")
        self.assertEqual(cm[5], "legal-order-compelling-transition")

    def test_table_parser_isolates_per_family(self):
        # Cross-family integer collision (the whole reason §6.9 namespaces by
        # family): code 3 means different things in different tables. Per
        # Core §6.9: codes 1-254 are family-local; the only cross-family
        # invariant is 255 = Other. Concrete witness:
        tables = self.cs.reason_code_tables()
        self.assertEqual(tables["custody-model"][3], "operator-boundary-change")
        self.assertEqual(tables["disclosure-profile"][3], "disclosure-policy-realignment")
        self.assertEqual(tables["erasure-evidence"][3], "legal-order-compelling-erasure")
        # All three are distinct semantic claims under code 3 — merging the
        # namespaces would silently reinterpret one of them.
        names_at_3 = {tables[fam][3] for fam in ("custody-model", "disclosure-profile", "erasure-evidence")}
        self.assertEqual(len(names_at_3), 3)

    # --- synthetic-injection lint behavior ---------------------------------------

    def _stub_tables(self) -> dict[str, dict[int, str]]:
        return {
            "custody-model": {
                1: "initial-deployment-correction",
                2: "key-custody-change",
                3: "operator-boundary-change",
                4: "governance-policy-change",
                255: "Other",
            },
            "disclosure-profile": {
                1: "initial-deployment-correction",
                2: "governance-policy-change",
                3: "legal-order-compelling-transition",
                4: "audience-scope-change",
                255: "Other",
            },
            "erasure-evidence": {
                1: "retention-expired",
                255: "Other",
            },
        }

    def _run(
        self,
        derivation_files: list[tuple[Path, str]] | None = None,
        generator_files: list[tuple[Path, str]] | None = None,
    ) -> list[str]:
        errors: list[str] = []
        self.cs.check_reason_code_corpus_parity(
            errors,
            derivation_files=derivation_files or [],
            generator_files=generator_files or [],
            tables=self._stub_tables(),
        )
        return errors

    def test_aligned_derivation_passes(self):
        # Custody-model family marker + table-row form, registered (code, name).
        blob = (
            "# Derivation\n\n"
            "Step 4 — `CustodyModelTransitionPayload` (Appendix A.5.1)\n\n"
            "| `reason_code` | `2` (key-custody-change) |\n"
        )
        self.assertEqual(
            self._run(derivation_files=[(Path("fixtures/vectors/append/xyz/derivation.md"), blob)]),
            [],
        )

    def test_drifted_derivation_fails_with_diagnostic(self):
        # Disclosure-profile fires: code 4 annotated as governance-policy-change,
        # registered as audience-scope-change. EXACTLY the item #29 BLOCKER drift.
        blob = (
            "# Derivation\n\n"
            "Step 4 — `DisclosureProfileTransitionPayload` (Appendix A.5.2)\n\n"
            "| `reason_code` | `4` (governance-policy-change) |\n"
        )
        errors = self._run(
            derivation_files=[(Path("fixtures/vectors/tamper/synth-016/derivation.md"), blob)],
        )
        self.assertEqual(len(errors), 1, msg=errors)
        self.assertIn("reason_code=4", errors[0])
        self.assertIn("'governance-policy-change'", errors[0])
        self.assertIn("'disclosure-profile'", errors[0])
        self.assertIn("'audience-scope-change'", errors[0])

    def test_unregistered_code_fails(self):
        # Code 99 is not in any registered table — Core §6.9 says verifiers
        # MUST reject unregistered codes.
        blob = (
            "# Derivation\n\n"
            "Step 4 — `CustodyModelTransitionPayload` (Appendix A.5.1)\n\n"
            "| `reason_code` | `99` (made-up-name) |\n"
        )
        errors = self._run(
            derivation_files=[(Path("fixtures/vectors/append/synth-99/derivation.md"), blob)],
        )
        self.assertEqual(len(errors), 1, msg=errors)
        self.assertIn("no code 99 registered", errors[0])
        self.assertIn("Core §6.9", errors[0])

    def test_family_ambiguous_file_fails(self):
        # Reason-code annotation present, but file does not name any
        # registered family marker — Core §6.9 forbids family-ambiguous
        # annotations because integer collision across families is real.
        blob = (
            "# Derivation\n\n"
            "Step 4 — Posture transition payload\n\n"
            "| `reason_code` | `2` (key-custody-change) |\n"
        )
        errors = self._run(
            derivation_files=[(Path("fixtures/vectors/append/synth-amb/derivation.md"), blob)],
        )
        self.assertEqual(len(errors), 1, msg=errors)
        self.assertIn("does not name a registered family", errors[0])

    def test_inline_body_form_also_caught(self):
        # Body-prose form: `reason_code = 2` (`key-custody-change` ...). Used
        # in append/007's derivation.md body text; lint must catch drift here
        # too, not only in table rows.
        blob = (
            "# Derivation\n\n"
            "References Appendix A.5.1.\n\n"
            "Concretely, `reason_code = 4` (`key-custody-change`) — clearly wrong.\n"
        )
        errors = self._run(
            derivation_files=[(Path("fixtures/vectors/append/synth-body/derivation.md"), blob)],
        )
        self.assertEqual(len(errors), 1, msg=errors)
        self.assertIn("reason_code=4", errors[0])
        self.assertIn("'key-custody-change'", errors[0])
        self.assertIn("'governance-policy-change'", errors[0])  # registered name for code 4

    def test_generator_comment_form_caught(self):
        # Generator form: `REASON_CODE = <int>  # <name>`. Same drift surface,
        # same family detection (the generator file references the family
        # marker by docstring or constant context).
        blob = (
            "\"\"\"Generator for trellis.disclosure-profile-transition.v1.\"\"\"\n"
            "FROM_DISCLOSURE_PROFILE = \"rl-profile-A\"\n"
            "REASON_CODE = 4                          # governance-policy-change\n"
        )
        errors = self._run(
            generator_files=[(Path("fixtures/vectors/_generator/gen_synth_016.py"), blob)],
        )
        self.assertEqual(len(errors), 1, msg=errors)
        self.assertIn("generator reason_code=4", errors[0])
        self.assertIn("'governance-policy-change'", errors[0])
        self.assertIn("'audience-scope-change'", errors[0])

    def test_other_code_255_is_cross_family_floor(self):
        # Core §6.9: 255 = Other is the only cross-family invariant. Annotating
        # 255 with anything but "Other" / "other" should fail.
        blob_ok = (
            "# Derivation\n\n"
            "Step 4 — `CustodyModelTransitionPayload` (Appendix A.5.1)\n\n"
            "| `reason_code` | `255` (Other) |\n"
        )
        self.assertEqual(
            self._run(derivation_files=[(Path("fixtures/vectors/append/synth-255/derivation.md"), blob_ok)]),
            [],
        )
        blob_bad = (
            "# Derivation\n\n"
            "Step 4 — `CustodyModelTransitionPayload` (Appendix A.5.1)\n\n"
            "| `reason_code` | `255` (Foo) |\n"
        )
        errors = self._run(
            derivation_files=[(Path("fixtures/vectors/append/synth-bad/derivation.md"), blob_bad)],
        )
        self.assertEqual(len(errors), 1, msg=errors)
        self.assertIn("'Foo'", errors[0])
        self.assertIn("'Other'", errors[0])

    def test_files_without_reason_code_are_skipped(self):
        # No reason_code annotation, no family marker, no work to do.
        blob = "# Some other vector\n\nNothing about reason codes here.\n"
        self.assertEqual(
            self._run(derivation_files=[(Path("fixtures/vectors/append/synth-none/derivation.md"), blob)]),
            [],
        )

    # --- live-corpus parity ------------------------------------------------------

    def test_real_corpus_parity_via_table_authority(self):
        # Belt-and-braces parity check against the live corpus, parallel to
        # R13's ``test_enum_matches_corpus``. The lint reads the spec table
        # dynamically — whichever state the §A.5.2 table is in (TODO item
        # #29's reconciliation may or may not have landed when this test
        # runs), the parity contract holds: every (code, annotated_name)
        # pair in the corpus MUST agree with whatever the table currently
        # registers. If a drift exists, the diagnostic names the file and
        # the (annotated, registered) disagreement so the fix path is
        # mechanical.
        errors: list[str] = []
        self.cs.check_reason_code_corpus_parity(errors)
        # NOTE: This assertion may fail until TODO item #29 lands the
        # §A.5.2 table reconciliation. That is the lint working as
        # designed — same as R13's first landing required the corpus to
        # align with the §19.1 enum. When #29 lands, this test goes
        # green.
        self.assertEqual(errors, [], msg=f"R19 found errors: {errors}")



if __name__ == "__main__":
    unittest.main()
