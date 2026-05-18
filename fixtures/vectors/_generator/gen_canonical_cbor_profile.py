"""Canonical CBOR §4.2.2 conformance corpus regenerator / verifier.

Authoring aid only. Orchestrates the Rust byte authority
(`integrity-stack/crates/integrity-cbor/src/lib.rs::encode_canonical_cbor_value`,
exposed via the `canonical_cbor_emit` cargo example) against the JSON case
files at `fixtures/vectors/canonical-cbor/cases/`.

Per `_generator/README.md` this script uses stdlib only (no `cbor2`, no
`cryptography`) — the Rust example is the encoder; this script orchestrates,
diffs, and reports.

## Usage

```sh
# Verify the committed corpus against the Rust oracle (default — used by CI / parity gate)
python3 fixtures/vectors/_generator/gen_canonical_cbor_profile.py

# Regenerate `expected_output_hex` / `expected_reject_code` in place
# (use only when intentionally regenerating after a Rust authority change)
python3 fixtures/vectors/_generator/gen_canonical_cbor_profile.py --write
```

## Exit codes

- 0: every case agrees with the Rust oracle (or is a forward-compatibility
  case that the Rust adapter correctly reports as `unimplemented`).
- 1: at least one case disagrees with the Rust oracle.
- 2: harness error (cargo build failed, JSON parse failed, etc.).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # fixtures/vectors/
CORPUS = ROOT / "canonical-cbor"
MANIFEST = CORPUS / "manifest.json"
TRELLIS = ROOT.parent.parent                            # trellis/

# Cargo workspace root for `cargo run --example`. `cd trellis/` and invoke
# from there — the workspace Cargo.toml registers trellis-conformance.
CARGO_CWD = TRELLIS


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Canonical CBOR §4.2.2 conformance corpus regenerator."
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Regenerate expected_output_hex / expected_reject_code from the Rust oracle.",
    )
    parser.add_argument(
        "--cargo-target-dir",
        default=None,
        help="Override CARGO_TARGET_DIR for the cargo invocation.",
    )
    args = parser.parse_args()

    manifest = _read_json(MANIFEST)
    cases_index = manifest["cases"]

    # Single batched cargo invocation — cargo builds the example once and the
    # adapter loops over every case named in the manifest.
    records = _invoke_rust_adapter(args.cargo_target_dir)
    if records is None:
        return 2

    records_by_id = {record["case_id"]: record for record in records}

    failures: list[str] = []
    regenerations: list[Path] = []

    for index_entry in cases_index:
        case_id = index_entry["case_id"]
        case_path = CORPUS / index_entry["file"]
        case = _read_json(case_path)
        record = records_by_id.get(case_id)
        if record is None:
            failures.append(
                f"{case_id}: Rust adapter produced no record for this case (manifest order mismatch?)"
            )
            continue

        result = record.get("result")
        kind = case["kind"]
        forward_compat = bool(case.get("forward_compatibility", False))

        if forward_compat:
            # Adapter contract: Rust oracle returns `unimplemented` for every
            # forward-compatibility case. Any other result is a regression.
            if result != "unimplemented":
                failures.append(
                    f"{case_id}: forward-compatibility case expected result=unimplemented "
                    f"from Rust adapter, got result={result!r}: {record}"
                )
            continue

        if kind == "encode":
            if result != "pass":
                failures.append(
                    f"{case_id} (kind=encode): expected pass, got result={result!r} — "
                    f"output_hex={record.get('output_hex')!r}, "
                    f"reason={record.get('reason')!r}, "
                    f"stderr_excerpt={record.get('stderr_excerpt')!r}"
                )
                continue
            actual = record["output_hex"]
            expected = case.get("expected_output_hex")
            if args.write:
                if case.get("expected_output_hex") != actual:
                    case["expected_output_hex"] = actual
                    _write_json(case_path, case)
                    regenerations.append(case_path)
                continue
            if expected != actual:
                failures.append(
                    f"{case_id} (kind=encode):\n"
                    f"  committed expected_output_hex: {expected}\n"
                    f"  Rust oracle actual:           {actual}\n"
                    f"  case file: {case_path.relative_to(TRELLIS)}\n"
                    f"  reproduce: (cd {TRELLIS}; cargo run -q --example canonical_cbor_emit -- "
                    f"--case {case_path.relative_to(TRELLIS)})"
                )
        elif kind == "reject":
            if result != "pass":
                actual_code = record.get("reject_code")
                expected_code = case.get("expected_reject_code")
                if args.write and actual_code is not None and actual_code != expected_code:
                    case["expected_reject_code"] = actual_code
                    _write_json(case_path, case)
                    regenerations.append(case_path)
                    continue
                failures.append(
                    f"{case_id} (kind=reject):\n"
                    f"  committed expected_reject_code: {expected_code}\n"
                    f"  Rust oracle actual reject_code: {actual_code}\n"
                    f"  Rust adapter result:            {result}\n"
                    f"  stderr_excerpt: {record.get('stderr_excerpt')!r}\n"
                    f"  case file: {case_path.relative_to(TRELLIS)}\n"
                    f"  reproduce: (cd {TRELLIS}; cargo run -q --example canonical_cbor_emit -- "
                    f"--case {case_path.relative_to(TRELLIS)})"
                )
        else:
            failures.append(f"{case_id}: unknown kind {kind!r}")

    if regenerations:
        print(f"--write: regenerated {len(regenerations)} case file(s):", file=sys.stderr)
        for path in regenerations:
            print(f"  {path.relative_to(TRELLIS)}", file=sys.stderr)

    if failures:
        print(
            f"\ncanonical-cbor corpus: {len(failures)} mismatch(es) vs Rust oracle\n",
            file=sys.stderr,
        )
        for failure in failures:
            print(failure, file=sys.stderr)
            print(file=sys.stderr)
        return 1

    print(
        f"canonical-cbor corpus: {len(cases_index)} cases agree with Rust oracle "
        f"({sum(1 for c in cases_index if c.get('forward_compatibility'))} forward-compatibility)."
    )
    return 0


def _invoke_rust_adapter(cargo_target_dir: str | None) -> list[dict] | None:
    """Runs `cargo run --example canonical_cbor_emit -- --manifest <path>` and
    parses the newline-delimited JSON output. Returns None on harness failure.
    """
    command = [
        "cargo",
        "run",
        "-q",
        "--example",
        "canonical_cbor_emit",
        "--",
        "--manifest",
        str(MANIFEST),
    ]
    env_extra = {}
    if cargo_target_dir:
        env_extra["CARGO_TARGET_DIR"] = cargo_target_dir

    import os
    env = dict(os.environ)
    env.update(env_extra)

    try:
        result = subprocess.run(
            command,
            cwd=CARGO_CWD,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as error:
        print(f"cargo invocation failed: {error}", file=sys.stderr)
        return None

    if result.returncode != 0:
        print("cargo run failed:", file=sys.stderr)
        print(f"  command: {' '.join(command)}", file=sys.stderr)
        print(f"  cwd: {CARGO_CWD}", file=sys.stderr)
        print(f"  exit code: {result.returncode}", file=sys.stderr)
        print(f"  stderr:\n{result.stderr}", file=sys.stderr)
        return None

    records: list[dict] = []
    for line_number, line in enumerate(result.stdout.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            records.append(json.loads(stripped))
        except json.JSONDecodeError as error:
            print(
                f"adapter stdout line {line_number} is not valid JSON: {error}\n  line: {line!r}",
                file=sys.stderr,
            )
            return None
    return records


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, document: dict) -> None:
    # Compact-ish stable formatting: 2-space indent, sorted keys NOT applied
    # (we keep author-provided key order in cases for readability), newline at EOF.
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
