# Trellis Makefile
#
# Primary entry point for building and testing the Trellis integrity substrate.

# Paths
TRELLIS_PY_DIR = trellis-py
SCRIPTS_DIR = scripts
VECTORS_DIR = fixtures/vectors

# Basic configuration
PYTHON ?= $(if $(wildcard $(CURDIR)/$(TRELLIS_PY_DIR)/.venv/bin/python),$(CURDIR)/$(TRELLIS_PY_DIR)/.venv/bin/python,python3)
CARGO = cargo
PYTEST = $(PYTHON) -m pytest

.PHONY: all help build test test-rust test-python test-scripts test-postgres check-specs check-specs-strict check-verifier-isolation lint fmt clean

all: build test

help:
	@echo "Trellis Build & Test Tool"
	@echo ""
	@echo "Usage:"
	@echo "  make build          Build all Rust crates"
	@echo "  make test           Run all tests (Rust, Python, Scripts, Specs)"
	@echo "  make test-rust      Run all Rust tests"
	@echo "  make test-python    Run Python conformance tests"
	@echo "  make test-scripts   Run tests for helper scripts"
	@echo "  make test-postgres  Run async Postgres + parity integration tests (needs initdb/pg_ctl/openssl on PATH)"
	@echo "  make check-specs    Run spec discipline and coverage lint"
	@echo "  make check-specs-strict  Run check-specs + vector-renumbering guard (CI variant)"
	@echo "  make check-verifier-isolation  Assert integrity-verify stays HPKE-clean (Core §16)"
	@echo "  make lint           Run Rust clippy"
	@echo "  make fmt            Check Rust formatting"
	@echo "  make clean          Clean build artifacts"
	@echo ""

build:
	@echo "Building Rust workspace..."
	$(CARGO) build --workspace

test: test-rust test-python test-scripts check-specs check-verifier-isolation

test-rust:
	@echo "Running Rust tests..."
	$(CARGO) nextest run --workspace

test-python:
	@echo "Running Python conformance tests..."
	cd $(TRELLIS_PY_DIR) && PYTHONPATH=src $(PYTHON) -m trellis_py.conformance --vectors ../$(VECTORS_DIR)
	@echo "Checking for Python unit tests..."
	-cd $(TRELLIS_PY_DIR) && $(PYTEST) -q

test-scripts:
	@echo "Running script tests..."
	$(PYTHON) $(SCRIPTS_DIR)/test_check_specs.py
	$(PYTHON) $(SCRIPTS_DIR)/test_check_vector_renumbering.py
	$(PYTHON) $(SCRIPTS_DIR)/test_check_verifier_isolation.py
	$(PYTHON) $(SCRIPTS_DIR)/check-http-api-schema.py
	# Refactor G-6 slice: Python gen_export_001.py vs committed export/001-two-event-chain (not ratification G-6 spec lint).
	# Rust writer + verifier legs: trellis-export-writer crate test + trellis-conformance replay — see ratification-checklist.md#gate-label-crosswalk-refactoring-tracker.
	$(PYTHON) $(SCRIPTS_DIR)/check_export_001_generator_sync.py
	# Cross-runtime parity: three named gates run in sequence —
	#   1. generic-cbor-profile  (every R1–R7 case in fixtures/vectors/canonical-cbor/manifest.json
	#                             vs the Rust oracle integrity-cbor::encode_canonical_cbor_value)
	#   2. signed-acts-projection (Python signature-export generator + WOS verifier vs the
	#                              committed corpus; Rust consumes the same corpus through test-rust
	#                              `trellis-verify-wos` + conformance)
	#   3. seal-fence             (Python verify_seal_fence_extension vs Rust integrity-verify
	#                              SealFenceTamper variants over every export fixture)
	$(PYTHON) $(SCRIPTS_DIR)/check_cross_runtime_parity.py

# Targeted run of the Postgres-side integration suite. `cargo nextest run --workspace`
# already exercises these — this target exists for fast iteration on the
# canonical-side of the wos-server EventStore composition (per VISION.md §V).
# Requires `initdb`, `pg_ctl`, and `openssl` discoverable on PATH (Postgres
# 14+; tested against Postgres 16 via `/opt/homebrew/opt/postgresql@16/bin`).
test-postgres:
	@echo "Running trellis-store-postgres-async + parity integration tests..."
	$(CARGO) nextest run -p trellis-store-postgres-async
	$(CARGO) nextest run -p trellis-conformance --test store_parity

check-specs:
	@echo "Running spec checks..."
	$(PYTHON) $(SCRIPTS_DIR)/check-specs.py

# Strict pre-merge variant: enables the vector-renumbering guard
# (`TRELLIS_CHECK_RENUMBERING=1`) that compares vector NNN- prefixes against
# the base ref (default `origin/main`, override via `TRELLIS_RATIFICATION_REF`).
# CI invokes this target; local dev uses `check-specs` (without the guard).
check-specs-strict:
	@echo "Running spec checks (strict, with renumbering guard)..."
	TRELLIS_CHECK_RENUMBERING=1 $(PYTHON) $(SCRIPTS_DIR)/check-specs.py

# HPKE lives in `integrity-hpke` (integrity-stack); service and conformance crates
# exercise it via `cargo nextest run --workspace` in `make test`. This target only
# asserts the offline verifier package (`integrity-verify`) stays HPKE-clean.
# Asserts `cargo tree -p integrity-verify` is HPKE-clean (no `hpke`,
# `x25519-dalek`, `chacha20poly1305`, or `hkdf`). Core §16
# (Verification Independence) requires the offline verifier path to
# stay free of HPKE deps; ADR 0009 §"Architectural posture" explains
# why the sibling-crate boundary is what enforces it. Runs in
# `make test`; standalone for fast iteration during dep-graph work.
check-verifier-isolation:
	@bash $(SCRIPTS_DIR)/check-verifier-isolation.sh

lint:
	@echo "Running Rust clippy..."
	$(CARGO) clippy --workspace -- -D warnings

fmt:
	@echo "Checking Rust formatting..."
	$(CARGO) fmt --all -- --check

clean:
	@echo "Cleaning build artifacts..."
	$(CARGO) clean
	find . -name "__pycache__" -type d -exec rm -rf {} +
	rm -f $(TRELLIS_PY_DIR)/BYTE-MATCH-REPORT.json
