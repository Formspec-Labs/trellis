//! Trellis DI topology boundary gate (`TRELLIS-DI-TOPOLOGY-TODO.md`).
//!
//! Deterministic source + manifest scanner that fails `cargo test` when the
//! Trellis-internal injection boundary is violated. Generic Trellis service
//! code must not depend on domain admission vocabulary, Formspec
//! binding/server crates, fixture/conformance/verifier-only crates, and must
//! not derive profile/schema/direct-submit metadata from event-type string
//! prefixes.
//!
//! Modelled on
//! `formspec-server/crates/formspec-server/tests/dependency_baseline.rs`.
//!
//! ## Source scanning notes
//!
//! - `strip_test_modules` cuts from the first `#[cfg(test)]` line to EOF on
//!   the convention that test modules are file-final. This is brittle for
//!   files with multiple `#[cfg(test)]` blocks scattered through the body,
//!   but every gated file in this crate today follows the convention.
//! - The "production code does not import domain vocabulary" check matches
//!   both `use <crate>` statements and path-qualified `<crate>::` usage so a
//!   refactor cannot smuggle the dependency in via a fully-qualified path.
//! - `read_generic_server_files` enumerates `src/*.rs` under
//!   `trellis-server` and applies a denylist (composition, tests) so adding
//!   a new generic module automatically falls under the gate.

use std::fs;
use std::path::{Path, PathBuf};

/// Crates whose normal (non-dev) dependency tables must stay free of
/// WOS/Formspec domain vocabulary and admission adapter crates.
const NEUTRAL_CRATES: &[&str] = &[
    "trellis-core",
    "trellis-export-writer",
    "trellis-server-ports",
];

/// Tokens that must not appear under `[dependencies]` of any [`NEUTRAL_CRATES`]
/// manifest. Dev-dependencies are intentionally allowed for fixture-bearing
/// tests inside the same crate.
const FORBIDDEN_NEUTRAL_DEPS: &[&str] = &[
    "wos-events",
    "formspec-trellis-binding",
    "trellis-admission-wos",
    "trellis-admission-formspec",
    "trellis-verify-wos",
    "trellis-conformance",
    "trellis-interop-c2pa",
    "trellis-interop-did",
];

/// Source-file basenames inside `trellis-server/src/` that the gate excludes
/// from the generic-module scan. Only the composition root and the test
/// harness may name domain adapters.
const GENERIC_SERVER_DENYLIST: &[&str] = &["composition.rs", "test_harness.rs"];

/// Crate-level token roots that count as domain vocabulary. Production code
/// in generic modules may not contain `use <root>` *or* `<root>::` outside
/// comments.
const FORBIDDEN_DOMAIN_ROOTS: &[&str] = &[
    "wos_events",
    "trellis_admission_wos",
    "trellis_admission_formspec",
    "formspec_trellis_binding",
];

/// String-prefix dispatch tokens forbidden in generic service code; the
/// admission contract supplies `event_family` / `profile_id` instead.
const FORBIDDEN_PREFIX_DISPATCH_TOKENS: &[&str] = &[
    "starts_with(\"wos.\")",
    "starts_with(\"substrate.append.\")",
];

#[test]
fn neutral_crates_have_no_domain_dependencies() {
    for crate_name in NEUTRAL_CRATES {
        let manifest_path = trellis_root().join("crates").join(crate_name).join("Cargo.toml");
        let manifest = fs::read_to_string(&manifest_path)
            .unwrap_or_else(|err| panic!("read {manifest_path:?}: {err}"));
        let deps_section = normal_dependency_section(&manifest);
        for forbidden in FORBIDDEN_NEUTRAL_DEPS {
            assert!(
                !deps_section.contains(forbidden),
                "{crate_name} must not depend on `{forbidden}` (Boundary Gate)"
            );
        }
    }
}

#[test]
fn admission_adapters_do_not_depend_on_each_other() {
    let wos_manifest = read_manifest("trellis-admission-wos");
    let formspec_manifest = read_manifest("trellis-admission-formspec");
    assert!(
        !wos_manifest.contains("trellis-admission-formspec"),
        "trellis-admission-wos must not depend on trellis-admission-formspec (Boundary Gate)"
    );
    assert!(
        !formspec_manifest.contains("trellis-admission-wos"),
        "trellis-admission-formspec must not depend on trellis-admission-wos (Boundary Gate)"
    );
}

#[test]
fn service_client_has_no_formspec_or_admission_dependencies() {
    // D12 permits `trellis-service-client -> wos-events` for the shared WOS
    // typed-helper surface only. Formspec ceremony and admission adapters
    // must not appear in the shared client crate.
    let manifest = read_manifest("trellis-service-client");
    let deps_section = normal_dependency_section(&manifest);
    for forbidden in [
        "formspec-trellis-binding",
        "trellis-admission-wos",
        "trellis-admission-formspec",
        "formspec-server",
        "formspec-server-ports",
        "formspec-server-substrate-trellis",
    ] {
        assert!(
            !deps_section.contains(forbidden),
            "trellis-service-client must not depend on `{forbidden}` (D12 / DI-004)"
        );
    }
}

#[test]
fn generic_server_files_do_not_import_domain_vocabulary_in_production() {
    for (relative_path, source) in read_generic_server_files() {
        let production_source = strip_test_modules(&source);
        for line in production_source.lines() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for root in FORBIDDEN_DOMAIN_ROOTS {
                let use_token = format!("use {root}");
                let path_token = format!("{root}::");
                assert!(
                    !line.contains(&use_token),
                    "{relative_path}: production code must not contain `{use_token}` \
                     (Boundary Gate). Move domain wiring into `composition.rs`."
                );
                assert!(
                    !line.contains(&path_token),
                    "{relative_path}: production code must not reference `{path_token}` \
                     (Boundary Gate). Move domain wiring into `composition.rs`. \
                     Offending line: `{line}`"
                );
            }
        }
    }
}

#[test]
fn generic_server_files_do_not_use_prefix_dispatch_for_profile_metadata() {
    for (relative_path, source) in read_generic_server_files() {
        let production_source = strip_test_modules(&source);
        for forbidden in FORBIDDEN_PREFIX_DISPATCH_TOKENS {
            assert!(
                !production_source.contains(forbidden),
                "{relative_path}: profile/schema/direct-submit dispatch must not match on \
                 event_type prefixes (`{forbidden}`); consult `AdmittedEvent` instead."
            );
        }
    }
}

#[test]
fn neutral_port_crate_does_not_import_domain_vocabulary() {
    let ports_lib = fs::read_to_string(
        trellis_root()
            .join("crates")
            .join("trellis-server-ports")
            .join("src")
            .join("lib.rs"),
    )
    .expect("trellis-server-ports lib.rs");
    let production_source = strip_test_modules(&ports_lib);
    for line in production_source.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for forbidden in [
            "use wos_events",
            "use trellis_admission_wos",
            "use trellis_admission_formspec",
            "use formspec_trellis_binding",
        ] {
            assert!(
                !line.contains(forbidden),
                "trellis-server-ports must not contain `{forbidden}` (Boundary Gate)"
            );
        }
    }
}

#[test]
fn service_client_contains_wos_imports_to_extension_helper_module() {
    // D12 + DI-004: `trellis-service-client` may depend on `wos-events` only
    // through the blessed WOS typed-helper surface (`wos_ext`). The crate
    // root and any other module must remain WOS-agnostic so the shared HTTP
    // client stays reusable by Formspec and future producers without
    // inheriting WOS dialect.
    let client_root = trellis_root().join("crates").join("trellis-service-client").join("src");
    let entries =
        fs::read_dir(&client_root).expect("read trellis-service-client src directory");
    for entry in entries {
        let entry = entry.expect("entry");
        let path = entry.path();
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        if !file_name.ends_with(".rs") || file_name == "wos_ext.rs" {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read {path:?}: {err}"));
        let production_source = strip_test_modules(&source);
        for line in production_source.lines() {
            let stripped = line.trim_start();
            if stripped.starts_with("//") {
                continue;
            }
            for forbidden in ["use wos_events", "wos_events::"] {
                assert!(
                    !line.contains(forbidden),
                    "{file_name}: trellis-service-client must contain WOS imports to \
                     `wos_ext.rs` (D12 / DI-004); found `{forbidden}` in `{line}`."
                );
            }
        }
    }
}

/// Reads every `*.rs` file under `trellis-server/src/` that is NOT on
/// [`GENERIC_SERVER_DENYLIST`]. Adding a new generic module automatically
/// falls under the gate.
fn read_generic_server_files() -> Vec<(String, String)> {
    let server_root = trellis_root().join("crates").join("trellis-server").join("src");
    let mut files = Vec::new();
    for entry in fs::read_dir(&server_root).expect("read trellis-server src directory") {
        let entry = entry.expect("entry");
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        if !file_name.ends_with(".rs") {
            continue;
        }
        if GENERIC_SERVER_DENYLIST.contains(&file_name.as_str()) {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read {path:?}: {err}"));
        files.push((file_name, source));
    }
    // Include the bin entrypoint when it exists; it's a generic production
    // module that wires `state_from_env` + `router`.
    let bin_path = server_root.join("bin");
    if bin_path.is_dir() {
        for entry in fs::read_dir(&bin_path).expect("read trellis-server bin directory") {
            let entry = entry.expect("entry");
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_string();
            if !file_name.ends_with(".rs") {
                continue;
            }
            let source = fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("read {path:?}: {err}"));
            files.push((format!("bin/{file_name}"), source));
        }
    }
    files
}

/// Returns the dependency block of every dependency table, ignoring dev/build
/// dependency sections. Supports both the flat `[dependencies]` form and the
/// per-dependency `[dependencies.<name>]` form, plus
/// `[target.<cfg>.dependencies]`.
fn normal_dependency_section(manifest: &str) -> String {
    let mut out = String::new();
    let mut in_normal_deps = false;
    let mut current_per_dep_name: Option<String> = None;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if let Some(header) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if header == "dependencies" {
                in_normal_deps = true;
                current_per_dep_name = None;
            } else if let Some(name) = header.strip_prefix("dependencies.") {
                in_normal_deps = false;
                current_per_dep_name = Some(name.to_string());
                out.push_str(name);
                out.push('\n');
            } else if header.starts_with("target.") && header.ends_with(".dependencies") {
                in_normal_deps = true;
                current_per_dep_name = None;
            } else if let Some(rest) = header.strip_prefix("target.") {
                if let Some(name) = rest
                    .strip_suffix("]")
                    .unwrap_or(rest)
                    .rsplit('.')
                    .next()
                    .filter(|tail| tail.starts_with("dependencies."))
                {
                    current_per_dep_name = Some(name.to_string());
                    out.push_str(name);
                    out.push('\n');
                }
                in_normal_deps = false;
            } else {
                in_normal_deps = false;
                current_per_dep_name = None;
            }
            continue;
        }
        if in_normal_deps || current_per_dep_name.is_some() {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Strips from the first `#[cfg(test)]` line to EOF on the convention that
/// test modules are file-final. Simpler and more robust than the previous
/// brace counter, which would mis-handle string literals or comments
/// containing `{` / `}`.
fn strip_test_modules(source: &str) -> String {
    match source.find("#[cfg(test)]") {
        Some(start) => {
            // Anchor on the start of the line containing the marker so trailing
            // production code on the same line is preserved (rare but valid).
            let line_start = source[..start].rfind('\n').map_or(0, |idx| idx + 1);
            source[..line_start].to_string()
        }
        None => source.to_string(),
    }
}

fn read_manifest(crate_name: &str) -> String {
    let path = trellis_root().join("crates").join(crate_name).join("Cargo.toml");
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {path:?}: {err}"))
}

fn trellis_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("trellis root")
        .to_path_buf()
}
