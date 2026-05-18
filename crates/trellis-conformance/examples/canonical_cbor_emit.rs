//! Canonical CBOR §4.2.2 conformance adapter (Rust oracle).
//!
//! This binary is the Rust adapter for the canonical-CBOR runtime-port contract
//! defined in `thoughts/specs/2026-05-18-canonical-cbor-runtime-port.md` §3.
//! It consumes JSON case files from `trellis/fixtures/vectors/canonical-cbor/`
//! and emits one JSON result record per case on stdout, matching the adapter
//! output schema. The Python orchestrator
//! (`fixtures/vectors/_generator/gen_canonical_cbor_profile.py`) and the
//! Task A2 parity gate consume the output.
//!
//! ## Usage
//!
//! ```sh
//! # Run one case:
//! cargo run -q --example canonical_cbor_emit -- --case path/to/case.json
//!
//! # Batched: run every case named in a manifest:
//! cargo run -q --example canonical_cbor_emit -- --manifest path/to/manifest.json
//! ```
//!
//! ## Output schema (one JSON record per case, newline-delimited)
//!
//! ```json
//! { "case_id": "...", "result": "pass" | "fail" | "error" | "unimplemented",
//!   "output_hex": "...",          // present iff result=pass AND case kind=encode
//!   "reject_code": "...",         // present iff case kind=reject (closed set)
//!   "reason": "...",              // present iff result=unimplemented or error
//!   "stderr_excerpt": "...",      // present iff result=fail or error (≤ 2 KiB)
//!   "runtime": "rust-integrity-cbor",
//!   "library_version": "..." }
//! ```
//!
//! Forward-compatibility cases (`forward_compatibility: true`) always return
//! `result=unimplemented` from this Rust adapter, reflecting the inert-rule
//! status documented in `trellis/specs/canonical-cbor-profile.md` §2 (R6, R7,
//! R2 parse-side). External-runtime adapters that DO implement the rule
//! return the rule-correct result; the parity gate accepts both.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ciborium::Value;
use integrity_cbor::{
    CborHelperError, decode_cbor_value, encode_canonical_cbor_value,
};
use serde_json::{Map, Value as JsonValue, json};

const RUNTIME_NAME: &str = "rust-integrity-cbor";
const LIBRARY_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let mode = match parse_args(&args) {
        Ok(mode) => mode,
        Err(message) => {
            eprintln!("usage: canonical_cbor_emit --case <path> | --manifest <path>");
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };

    match mode {
        Mode::Case(path) => match run_case_file(&path) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::from(2)
            }
        },
        Mode::Manifest(path) => match run_manifest(&path) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::from(2)
            }
        },
    }
}

enum Mode {
    Case(PathBuf),
    Manifest(PathBuf),
}

fn parse_args(args: &[String]) -> Result<Mode, String> {
    match args.len() {
        2 if args[0] == "--case" => Ok(Mode::Case(PathBuf::from(&args[1]))),
        2 if args[0] == "--manifest" => Ok(Mode::Manifest(PathBuf::from(&args[1]))),
        _ => Err("expected --case <path> or --manifest <path>".to_owned()),
    }
}

fn run_manifest(manifest_path: &Path) -> Result<(), String> {
    let manifest_bytes = fs::read(manifest_path)
        .map_err(|error| format!("read manifest {}: {error}", manifest_path.display()))?;
    let manifest: JsonValue = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("parse manifest JSON: {error}"))?;
    let cases = manifest
        .get("cases")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| "manifest is missing `cases` array".to_owned())?;
    let base = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    for case_index in cases {
        let file = case_index
            .get("file")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "manifest case entry missing `file`".to_owned())?;
        let case_path = base.join(file);
        run_case_file(&case_path)?;
    }
    Ok(())
}

fn run_case_file(case_path: &Path) -> Result<(), String> {
    let case_bytes = fs::read(case_path)
        .map_err(|error| format!("read case {}: {error}", case_path.display()))?;
    let case: JsonValue = serde_json::from_slice(&case_bytes)
        .map_err(|error| format!("parse case JSON {}: {error}", case_path.display()))?;

    let case_id = case
        .get("case_id")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| format!("case {} missing `case_id`", case_path.display()))?
        .to_owned();
    let kind = case
        .get("kind")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| format!("case {case_id} missing `kind`"))?;
    let forward_compatibility = case
        .get("forward_compatibility")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false);
    let input = case
        .get("input")
        .ok_or_else(|| format!("case {case_id} missing `input`"))?;

    // Forward-compatibility cases: the Rust oracle does not enforce the rule
    // (R6 compaction, R7 generic-tag allowlist, R2 parse-side
    // indefinite-length reject, R5+R6 zero-width). The adapter returns
    // `unimplemented` regardless of input. External adapters that DO
    // enforce the rule return the rule-correct result; the parity gate
    // accepts both.
    if forward_compatibility {
        emit_record(json!({
            "case_id": case_id,
            "result": "unimplemented",
            "reason": "Rust oracle does not enforce this rule today; see canonical-cbor-profile.md §2 status notes.",
            "runtime": RUNTIME_NAME,
            "library_version": LIBRARY_VERSION,
        }));
        return Ok(());
    }

    let value = match build_value(input) {
        Ok(value) => value,
        Err(error) => {
            emit_record(json!({
                "case_id": case_id,
                "result": "error",
                "reason": "failed to build CBOR input value",
                "stderr_excerpt": truncate(&error, 2048),
                "runtime": RUNTIME_NAME,
                "library_version": LIBRARY_VERSION,
            }));
            return Ok(());
        }
    };

    match (kind, encode_canonical_cbor_value(&value)) {
        ("encode", Ok(bytes)) => {
            let expected = case.get("expected_output_hex").and_then(JsonValue::as_str);
            let actual = hex_lower(&bytes);
            let result = match expected {
                Some(expected) if expected == actual => "pass",
                Some(_) => "fail",
                None => "pass", // case file did not pin an expected — adapter still reports the bytes
            };
            let mut record = Map::new();
            record.insert("case_id".into(), json!(case_id));
            record.insert("result".into(), json!(result));
            record.insert("output_hex".into(), json!(actual));
            if let Some(expected) = expected {
                record.insert("expected_output_hex".into(), json!(expected));
            }
            record.insert("runtime".into(), json!(RUNTIME_NAME));
            record.insert("library_version".into(), json!(LIBRARY_VERSION));
            emit_record(JsonValue::Object(record));
        }
        ("encode", Err(error)) => {
            emit_record(json!({
                "case_id": case_id,
                "result": "fail",
                "reason": "encoder rejected an input declared `kind=encode`",
                "stderr_excerpt": truncate(&error.0, 2048),
                "runtime": RUNTIME_NAME,
                "library_version": LIBRARY_VERSION,
            }));
        }
        ("reject", Ok(bytes)) => {
            emit_record(json!({
                "case_id": case_id,
                "result": "fail",
                "reason": "encoder accepted an input declared `kind=reject`",
                "output_hex": hex_lower(&bytes),
                "runtime": RUNTIME_NAME,
                "library_version": LIBRARY_VERSION,
            }));
        }
        ("reject", Err(error)) => {
            let expected = case
                .get("expected_reject_code")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            let actual = classify_reject(&error);
            let result = match actual.as_deref() {
                Some(code) if code == expected => "pass",
                Some(_) => "fail",
                None => "fail",
            };
            let mut record = Map::new();
            record.insert("case_id".into(), json!(case_id));
            record.insert("result".into(), json!(result));
            if let Some(code) = actual {
                record.insert("reject_code".into(), json!(code));
            }
            record.insert("expected_reject_code".into(), json!(expected));
            record.insert("stderr_excerpt".into(), json!(truncate(&error.0, 2048)));
            record.insert("runtime".into(), json!(RUNTIME_NAME));
            record.insert("library_version".into(), json!(LIBRARY_VERSION));
            emit_record(JsonValue::Object(record));
        }
        (other, _) => {
            return Err(format!("case {case_id} has unknown kind `{other}`"));
        }
    }
    Ok(())
}

/// Maps a `CborHelperError` to a normalized reject code per the closed set
/// in `thoughts/specs/2026-05-18-canonical-cbor-runtime-port.md` §4.
fn classify_reject(error: &CborHelperError) -> Option<String> {
    let message = error.0.as_str();
    if message.contains("duplicate canonical CBOR map key") {
        Some("duplicate_map_key".to_owned())
    } else if message.contains("CBOR float must be finite") {
        Some("non_finite_float".to_owned())
    } else if message.contains("CBOR float must use canonical +0") {
        Some("negative_zero_float".to_owned())
    } else {
        // Provider-specific text. The closed set explicitly excludes free-form
        // error strings; surface `None` and let the harness report the raw text
        // in `stderr_excerpt` for triage.
        None
    }
}

/// Recursively converts the manifest's `input` JSON description into a
/// `ciborium::Value`. The closed-set shape is documented in
/// `trellis/fixtures/vectors/canonical-cbor/README.md`.
fn build_value(input: &JsonValue) -> Result<Value, String> {
    let object = input
        .as_object()
        .ok_or_else(|| format!("input must be a JSON object, got: {input}"))?;
    if object.len() != 1 {
        return Err(format!(
            "input must be a single-key tagged-union object, got {} keys: {:?}",
            object.len(),
            object.keys().collect::<Vec<_>>()
        ));
    }
    let (variant, body) = object.iter().next().expect("checked len == 1");
    match variant.as_str() {
        "uint" => {
            let n = body
                .as_u64()
                .ok_or_else(|| format!("uint variant must be a JSON unsigned integer: {body}"))?;
            Ok(Value::Integer(n.into()))
        }
        "nint" => {
            let n = body
                .as_i64()
                .ok_or_else(|| format!("nint variant must be a JSON signed integer: {body}"))?;
            if n >= 0 {
                return Err(format!("nint variant requires a negative integer, got {n}"));
            }
            Ok(Value::Integer(n.into()))
        }
        "tstr" => {
            let s = body
                .as_str()
                .ok_or_else(|| format!("tstr variant must be a JSON string: {body}"))?;
            Ok(Value::Text(s.to_owned()))
        }
        "bstr_hex" => {
            let s = body
                .as_str()
                .ok_or_else(|| format!("bstr_hex variant must be a JSON string: {body}"))?;
            let bytes = decode_hex(s).map_err(|error| format!("bstr_hex decode: {error}"))?;
            Ok(Value::Bytes(bytes))
        }
        "bool" => {
            let b = body
                .as_bool()
                .ok_or_else(|| format!("bool variant must be JSON bool: {body}"))?;
            Ok(Value::Bool(b))
        }
        "null" => Ok(Value::Null),
        "float" => {
            let f = body
                .as_f64()
                .ok_or_else(|| format!("float variant must be JSON number: {body}"))?;
            Ok(Value::Float(f))
        }
        "float_special" => {
            let s = body
                .as_str()
                .ok_or_else(|| format!("float_special variant must be JSON string: {body}"))?;
            let f = match s {
                "nan" => f64::NAN,
                "+inf" => f64::INFINITY,
                "-inf" => f64::NEG_INFINITY,
                "negative_zero" => -0.0_f64,
                other => return Err(format!("unknown float_special `{other}`")),
            };
            Ok(Value::Float(f))
        }
        "array" => {
            let items = body
                .as_array()
                .ok_or_else(|| format!("array variant body must be JSON array: {body}"))?;
            let mut values = Vec::with_capacity(items.len());
            for item in items {
                values.push(build_value(item)?);
            }
            Ok(Value::Array(values))
        }
        "map" => {
            let entries = body
                .as_array()
                .ok_or_else(|| format!("map variant body must be JSON array: {body}"))?;
            let mut pairs = Vec::with_capacity(entries.len());
            for entry in entries {
                let object = entry.as_object().ok_or_else(|| {
                    format!("map entry must be {{key, value}} JSON object: {entry}")
                })?;
                let key = object
                    .get("key")
                    .ok_or_else(|| format!("map entry missing `key`: {entry}"))?;
                let value = object
                    .get("value")
                    .ok_or_else(|| format!("map entry missing `value`: {entry}"))?;
                pairs.push((build_value(key)?, build_value(value)?));
            }
            // Preserve author-provided order — the canonical encoder re-sorts
            // per R3. Tests that the corpus is exercising sort behavior depend
            // on this preimage NOT being pre-sorted by build_value.
            Ok(Value::Map(pairs))
        }
        "tag" => {
            let object = body.as_object().ok_or_else(|| {
                format!("tag variant body must be {{number, value}} object: {body}")
            })?;
            let number = object
                .get("number")
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| format!("tag variant requires unsigned `number`: {body}"))?;
            let inner = object
                .get("value")
                .ok_or_else(|| format!("tag variant requires `value`: {body}"))?;
            Ok(Value::Tag(number, Box::new(build_value(inner)?)))
        }
        "bytes_hex" => {
            // Pre-encoded CBOR bytes. Used for parse-side tests (R2
            // indefinite-length input). Decode them into a ciborium::Value
            // first; the canonical encoder then re-emits.
            let s = body
                .as_str()
                .ok_or_else(|| format!("bytes_hex variant must be JSON string: {body}"))?;
            let bytes = decode_hex(s).map_err(|error| format!("bytes_hex decode: {error}"))?;
            decode_cbor_value(&bytes).map_err(|error| format!("decode CBOR: {error}"))
        }
        other => Err(format!(
            "unknown input variant `{other}` (expected one of: uint, nint, tstr, bstr_hex, bool, null, float, float_special, array, map, tag, bytes_hex)"
        )),
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(format!("hex length {} is not even", s.len()));
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    let chars: Vec<char> = s.chars().collect();
    for pair in chars.chunks(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(c: char) -> Result<u8, String> {
    match c {
        '0'..='9' => Ok(c as u8 - b'0'),
        'a'..='f' => Ok(c as u8 - b'a' + 10),
        'A'..='F' => Ok(c as u8 - b'A' + 10),
        _ => Err(format!("invalid hex char `{c}`")),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        let mut out = s[..max].to_owned();
        out.push_str("…");
        out
    }
}

fn emit_record(record: JsonValue) {
    // Newline-delimited JSON on stdout. One record per case. Manifest mode
    // emits one record per case in order. The Python orchestrator reads
    // line-by-line and matches against `case_id`.
    let line = serde_json::to_string(&record).expect("JSON record serializable");
    println!("{line}");
}
