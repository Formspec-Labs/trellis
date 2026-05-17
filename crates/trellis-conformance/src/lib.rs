// Rust guideline compliant 2026-02-21
//! Conformance harness for the committed Trellis vector corpus.

#![forbid(unsafe_code)]

#[cfg(test)]
mod model_checks;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use ciborium::Value;
    use integrity_bundle::{Bundle, BundleEntry};
    use integrity_verify::trellis::{
        VerificationReport, verify_export_zip, verify_tampered_ledger,
    };
    use trellis_cddl::canonical_event_hash_preimage;
    use trellis_core::{AuthoredEvent, SigningKeyMaterial, append_event};
    use trellis_store_memory::MemoryStore;
    use trellis_types::{
        EVENT_DOMAIN, checkpoint_digest, decode_cbor_value, domain_separated_sha256, sha256_bytes,
    };

    fn fixture_label(fixture: &Path) -> String {
        format!("fixture `{}`", fixture.display())
    }

    fn read_fixture_bytes(fixture: &Path, path: &Path, operation: &str) -> Vec<u8> {
        fs::read(path).unwrap_or_else(|err| {
            panic!(
                "{}: {operation} (`{}`): {err}",
                fixture_label(fixture),
                path.display()
            )
        })
    }

    fn fixtures_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/vectors")
    }

    #[test]
    fn committed_vectors_match_the_rust_runtime() {
        for op in [
            "append",
            "export",
            "verify",
            "tamper",
            "projection",
            "shred",
        ] {
            for dir in vector_dirs(op) {
                assert_fixture_matches(&dir);
            }
        }
    }

    fn vector_dirs(op: &str) -> Vec<PathBuf> {
        let base = fixtures_root().join(op);
        let read_dir = fs::read_dir(&base).unwrap_or_else(|err| {
            panic!(
                "vector corpus discovery: read_dir `{}`: {err}",
                base.display()
            )
        });
        let mut dirs = read_dir
            .map(|entry| {
                entry
                    .unwrap_or_else(|err| {
                        panic!(
                            "vector corpus discovery: directory entry under `{}`: {err}",
                            base.display()
                        )
                    })
                    .path()
            })
            .filter(|path| path.is_dir() && path.join("manifest.toml").exists())
            .collect::<Vec<_>>();
        dirs.sort();
        dirs
    }

    fn assert_fixture_matches(root: &Path) {
        let manifest = manifest_for(root);
        // F6 — deprecated tombstones preserve the `<op>/NNN` prefix for the
        // R16 pre-merge guard but carry no replayable bytes; skip them.
        if manifest.get("status").and_then(toml::Value::as_str) == Some("deprecated") {
            return;
        }
        let op = manifest
            .get("op")
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("{}: manifest must name an `op` field", fixture_label(root)));

        match op {
            "append" => assert_append_fixture_matches(root, &manifest),
            "export" => assert_export_fixture_matches(root, &manifest),
            "verify" => assert_verify_fixture_matches(root, &manifest),
            "tamper" => assert_tamper_fixture_matches(root, &manifest),
            "projection" => assert_projection_fixture_matches(root, &manifest),
            "shred" => assert_shred_fixture_matches(root, &manifest),
            other => panic!("{}: unsupported vector op `{other}`", fixture_label(root)),
        }
    }

    fn manifest_for(dir: &Path) -> toml::Value {
        let path = dir.join("manifest.toml");
        let raw = fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!(
                "fixture `{}`: read manifest `{}`: {err}",
                dir.display(),
                path.display()
            )
        });
        toml::from_str(&raw).unwrap_or_else(|err| {
            panic!(
                "fixture `{}`: TOML parse `{}`: {err}",
                dir.display(),
                path.display()
            )
        })
    }

    fn assert_append_fixture_matches(root: &Path, manifest: &toml::Value) {
        let inputs = table(root, manifest, "inputs");
        let authored_event = read_fixture_bytes(
            root,
            &root.join(path_field(root, inputs, "authored_event")),
            "read authored_event",
        );
        let expected_author_hash = read_fixture_bytes(
            root,
            &root.join("author-event-hash.bin"),
            "read author-event-hash.bin",
        );
        let expected_canonical_event = read_fixture_bytes(
            root,
            &root.join("expected-event-payload.cbor"),
            "read expected-event-payload.cbor",
        );
        let expected_sig_structure = read_fixture_bytes(
            root,
            &root.join("sig-structure.bin"),
            "read sig-structure.bin",
        );
        let expected_signed_event = read_fixture_bytes(
            root,
            &root.join("expected-event.cbor"),
            "read expected-event.cbor",
        );
        let expected_append_head = read_fixture_bytes(
            root,
            &root.join("expected-append-head.cbor"),
            "read expected-append-head.cbor",
        );
        let signing_key = read_fixture_bytes(
            root,
            &root.join(signing_key_name(root, inputs)),
            "read signing key",
        );

        let mut store = MemoryStore::new();
        let artifacts = append_event(
            &mut store,
            &SigningKeyMaterial::new(signing_key),
            &AuthoredEvent::new(authored_event),
        )
        .unwrap();

        assert_eq!(
            artifacts.author_event_hash.as_slice(),
            expected_author_hash.as_slice()
        );
        assert_eq!(artifacts.canonical_event, expected_canonical_event);
        assert_eq!(artifacts.sig_structure, expected_sig_structure);
        assert_eq!(artifacts.signed_event, expected_signed_event);
        assert_eq!(artifacts.append_head, expected_append_head);
    }

    fn assert_export_fixture_matches(root: &Path, manifest: &toml::Value) {
        let inputs = table(root, manifest, "inputs");
        let expected = table(root, manifest, "expected");
        let ledger_state = decode_cbor_value(&read_fixture_bytes(
            root,
            &root.join(path_field(root, inputs, "ledger_state")),
            "read ledger_state",
        ))
        .unwrap();
        let ledger_state_map = ledger_state.as_map().unwrap();
        let root_dir = value_text(root, map_value(root, ledger_state_map, "root_dir"));
        let members = map_value(root, ledger_state_map, "members")
            .as_array()
            .unwrap();

        let mut package = Bundle::new();
        for member in members {
            let member_name = member.as_text().unwrap();
            package.add_entry(BundleEntry::new(
                format!("{root_dir}/{member_name}"),
                read_fixture_bytes(root, &root.join(member_name), "export package member"),
            ));
        }

        let actual = package.to_zip_bytes().unwrap();
        let expected_zip = read_fixture_bytes(
            root,
            &root.join(path_field(root, expected, "zip")),
            "read expected export zip",
        );
        assert_eq!(
            actual,
            expected_zip,
            "export ZIP mismatch at {}",
            root.display()
        );

        let vector_id = manifest
            .get("id")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        if vector_id == "export/001-two-event-chain" {
            let corpus_root = root.parent().unwrap().parent().unwrap();
            let writer_package = trellis_export_writer::write_export(
                trellis_export_writer::export_001_writer_input(corpus_root),
            )
            .unwrap_or_else(|err| {
                panic!(
                    "{}: export-writer corpus replay (`write_export`) failed: {err}",
                    fixture_label(root)
                )
            });
            assert_eq!(
                writer_package.zip_bytes,
                expected_zip,
                "{}: `Bundle::to_zip_bytes` oracle agreed with corpus, but `write_export` differed",
                fixture_label(root)
            );
        }
    }

    fn assert_verify_fixture_matches(root: &Path, manifest: &toml::Value) {
        let inputs = table(root, manifest, "inputs");
        let expected_report = table_in_table(root, table(root, manifest, "expected"), "report");
        let export_zip = read_fixture_bytes(
            root,
            &root.join(path_field(root, inputs, "export_zip")),
            "read export_zip",
        );
        let expected_kind = pathless_string(expected_report, "first_failure_kind");
        let expected_event_id = pathless_string(expected_report, "failing_event_id");
        if expected_kind.as_deref().is_some_and(is_wos_kind) {
            let report = trellis_verify_wos::verify_export_zip(&export_zip);
            assert_wos_report_matches(
                root,
                expected_report,
                &report,
                expected_kind.as_deref(),
                expected_event_id.as_deref(),
            );
            return;
        }
        let report = verify_export_zip(&export_zip);

        assert_eq!(
            report.structure_verified,
            bool_field(root, expected_report, "structure_verified"),
            "{}: structure_verified mismatch: {report:?}",
            fixture_label(root)
        );
        if report.integrity_verified && !bool_field(root, expected_report, "integrity_verified") {
            let wos_report = trellis_verify_wos::verify_export_zip(&export_zip);
            let combined_integrity = wos_integrity_verified(&wos_report);
            if !combined_integrity {
                assert_wos_report_matches(
                    root,
                    expected_report,
                    &wos_report,
                    None,
                    expected_event_id.as_deref(),
                );
                return;
            }
        }
        assert_eq!(
            report.integrity_verified,
            bool_field(root, expected_report, "integrity_verified")
        );
        assert_eq!(
            report.readability_verified,
            bool_field(root, expected_report, "readability_verified")
        );
        if let Some(expected_count) =
            optional_int_field(expected_report, "posture_transition_count")
        {
            assert_eq!(report.posture_transitions.len() as i64, expected_count);
        }
        if let Some(expected_kind) = expected_kind {
            assert_eq!(
                first_failure(&report).map(|failure| failure.kind.as_str()),
                Some(expected_kind.as_str()),
            );
        }
        if let Some(expected_loc) = pathless_string(expected_report, "failing_event_id") {
            assert_eq!(
                first_failure(&report).map(|failure| failure.location.as_str()),
                Some(expected_loc.as_str()),
            );
        }
    }

    fn assert_tamper_fixture_matches(root: &Path, manifest: &toml::Value) {
        let inputs = table(root, manifest, "inputs");
        let expected_report = table_in_table(root, table(root, manifest, "expected"), "report");
        let expected_tamper_kind = pathless_string(expected_report, "tamper_kind");
        let report = if inputs.contains_key("export_zip") {
            let export_zip = read_fixture_bytes(
                root,
                &root.join(path_field(root, inputs, "export_zip")),
                "read tamper export_zip",
            );
            if expected_tamper_kind.as_deref().is_some_and(is_wos_kind) {
                let report = trellis_verify_wos::verify_export_zip(&export_zip);
                let expected_event_id = pathless_string(expected_report, "failing_event_id");
                assert_wos_report_matches(
                    root,
                    expected_report,
                    &report,
                    expected_tamper_kind.as_deref(),
                    expected_event_id.as_deref(),
                );
                return;
            }
            verify_export_zip(&export_zip)
        } else if expected_tamper_kind.as_deref().is_some_and(is_wos_kind) {
            let signing_key_registry = read_fixture_bytes(
                root,
                &root.join(path_field(root, inputs, "signing_key_registry")),
                "read signing_key_registry",
            );
            let ledger = read_fixture_bytes(
                root,
                &root.join(path_field(root, inputs, "ledger")),
                "read ledger",
            );
            let initial_posture_declaration =
                optional_path_field(inputs, "initial_posture_declaration").map(|path| {
                    read_fixture_bytes(root, &root.join(path), "read initial_posture_declaration")
                });
            let posture_declaration = optional_path_field(inputs, "posture_declaration")
                .map(|path| read_fixture_bytes(root, &root.join(path), "read posture_declaration"));
            let report = trellis_verify_wos::verify_tampered_ledger(
                &signing_key_registry,
                &ledger,
                initial_posture_declaration.as_deref(),
                posture_declaration.as_deref(),
            )
            .unwrap();
            assert_wos_report_matches(
                root,
                expected_report,
                &report,
                expected_tamper_kind.as_deref(),
                pathless_string(expected_report, "failing_event_id").as_deref(),
            );
            return;
        } else {
            verify_tampered_ledger(
                &read_fixture_bytes(
                    root,
                    &root.join(path_field(root, inputs, "signing_key_registry")),
                    "read signing_key_registry",
                ),
                &read_fixture_bytes(
                    root,
                    &root.join(path_field(root, inputs, "ledger")),
                    "read ledger",
                ),
                optional_path_field(inputs, "initial_posture_declaration")
                    .map(|path| {
                        read_fixture_bytes(
                            root,
                            &root.join(path),
                            "read initial_posture_declaration",
                        )
                    })
                    .as_deref(),
                optional_path_field(inputs, "posture_declaration")
                    .map(|path| {
                        read_fixture_bytes(root, &root.join(path), "read posture_declaration")
                    })
                    .as_deref(),
            )
            .unwrap()
        };

        assert_eq!(
            report.structure_verified,
            bool_field(root, expected_report, "structure_verified")
        );
        assert_eq!(
            report.integrity_verified,
            bool_field(root, expected_report, "integrity_verified")
        );
        assert_eq!(
            report.readability_verified,
            bool_field(root, expected_report, "readability_verified")
        );

        if let Some(expected_kind) = expected_tamper_kind {
            assert_eq!(
                first_failure(&report).map(|failure| failure.kind.as_str()),
                Some(expected_kind.as_str()),
            );
        }
        if let Some(expected_event_id) = pathless_string(expected_report, "failing_event_id") {
            assert_eq!(
                first_failure(&report).map(|failure| failure.location.as_str()),
                Some(expected_event_id.as_str()),
            );
        }
    }

    fn assert_wos_report_matches(
        root: &Path,
        expected_report: &toml::value::Table,
        report: &trellis_verify_wos::WosVerificationReport,
        expected_kind: Option<&str>,
        expected_event_id: Option<&str>,
    ) {
        assert_eq!(
            report.trellis.structure_verified,
            bool_field(root, expected_report, "structure_verified")
        );
        let combined_integrity = wos_integrity_verified(report);
        assert_eq!(
            combined_integrity,
            bool_field(root, expected_report, "integrity_verified")
        );
        assert_eq!(
            report.trellis.readability_verified,
            bool_field(root, expected_report, "readability_verified")
        );
        if let Some(expected_kind) = expected_kind {
            // First check `wos_findings` (DomainFinding emitted from WOS
            // validators); fall back to Trellis-Core `event_failures` when
            // the kind is a Core-emitted failure routed through the WOS
            // path because the resolution required a WOS resolver
            // (e.g. `response_ref_mismatch`).
            let actual_kind = first_wos_failure(report)
                .map(|finding| finding.kind.as_str())
                .or_else(|| {
                    report
                        .trellis
                        .event_failures
                        .first()
                        .map(|failure| failure.kind.as_str())
                });
            assert_eq!(actual_kind, Some(expected_kind));
        }
        if let Some(expected_event_id) = expected_event_id {
            let actual_event_id = first_wos_failure(report)
                .and_then(|finding| finding.event_hash)
                .map(|hash| hex_string(&hash))
                .or_else(|| {
                    report
                        .trellis
                        .event_failures
                        .first()
                        .map(|failure| failure.location.clone())
                });
            assert_eq!(actual_event_id, Some(expected_event_id.to_string()));
        }
    }

    fn wos_integrity_verified(report: &trellis_verify_wos::WosVerificationReport) -> bool {
        report.trellis.integrity_verified && first_wos_failure(report).is_none()
    }

    fn first_wos_failure(
        report: &trellis_verify_wos::WosVerificationReport,
    ) -> Option<&trellis_verify_wos::WosFinding> {
        report
            .wos_findings
            .iter()
            .find(|finding| finding.severity == integrity_verify::trellis::Severity::Failure)
    }

    fn is_wos_kind(kind: &str) -> bool {
        matches!(
            kind,
            "case_created_event_type_mismatch"
                | "case_created_event_unresolved"
                | "case_created_handoff_mismatch"
                | "case_created_payload_invalid"
                | "case_created_payload_unreadable"
                | "clock_calendar_mismatch"
                | "intake_event_type_mismatch"
                | "intake_event_unresolved"
                | "intake_handoff_catalog_digest_mismatch"
                | "intake_handoff_catalog_duplicate_event"
                | "intake_handoff_catalog_invalid"
                | "intake_handoff_mismatch"
                | "intake_payload_invalid"
                | "intake_payload_unreadable"
                | "intake_response_hash_mismatch"
                | "malformed_response_digest"
                | "missing_intake_handoff_catalog"
                | "missing_signature_catalog"
                | "rescission_terminality_violation"
                | "response_ref_mismatch"
                | "signature_affirmation_payload_invalid"
                | "signature_affirmation_payload_unreadable"
                | "signature_catalog_digest_mismatch"
                | "signature_catalog_duplicate_event"
                | "signature_catalog_event_type_mismatch"
                | "signature_catalog_event_unresolved"
                | "signature_catalog_invalid"
                | "signature_catalog_mismatch"
        )
    }

    fn hex_string(bytes: &[u8]) -> String {
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
        }
        text
    }

    fn first_failure(
        report: &VerificationReport,
    ) -> Option<&integrity_verify::trellis::VerificationFailure> {
        report
            .event_failures
            .first()
            .or_else(|| report.checkpoint_failures.first())
            .or_else(|| report.proof_failures.first())
    }

    fn assert_projection_fixture_matches(root: &Path, manifest: &toml::Value) {
        let inputs = table(root, manifest, "inputs");
        let expected = table(root, manifest, "expected");

        if expected.contains_key("watermark") {
            let view = decode_cbor_value(&read_fixture_bytes(
                root,
                &root.join(path_field(root, inputs, "view")),
                "read view",
            ))
            .unwrap();
            let view_map = view.as_map().unwrap();
            let watermark = map_value(root, view_map, "watermark").clone();
            let watermark_bytes = encode_value(root, &watermark);
            assert_eq!(
                watermark_bytes,
                read_fixture_bytes(
                    root,
                    &root.join(path_field(root, expected, "watermark")),
                    "read expected watermark",
                )
            );

            let checkpoint_payload = sign1_payload_bytes(
                root,
                &read_fixture_bytes(
                    root,
                    &root.join(path_field(root, inputs, "checkpoint")),
                    "read checkpoint",
                ),
            );
            let checkpoint_payload_value = decode_cbor_value(&checkpoint_payload).unwrap();
            let checkpoint_scope =
                map_bytes(root, checkpoint_payload_value.as_map().unwrap(), "scope");
            let checkpoint_digest_bytes = checkpoint_digest(&checkpoint_scope, &checkpoint_payload);
            let watermark_map = watermark.as_map().unwrap();
            assert_eq!(
                map_fixed_bytes(root, watermark_map, "checkpoint_ref", 32),
                checkpoint_digest_bytes.to_vec(),
            );

            if expected.contains_key("staff_view_decision_binding") {
                let fields = table(root, manifest, "staff_view_decision_binding_fields");
                let binding = Value::Map(vec![
                    (Value::Text("watermark".into()), watermark.clone()),
                    (
                        Value::Text("extensions".into()),
                        if pathless_string(fields, "extensions").as_deref() == Some("null") {
                            Value::Null
                        } else {
                            unreachable!("current staff-view vector pins null extensions")
                        },
                    ),
                    (
                        Value::Text("staff_view_ref".into()),
                        Value::Text(pathless_string(fields, "staff_view_ref").unwrap()),
                    ),
                    (
                        Value::Text("stale_acknowledged".into()),
                        Value::Bool(bool_field(root, fields, "stale_acknowledged")),
                    ),
                ]);
                assert_eq!(
                    encode_value(root, &binding),
                    read_fixture_bytes(
                        root,
                        &root.join(path_field(root, expected, "staff_view_decision_binding",)),
                        "read staff_view_decision_binding",
                    )
                );
            }
        }

        if expected.contains_key("view_rebuilt") {
            let chain = decode_cbor_value(&read_fixture_bytes(
                root,
                &root.join(path_field(root, inputs, "chain")),
                "read chain",
            ))
            .unwrap();
            let events = chain.as_array().unwrap();
            let last_payload = decode_cbor_value(&sign1_payload_bytes_from_value(
                root,
                events.last().unwrap(),
            ))
            .unwrap();
            let last_payload_map = last_payload.as_map().unwrap();
            let scope = map_bytes(root, last_payload_map, "ledger_scope");
            let canonical_hash = domain_separated_sha256(
                EVENT_DOMAIN,
                &canonical_event_hash_preimage(
                    &scope,
                    &sign1_payload_bytes_from_value(root, events.last().unwrap()),
                ),
            );
            let rebuilt = Value::Map(vec![
                (
                    Value::Text("event_count".into()),
                    Value::Integer((events.len() as u64).into()),
                ),
                (
                    Value::Text("last_canonical_event_hash".into()),
                    Value::Bytes(canonical_hash.to_vec()),
                ),
            ]);
            let rebuilt_bytes = encode_value(root, &rebuilt);
            assert_eq!(
                rebuilt_bytes,
                read_fixture_bytes(
                    root,
                    &root.join(path_field(root, expected, "view_rebuilt")),
                    "read view_rebuilt",
                )
            );
            assert_eq!(
                rebuilt_bytes,
                read_fixture_bytes(
                    root,
                    &root.join(path_field(root, inputs, "view")),
                    "read view (rebuilt parity)",
                )
            );
        }

        if expected.contains_key("cadence_report") {
            let cadence = table(root, manifest, "cadence");
            let observed = table_paths(root, inputs, "checkpoints")
                .into_iter()
                .map(|path| {
                    let payload = sign1_payload_bytes(
                        root,
                        &read_fixture_bytes(root, &root.join(path), "read checkpoint chain"),
                    );
                    let payload_value = decode_cbor_value(&payload).unwrap();
                    map_u64(root, payload_value.as_map().unwrap(), "tree_size")
                })
                .collect::<Vec<_>>();
            let required = integer_array(root, cadence, "required_tree_sizes");
            let missing = required
                .iter()
                .copied()
                .filter(|value| !observed.contains(value))
                .collect::<Vec<_>>();
            let report = Value::Map(vec![
                (
                    Value::Text("interval".into()),
                    Value::Integer((int_field(root, cadence, "interval")).into()),
                ),
                (
                    Value::Text("cadence_kind".into()),
                    Value::Text(pathless_string(cadence, "kind").unwrap()),
                ),
                (
                    Value::Text("failure_code".into()),
                    match pathless_string(cadence, "failure_code") {
                        Some(value) => Value::Text(value),
                        None => Value::Null,
                    },
                ),
                (
                    Value::Text("cadence_satisfied".into()),
                    Value::Bool(!bool_field(root, cadence, "expect_failure")),
                ),
                (
                    Value::Text("missing_tree_sizes".into()),
                    Value::Array(
                        missing
                            .iter()
                            .map(|value| Value::Integer((*value).into()))
                            .collect(),
                    ),
                ),
                (
                    Value::Text("expected_tree_sizes".into()),
                    Value::Array(
                        required
                            .iter()
                            .map(|value| Value::Integer((*value).into()))
                            .collect(),
                    ),
                ),
                (
                    Value::Text("observed_tree_sizes".into()),
                    Value::Array(
                        observed
                            .iter()
                            .map(|value| Value::Integer((*value).into()))
                            .collect(),
                    ),
                ),
            ]);
            assert_eq!(
                encode_value(root, &report),
                read_fixture_bytes(
                    root,
                    &root.join(path_field(root, expected, "cadence_report")),
                    "read cadence_report",
                )
            );
        }
    }

    fn assert_shred_fixture_matches(root: &Path, manifest: &toml::Value) {
        let inputs = table(root, manifest, "inputs");
        let expected = table(root, manifest, "expected");
        let procedure = table(root, manifest, "procedure");
        let chain = decode_cbor_value(&read_fixture_bytes(
            root,
            &root.join(path_field(root, inputs, "chain")),
            "read chain",
        ))
        .unwrap();
        let events = chain.as_array().unwrap();
        let target_event_payload =
            decode_cbor_value(&sign1_payload_bytes_from_value(root, &events[0])).unwrap();
        let target_content_hash = map_fixed_bytes(
            root,
            target_event_payload.as_map().unwrap(),
            "content_hash",
            32,
        );

        let declared_scope = table_paths_as_strings(root, procedure, "cascade_scope");
        let mut report_entries = vec![(
            Value::Text("declared_scope".into()),
            Value::Array(declared_scope.iter().cloned().map(Value::Text).collect()),
        )];

        if let Some(snapshot_path) = optional_path_field(inputs, "backup_snapshot") {
            let snapshot_bytes =
                read_fixture_bytes(root, &root.join(snapshot_path), "read backup_snapshot");
            report_entries.push((
                Value::Text("backup_snapshot_ref".into()),
                Value::Bytes(sha256_bytes(&snapshot_bytes).to_vec()),
            ));
        }

        report_entries.push((
            Value::Text("expected_post_state".into()),
            Value::Map(
                declared_scope
                    .into_iter()
                    .map(|scope| {
                        let state = if inputs.contains_key("backup_snapshot") {
                            Value::Map(vec![
                                (
                                    Value::Text("rationale".into()),
                                    Value::Text(format!(
                                        "{scope}-backup-restore-refused-per-§16.5"
                                    )),
                                ),
                                (
                                    Value::Text("backup_resurrection_refused".into()),
                                    Value::Bool(true),
                                ),
                                (
                                    Value::Text("invalidated_or_plaintext_absent".into()),
                                    Value::Bool(true),
                                ),
                            ])
                        } else {
                            Value::Map(vec![
                                (
                                    Value::Text("rationale".into()),
                                    Value::Text(format!("{scope}-in-declared-cascade-scope")),
                                ),
                                (
                                    Value::Text("invalidated_or_plaintext_absent".into()),
                                    Value::Bool(true),
                                ),
                            ])
                        };
                        (Value::Text(scope), state)
                    })
                    .collect(),
            ),
        ));
        report_entries.push((
            Value::Text("target_content_hash".into()),
            Value::Bytes(target_content_hash.clone()),
        ));

        let report = Value::Map(report_entries);
        assert_eq!(
            encode_value(root, &report),
            read_fixture_bytes(
                root,
                &root.join(path_field(root, expected, "cascade_report")),
                "read cascade_report",
            )
        );
    }

    fn signing_key_name<'a>(fixture: &Path, inputs: &'a toml::value::Table) -> &'a str {
        optional_path_field(inputs, "signing_key")
            .or_else(|| optional_path_field(inputs, "signing_key_b"))
            .unwrap_or_else(|| {
                panic!(
                    "{}: append manifest must name `signing_key` or `signing_key_b`",
                    fixture_label(fixture)
                )
            })
    }

    fn table<'a>(fixture: &Path, value: &'a toml::Value, key: &str) -> &'a toml::value::Table {
        value
            .get(key)
            .and_then(toml::Value::as_table)
            .unwrap_or_else(|| panic!("{}: manifest missing `{key}` table", fixture_label(fixture)))
    }

    fn table_in_table<'a>(
        fixture: &Path,
        table: &'a toml::value::Table,
        key: &str,
    ) -> &'a toml::value::Table {
        table
            .get(key)
            .and_then(toml::Value::as_table)
            .unwrap_or_else(|| {
                panic!(
                    "{}: manifest missing `{key}` nested table",
                    fixture_label(fixture)
                )
            })
    }

    fn path_field<'a>(fixture: &Path, table: &'a toml::value::Table, key: &str) -> &'a str {
        table
            .get(key)
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "{}: manifest missing string field `{key}`",
                    fixture_label(fixture)
                )
            })
    }

    fn optional_path_field<'a>(table: &'a toml::value::Table, key: &str) -> Option<&'a str> {
        table.get(key).and_then(toml::Value::as_str)
    }

    fn bool_field(fixture: &Path, table: &toml::value::Table, key: &str) -> bool {
        table
            .get(key)
            .and_then(toml::Value::as_bool)
            .unwrap_or_else(|| panic!("{}: manifest missing bool `{key}`", fixture_label(fixture)))
    }

    fn int_field(fixture: &Path, table: &toml::value::Table, key: &str) -> i64 {
        table
            .get(key)
            .and_then(toml::Value::as_integer)
            .unwrap_or_else(|| {
                panic!(
                    "{}: manifest missing integer `{key}`",
                    fixture_label(fixture)
                )
            })
    }

    fn optional_int_field(table: &toml::value::Table, key: &str) -> Option<i64> {
        table.get(key).and_then(toml::Value::as_integer)
    }

    fn pathless_string(table: &toml::value::Table, key: &str) -> Option<String> {
        table
            .get(key)
            .and_then(toml::Value::as_str)
            .map(ToOwned::to_owned)
    }

    fn table_paths(fixture: &Path, table: &toml::value::Table, key: &str) -> Vec<String> {
        table
            .get(key)
            .and_then(toml::Value::as_array)
            .unwrap_or_else(|| panic!("{}: manifest missing `{key}` array", fixture_label(fixture)))
            .iter()
            .map(|value| {
                value.as_str().unwrap_or_else(|| {
                    panic!(
                        "{}: `{key}` array entries must be strings",
                        fixture_label(fixture)
                    )
                })
            })
            .map(ToOwned::to_owned)
            .collect()
    }

    fn table_paths_as_strings(
        fixture: &Path,
        table: &toml::value::Table,
        key: &str,
    ) -> Vec<String> {
        table_paths(fixture, table, key)
    }

    fn integer_array(fixture: &Path, table: &toml::value::Table, key: &str) -> Vec<u64> {
        table
            .get(key)
            .and_then(toml::Value::as_array)
            .unwrap_or_else(|| {
                panic!(
                    "{}: manifest missing `{key}` integer array",
                    fixture_label(fixture)
                )
            })
            .iter()
            .map(|value| {
                value.as_integer().unwrap_or_else(|| {
                    panic!(
                        "{}: `{key}` array entries must be integers",
                        fixture_label(fixture)
                    )
                }) as u64
            })
            .collect()
    }

    fn encode_value(fixture: &Path, value: &Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes)
            .unwrap_or_else(|err| panic!("{}: CBOR encode: {err}", fixture_label(fixture)));
        bytes
    }

    fn sign1_payload_bytes(fixture: &Path, bytes: &[u8]) -> Vec<u8> {
        let decoded = decode_cbor_value(bytes).unwrap_or_else(|err| {
            panic!(
                "{}: decode Sign1 wrapper CBOR: {err}",
                fixture_label(fixture)
            )
        });
        sign1_payload_value(fixture, &decoded)
            .as_bytes()
            .unwrap_or_else(|| {
                panic!(
                    "{}: Sign1 payload field is not bytes",
                    fixture_label(fixture)
                )
            })
            .clone()
    }

    fn sign1_payload_bytes_from_value(fixture: &Path, value: &Value) -> Vec<u8> {
        sign1_payload_value(fixture, value)
            .as_bytes()
            .unwrap_or_else(|| {
                panic!(
                    "{}: Sign1 payload field is not bytes",
                    fixture_label(fixture)
                )
            })
            .clone()
    }

    fn sign1_payload_value<'a>(fixture: &Path, value: &'a Value) -> &'a Value {
        match value {
            Value::Tag(18, inner) => {
                let items = inner.as_array().unwrap_or_else(|| {
                    panic!(
                        "{}: Sign1 tag payload must be a CBOR array",
                        fixture_label(fixture)
                    )
                });
                items.get(2).unwrap_or_else(|| {
                    panic!(
                        "{}: Sign1 array too short (missing payload at index 2)",
                        fixture_label(fixture)
                    )
                })
            }
            _ => panic!(
                "{}: expected tag-18 COSE_Sign1 value",
                fixture_label(fixture)
            ),
        }
    }

    fn map_value<'a>(fixture: &Path, map: &'a [(Value, Value)], key: &str) -> &'a Value {
        map.iter()
            .find(|(candidate, _)| candidate.as_text().is_some_and(|text| text == key))
            .map(|(_, value)| value)
            .unwrap_or_else(|| panic!("{}: CBOR map missing key `{key}`", fixture_label(fixture)))
    }

    fn value_text(fixture: &Path, value: &Value) -> String {
        value
            .as_text()
            .unwrap_or_else(|| panic!("{}: expected CBOR text value", fixture_label(fixture)))
            .to_string()
    }

    fn map_bytes(fixture: &Path, map: &[(Value, Value)], key: &str) -> Vec<u8> {
        map_value(fixture, map, key)
            .as_bytes()
            .unwrap_or_else(|| panic!("{}: map[{key}] is not bytes", fixture_label(fixture)))
            .clone()
    }

    fn map_fixed_bytes(
        fixture: &Path,
        map: &[(Value, Value)],
        key: &str,
        expected_len: usize,
    ) -> Vec<u8> {
        let bytes = map_bytes(fixture, map, key);
        assert_eq!(bytes.len(), expected_len);
        bytes
    }

    fn map_u64(fixture: &Path, map: &[(Value, Value)], key: &str) -> u64 {
        map_value(fixture, map, key)
            .as_integer()
            .and_then(|value| value.try_into().ok())
            .unwrap_or_else(|| {
                panic!(
                    "{}: map[{key}] is not a UInt-compatible integer",
                    fixture_label(fixture)
                )
            })
    }
}
