// Rust guideline compliant 2026-02-21
//! Trellis substrate HTTP service.
//!
//! The service is the composition root between product-facing HTTP append
//! calls and Trellis Core byte construction. Consumers share the
//! `trellis-service-client` wire DTOs; this crate owns admission,
//! authorization, persistence, export publication, and registry reads.
//!
//! Axum routing is exposed via [`router`]; durable bootstrap and HTTP replay state via
//! [`TrellisServerState`] / [`state_from_env`] (implemented in `src/http.rs` and `src/state.rs`).
//! This file remains a large composition root (profile dispatch, bundle publication, CBOR/registry
//! helpers, and related tests), not a thin re-export-only façade.
//!
//! **HTTP replay idempotency** is enforced only through
//! [`stack_common_idempotency::InMemoryHttpReplayStore`] wired into
//! [`stack_common_http::idempotency::HttpIdempotencyState`] middleware (ADR
//! 0092c). There is no parallel `IdempotencyStore` port in `trellis-server-ports`.
//!
//! **Governance overlay (TWREF-064):** `wos-server` may restrict which WOS literals it emits
//! over HTTP before calling Trellis, while Trellis admits the union of WOS registry
//! literals plus Formspec append dialect subjects to admission policy. Bearer
//! credentials targeting Trellis are the substrate trust root: durable non-permissive
//! startups require HS256 JWTs whose `scopes` claim authorizes the URL scope (TWREF-022);
//! dev/demo may use `TRELLIS_STORAGE=memory` or `TRELLIS_PERMISSIVE_SCOPE_AUTH=1` for allow-all scope checks.
//!
//! **Case scope versus Trellis URL scope (TWREF-005):** Admission here keys off `event_type` and payload shape for the
//! HTTP `{scope}` segment plus tenant headers. It does not fetch WOS case relationship rows; product servers must map
//! their governed case identity into scope and credentials deliberately. Formspec and WOS append dialects share the
//! same route but diverge in `RoutedEventAdmissionPolicy` on the `substrate.append.*` prefix versus `wos.*` literals.

#![forbid(unsafe_code)]

mod admission;
mod append;
mod artifacts;
mod composition;
mod event_repository;
mod http;
pub mod openapi;
mod scope_startup;
mod state;

#[doc(inline)]
pub use composition::{AdmissionRouter, default_admission_policy};

use artifacts::BundleRecord;

#[doc(inline)]
pub use event_repository::{EventRepository, InMemoryEventRepository, PostgresEventRepository};
#[doc(inline)]
pub use scope_startup::TrellisScopeAuthorizerStartupInputs;

#[doc(inline)]
pub use openapi::TrellisServerOpenApi;

#[doc(inline)]
pub use http::router;
#[doc(inline)]
pub use state::{TrellisServerState, state_from_env};

#[cfg(feature = "test-harness")]
pub mod test_harness;

use std::time::{SystemTime, UNIX_EPOCH};

use integrity_cbor::{
    CborHelperError, Value, domain_separated_sha256, map_lookup_bytes, map_lookup_fixed_bytes,
    map_lookup_map,
};
use serde::{Deserialize, Serialize};
use stack_common_auth::{BaseClaims, Claims};
use stack_common_error::StackError;
use trellis_cddl::canonical_event_hash_preimage;
use trellis_core::SigningKeyMaterial as CoreSigningKey;
use trellis_export_writer::{
    ExportWriterInput, RegistrySnapshot as ExportRegistrySnapshot,
    SigningKeyMaterial as ExportSigningKey, TrellisTimestamp, write_export,
};
use trellis_service_client::{ComputeContext, SubstrateAppendResult, VerificationReceipt};
use trellis_types::{ArtifactType, EVENT_DOMAIN, StoredEvent};

use crate::openapi::EventTypeRegistryView;

/// Formspec intake proof append event literal admitted at the service edge.
pub use composition::FORMSPEC_RESPONSE_SUBMITTED;
// Catalog version label is producer-neutral after DI-001/DI-002: the catalog
// projects both WOS and Formspec admitted literals through `composition`. The
// old `wos-events:` namespace was misleading once Formspec joined the catalog.
const EVENT_TYPE_REGISTRY_VERSION: &str = "trellis-events:2026-05-15";
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8080";

#[must_use]
pub const fn default_bind_addr() -> &'static str {
    DEFAULT_BIND_ADDR
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TenantHeaderMode {
    Wos,
    Formspec,
    MultiProducer,
}

/// Server-owned JWT claims for optional service auth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrellisClaims {
    #[serde(flatten)]
    pub base: BaseClaims,
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl Claims for TrellisClaims {
    fn base(&self) -> &BaseClaims {
        &self.base
    }
}

/// Parsed signing material shared by append and export paths.
#[derive(Clone, Debug)]
pub struct ServerSigningKey {
    cose_key: Vec<u8>,
    export_key: ExportSigningKey,
    valid_to: Option<TrellisTimestamp>,
}

impl ServerSigningKey {
    /// Parses Ed25519 COSE_Key bytes.
    ///
    /// # Errors
    /// Returns an error when the key cannot be decoded as Trellis Ed25519
    /// signing material.
    pub fn from_cose_key_bytes(
        cose_key: Vec<u8>,
        valid_from: TrellisTimestamp,
    ) -> Result<Self, StackError> {
        let parsed = trellis_cddl::parse_ed25519_cose_key(&cose_key)
            .map_err(|error| StackError::bad_request(format!("invalid signing key: {error}")))?;
        Ok(Self {
            cose_key,
            export_key: ExportSigningKey {
                private_seed: parsed.private_seed,
                public_key: parsed.public_key,
                valid_from,
                valid_to: None,
            },
            valid_to: None,
        })
    }

    #[must_use]
    pub fn with_valid_to(mut self, valid_to: Option<TrellisTimestamp>) -> Self {
        self.valid_to = valid_to;
        self.export_key.valid_to = valid_to;
        self
    }

    #[must_use]
    pub fn is_active_at(&self, timestamp: TrellisTimestamp) -> bool {
        self.valid_to
            .map(|valid_to| {
                (timestamp.unix_secs, timestamp.subsec_nanos)
                    <= (valid_to.unix_secs, valid_to.subsec_nanos)
            })
            .unwrap_or(true)
    }

    pub(crate) fn core_key(&self) -> CoreSigningKey {
        CoreSigningKey::new(self.cose_key.clone())
    }

    fn export_key(&self) -> ExportSigningKey {
        self.export_key.clone()
    }
}

/// Returns true when the export ZIP passes the same independent verifier used in conformance.
#[must_use]
pub(crate) fn export_bundle_cryptographically_verified(zip_bytes: &[u8]) -> bool {
    let report = integrity_verify::trellis::verify_export_zip(zip_bytes);
    report.structure_verified && report.integrity_verified
}

pub(crate) async fn publish_bundle(
    state: &TrellisServerState,
    scope: &[u8],
    events: &[StoredEvent],
    update_head: bool,
    compute: &ComputeContext,
) -> Result<BundleRecord, StackError> {
    if events.is_empty() {
        return Err(StackError::not_found("scope has no events"));
    }
    let timestamps = events
        .iter()
        .map(event_timestamp)
        .collect::<Result<Vec<_>, _>>()?;
    let generated_at = timestamps
        .last()
        .copied()
        .ok_or_else(|| StackError::internal("empty timestamp set"))?;
    let registry_bytes = event_type_registry_cbor(state.event_type_catalog.as_ref())?;
    let package = write_export(ExportWriterInput {
        scope: scope.to_vec(),
        events: events.to_vec(),
        registries: vec![ExportRegistrySnapshot {
            bytes: registry_bytes,
            registry_format: 1,
            registry_version: EVENT_TYPE_REGISTRY_VERSION.to_string(),
            bound_at_sequence: 0,
        }],
        signing_key: state.signing_key.export_key(),
        generator: "trellis-server".to_string(),
        generated_at,
        checkpoint_timestamps: timestamps,
        posture_declaration: append::export_posture_from_compute(compute),
        omitted_payload_checks: Vec::new(),
        readme_title: format!("Trellis export for {}", String::from_utf8_lossy(scope)),
        root_dir_override: None,
        external_anchors: Vec::new(),
        extensions: None,
        witness_key_registry: None,
    })?;
    let checkpoint_digest = format!("sha256:{}", hex::encode(package.head_checkpoint_digest));
    let key = format!(
        "{}/bundles/{}.zip",
        encode_path_segment(&String::from_utf8_lossy(scope)),
        checkpoint_digest.trim_start_matches("sha256:")
    );
    if !export_bundle_cryptographically_verified(&package.zip_bytes) {
        return Err(StackError::internal(
            "published export bundle failed independent verification",
        ));
    }
    let artifact_ref = state.artifact_store.put(&key, &package.zip_bytes).await?;
    let record = BundleRecord {
        checkpoint_digest,
        artifact_ref,
    };
    state
        .bundles
        .insert_published_record(scope, &record, update_head)
        .await;
    Ok(record)
}

pub(crate) fn append_result_for_event(
    scope: &str,
    event: &StoredEvent,
    artifact_type: ArtifactType,
    event_type: &str,
    bundle: &BundleRecord,
    export_verified: bool,
) -> Result<SubstrateAppendResult, StackError> {
    let canonical_hash = event_hash(scope.as_bytes(), event)?;
    let hash_hex = hex::encode(canonical_hash);
    Ok(SubstrateAppendResult {
        event_id: format!("evt_{}", &hash_hex[..16]),
        sequence: event.sequence(),
        canonical_event_hash: format!("sha256:{hash_hex}"),
        checkpoint_ref: format!("trellis://{scope}/checkpoints/{}", bundle.checkpoint_digest),
        bundle_ref: bundle.artifact_ref.uri.clone(),
        verification_receipt: VerificationReceipt {
            verified: export_verified,
            artifact_type,
            event_type: event_type.to_string(),
        },
    })
}

pub(crate) fn validate_existing_replay(
    event: &StoredEvent,
    event_type: &str,
    content_hash: [u8; 32],
) -> Result<(), StackError> {
    let summary = event_summary(event)?;
    if summary.event_type != event_type {
        return Err(StackError::conflict(
            "idempotency key reused with a different event type",
        ));
    }
    if summary.content_hash != content_hash {
        return Err(StackError::conflict(
            "idempotency key reused with a different payload",
        ));
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct EventSummary {
    event_type: String,
    content_hash: [u8; 32],
    authored_at: TrellisTimestamp,
}

fn event_summary(event: &StoredEvent) -> Result<EventSummary, StackError> {
    let value = integrity_cbor::decode_cbor_value(event.canonical_event()).map_err(|error| {
        StackError::bad_request(format!("canonical event decode failed: {error}"))
    })?;
    let map = value
        .as_map()
        .ok_or_else(|| StackError::bad_request("canonical event is not a map"))?;
    let content_hash = map_lookup_fixed_bytes(map, "content_hash", 32)
        .map_err(cbor_bad_request)?
        .try_into()
        .map_err(|_| StackError::internal("content_hash length changed"))?;
    let header = map_lookup_map(map, "header").map_err(cbor_bad_request)?;
    let event_type =
        String::from_utf8(map_lookup_bytes(header, "event_type").map_err(cbor_bad_request)?)
            .map_err(|_| StackError::bad_request("event_type is not UTF-8"))?;
    let authored_at = timestamp_from_header(header)?;
    Ok(EventSummary {
        event_type,
        content_hash,
        authored_at,
    })
}

fn event_timestamp(event: &StoredEvent) -> Result<TrellisTimestamp, StackError> {
    event_summary(event).map(|summary| summary.authored_at)
}

pub(crate) fn event_hash(scope: &[u8], event: &StoredEvent) -> Result<[u8; 32], StackError> {
    if let Some(hash) = event.canonical_event_hash() {
        return Ok(*hash);
    }
    Ok(domain_separated_sha256(
        EVENT_DOMAIN,
        &canonical_event_hash_preimage(scope, event.canonical_event()),
    ))
}

fn timestamp_from_header(map: &[(Value, Value)]) -> Result<TrellisTimestamp, StackError> {
    let value = integrity_cbor::map_lookup_value(map, "authored_at").map_err(cbor_bad_request)?;
    let Value::Array(items) = value else {
        return Err(StackError::bad_request(
            "authored_at is not a timestamp array",
        ));
    };
    if items.len() != 2 {
        return Err(StackError::bad_request(
            "authored_at timestamp length is invalid",
        ));
    }
    let seconds = value_to_u64(&items[0], "authored_at seconds")?;
    let nanos = value_to_u64(&items[1], "authored_at nanos")?;
    let nanos = u32::try_from(nanos)
        .map_err(|_| StackError::bad_request("authored_at nanos exceeds u32"))?;
    TrellisTimestamp::new(seconds, nanos)
}

fn value_to_u64(value: &Value, label: &str) -> Result<u64, StackError> {
    let Value::Integer(integer) = value else {
        return Err(StackError::bad_request(format!(
            "{label} is not an integer"
        )));
    };
    u64::try_from(*integer)
        .map_err(|_| StackError::bad_request(format!("{label} is negative or too large")))
}

pub(crate) fn now_timestamp() -> Result<TrellisTimestamp, StackError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| StackError::internal(format!("system clock before epoch: {error}")))?;
    TrellisTimestamp::new(duration.as_secs(), duration.subsec_nanos())
}

pub(crate) fn timestamp_value(timestamp: TrellisTimestamp) -> Value {
    Value::Array(vec![
        uint(timestamp.unix_secs),
        uint(u64::from(timestamp.subsec_nanos)),
    ])
}

pub(crate) fn event_type_registry_view(
    catalog: &composition::EventTypeCatalog,
) -> EventTypeRegistryView {
    EventTypeRegistryView {
        registry_version: EVENT_TYPE_REGISTRY_VERSION.to_string(),
        event_types: catalog
            .entries()
            .map(|entry| crate::openapi::EventTypeRegistryEntry {
                event_type: entry.event_type.clone(),
                schema_ref: entry.schema_ref.as_str().to_string(),
            })
            .collect(),
    }
}

fn event_type_registry_cbor(
    catalog: &composition::EventTypeCatalog,
) -> Result<Vec<u8>, StackError> {
    const SERVICE_CLASSIFICATION: &str = "x-trellis-service/public-metadata";
    let mut event_types = Vec::new();
    for entry in catalog.entries() {
        let map_entry = text_map(vec![
            ("privacy_class", Value::Text("publicMetadata".to_string())),
            (
                "binding_family",
                Value::Text(entry.event_family.as_str().to_string()),
            ),
        ])?;
        event_types.push((Value::Text(entry.event_type.clone()), map_entry));
    }
    let registry = text_map(vec![
        ("event_types", Value::Map(event_types)),
        (
            "classifications",
            Value::Array(vec![Value::Text(SERVICE_CLASSIFICATION.to_string())]),
        ),
        (
            "registry_version",
            Value::Text(EVENT_TYPE_REGISTRY_VERSION.to_string()),
        ),
    ])?;
    encode_value(&registry)
}

pub(crate) fn signing_key_registry_cbor(
    signing_key: &ExportSigningKey,
) -> Result<Vec<u8>, StackError> {
    let entry = text_map(vec![
        ("kid", Value::Bytes(signing_key.kid().to_vec())),
        ("pubkey", Value::Bytes(signing_key.public_key.to_vec())),
        ("suite_id", uint(1)),
        ("status", uint(0)),
        ("valid_from", timestamp_value(signing_key.valid_from)),
        (
            "valid_to",
            signing_key.valid_to.map_or(Value::Null, timestamp_value),
        ),
        ("supersedes", Value::Null),
        ("attestation", Value::Null),
    ])?;
    encode_value(&Value::Array(vec![entry]))
}

pub(crate) fn text_map(fields: Vec<(&str, Value)>) -> Result<Value, StackError> {
    canonical_map(
        fields
            .into_iter()
            .map(|(key, value)| (Value::Text(key.to_string()), value))
            .collect(),
    )
}

fn canonical_map(fields: Vec<(Value, Value)>) -> Result<Value, StackError> {
    let mut fields = fields
        .into_iter()
        .map(|(key, value)| {
            let encoded = encode_value(&key)?;
            Ok((encoded, key, value))
        })
        .collect::<Result<Vec<_>, StackError>>()?;
    fields.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(Value::Map(
        fields
            .into_iter()
            .map(|(_, key, value)| (key, value))
            .collect(),
    ))
}

pub(crate) fn encode_value(value: &Value) -> Result<Vec<u8>, StackError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map_err(|error| StackError::internal(format!("failed to encode CBOR: {error}")))?;
    Ok(bytes)
}

pub(crate) fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn cbor_bad_request(error: CborHelperError) -> StackError {
    StackError::bad_request(error.to_string())
}

fn encode_path_segment(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            other => {
                out.push('%');
                out.push(hex_digit(other >> 4));
                out.push(hex_digit(other & 0x0f));
            }
        }
    }
    out
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'A' + (value - 10)) as char,
        _ => unreachable!("nibble is in range"),
    }
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use integrity_seam::OsSecureRandom;
    use jsonwebtoken::Algorithm;
    use stack_common_auth::{JwtConfig, JwtIssuer, JwtVerifier};
    use stack_common_http::idempotency::{IDEMPOTENCY_KEY_HEADER, IDEMPOTENCY_REPLAY_HEADER};
    use stack_common_ops::HealthProbe;
    use tower::ServiceExt;
    use trellis_server_ports::{AdmissionEvent, ArtifactRef};
    use trellis_service_client::{ClientAttestation, SubstrateAppendBody};
    use wos_events::{ProvenanceKind, ProvenanceRecord, WOS_CANONICAL_EVENT_LITERALS};

    use crate::admission::ScopedAllowlistScopeAuthorizer;
    use crate::append::{AppendRunner, DefaultAppendRunner};
    use crate::state::TrellisHealthProbe;

    use std::fs;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use axum::http::StatusCode;
    use trellis_server_ports::{ArtifactStore, EventAdmissionPolicy};

    use super::*;

    #[derive(Clone)]
    struct RecordingAppendRunner {
        /// Increments for each `AppendRunner::run_append` entry (HTTP → orchestration seam).
        invocations: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl AppendRunner for RecordingAppendRunner {
        async fn run_append(
            &self,
            state: &TrellisServerState,
            command: append::AppendCommand,
        ) -> Result<append::AppendOutcome, StackError> {
            self.invocations.fetch_add(1, Ordering::SeqCst);
            DefaultAppendRunner.run_append(state, command).await
        }
    }

    /// Given a Trellis router built with an injected append runner probe, when `POST …/events`
    /// succeeds, then the HTTP handler routed through `AppendRunner` exactly once (TWREF-021:
    /// orchestration is not inlined past the outer HTTP/auth boundary).
    #[tokio::test]
    async fn given_fresh_append_when_http_post_then_append_runner_records_single_coordinator_pass()
    {
        // Given: Axum state substitutes [`RecordingAppendRunner`] ahead of [`DefaultAppendRunner`].
        let invocations = Arc::new(AtomicUsize::new(0));
        let runner = Arc::new(RecordingAppendRunner {
            invocations: invocations.clone(),
        });
        let app = router(test_state().with_append_runner(runner)).expect("router");

        // When: Client posts a valid append body.
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                append_body("idem-append-runner-delegation"),
            ))
            .await
            .expect("append response");

        // Then: Handler invoked the injected runner once; coordinator path executed underneath.
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            invocations.load(Ordering::SeqCst),
            1,
            "POST append must delegate through AppendRunner (AppendCoordinator) rather than inlining orchestration"
        );
    }

    /// Given a fresh append, when the HTTP handler runs, then admission executes
    /// exactly once inside the append coordinator (not duplicated in the handler).
    #[tokio::test]
    async fn given_fresh_append_when_http_post_then_admission_runs_once_in_coordinator() {
        let admission_calls = Arc::new(AtomicUsize::new(0));
        let inner = default_admission_policy();
        let counting = Arc::new(CountingAdmissionPolicy {
            inner,
            calls: admission_calls.clone(),
        });
        let app = router(test_state().with_admission_policy(counting)).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                append_body("idem-coordinator-admission"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            admission_calls.load(Ordering::SeqCst),
            1,
            "append coordinator must call admission exactly once per fresh append"
        );
    }

    /// Given a ledger idempotency replay, when the coordinator runs again with the
    /// same key, then admission runs once per pass and the sequence is unchanged.
    #[tokio::test]
    async fn given_ledger_idempotency_replay_when_coordinator_runs_then_admission_once_per_pass() {
        let admission_calls = Arc::new(AtomicUsize::new(0));
        let inner = default_admission_policy();
        let counting = Arc::new(CountingAdmissionPolicy {
            inner,
            calls: admission_calls.clone(),
        });
        let state = test_state().with_admission_policy(counting);
        let body: SubstrateAppendBody =
            serde_json::from_slice(&append_body("idem-coordinator-replay")).unwrap();
        let command = append::AppendCommand {
            scope: "case_123".to_string(),
            event_type: body.event_type.clone(),
            idempotency_key: body.idempotency_key.clone(),
            payload: body.payload.clone(),
            compute_context: append::port_compute_context(&body),
            client_attestation: body.client_attestation.clone(),
        };
        let first = state
            .append_coordinator()
            .append(command.clone())
            .await
            .expect("first append");
        assert_eq!(first.result.sequence, 0);
        assert_eq!(admission_calls.load(Ordering::SeqCst), 1);

        let second = state
            .append_coordinator()
            .append(command)
            .await
            .expect("ledger replay");
        assert_eq!(
            admission_calls.load(Ordering::SeqCst),
            2,
            "each coordinator pass admits once; ledger replay must not duplicate events"
        );
        assert_eq!(second.result.sequence, first.result.sequence);
        assert_eq!(
            second.result.canonical_event_hash,
            first.result.canonical_event_hash
        );
    }

    /// Given a WOS provenance append, when the handler completes, then the receipt
    /// carries the substrate event artifact type.
    #[tokio::test]
    async fn given_wos_append_when_completed_then_receipt_artifact_type_is_event() {
        let app = router(test_state()).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                append_body("idem-wos-profile"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let result: SubstrateAppendResult = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            result.verification_receipt.artifact_type,
            ArtifactType::Event,
            "WOS append receipts must project artifactType=event"
        );
    }

    /// Given a Formspec aggregate append, when admission runs, then the event is
    /// accepted and the receipt carries the substrate event artifact type.
    #[tokio::test]
    async fn given_formspec_response_submitted_when_appended_then_artifact_type_is_event() {
        let app = router(test_state()).expect("router");
        let response = app
            .oneshot(formspec_post_request(
                "/v1/scopes/formspec.prod-mvp/events",
                formspec_append_body("idem-fspec-profile"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let result: SubstrateAppendResult = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            result.verification_receipt.event_type,
            FORMSPEC_RESPONSE_SUBMITTED
        );
        assert_eq!(
            result.verification_receipt.artifact_type,
            ArtifactType::Event,
            "Formspec append receipts must project artifactType=event"
        );
    }

    #[test]
    fn given_signing_key_with_valid_to_when_registry_cbor_built_then_valid_to_is_encoded() {
        let valid_from = TrellisTimestamp::new(1_700_000_000, 0).expect("valid from");
        let valid_to = TrellisTimestamp::new(1_800_000_000, 0).expect("valid to");
        let key_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vectors/_keys/issuer-001.cose_key");
        let key = fs::read(key_path).expect("fixture key");
        let signing_key = ServerSigningKey::from_cose_key_bytes(key, valid_from)
            .expect("parse signing key")
            .with_valid_to(Some(valid_to));
        let registry_cbor = signing_key_registry_cbor(&signing_key.export_key())
            .expect("encode signing-key registry");
        let decoded = integrity_cbor::decode_cbor_value(&registry_cbor).expect("decode registry");
        let integrity_cbor::Value::Array(entries) = decoded else {
            panic!("registry must be a CBOR array");
        };
        let integrity_cbor::Value::Map(entry) = entries
            .first()
            .expect("registry must contain one signing-key entry")
        else {
            panic!("registry entry must be a CBOR map");
        };
        let valid_to_value = entry
            .iter()
            .find_map(|(key, value)| match (key, value) {
                (integrity_cbor::Value::Text(label), value) if label == "valid_to" => Some(value),
                _ => None,
            })
            .expect("registry entry must include valid_to");
        assert_eq!(
            valid_to_value,
            &integrity_cbor::Value::Array(vec![
                integrity_cbor::Value::Integer(1_800_000_000.into()),
                integrity_cbor::Value::Integer(0.into()),
            ]),
            "registry valid_to must reflect signing key expiry"
        );
    }

    #[test]
    fn given_corrupt_export_zip_when_verified_then_returns_false() {
        assert!(!export_bundle_cryptographically_verified(
            b"not-a-valid-export-zip"
        ));
    }

    #[tokio::test]
    async fn given_fresh_append_when_completed_then_receipt_verified_reflects_export_verify() {
        let app = router(test_state()).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                append_body("idem-export-verified"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let result: SubstrateAppendResult = serde_json::from_slice(&bytes).unwrap();
        assert!(
            result.verification_receipt.verified,
            "append receipt verified must be true only after export ZIP passes independent verification"
        );
    }

    #[tokio::test]
    async fn given_non_public_compute_context_when_append_requested_then_bad_request() {
        let app = router(test_state()).expect("router");
        let mut body: serde_json::Value =
            serde_json::from_slice(&append_body("idem-non-public-compute")).unwrap();
        body["computeContext"]["sensitivity"] = serde_json::Value::String("readerHeld".to_string());
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Inactive signing key (`valid_to` before wall-clock time) rejects append with BAD_REQUEST via
    /// `AppendCoordinator`; temporarily removing its `is_active_at` guard turns this case RED (201).
    #[tokio::test]
    async fn given_expired_signing_key_when_http_append_then_bad_request() {
        let key_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vectors/_keys/issuer-001.cose_key");
        let key = fs::read(key_path).expect("fixture key");
        let valid_from = TrellisTimestamp::new(1_600_000_000, 0).expect("valid from");
        let valid_to = TrellisTimestamp::new(1_700_000_010, 0).expect("valid to");
        let signing_key = ServerSigningKey::from_cose_key_bytes(key, valid_from)
            .expect("parse signing key")
            .with_valid_to(Some(valid_to));
        let state = TrellisServerState::new(
            Arc::new(InMemoryEventRepository::new()),
            signing_key,
            TenantHeaderMode::MultiProducer,
        );
        let app = router(state).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                append_body("idem-expired-signing-key"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn given_memory_storage_when_production_like_scope_posture_evaluated_then_false() {
        let inputs = TrellisScopeAuthorizerStartupInputs {
            storage_is_memory: true,
            permissive_scope_auth: false,
        };
        assert!(!inputs.production_like_scope_posture());
    }

    #[test]
    fn given_durable_storage_with_permissive_when_production_like_scope_posture_evaluated_then_false()
     {
        let inputs = TrellisScopeAuthorizerStartupInputs {
            storage_is_memory: false,
            permissive_scope_auth: true,
        };
        assert!(!inputs.production_like_scope_posture());
    }

    #[test]
    fn given_durable_storage_without_permissive_when_production_like_scope_posture_evaluated_then_true()
     {
        let inputs = TrellisScopeAuthorizerStartupInputs {
            storage_is_memory: false,
            permissive_scope_auth: false,
        };
        assert!(inputs.production_like_scope_posture());
    }

    #[test]
    fn given_production_like_posture_when_router_builds_with_allow_all_then_err() {
        let state = test_state().with_production_like_scope_posture(true);
        let err = router(state).expect_err("router must reject misleading posture");
        let msg = err.to_string();
        assert!(
            msg.contains("scoped ScopeAuthorizer") && msg.contains("TWREF-022"),
            "{msg}"
        );
    }

    #[test]
    fn given_production_like_posture_when_scoped_authorizer_without_jwt_then_router_err() {
        let state = test_state()
            .with_scope_authorizer(Arc::new(ScopedAllowlistScopeAuthorizer))
            .with_production_like_scope_posture(true);
        let err = router(state).expect_err("router must reject missing jwt verifier");
        let msg = err.to_string();
        assert!(
            msg.contains("jwt_verifier") && msg.contains("TWREF-022"),
            "{msg}"
        );
    }

    const TEST_JWT_SECRET: &[u8] = b"trellis-test-jwt-secret";

    fn test_jwt_config() -> JwtConfig {
        JwtConfig {
            algorithm: Algorithm::HS256,
            validate_exp: true,
            validate_iss: None,
            validate_aud: None,
            leeway_secs: 30,
        }
    }

    fn test_trellis_token(scopes: Vec<String>) -> String {
        let issuer = JwtIssuer::<TrellisClaims>::from_hs256(
            test_jwt_config(),
            TEST_JWT_SECRET,
            Box::new(OsSecureRandom),
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let jti = issuer.generate_jti().unwrap();
        let claims = TrellisClaims {
            base: BaseClaims {
                sub: "test-subject".to_string(),
                exp: now + 3600,
                iat: now,
                jti,
            },
            scopes,
        };
        issuer.issue(&claims).unwrap()
    }

    fn test_state_scoped_production_like() -> TrellisServerState {
        let verifier = JwtVerifier::<TrellisClaims>::from_hs256(test_jwt_config(), TEST_JWT_SECRET);
        TrellisServerState::new(
            Arc::new(InMemoryEventRepository::new()),
            test_signing_key(),
            TenantHeaderMode::MultiProducer,
        )
        .with_jwt_verifier(verifier)
        .with_scope_authorizer(Arc::new(ScopedAllowlistScopeAuthorizer))
        .with_production_like_scope_posture(true)
    }

    fn post_request_bearer(path: &str, body: Vec<u8>, bearer: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {bearer}"))
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_from_body(&body))
            .header("x-wos-tenant-id", "tenant-a")
            .header("x-wos-workspace-id", "workspace-a")
            .header("x-wos-environment-id", "prod")
            .header("x-wos-cell-id", "cell-a")
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn given_scoped_production_like_when_append_without_bearer_then_unauthorized() {
        let app = router(test_state_scoped_production_like()).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                append_body("idem-prodlike-no-bearer"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn given_scoped_production_like_when_append_jwt_missing_scope_then_forbidden() {
        let token = test_trellis_token(vec!["other_scope".to_string()]);
        let app = router(test_state_scoped_production_like()).expect("router");
        let response = app
            .oneshot(post_request_bearer(
                "/v1/scopes/case_123/events",
                append_body("idem-prodlike-wrong-scope"),
                &token,
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn given_production_like_server_when_append_omits_client_attestation_then_created() {
        let token = test_trellis_token(vec!["case_123".to_string()]);
        let app = router(test_state_scoped_production_like()).expect("router");
        let response = app
            .oneshot(post_request_bearer(
                "/v1/scopes/case_123/events",
                append_body("idem-prodlike-no-attest"),
                &token,
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn given_production_like_server_when_append_includes_client_attestation_then_bad_request()
    {
        let token = test_trellis_token(vec!["case_123".to_string()]);
        let app = router(test_state_scoped_production_like()).expect("router");
        let mut body: SubstrateAppendBody =
            serde_json::from_slice(&append_body("idem-prodlike-attest")).unwrap();
        body.client_attestation = Some(ClientAttestation {
            kid: "fixture-kid".into(),
            cose_sign1: "deadbeef".into(),
        });
        let response = app
            .oneshot(post_request_bearer(
                "/v1/scopes/case_123/events",
                serde_json::to_vec(&body).unwrap(),
                &token,
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let problem: serde_json::Value = serde_json::from_slice(&bytes).expect("problem body");
        let combined = format!(
            "{} {}",
            problem
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
            problem
                .get("detail")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
        );
        assert!(
            combined.contains("clientAttestation") && combined.contains("TWREF"),
            "problem should cite clientAttestation and TWREF, got {problem:?}"
        );
    }

    #[tokio::test]
    async fn given_production_like_server_when_client_attestation_has_empty_kid_then_bad_request() {
        let token = test_trellis_token(vec!["case_123".to_string()]);
        let app = router(test_state_scoped_production_like()).expect("router");
        let mut body: SubstrateAppendBody =
            serde_json::from_slice(&append_body("idem-prodlike-empty-kid")).unwrap();
        body.client_attestation = Some(ClientAttestation {
            kid: String::new(),
            cose_sign1: "00".into(),
        });
        let response = app
            .oneshot(post_request_bearer(
                "/v1/scopes/case_123/events",
                serde_json::to_vec(&body).unwrap(),
                &token,
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn given_test_server_when_append_includes_client_attestation_then_bad_request() {
        let app = router(test_state()).expect("router");
        let mut body: SubstrateAppendBody =
            serde_json::from_slice(&append_body("idem-client-attestation-present")).unwrap();
        body.client_attestation = Some(ClientAttestation {
            kid: "fixture-kid".into(),
            cose_sign1: "deadbeef".into(),
        });
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let ctype = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(
            ctype.contains("application/problem+json"),
            "expected application/problem+json, got {ctype:?}"
        );
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let problem: serde_json::Value = serde_json::from_slice(&bytes).expect("problem body");
        let mut message = problem
            .get("title")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(detail) = problem.get("detail").and_then(|value| value.as_str()) {
            if !message.is_empty() {
                message.push(' ');
            }
            message.push_str(detail);
        }
        assert!(
            message.contains("clientAttestation"),
            "problem title/detail should cite clientAttestation, got {problem:?}"
        );
    }

    #[tokio::test]
    async fn given_fresh_append_when_coordinator_completes_then_persisted_hash_matches_wire() {
        let repo = Arc::new(InMemoryEventRepository::new());
        let state = TrellisServerState::new(
            repo.clone(),
            test_signing_key(),
            TenantHeaderMode::MultiProducer,
        );
        let body: SubstrateAppendBody =
            serde_json::from_slice(&append_body("idem-coordinator-persisted-hash")).unwrap();
        let command = append::AppendCommand {
            scope: "case_123".to_string(),
            event_type: body.event_type.clone(),
            idempotency_key: body.idempotency_key.clone(),
            payload: body.payload.clone(),
            compute_context: append::port_compute_context(&body),
            client_attestation: body.client_attestation.clone(),
        };
        let outcome = state
            .append_coordinator()
            .append(command)
            .await
            .expect("coordinator append");
        let stored = repo
            .list_scope(b"case_123")
            .await
            .expect("list scope")
            .pop()
            .expect("one event");
        let hex_digest = outcome
            .result
            .canonical_event_hash
            .strip_prefix("sha256:")
            .expect("hash prefix");
        let bytes = hex::decode(hex_digest).expect("digest hex");
        let hash: [u8; 32] = bytes.try_into().expect("canonical hash is 32 bytes");
        assert_eq!(
            stored
                .canonical_event_hash()
                .expect("persisted substrate hash"),
            &hash,
            "coordinator commits before returning the append receipt canonical hash field",
        );
    }

    #[tokio::test]
    async fn append_wos_event_publishes_bundle_and_registries() {
        let app = router(test_state()).expect("router");
        let body = append_body("idem-1");
        let response = app
            .clone()
            .oneshot(post_request("/v1/scopes/case_123/events", body))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let result: SubstrateAppendResult = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result.sequence, 0);
        assert_eq!(
            result.verification_receipt.event_type,
            "wos.kernel.case_created"
        );
        assert!(result.canonical_event_hash.starts_with("sha256:"));

        let bundle = app
            .clone()
            .oneshot(get_request("/v1/scopes/case_123/bundles/head"))
            .await
            .expect("bundle response");
        assert_eq!(bundle.status(), StatusCode::OK);
        let bundle_bytes = to_bytes(bundle.into_body(), 10 * 1024 * 1024)
            .await
            .unwrap();
        assert!(bundle_bytes.len() > 100);

        let registry = app
            .oneshot(get_request("/v1/scopes/case_123/registries/event-types"))
            .await
            .expect("registry response");
        assert_eq!(registry.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn given_same_scope_and_events_when_bundle_published_twice_then_zip_bytes_are_identical()
    {
        let state = test_state();
        let app = router(state.clone()).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_deterministic/events",
                append_body("idem-deterministic-1"),
            ))
            .await
            .expect("append deterministic event response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let events = state
            .repository
            .list_scope(b"case_deterministic")
            .await
            .expect("load deterministic scope events");
        let compute = append::default_public_compute_context();
        let first = publish_bundle(&state, b"case_deterministic", &events, false, &compute)
            .await
            .expect("first publish");
        let second = publish_bundle(&state, b"case_deterministic", &events, false, &compute)
            .await
            .expect("second publish");
        let first_bytes = state
            .artifact_store
            .get(&first.artifact_ref)
            .await
            .expect("load first bundle")
            .expect("first bundle bytes");
        let second_bytes = state
            .artifact_store
            .get(&second.artifact_ref)
            .await
            .expect("load second bundle")
            .expect("second bundle bytes");
        assert_eq!(
            first_bytes, second_bytes,
            "publishing identical ledger state twice must produce byte-identical ZIP output"
        );
    }

    #[tokio::test]
    async fn given_unreachable_artifact_store_when_health_probe_runs_then_reports_degraded() {
        struct FailingArtifactStore;

        #[async_trait]
        impl ArtifactStore for FailingArtifactStore {
            type Error = StackError;

            async fn put(&self, _key: &str, _bytes: &[u8]) -> Result<ArtifactRef, Self::Error> {
                Err(StackError::unavailable("artifact store offline"))
            }

            async fn get(
                &self,
                _artifact_ref: &ArtifactRef,
            ) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(None)
            }
        }

        let state = test_state().with_artifact_store(Arc::new(FailingArtifactStore));
        let health = TrellisHealthProbe::new(state).check().await;
        assert_eq!(
            health.status,
            stack_common_ops::ComponentStatus::Degraded,
            "unreachable artifact store must degrade readiness: {health:?}"
        );
    }

    #[tokio::test]
    async fn given_repository_list_scope_unreachable_when_health_probe_runs_then_reports_degraded()
    {
        struct FailingEventRepository;

        #[async_trait]
        impl EventRepository for FailingEventRepository {
            async fn list_scope(&self, _scope: &[u8]) -> Result<Vec<StoredEvent>, StackError> {
                Err(StackError::unavailable(
                    "repository list_scope unreachable for test probe",
                ))
            }

            async fn append_event(&self, _event: StoredEvent) -> Result<(), StackError> {
                Err(StackError::internal("append not exercised in probe test"))
            }
        }

        let state = TrellisServerState::new(
            Arc::new(FailingEventRepository),
            test_signing_key(),
            TenantHeaderMode::MultiProducer,
        );
        let health = TrellisHealthProbe::new(state).check().await;
        assert_eq!(
            health.status,
            stack_common_ops::ComponentStatus::Degraded,
            "repository probe failure must degrade readiness: {health:?}"
        );
    }

    #[tokio::test]
    async fn openapi_document_is_served_and_declares_substrate_routes() {
        let app = router(test_state()).expect("router");
        let response = app
            .oneshot(get_request("/openapi.json"))
            .await
            .expect("OpenAPI response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        crate::openapi::assert_trellis_openapi_shape(&doc);
    }

    /// Given a successful substrate append, when the same JSON body and idempotency key are
    /// POSTed again, then the HTTP replay middleware returns the stored response with
    /// `x-replay: true` (no second ledger append).
    #[tokio::test]
    async fn given_identical_append_when_posted_twice_then_http_middleware_replays() {
        let app = router(test_state()).expect("router");
        let body = append_body("idem-2");
        let first = app
            .clone()
            .oneshot(post_request("/v1/scopes/case_123/events", body.clone()))
            .await
            .expect("first append");
        assert_eq!(first.status(), StatusCode::CREATED);

        let second = app
            .oneshot(post_request("/v1/scopes/case_123/events", body))
            .await
            .expect("second append");
        assert_eq!(second.status(), StatusCode::CREATED);
        assert_eq!(
            second.headers().get(IDEMPOTENCY_REPLAY_HEADER).unwrap(),
            "true"
        );
    }

    /// Given a recorded HTTP idempotency entry for key K, when a second POST reuses K with a
    /// different body hash, then the shared middleware returns 409 and must not set `x-replay`.
    #[tokio::test]
    async fn given_recorded_replay_when_same_key_different_body_then_conflict_without_replay_header()
     {
        let app = router(test_state()).expect("router");
        let idem = "twref055-body-conflict";
        let first_body = append_body(idem);
        let first = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                first_body.clone(),
            ))
            .await
            .expect("first append");
        assert_eq!(first.status(), StatusCode::CREATED);

        let mut variant: serde_json::Value = serde_json::from_slice(&first_body).expect("json");
        variant["payload"]["id"] = serde_json::Value::String("prov-alternate-body-hash".into());
        let second_body = serde_json::to_vec(&variant).expect("encode");

        let second = app
            .oneshot(post_request("/v1/scopes/case_123/events", second_body))
            .await
            .expect("second append");
        assert_eq!(second.status(), StatusCode::CONFLICT);
        assert!(
            second.headers().get(IDEMPOTENCY_REPLAY_HEADER).is_none(),
            "409 conflict path must not mark responses as replayed"
        );
        let bytes = to_bytes(second.into_body(), 1024 * 1024).await.unwrap();
        let problem: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(problem["error_code"], "INFRA-4090");
        let title = problem["title"].as_str().unwrap_or_default();
        let detail = problem["detail"].as_str().unwrap_or_default();
        let combined = format!("{title} {detail}");
        assert!(
            combined.contains("idempotency"),
            "unexpected problem payload: {problem}"
        );
    }

    /// Given TWREF-055 closure, when `trellis-server-ports` is audited, then it must not reintroduce
    /// a parallel HTTP `IdempotencyStore` trait—replay stays on `stack_common_idempotency`.
    #[test]
    fn twref055_trellis_server_ports_has_no_parallel_http_idempotency_trait() {
        const PORTS_LIB: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../trellis-server-ports/src/lib.rs"
        ));
        assert!(
            !PORTS_LIB.contains("trait IdempotencyStore"),
            "TWREF-055: HTTP replay stays on stack_common_idempotency::HttpReplayStore (ADR 0092c)"
        );
        assert!(
            !PORTS_LIB.contains("IdempotencyReplay"),
            "TWREF-055: orphan IdempotencyReplay must not return alongside duplicate traits"
        );
    }

    /// Given distinct WOS tenant headers, when the same idempotency key and POST body are used,
    /// then the second tenant must not replay the first tenant's HTTP middleware cache entry.
    #[tokio::test]
    async fn given_distinct_wos_tenants_when_same_idempotency_body_then_no_cross_tenant_http_replay()
     {
        let app = router(test_state()).expect("router");
        let body = append_body("twref055-tenant-scope");
        let first = app
            .clone()
            .oneshot(post_request("/v1/scopes/case_123/events", body.clone()))
            .await
            .expect("tenant-a append");
        assert_eq!(first.status(), StatusCode::CREATED);

        let second = app
            .oneshot(post_request_with_wos_tenant(
                "/v1/scopes/case_123/events",
                body,
                "tenant-b",
            ))
            .await
            .expect("tenant-b append");
        assert_eq!(second.status(), StatusCode::CREATED);
        assert!(
            second.headers().get(IDEMPOTENCY_REPLAY_HEADER).is_none(),
            "tenant B must not replay tenant A's HttpReplayStore entry"
        );
    }

    #[test]
    fn given_admission_wos_literals_when_defined_then_aliases_substrate_canonical_export() {
        // TWREF-017: the WOS admission adapter's canonical literal table must
        // remain the same slice as `wos-events::WOS_CANONICAL_EVENT_LITERALS`.
        // After DI-001 the alias lives in trellis-admission-wos; this test guards
        // against drift through the parent trellis-server build.
        assert!(
            std::ptr::eq(
                wos_events::WOS_CANONICAL_EVENT_LITERALS.as_ptr(),
                WOS_CANONICAL_EVENT_LITERALS.as_ptr()
            ),
            "trellis-admission-wos::WOS_CANONICAL_EVENT_LITERALS must alias wos-events WOS_CANONICAL_EVENT_LITERALS (TWREF-017)"
        );
        assert_eq!(
            wos_events::WOS_CANONICAL_EVENT_LITERALS.len(),
            WOS_CANONICAL_EVENT_LITERALS.len(),
            "substrate literal slice length drift"
        );
    }

    #[tokio::test]
    async fn unknown_wos_event_type_is_rejected() {
        let app = router(test_state()).expect("router");
        let mut value: serde_json::Value = serde_json::from_slice(&append_body("idem-3")).unwrap();
        value["eventType"] = serde_json::Value::String("wos.kernel.unknown".to_string());
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                serde_json::to_vec(&value).unwrap(),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn formspec_append_rejects_wrong_event_type() {
        let app = router(test_state()).expect("router");
        let mut body: serde_json::Value =
            serde_json::from_slice(&formspec_append_body("idem-fspec-wrong-type")).unwrap();
        body["eventType"] = serde_json::Value::String("wos.kernel.case_created".to_string());
        let response = app
            .oneshot(formspec_post_request(
                "/v1/scopes/formspec.prod-mvp/events",
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn formspec_append_rejects_missing_aggregate_type() {
        let app = router(test_state()).expect("router");
        let mut body: serde_json::Value =
            serde_json::from_slice(&formspec_append_body("idem-fspec-missing-aggregate")).unwrap();
        body["payload"] = serde_json::json!({
            "aggregateId": "resp-missing-aggregate",
            "payload": { "status": "submitted" }
        });
        let response = app
            .oneshot(formspec_post_request(
                "/v1/scopes/formspec.prod-mvp/events",
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    fn test_signing_key() -> ServerSigningKey {
        let key_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vectors/_keys/issuer-001.cose_key");
        let key = fs::read(key_path).expect("fixture key");
        ServerSigningKey::from_cose_key_bytes(key, TrellisTimestamp::new(0, 0).unwrap())
            .expect("signing key")
    }

    fn test_state() -> TrellisServerState {
        TrellisServerState::new(
            Arc::new(InMemoryEventRepository::new()),
            test_signing_key(),
            TenantHeaderMode::MultiProducer,
        )
    }

    fn formspec_append_body(idempotency_key: &str) -> Vec<u8> {
        let body = SubstrateAppendBody {
            event_type: FORMSPEC_RESPONSE_SUBMITTED.to_string(),
            idempotency_key: idempotency_key.to_string(),
            actor: trellis_service_client::AppendActor::service("formspec-server"),
            payload: serde_json::json!({
                "aggregateType": "formspec.response",
                "aggregateId": format!("resp-{idempotency_key}"),
                "payload": { "status": "submitted" }
            }),
            compute_context: trellis_service_client::ComputeContext::no_delegated_compute(
                "formspec-server",
            ),
            client_attestation: None,
        };
        serde_json::to_vec(&body).unwrap()
    }

    fn formspec_post_request(path: &str, body: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_from_body(&body))
            .header("x-formspec-tenant-id", "tenant-a")
            .header("x-formspec-workspace-id", "workspace-a")
            .header("x-formspec-environment-id", "prod")
            .header("x-formspec-cell-id", "cell-a")
            .body(Body::from(body))
            .unwrap()
    }

    fn append_body(idempotency_key: &str) -> Vec<u8> {
        let mut record = ProvenanceRecord::blank(ProvenanceKind::CaseCreated);
        record.id = format!("prov-{idempotency_key}");
        let body = SubstrateAppendBody {
            event_type: "wos.kernel.case_created".to_string(),
            idempotency_key: idempotency_key.to_string(),
            actor: trellis_service_client::AppendActor::service("wos-server"),
            payload: serde_json::to_value(record).unwrap(),
            compute_context: trellis_service_client::ComputeContext::no_delegated_compute(
                "wos-server",
            ),
            client_attestation: None,
        };
        serde_json::to_vec(&body).unwrap()
    }

    fn post_request(path: &str, body: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_from_body(&body))
            .header("x-wos-tenant-id", "tenant-a")
            .header("x-wos-workspace-id", "workspace-a")
            .header("x-wos-environment-id", "prod")
            .header("x-wos-cell-id", "cell-a")
            .body(Body::from(body))
            .unwrap()
    }

    fn post_request_with_wos_tenant(path: &str, body: Vec<u8>, tenant: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_from_body(&body))
            .header("x-wos-tenant-id", tenant)
            .header("x-wos-workspace-id", "workspace-a")
            .header("x-wos-environment-id", "prod")
            .header("x-wos-cell-id", "cell-a")
            .body(Body::from(body))
            .unwrap()
    }

    fn get_request(path: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(path)
            .header("x-wos-tenant-id", "tenant-a")
            .header("x-wos-workspace-id", "workspace-a")
            .header("x-wos-environment-id", "prod")
            .header("x-wos-cell-id", "cell-a")
            .body(Body::empty())
            .unwrap()
    }

    fn idempotency_from_body(body: &[u8]) -> String {
        let value: serde_json::Value = serde_json::from_slice(body).unwrap();
        value["idempotencyKey"].as_str().unwrap().to_string()
    }

    struct CountingAdmissionPolicy {
        inner: Arc<dyn EventAdmissionPolicy<Error = StackError>>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl EventAdmissionPolicy for CountingAdmissionPolicy {
        type Error = StackError;

        async fn admit(
            &self,
            event: &AdmissionEvent<'_>,
        ) -> Result<trellis_server_ports::AdmittedEvent, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.admit(event).await
        }
    }
}
