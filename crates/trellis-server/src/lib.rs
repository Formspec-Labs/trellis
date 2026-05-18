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
//! This file remains a large composition root (event admission dispatch, bundle publication, CBOR/registry
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
mod export_profile;
mod http;
pub mod openapi;
mod scope_startup;
mod state;

#[doc(inline)]
pub use composition::{AdmissionRouter, default_admission_policy};

use artifacts::{BundleIdentity, BundleRecord};

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
    CborHelperError, Value, domain_separated_sha256, encode_canonical_cbor_value, map_lookup_bytes,
    map_lookup_fixed_bytes, map_lookup_map,
};
use serde::{Deserialize, Serialize};
use stack_common_auth::{BaseClaims, Claims};
use stack_common_error::StackError;
use trellis_cddl::canonical_event_hash_preimage;
use trellis_core::SigningKeyMaterial as CoreSigningKey;
use trellis_export_writer::{
    ExportSealFence, ExportWriterInput, RegistrySnapshot as ExportRegistrySnapshot,
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
const EXPORT_ATTEMPT_DOMAIN: &str = "trellis-export-attempt-v1";
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
    let seal_version =
        u64::try_from(events.len()).map_err(|_| StackError::internal("event count exceeds u64"))?;
    let high_water_event = events
        .last()
        .ok_or_else(|| StackError::internal("empty event set"))?;
    let high_water_sequence = high_water_event.sequence();
    let high_water_event_hash = event_hash(scope, high_water_event)?;
    let export_attempt_id = export_attempt_id(
        scope,
        seal_version,
        high_water_sequence,
        high_water_event_hash,
    )?;
    let registry_bytes = event_type_registry_cbor(state.event_type_catalog.as_ref())?;
    let policy_artifacts = composition::default_signature_policy_artifacts();
    let export_profile = export_profile::build_export_profile_members(
        scope,
        events,
        generated_at,
        &policy_artifacts,
    )?;
    let profile_validation_required = export_profile.requires_profile_validation();
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
        seal_fence: Some(ExportSealFence {
            bundle_scope: scope.to_vec(),
            export_attempt_id: export_attempt_id.clone(),
            seal_version,
            event_count: seal_version,
            high_water_sequence,
        }),
        witness_key_registry: None,
        signed_acts_catalog: export_profile.signed_acts_catalog,
        signed_acts_manifest: export_profile.signed_acts_manifest,
        policy_closure: export_profile.policy_closure,
    })?;
    let checkpoint_digest = format!("sha256:{}", hex::encode(package.head_checkpoint_digest));
    let key = format!(
        "{}/bundles/{}.zip",
        encode_path_segment(&String::from_utf8_lossy(scope)),
        export_attempt_id.trim_start_matches("sha256:")
    );
    let identity = BundleIdentity {
        checkpoint_digest: checkpoint_digest.clone(),
        seal_version,
        export_attempt_id: export_attempt_id.clone(),
    };
    if !export_bundle_cryptographically_verified(&package.zip_bytes) {
        return Err(StackError::internal(
            "published export bundle failed independent verification",
        ));
    }
    if profile_validation_required && !(state.profile_export_verifier.as_ref())(&package.zip_bytes)
    {
        return Err(StackError::internal(
            "published export bundle failed WOS/Formspec profile verification",
        ));
    }
    state.bundles.reserve_publishable(scope, &identity).await?;
    let artifact_ref = state
        .artifact_store
        .put_immutable(&key, &package.zip_bytes)
        .await?;
    let record = BundleRecord {
        checkpoint_digest,
        seal_version,
        export_attempt_id,
        artifact_ref,
    };
    state
        .bundles
        .insert_published_record(scope, &record, update_head)
        .await?;
    Ok(record)
}

fn export_attempt_id(
    scope: &[u8],
    seal_version: u64,
    high_water_sequence: u64,
    high_water_event_hash: [u8; 32],
) -> Result<String, StackError> {
    let material = text_map(vec![
        ("bundle_scope", Value::Bytes(scope.to_vec())),
        ("seal_version", uint(seal_version)),
        ("high_water_sequence", uint(high_water_sequence)),
        (
            "high_water_event_hash",
            Value::Bytes(high_water_event_hash.to_vec()),
        ),
    ])?;
    let digest = domain_separated_sha256(EXPORT_ATTEMPT_DOMAIN, &encode_value(&material)?);
    Ok(format!("sha256:{}", hex::encode(digest)))
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
    debug_assert!(
        !catalog.is_empty(),
        "default event-type catalog must not be empty"
    );
    let mut event_types = Vec::with_capacity(catalog.len());
    for entry in catalog.entries() {
        debug_assert!(
            catalog.get(&entry.event_type).is_some(),
            "catalog entry must resolve by its own event type"
        );
        event_types.push(crate::openapi::EventTypeRegistryEntry {
            event_type: entry.event_type.clone(),
            schema_ref: entry.schema_ref.as_str().to_string(),
        });
    }
    EventTypeRegistryView {
        registry_version: EVENT_TYPE_REGISTRY_VERSION.to_string(),
        event_types,
    }
}

fn event_type_registry_cbor(
    catalog: &composition::EventTypeCatalog,
) -> Result<Vec<u8>, StackError> {
    const SERVICE_CLASSIFICATION: &str = "x-trellis-service/public-metadata";
    let mut event_types = Vec::with_capacity(catalog.len());
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
    encode_canonical_cbor_value(value)
        .map_err(|error| StackError::internal(format!("failed to encode CBOR: {error}")))
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
    use wos_events::{
        ProvenanceKind, ProvenanceRecord, SignatureAdmissionFailedInput, SignatureAffirmationInput,
        WOS_CANONICAL_EVENT_LITERALS,
    };

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

    #[test]
    fn encode_value_canonicalizes_nested_maps() {
        let value = Value::Map(vec![(
            Value::Text("consent".to_string()),
            Value::Map(vec![
                (
                    Value::Text("z".to_string()),
                    Value::Text("last".to_string()),
                ),
                (
                    Value::Text("a".to_string()),
                    Value::Text("first".to_string()),
                ),
            ]),
        )]);

        let bytes = encode_value(&value).expect("canonical bytes");
        let decoded = integrity_cbor::decode_cbor_value(&bytes).expect("decode canonical bytes");
        let root = decoded.as_map().expect("root map");
        let consent = root[0].1.as_map().expect("consent map");
        let keys = consent
            .iter()
            .map(|(key, _)| key.as_text().expect("text key"))
            .collect::<Vec<_>>();

        assert_eq!(keys, vec!["a", "z"]);
    }

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

    struct ConflictOnImmutableArtifactStore;

    #[async_trait]
    impl ArtifactStore for ConflictOnImmutableArtifactStore {
        type Error = StackError;

        async fn put(&self, key: &str, _bytes: &[u8]) -> Result<ArtifactRef, Self::Error> {
            Ok(ArtifactRef::new(format!("memory://conflict/{key}")))
        }

        async fn put_immutable(
            &self,
            _key: &str,
            _bytes: &[u8],
        ) -> Result<ArtifactRef, Self::Error> {
            Err(StackError::conflict(
                "artifact key already exists with different bytes",
            ))
        }

        async fn get(&self, _artifact_ref: &ArtifactRef) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(None)
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
                "/v1/scopes/formspec.managed-single-cell/events",
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
    async fn publish_bundle_propagates_immutable_artifact_conflict() {
        let state = test_state();
        let app = router(state.clone()).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_publish_conflict/events",
                append_body("idem-publish-conflict"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let events = state
            .repository
            .list_scope(b"case_publish_conflict")
            .await
            .expect("load scope events");
        let conflict_state = state.with_artifact_store(Arc::new(ConflictOnImmutableArtifactStore));

        let error = publish_bundle(
            &conflict_state,
            b"case_publish_conflict",
            &events,
            false,
            &append::default_public_compute_context(),
        )
        .await
        .expect_err("immutable artifact conflict must propagate");

        assert_eq!(error.code().as_str(), "INFRA-4090");
    }

    #[tokio::test]
    async fn publish_bundle_checks_index_identity_before_artifact_write() {
        #[derive(Default)]
        struct CountingArtifactStore {
            puts: AtomicUsize,
        }

        #[async_trait]
        impl ArtifactStore for CountingArtifactStore {
            type Error = StackError;

            async fn put(&self, key: &str, _bytes: &[u8]) -> Result<ArtifactRef, Self::Error> {
                self.puts.fetch_add(1, Ordering::SeqCst);
                Ok(ArtifactRef::new(format!("memory://{key}")))
            }

            async fn put_immutable(
                &self,
                key: &str,
                _bytes: &[u8],
            ) -> Result<ArtifactRef, Self::Error> {
                self.puts.fetch_add(1, Ordering::SeqCst);
                Ok(ArtifactRef::new(format!("memory://{key}")))
            }

            async fn get(
                &self,
                _artifact_ref: &ArtifactRef,
            ) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(None)
            }
        }

        let source_state = test_state();
        let app = router(source_state.clone()).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_preflight_conflict/events",
                append_body("idem-preflight-conflict"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let events = source_state
            .repository
            .list_scope(b"case_preflight_conflict")
            .await
            .expect("load scope events");

        let store = Arc::new(CountingArtifactStore::default());
        let publish_state = test_state().with_artifact_store(store.clone());
        publish_state
            .bundles
            .insert_published_record(
                b"case_preflight_conflict",
                &BundleRecord {
                    checkpoint_digest: format!("sha256:{}", "00".repeat(32)),
                    seal_version: 1,
                    export_attempt_id: format!("sha256:{}", "11".repeat(32)),
                    artifact_ref: ArtifactRef::new(
                        "memory://trellis/case_preflight_conflict/bundles/prior.zip",
                    ),
                },
                true,
            )
            .await
            .expect("seed conflicting bundle identity");

        let error = publish_bundle(
            &publish_state,
            b"case_preflight_conflict",
            &events,
            false,
            &append::default_public_compute_context(),
        )
        .await
        .expect_err("conflicting seal identity must reject");

        assert_eq!(error.code().as_str(), "INFRA-4090");
        assert_eq!(
            store.puts.load(Ordering::SeqCst),
            0,
            "known bundle-index conflicts must fail before artifact writes"
        );
    }

    #[tokio::test]
    async fn head_bundle_returns_conflict_when_checkpoint_artifact_identity_conflicts() {
        let state = test_state();
        let app = router(state.clone()).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_head_conflict/events",
                append_body("idem-head-conflict"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let conflict_app =
            router(state.with_artifact_store(Arc::new(ConflictOnImmutableArtifactStore)))
                .expect("router");

        let response = conflict_app
            .oneshot(get_request("/v1/scopes/case_head_conflict/bundles/head"))
            .await
            .expect("head bundle response");

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn pinned_bundle_returns_existing_checkpoint_with_normalized_digest_forms() {
        let state = test_state();
        let app = router(state.clone()).expect("router");
        let response = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_pinned_bundle/events",
                append_body("idem-pinned-bundle"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), 10 * 1024 * 1024)
            .await
            .expect("append response body");
        let result: SubstrateAppendResult =
            serde_json::from_slice(&body).expect("append response JSON");
        let digest = result
            .checkpoint_ref
            .rsplit('/')
            .next()
            .expect("checkpoint digest in ref");
        let hex_digest = digest.strip_prefix("sha256:").expect("sha256 digest");

        let head = app
            .clone()
            .oneshot(get_request("/v1/scopes/case_pinned_bundle/bundles/head"))
            .await
            .expect("head bundle response");
        assert_eq!(head.status(), StatusCode::OK);
        let head_bytes = to_bytes(head.into_body(), 10 * 1024 * 1024)
            .await
            .expect("head bundle bytes")
            .to_vec();

        let prefixed_path = format!("/v1/scopes/case_pinned_bundle/bundles/{digest}");
        let prefixed = app
            .clone()
            .oneshot(get_request(&prefixed_path))
            .await
            .expect("prefixed pinned bundle response");
        assert_eq!(prefixed.status(), StatusCode::OK);
        let prefixed_bytes = to_bytes(prefixed.into_body(), 10 * 1024 * 1024)
            .await
            .expect("prefixed pinned bundle bytes")
            .to_vec();

        let bare_path = format!("/v1/scopes/case_pinned_bundle/bundles/{hex_digest}");
        let bare = app
            .clone()
            .oneshot(get_request(&bare_path))
            .await
            .expect("bare pinned bundle response");
        assert_eq!(bare.status(), StatusCode::OK);
        let bare_bytes = to_bytes(bare.into_body(), 10 * 1024 * 1024)
            .await
            .expect("bare pinned bundle bytes")
            .to_vec();

        let uppercase_path = format!(
            "/v1/scopes/case_pinned_bundle/bundles/sha256:{}",
            hex_digest.to_ascii_uppercase()
        );
        let uppercase = app
            .oneshot(get_request(&uppercase_path))
            .await
            .expect("uppercase pinned bundle response");
        assert_eq!(uppercase.status(), StatusCode::OK);
        let uppercase_bytes = to_bytes(uppercase.into_body(), 10 * 1024 * 1024)
            .await
            .expect("uppercase pinned bundle bytes")
            .to_vec();

        assert_eq!(head_bytes, prefixed_bytes);
        assert_eq!(head_bytes, bare_bytes);
        assert_eq!(head_bytes, uppercase_bytes);
    }

    #[tokio::test]
    async fn pinned_bundle_returns_not_found_for_unknown_checkpoint_after_head_publish() {
        let state = test_state();
        let app = router(state).expect("router");
        let response = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_pinned_missing/events",
                append_body("idem-pinned-missing"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);

        let missing = app
            .oneshot(get_request(&format!(
                "/v1/scopes/case_pinned_missing/bundles/sha256:{}",
                "ff".repeat(32)
            )))
            .await
            .expect("missing pinned bundle response");

        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn signature_affirmation_append_publishes_profile_members_verified_by_wos_verifier() {
        let app = router(test_state()).expect("router");
        let response = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_signature/events",
                signature_affirmation_append_body("idem-signature-export"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);

        let bundle = app
            .oneshot(get_request("/v1/scopes/case_signature/bundles/head"))
            .await
            .expect("bundle response");
        assert_eq!(bundle.status(), StatusCode::OK);
        let bundle_bytes = to_bytes(bundle.into_body(), 10 * 1024 * 1024)
            .await
            .expect("bundle bytes")
            .to_vec();
        let members = integrity_bundle::read_stored_zip(&bundle_bytes).expect("parse bundle");
        assert!(
            members.iter().any(|entry| entry
                .path()
                .ends_with(trellis_export_writer::SIGNED_ACTS_MEMBER)),
            "signature exports must carry 066-signed-acts.cbor"
        );
        assert!(
            members.iter().any(|entry| entry
                .path()
                .ends_with(trellis_export_writer::POLICY_CLOSURE_MEMBER)),
            "signature exports must carry 067-policy-closure.cbor"
        );

        let report = trellis_verify_wos::verify_export_zip(&bundle_bytes);
        assert!(
            report.substrate().structure_verified && report.substrate().integrity_verified,
            "{report:#?}"
        );
        assert!(
            report.wos_findings.is_empty() && report.relying_party_valid(),
            "{report:#?}"
        );
    }

    #[tokio::test]
    async fn signature_affirmation_with_deployment_local_intent_suppresses_policy_closure() {
        let app = router(test_state()).expect("router");
        let response = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_deployment_local_signature/events",
                signature_affirmation_append_body_with_intent(
                    "idem-deployment-local-signature",
                    "urn:acme:signing-intent:supervisor-approval",
                    None,
                    None,
                ),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);

        let bundle = app
            .oneshot(get_request(
                "/v1/scopes/case_deployment_local_signature/bundles/head",
            ))
            .await
            .expect("bundle response");
        assert_eq!(bundle.status(), StatusCode::OK);
        let bundle_bytes = to_bytes(bundle.into_body(), 10 * 1024 * 1024)
            .await
            .expect("bundle bytes")
            .to_vec();
        let members = integrity_bundle::read_stored_zip(&bundle_bytes).expect("parse bundle");
        assert!(
            members.iter().any(|entry| entry
                .path()
                .ends_with(trellis_export_writer::SIGNED_ACTS_MEMBER)),
            "signature exports must still carry 066-signed-acts.cbor"
        );
        assert!(
            members.iter().all(|entry| !entry
                .path()
                .ends_with(trellis_export_writer::POLICY_CLOSURE_MEMBER)),
            "deployment-local policy inputs are not represented by the default closure evidence"
        );

        let report = trellis_verify_wos::verify_export_zip(&bundle_bytes);
        assert_missing_policy_closure_advisory(&report);
        assert!(report.relying_party_valid(), "{report:#?}");
    }

    #[tokio::test]
    async fn signature_affirmation_with_unregistered_wos_intent_suppresses_policy_closure() {
        let app = router(test_state()).expect("router");
        let response = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_unregistered_wos_signature/events",
                signature_affirmation_append_body_with_intent(
                    "idem-unregistered-wos-signature",
                    "urn:wos:signing-intent:not-registered",
                    None,
                    None,
                ),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);

        let bundle = app
            .oneshot(get_request(
                "/v1/scopes/case_unregistered_wos_signature/bundles/head",
            ))
            .await
            .expect("bundle response");
        assert_eq!(bundle.status(), StatusCode::OK);
        let bundle_bytes = to_bytes(bundle.into_body(), 10 * 1024 * 1024)
            .await
            .expect("bundle bytes")
            .to_vec();
        let members = integrity_bundle::read_stored_zip(&bundle_bytes).expect("parse bundle");
        assert!(
            members.iter().any(|entry| entry
                .path()
                .ends_with(trellis_export_writer::SIGNED_ACTS_MEMBER)),
            "signature exports must still carry 066-signed-acts.cbor"
        );
        assert!(
            members.iter().all(|entry| !entry
                .path()
                .ends_with(trellis_export_writer::POLICY_CLOSURE_MEMBER)),
            "unregistered WOS namespace intents are not covered by the baseline policy closure"
        );

        let report = trellis_verify_wos::verify_export_zip(&bundle_bytes);
        assert_missing_policy_closure_advisory(&report);
        assert!(report.relying_party_valid(), "{report:#?}");
    }

    #[tokio::test]
    async fn signature_admission_failed_append_publishes_rejected_profile_projection() {
        let app = router(test_state()).expect("router");
        let response = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_rejected_signature/events",
                signature_admission_failed_append_body("idem-rejected-signature-export"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);

        let bundle = app
            .oneshot(get_request(
                "/v1/scopes/case_rejected_signature/bundles/head",
            ))
            .await
            .expect("bundle response");
        assert_eq!(bundle.status(), StatusCode::OK);
        let bundle_bytes = to_bytes(bundle.into_body(), 10 * 1024 * 1024)
            .await
            .expect("bundle bytes")
            .to_vec();
        let members = integrity_bundle::read_stored_zip(&bundle_bytes).expect("parse bundle");
        let signed_acts = members
            .iter()
            .find(|entry| {
                entry
                    .path()
                    .ends_with(trellis_export_writer::SIGNED_ACTS_MEMBER)
            })
            .expect("signed acts member");
        let catalog =
            integrity_cbor::decode_cbor_value(signed_acts.bytes()).expect("signed acts cbor");
        let root = catalog.as_map().expect("signed acts root map");
        let acts = integrity_cbor::map_lookup_array(root, "acts").expect("acts");
        let act = acts.first().expect("one rejected act").as_map().unwrap();
        let admission = integrity_cbor::map_lookup_map(act, "admission").expect("admission");
        assert_eq!(
            integrity_cbor::map_lookup_text(admission, "outcome").expect("outcome"),
            "rejected"
        );
        assert_eq!(
            integrity_cbor::map_lookup_text(admission, "failure_reason").expect("failure_reason"),
            "method_unregistered"
        );

        let report = trellis_verify_wos::verify_export_zip(&bundle_bytes);
        assert!(
            report.wos_findings.is_empty() && report.relying_party_valid(),
            "{report:#?}"
        );
    }

    #[tokio::test]
    async fn signature_admission_failed_with_posture_floor_unmet_suppresses_policy_closure() {
        let app = router(test_state()).expect("router");
        let response = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_posture_failed_signature/events",
                signature_admission_failed_append_body_with_reason(
                    "idem-posture-failed-signature",
                    "posture_floor_unmet",
                    "urn:wos:signing-intent:applicant-signature",
                ),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);

        let bundle = app
            .oneshot(get_request(
                "/v1/scopes/case_posture_failed_signature/bundles/head",
            ))
            .await
            .expect("bundle response");
        assert_eq!(bundle.status(), StatusCode::OK);
        let bundle_bytes = to_bytes(bundle.into_body(), 10 * 1024 * 1024)
            .await
            .expect("bundle bytes")
            .to_vec();
        let members = integrity_bundle::read_stored_zip(&bundle_bytes).expect("parse bundle");
        assert!(
            members.iter().any(|entry| entry
                .path()
                .ends_with(trellis_export_writer::SIGNED_ACTS_MEMBER)),
            "signature exports must still carry 066-signed-acts.cbor"
        );
        assert!(
            members.iter().all(|entry| !entry
                .path()
                .ends_with(trellis_export_writer::POLICY_CLOSURE_MEMBER)),
            "posture-specific rejection policy is not represented by the default closure evidence"
        );

        let report = trellis_verify_wos::verify_export_zip(&bundle_bytes);
        assert!(
            report.wos_findings.is_empty() && report.relying_party_valid(),
            "{report:#?}"
        );
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
        assert_eq!(first.seal_version, 1);
        assert_eq!(first.export_attempt_id, second.export_attempt_id);
        assert!(
            first
                .artifact_ref
                .uri
                .contains(first.export_attempt_id.trim_start_matches("sha256:")),
            "bundle artifact key should be export-attempt keyed: {}",
            first.artifact_ref.uri
        );
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
        let manifest = manifest_payload_from_bundle(&first_bytes);
        let manifest_map = manifest.as_map().expect("manifest map");
        let extensions = map_lookup_map(manifest_map, "extensions").expect("extensions");
        let seal_fence = extensions
            .iter()
            .find(|(key, _)| key.as_text() == Some("trellis.export.seal-fence.v1"))
            .map(|(_, value)| value.as_map().expect("seal fence map"))
            .expect("seal fence extension");
        assert_eq!(
            map_lookup_bytes(seal_fence, "bundle_scope")
                .expect("bundle scope")
                .as_slice(),
            b"case_deterministic"
        );
        assert_eq!(
            seal_fence
                .iter()
                .find(|(key, _)| key.as_text() == Some("export_attempt_id"))
                .and_then(|(_, value)| value.as_text()),
            Some(first.export_attempt_id.as_str())
        );
        assert_eq!(
            seal_fence
                .iter()
                .find(|(key, _)| key.as_text() == Some("policy_closure_digest"))
                .map(|(_, value)| value),
            Some(&Value::Null)
        );
        assert_eq!(
            first_bytes, second_bytes,
            "publishing identical ledger state twice must produce byte-identical ZIP output"
        );
    }

    #[tokio::test]
    async fn signature_profile_bundle_republish_is_byte_identical() {
        let state = test_state();
        let app = router(state.clone()).expect("router");
        let first_response = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_signature_deterministic/events",
                signature_affirmation_append_body("idem-signature-deterministic-1"),
            ))
            .await
            .expect("append signature response");
        assert_eq!(first_response.status(), StatusCode::CREATED);
        let second_response = app
            .oneshot(post_request(
                "/v1/scopes/case_signature_deterministic/events",
                signature_admission_failed_append_body("idem-signature-deterministic-2"),
            ))
            .await
            .expect("append rejected signature response");
        assert_eq!(second_response.status(), StatusCode::CREATED);

        let events = state
            .repository
            .list_scope(b"case_signature_deterministic")
            .await
            .expect("load deterministic signature scope events");
        let compute = append::default_public_compute_context();
        let first = publish_bundle(
            &state,
            b"case_signature_deterministic",
            &events,
            false,
            &compute,
        )
        .await
        .expect("first publish");
        let second = publish_bundle(
            &state,
            b"case_signature_deterministic",
            &events,
            false,
            &compute,
        )
        .await
        .expect("second publish");
        assert_eq!(first.seal_version, 2);
        assert_eq!(first.export_attempt_id, second.export_attempt_id);
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
            "profile-bearing bundles must remain byte-identical for the same closed signature event set"
        );
    }

    #[tokio::test]
    async fn failing_profile_verification_prevents_artifact_storage() {
        #[derive(Default)]
        struct CountingArtifactStore {
            puts: AtomicUsize,
        }

        #[async_trait]
        impl ArtifactStore for CountingArtifactStore {
            type Error = StackError;

            async fn put(&self, key: &str, _bytes: &[u8]) -> Result<ArtifactRef, Self::Error> {
                self.puts.fetch_add(1, Ordering::SeqCst);
                Ok(ArtifactRef::new(format!("memory://{key}")))
            }

            async fn put_immutable(
                &self,
                key: &str,
                _bytes: &[u8],
            ) -> Result<ArtifactRef, Self::Error> {
                self.puts.fetch_add(1, Ordering::SeqCst);
                Ok(ArtifactRef::new(format!("memory://{key}")))
            }

            async fn get(
                &self,
                _artifact_ref: &ArtifactRef,
            ) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(None)
            }
        }

        let store = Arc::new(CountingArtifactStore::default());
        let state = test_state()
            .with_artifact_store(store.clone())
            .with_profile_export_verifier(Arc::new(|_zip_bytes| false));
        let app = router(state).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_signature_verifier_failure/events",
                signature_affirmation_append_body("idem-signature-verifier-failure"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            store.puts.load(Ordering::SeqCst),
            0,
            "profile verification must fail before export bytes are stored"
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

            async fn put_immutable(
                &self,
                _key: &str,
                _bytes: &[u8],
            ) -> Result<ArtifactRef, Self::Error> {
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
                "/v1/scopes/formspec.managed-single-cell/events",
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
                "/v1/scopes/formspec.managed-single-cell/events",
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    fn assert_missing_policy_closure_advisory(report: &trellis_verify_wos::WosVerificationReport) {
        assert_eq!(
            report.wos_findings.len(),
            1,
            "signed-scope bundle without closure evidence should emit one advisory: {report:#?}"
        );
        let finding = &report.wos_findings[0];
        assert_eq!(finding.kind, "policy_closure_missing_for_signed_scope");
        assert_eq!(
            finding.severity,
            integrity_verify::trellis::Severity::Advisory
        );
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

    fn manifest_payload_from_bundle(bundle_bytes: &[u8]) -> Value {
        const COSE_SIGN1_TAG: u64 = 18;

        let entries = integrity_bundle::read_stored_zip(bundle_bytes).expect("parse bundle ZIP");
        let manifest_bytes = entries
            .iter()
            .find(|entry| {
                entry
                    .path()
                    .ends_with(trellis_export_writer::MANIFEST_MEMBER)
            })
            .map(|entry| entry.bytes())
            .expect("manifest member");
        let sign1 = integrity_cbor::decode_cbor_value(manifest_bytes).expect("manifest COSE CBOR");
        let Value::Tag(tag, inner) = sign1 else {
            panic!("manifest member must be tagged COSE_Sign1");
        };
        assert_eq!(tag, COSE_SIGN1_TAG);
        let fields = inner.as_array().expect("COSE_Sign1 array");
        let payload = fields
            .get(2)
            .and_then(Value::as_bytes)
            .expect("embedded manifest payload");
        integrity_cbor::decode_cbor_value(payload).expect("manifest payload CBOR")
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

    fn signature_affirmation_append_body(idempotency_key: &str) -> Vec<u8> {
        signature_affirmation_append_body_with_intent(
            idempotency_key,
            "urn:wos:signing-intent:applicant-signature",
            None,
            None,
        )
    }

    fn signature_affirmation_append_body_with_intent(
        idempotency_key: &str,
        signing_intent: &str,
        profile_ref: Option<&str>,
        profile_key: Option<&str>,
    ) -> Vec<u8> {
        let mut record = ProvenanceRecord::signature_affirmation(SignatureAffirmationInput {
            signer_id: "applicant",
            role_id: "role-applicant-signer",
            role: "applicant",
            document_id: "benefits-application",
            signing_act_id: "signing-act-server-test",
            document_ref: serde_json::json!({
                "documentId": "benefits-application",
                "locale": "en-US"
            }),
            document_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            presentation_hash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            document_hash_algorithm: "sha-256",
            source_signature_system: "formspec",
            source_signature_id: "sig-server-test",
            signed_payload_digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            signed_payload_digest_algorithm: "sha-256",
            signing_intent,
            signed_at: "2026-05-16T18:31:00Z",
            identity_binding: serde_json::json!({
                "kind": "subjectRef",
                "ref": "applicant"
            }),
            consent_reference: serde_json::json!({
                "textRef": "consent-v1",
                "acceptedAt": "2026-05-16T18:30:00Z"
            }),
            signature_provider: "formspec-local",
            ceremony_id: "ceremony-server-test",
            profile_ref,
            profile_key,
            source_response_ref: "formspec://responses/resp-server-test",
            signer_authority: None,
            custody_hook_eligible: true,
            primitive_verification: serde_json::json!({
                "status": "verified"
            }),
            verification_receipt: None,
            witnessed_signature_ref: None,
        });
        record.id = format!("prov-{idempotency_key}");
        record.timestamp = "2026-05-16T18:31:00Z".to_string();
        let event_type = ProvenanceKind::SignatureAffirmation
            .canonical_event_literal()
            .expect("signature affirmation has event literal")
            .to_string();
        let body = SubstrateAppendBody {
            event_type,
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

    fn signature_admission_failed_append_body(idempotency_key: &str) -> Vec<u8> {
        signature_admission_failed_append_body_with_reason(
            idempotency_key,
            "method_unregistered",
            "urn:wos:signing-intent:applicant-signature",
        )
    }

    fn signature_admission_failed_append_body_with_reason(
        idempotency_key: &str,
        reason: &'static str,
        signing_intent: &'static str,
    ) -> Vec<u8> {
        let mut failure_context = serde_json::Map::new();
        failure_context.insert(
            "methodUri".to_string(),
            serde_json::Value::String("urn:formspec:sig-method:unknown@1".to_string()),
        );
        let mut record = ProvenanceRecord::signature_admission_failed(
            SignatureAdmissionFailedInput {
                reason,
                response_id: "resp-rejected-server-test",
                signed_payload_digest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                signature_id: "sig-rejected-server-test",
                signing_intent,
                signer_id: Some("applicant"),
                signer_authority: None,
                failure_context: Some(failure_context),
                emitted_at: "2026-05-16T18:32:00Z",
            },
        );
        record.id = format!("prov-{idempotency_key}");
        record.timestamp = "2026-05-16T18:32:00Z".to_string();
        let event_type = ProvenanceKind::SignatureAdmissionFailed
            .canonical_event_literal()
            .expect("signature admission failed has event literal")
            .to_string();
        let body = SubstrateAppendBody {
            event_type,
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
