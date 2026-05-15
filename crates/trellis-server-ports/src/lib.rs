// Rust guideline compliant 2026-02-21
//! Composition-root port contracts for the Trellis service boundary.
//!
//! This crate owns the service-facing seams. Protocol byte construction stays
//! in `trellis-core` / `trellis-types`; deployment volatility lives behind the
//! traits here.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;

use async_trait::async_trait;
pub use stack_common_error::StackError;
pub use stack_common_object_store::{ObjectByteEvidence, S3ObjectConfig};
pub use stack_common_postgres::PoolConfig as PostgresPoolConfig;
pub use trellis_core::LedgerStore;
use trellis_types::StoredEvent;

/// Ledger scope bytes.
pub type ScopeId = Vec<u8>;

/// Event type literal admitted at the service edge.
pub type EventType = String;

/// Schema reference bound to an event type.
pub type SchemaRef = String;

/// Opaque artifact locator returned by an artifact store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactRef {
    pub uri: String,
    pub evidence: Option<ObjectByteEvidence>,
}

impl ArtifactRef {
    #[must_use]
    pub fn new(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            evidence: None,
        }
    }

    #[must_use]
    pub fn with_evidence(uri: impl Into<String>, evidence: ObjectByteEvidence) -> Self {
        Self {
            uri: uri.into(),
            evidence: Some(evidence),
        }
    }
}

/// Durable artifact store for export bundles and verifier material.
#[async_trait]
pub trait ArtifactStore: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn put(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, Self::Error>;

    async fn get(&self, artifact_ref: &ArtifactRef) -> Result<Option<Vec<u8>>, Self::Error>;
}

/// S3-compatible artifact-store adapter backed by shared stack object helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3CompatibleArtifactStore {
    config: S3ObjectConfig,
    prefix: String,
}

impl S3CompatibleArtifactStore {
    #[must_use]
    pub fn new(config: S3ObjectConfig, prefix: impl Into<String>) -> Self {
        Self {
            config,
            prefix: prefix.into(),
        }
    }

    fn location_for_key(&self, key: &str) -> Result<String, StackError> {
        let key_segments = key
            .split('/')
            .map(str::trim)
            .filter(|segment| !segment.is_empty())
            .map(stack_common_object_store::path_segment)
            .collect::<Vec<_>>();
        if key_segments.is_empty() {
            return Err(StackError::bad_request("artifact key is empty"));
        }

        let prefix = self.prefix.trim_matches('/');
        if prefix.is_empty() {
            Ok(key_segments.join("/"))
        } else {
            Ok(format!("{prefix}/{}", key_segments.join("/")))
        }
    }

    fn uri_for_location(&self, location: &str) -> String {
        format!("s3://{}/{location}", self.config.bucket)
    }
}

#[async_trait]
impl ArtifactStore for S3CompatibleArtifactStore {
    type Error = StackError;

    async fn put(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, Self::Error> {
        let location = self.location_for_key(key)?;
        let uri = self.uri_for_location(&location);
        let evidence =
            stack_common_object_store::write_s3_object_bytes(&self.config, &uri, bytes).await?;
        Ok(ArtifactRef::with_evidence(uri, evidence))
    }

    async fn get(&self, artifact_ref: &ArtifactRef) -> Result<Option<Vec<u8>>, Self::Error> {
        let location =
            stack_common_object_store::parse_s3_object_uri(&self.config, &artifact_ref.uri)?;
        let store = stack_common_object_store::build_s3_store(&self.config)?;
        let bytes = stack_common_object_store::read_object_bytes(&store, &location).await?;
        Ok(Some(bytes))
    }
}

/// Active signing-key descriptor for a scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningKeyDescriptor {
    pub kid: Vec<u8>,
    pub suite_id: u64,
    pub key_ref: String,
}

/// Signing-key lookup port.
#[async_trait]
pub trait SigningKeyRegistry: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn active_signing_key(&self, scope: &[u8]) -> Result<SigningKeyDescriptor, Self::Error>;
}

/// Signing request passed to deployment-owned signing backends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignRequest<'a> {
    pub key: &'a SigningKeyDescriptor,
    pub payload: &'a [u8],
}

/// Signature bytes returned by a signing backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureBytes(pub Vec<u8>);

/// Signing backend port.
#[async_trait]
pub trait Signer: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn sign(&self, request: SignRequest<'_>) -> Result<SignatureBytes, Self::Error>;
}

/// Payload-protection request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectPayloadRequest<'a> {
    pub scope: &'a [u8],
    pub plaintext: &'a [u8],
    pub recipients: &'a [Recipient],
}

/// Payload recipient selected for HPKE protection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient {
    pub kid: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Protected payload bytes and associated recipient metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedPayload {
    pub bytes: Vec<u8>,
    pub recipients: Vec<Recipient>,
}

/// Payload protection policy/backing implementation.
#[async_trait]
pub trait PayloadProtector: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn protect(
        &self,
        request: ProtectPayloadRequest<'_>,
    ) -> Result<ProtectedPayload, Self::Error>;

    async fn open(
        &self,
        scope: &[u8],
        protected: &ProtectedPayload,
    ) -> Result<Vec<u8>, Self::Error>;
}

/// Recipient lookup for protected payloads.
#[async_trait]
pub trait RecipientResolver: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn recipients_for(
        &self,
        scope: &[u8],
        event_type: &str,
    ) -> Result<Vec<Recipient>, Self::Error>;
}

/// Event payload offered to service-level admission policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionEvent<'a> {
    pub scope: &'a [u8],
    pub event_type: &'a str,
    pub payload: &'a [u8],
}

/// Service-level event admission policy.
#[async_trait]
pub trait EventAdmissionPolicy: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn admit(&self, event: &AdmissionEvent<'_>) -> Result<(), Self::Error>;
}

/// Scope action checked by the authorizer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeAction {
    Append,
    Read,
    Administer,
}

/// Scope authorization request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeAuthorization<'a> {
    pub actor: &'a str,
    pub scope: &'a [u8],
    pub action: ScopeAction,
}

/// Scope authorization port.
#[async_trait]
pub trait ScopeAuthorizer: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn authorize(&self, request: &ScopeAuthorization<'_>) -> Result<(), Self::Error>;
}

/// Stored idempotency replay result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdempotencyReplay {
    Miss,
    Hit(Vec<u8>),
    Conflict,
}

/// Idempotency/replay port for Trellis HTTP requests.
#[async_trait]
pub trait IdempotencyStore: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn resolve(
        &self,
        scope: &[u8],
        key: &[u8],
        request_hash: &[u8],
    ) -> Result<IdempotencyReplay, Self::Error>;

    async fn record(
        &self,
        scope: &[u8],
        key: &[u8],
        request_hash: &[u8],
        response: &[u8],
    ) -> Result<(), Self::Error>;
}

/// Clock port for deterministic tests and production time.
pub trait Clock {
    fn now_unix_millis(&self) -> u64;
}

/// Identifier generation port.
pub trait IdGenerator {
    type Error: std::error::Error + Send + Sync + 'static;

    fn new_id(&mut self, prefix: &str) -> Result<String, Self::Error>;
}

/// Entropy source for nonces and key generation.
pub trait EntropySource {
    type Error: std::error::Error + Send + Sync + 'static;

    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error>;
}

/// Sensitivity class disclosed for delegated compute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComputeSensitivity {
    PublicMetadata,
    ProviderReadable,
    ReaderHeld,
    Restricted,
}

impl ComputeSensitivity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PublicMetadata => "publicMetadata",
            Self::ProviderReadable => "providerReadable",
            Self::ReaderHeld => "readerHeld",
            Self::Restricted => "restricted",
        }
    }
}

/// Required delegated-compute disclosure context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeContext {
    pub declaration_id: String,
    pub actor: String,
    pub sensitivity: ComputeSensitivity,
}

/// Compute-disclosure port. Producers cannot create an append unit of work
/// without a [`ComputeContext`].
#[async_trait]
pub trait ComputeDisclosure: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn declare_compute(
        &self,
        actor: &str,
        sensitivity: ComputeSensitivity,
    ) -> Result<ComputeContext, Self::Error>;
}

/// Deterministic no-op compute disclosure implementation for deployments that
/// have no delegated compute yet but still need the required seam.
#[derive(Default, Debug, Clone, Copy)]
pub struct NoopComputeDisclosure;

#[async_trait]
impl ComputeDisclosure for NoopComputeDisclosure {
    type Error = Infallible;

    async fn declare_compute(
        &self,
        actor: &str,
        sensitivity: ComputeSensitivity,
    ) -> Result<ComputeContext, Self::Error> {
        Ok(ComputeContext {
            declaration_id: format!("compute:{actor}:{}", sensitivity.as_str()),
            actor: actor.to_string(),
            sensitivity,
        })
    }
}

/// Atomic append work accepted by the Trellis service layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendUnitOfWork {
    event: StoredEvent,
    compute_context: ComputeContext,
}

impl AppendUnitOfWork {
    #[must_use]
    pub fn new(event: StoredEvent, compute_context: ComputeContext) -> Self {
        Self {
            event,
            compute_context,
        }
    }

    #[must_use]
    pub fn event(&self) -> &StoredEvent {
        &self.event
    }

    #[must_use]
    pub fn compute_context(&self) -> &ComputeContext {
        &self.compute_context
    }
}

/// Projection registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionRegistration {
    pub projection_id: String,
    pub description: String,
}

/// Projection watermark emitted after derived state is updated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionWatermark {
    pub projection_id: String,
    pub scope: ScopeId,
    pub sequence: u64,
}

/// Projection runtime port for derived-state consumers.
#[async_trait]
pub trait ProjectionRuntime: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn register(&mut self, registration: ProjectionRegistration) -> Result<(), Self::Error>;

    async fn watermark(
        &mut self,
        projection_id: &str,
        scope: &[u8],
        sequence: u64,
    ) -> Result<ProjectionWatermark, Self::Error>;

    async fn replay_from(
        &self,
        projection_id: &str,
        scope: &[u8],
        from_sequence: u64,
    ) -> Result<Vec<StoredEvent>, Self::Error>;
}

/// In-memory projection runtime for tests and local composition.
#[derive(Default, Debug)]
pub struct InMemoryProjectionRuntime {
    registrations: BTreeSet<String>,
    watermarks: BTreeMap<(String, ScopeId), u64>,
    events: Vec<StoredEvent>,
}

impl InMemoryProjectionRuntime {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_event(&mut self, event: StoredEvent) {
        self.events.push(event);
    }
}

#[async_trait]
impl ProjectionRuntime for InMemoryProjectionRuntime {
    type Error = StackError;

    async fn register(&mut self, registration: ProjectionRegistration) -> Result<(), Self::Error> {
        self.registrations.insert(registration.projection_id);
        Ok(())
    }

    async fn watermark(
        &mut self,
        projection_id: &str,
        scope: &[u8],
        sequence: u64,
    ) -> Result<ProjectionWatermark, Self::Error> {
        if !self.registrations.contains(projection_id) {
            return Err(StackError::bad_request(format!(
                "projection `{projection_id}` is not registered"
            )));
        }
        let watermark = ProjectionWatermark {
            projection_id: projection_id.to_string(),
            scope: scope.to_vec(),
            sequence,
        };
        self.watermarks.insert(
            (watermark.projection_id.clone(), watermark.scope.clone()),
            sequence,
        );
        Ok(watermark)
    }

    async fn replay_from(
        &self,
        projection_id: &str,
        scope: &[u8],
        from_sequence: u64,
    ) -> Result<Vec<StoredEvent>, Self::Error> {
        if !self.registrations.contains(projection_id) {
            return Err(StackError::bad_request(format!(
                "projection `{projection_id}` is not registered"
            )));
        }
        Ok(self
            .events
            .iter()
            .filter(|event| event.scope() == scope && event.sequence() >= from_sequence)
            .cloned()
            .collect())
    }
}

/// Posture declaration for a case scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostureDeclaration {
    pub posture_id: String,
    pub profile: String,
    pub custody_model: String,
}

/// Posture transition emitted for custody/profile changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostureTransition {
    pub from: String,
    pub to: String,
    pub reason: String,
}

/// Recorded posture event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PostureEvent {
    Initial {
        scope: ScopeId,
        posture: PostureDeclaration,
    },
    Transition {
        scope: ScopeId,
        transition: PostureTransition,
    },
}

/// Posture ledger port.
#[async_trait]
pub trait PostureLedger: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn declare_initial(
        &mut self,
        scope: &[u8],
        posture: PostureDeclaration,
    ) -> Result<PostureEvent, Self::Error>;

    async fn transition(
        &mut self,
        scope: &[u8],
        transition: PostureTransition,
    ) -> Result<PostureEvent, Self::Error>;
}

/// In-memory posture ledger.
#[derive(Default, Debug)]
pub struct InMemoryPostureLedger {
    events: Vec<PostureEvent>,
}

impl InMemoryPostureLedger {
    #[must_use]
    pub fn events(&self) -> &[PostureEvent] {
        &self.events
    }
}

#[async_trait]
impl PostureLedger for InMemoryPostureLedger {
    type Error = Infallible;

    async fn declare_initial(
        &mut self,
        scope: &[u8],
        posture: PostureDeclaration,
    ) -> Result<PostureEvent, Self::Error> {
        let event = PostureEvent::Initial {
            scope: scope.to_vec(),
            posture,
        };
        self.events.push(event.clone());
        Ok(event)
    }

    async fn transition(
        &mut self,
        scope: &[u8],
        transition: PostureTransition,
    ) -> Result<PostureEvent, Self::Error> {
        let event = PostureEvent::Transition {
            scope: scope.to_vec(),
            transition,
        };
        self.events.push(event.clone());
        Ok(event)
    }
}

/// Registry binding emitted at a known chain sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryBinding {
    pub scope: ScopeId,
    pub event_type: EventType,
    pub schema_ref: SchemaRef,
    pub bound_at_sequence: u64,
}

/// Registry binding port.
#[async_trait]
pub trait RegistryBinder: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn bind_event_type(
        &mut self,
        scope: &[u8],
        event_type: &str,
        schema_ref: &str,
        bound_at_sequence: u64,
    ) -> Result<RegistryBinding, Self::Error>;

    async fn resolve(
        &self,
        scope: &[u8],
        event_type: &str,
        at_sequence: u64,
    ) -> Result<Option<RegistryBinding>, Self::Error>;
}

/// In-memory registry binder with deterministic sequence resolution.
#[derive(Default, Debug)]
pub struct InMemoryRegistryBinder {
    bindings: Vec<RegistryBinding>,
}

#[async_trait]
impl RegistryBinder for InMemoryRegistryBinder {
    type Error = Infallible;

    async fn bind_event_type(
        &mut self,
        scope: &[u8],
        event_type: &str,
        schema_ref: &str,
        bound_at_sequence: u64,
    ) -> Result<RegistryBinding, Self::Error> {
        let binding = RegistryBinding {
            scope: scope.to_vec(),
            event_type: event_type.to_string(),
            schema_ref: schema_ref.to_string(),
            bound_at_sequence,
        };
        self.bindings.push(binding.clone());
        Ok(binding)
    }

    async fn resolve(
        &self,
        scope: &[u8],
        event_type: &str,
        at_sequence: u64,
    ) -> Result<Option<RegistryBinding>, Self::Error> {
        Ok(self
            .bindings
            .iter()
            .filter(|binding| {
                binding.scope == scope
                    && binding.event_type == event_type
                    && binding.bound_at_sequence <= at_sequence
            })
            .max_by_key(|binding| binding.bound_at_sequence)
            .cloned())
    }
}

/// Registration-time metadata budget review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetReviewRecord {
    pub reviewer: String,
    pub plaintext_fields: Vec<String>,
    pub considered: bool,
}

/// Event type registration request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventTypeSpec {
    pub event_type: EventType,
    pub schema_ref: SchemaRef,
    pub budget_review: BudgetReviewRecord,
}

/// Registered event type reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventTypeRef {
    pub event_type: EventType,
    pub schema_ref: SchemaRef,
}

/// Registration-time budget review failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BudgetViolation {
    EmptyReviewer,
    NotConsidered,
}

impl std::fmt::Display for BudgetViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyReviewer => f.write_str("event type budget review requires a reviewer"),
            Self::NotConsidered => {
                f.write_str("event type budget review must mark metadata budget as considered")
            }
        }
    }
}

impl std::error::Error for BudgetViolation {}

/// Event type registry gate.
pub trait EventTypeRegistry {
    fn register(&mut self, spec: EventTypeSpec) -> Result<EventTypeRef, BudgetViolation>;
}

/// In-memory registry gate that enforces required budget review metadata.
#[derive(Default, Debug)]
pub struct ReviewGateEventTypeRegistry {
    entries: BTreeMap<EventType, EventTypeRef>,
}

impl EventTypeRegistry for ReviewGateEventTypeRegistry {
    fn register(&mut self, spec: EventTypeSpec) -> Result<EventTypeRef, BudgetViolation> {
        if spec.budget_review.reviewer.trim().is_empty() {
            return Err(BudgetViolation::EmptyReviewer);
        }
        if !spec.budget_review.considered {
            return Err(BudgetViolation::NotConsidered);
        }
        let event_ref = EventTypeRef {
            event_type: spec.event_type,
            schema_ref: spec.schema_ref,
        };
        self.entries
            .insert(event_ref.event_type.clone(), event_ref.clone());
        Ok(event_ref)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(scope: &[u8], sequence: u64) -> StoredEvent {
        StoredEvent::new(scope.to_vec(), sequence, vec![sequence as u8], vec![0xaa])
    }

    #[test]
    fn s3_artifact_store_builds_sanitized_prefixed_locations() {
        let store = S3CompatibleArtifactStore::new(
            S3ObjectConfig {
                bucket: "proof-bundles".to_string(),
                endpoint: None,
                region: None,
            },
            "/case exports/",
        );

        assert_eq!(
            store
                .location_for_key("case 1/export bundle.zip")
                .expect("location"),
            "case exports/case_1/export_bundle.zip"
        );
    }

    #[tokio::test]
    async fn append_unit_requires_compute_context() {
        let context = NoopComputeDisclosure
            .declare_compute("agent-a", ComputeSensitivity::ReaderHeld)
            .await
            .expect("compute context");
        let unit = AppendUnitOfWork::new(event(b"case-1", 0), context.clone());

        assert_eq!(unit.compute_context(), &context);
        assert_eq!(unit.event().scope(), b"case-1");
    }

    #[tokio::test]
    async fn projection_runtime_requires_registration_and_replays_from_watermark() {
        let mut runtime = InMemoryProjectionRuntime::new();
        runtime.record_event(event(b"case-1", 0));
        runtime.record_event(event(b"case-1", 1));
        runtime.record_event(event(b"case-2", 0));

        assert!(
            runtime
                .watermark("case-view", b"case-1", 0)
                .await
                .expect_err("unregistered projection")
                .to_string()
                .contains("not registered")
        );

        runtime
            .register(ProjectionRegistration {
                projection_id: "case-view".to_string(),
                description: "case projection".to_string(),
            })
            .await
            .expect("register");
        let watermark = runtime
            .watermark("case-view", b"case-1", 1)
            .await
            .expect("watermark");
        assert_eq!(watermark.sequence, 1);

        let replay = runtime
            .replay_from("case-view", b"case-1", 1)
            .await
            .expect("replay");
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].sequence(), 1);
    }

    #[tokio::test]
    async fn posture_ledger_records_initial_and_transition_events() {
        let mut ledger = InMemoryPostureLedger::default();

        ledger
            .declare_initial(
                b"case-1",
                PostureDeclaration {
                    posture_id: "posture-1".to_string(),
                    profile: "phase1".to_string(),
                    custody_model: "reader-held".to_string(),
                },
            )
            .await
            .expect("initial");
        ledger
            .transition(
                b"case-1",
                PostureTransition {
                    from: "posture-1".to_string(),
                    to: "posture-2".to_string(),
                    reason: "profile upgrade".to_string(),
                },
            )
            .await
            .expect("transition");

        assert_eq!(ledger.events().len(), 2);
    }

    #[tokio::test]
    async fn registry_binder_resolves_largest_binding_not_after_sequence() {
        let mut binder = InMemoryRegistryBinder::default();
        binder
            .bind_event_type(b"case-1", "wos.kernel.case_created", "schema:v1", 2)
            .await
            .expect("bind v1");
        binder
            .bind_event_type(b"case-1", "wos.kernel.case_created", "schema:v2", 5)
            .await
            .expect("bind v2");

        assert!(
            binder
                .resolve(b"case-1", "wos.kernel.case_created", 1)
                .await
                .expect("resolve")
                .is_none()
        );
        assert_eq!(
            binder
                .resolve(b"case-1", "wos.kernel.case_created", 4)
                .await
                .expect("resolve")
                .expect("binding")
                .schema_ref,
            "schema:v1"
        );
        assert_eq!(
            binder
                .resolve(b"case-1", "wos.kernel.case_created", 5)
                .await
                .expect("resolve")
                .expect("binding")
                .schema_ref,
            "schema:v2"
        );
    }

    #[test]
    fn event_type_registry_requires_budget_review() {
        let mut registry = ReviewGateEventTypeRegistry::default();

        let err = registry
            .register(EventTypeSpec {
                event_type: "wos.kernel.case_created".to_string(),
                schema_ref: "schema:v1".to_string(),
                budget_review: BudgetReviewRecord {
                    reviewer: "".to_string(),
                    plaintext_fields: vec![],
                    considered: true,
                },
            })
            .expect_err("reviewer required");
        assert_eq!(err, BudgetViolation::EmptyReviewer);

        let event_ref = registry
            .register(EventTypeSpec {
                event_type: "wos.kernel.case_created".to_string(),
                schema_ref: "schema:v1".to_string(),
                budget_review: BudgetReviewRecord {
                    reviewer: "security-review".to_string(),
                    plaintext_fields: vec!["eventType".to_string()],
                    considered: true,
                },
            })
            .expect("register");
        assert_eq!(event_ref.schema_ref, "schema:v1");
    }
}
