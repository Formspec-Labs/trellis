// Rust guideline compliant 2026-02-21
//! Composition-root port contracts for the Trellis service boundary.
//!
//! HTTP request-body replay/idempotency is **not** a port here—it is enforced by
//! `stack-common-http` middleware using `stack-common-idempotency` replay traits
//! (`HttpReplayStore` / `InMemoryHttpReplayStore` in `trellis-server`). Older
//! `IdempotencyStore` port stubs were retired (TWREF-055).
//!
//! This crate owns the service-facing seams. Protocol byte construction stays
//! in `trellis-core` / `trellis-types`; deployment volatility lives behind the
//! traits here.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
pub use stack_common_error::StackError;
pub use stack_common_object_store::{ObjectByteEvidence, S3ObjectConfig};
pub use stack_common_postgres::PoolConfig as PostgresPoolConfig;
pub use trellis_core::LedgerStore;
pub use trellis_service_client::{ComputeContext, ComputeSensitivity};
use trellis_types::StoredEvent;

/// Ledger scope bytes.
pub type ScopeId = Vec<u8>;

/// Event type literal admitted at the service edge.
pub type EventType = String;

/// Validated event-type catalog reference.
///
/// Schema references must be non-empty and URI-like (`<scheme>:...`). The
/// underlying string preserves the original wire spelling for receipts, event-
/// type catalog projection, and audit logging.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SchemaRef(String);

impl SchemaRef {
    /// Parses and validates a schema reference.
    ///
    /// # Errors
    /// Returns [`SchemaRefError`] when the input is empty, all whitespace, or
    /// missing a `<scheme>:` prefix (event-type catalog references must be
    /// URI-like so generic Trellis code can dispatch on them deterministically).
    pub fn new(value: impl Into<String>) -> Result<Self, SchemaRefError> {
        let raw = value.into();
        if raw.trim().is_empty() {
            return Err(SchemaRefError::Empty);
        }
        let Some((scheme, rest)) = raw.split_once(':') else {
            return Err(SchemaRefError::MissingScheme);
        };
        if scheme.is_empty() || rest.is_empty() {
            return Err(SchemaRefError::MissingScheme);
        }
        Ok(Self(raw))
    }

    /// Returns the underlying string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the underlying string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for SchemaRef {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SchemaRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Errors raised when constructing a [`SchemaRef`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaRefError {
    /// The supplied value was empty or whitespace.
    Empty,
    /// The supplied value did not have a `<scheme>:` prefix.
    MissingScheme,
}

impl std::fmt::Display for SchemaRefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("schema reference cannot be empty"),
            Self::MissingScheme => {
                f.write_str("schema reference must be URI-like (`<scheme>:...`)")
            }
        }
    }
}

impl std::error::Error for SchemaRefError {}

/// Stable identifier for the verification profile bound to an event family.
///
/// Profile ids are bit-identical to the integers serialized in
/// [`trellis_service_client::VerificationReceipt`] so that wire compatibility
/// holds across the admission refactor. Generic Trellis service code must use
/// this value rather than re-parsing event-type prefixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProfileId(u64);

impl ProfileId {
    /// Wraps a profile-id constant from `integrity_verify`.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying u64 used on the wire.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for ProfileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Logical event-family identifier emitted by admission for catalog/projection routing.
///
/// Generic Trellis code dispatches on the family rather than the wire literal
/// so producers can extend the catalog without editing service modules.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventFamilyId(String);

impl EventFamilyId {
    /// Builds a family identifier; whitespace-only inputs are rejected.
    ///
    /// # Errors
    /// Returns [`EventFamilyIdError::Empty`] when the input has no
    /// non-whitespace characters.
    pub fn new(value: impl Into<String>) -> Result<Self, EventFamilyIdError> {
        let raw = value.into();
        if raw.trim().is_empty() {
            return Err(EventFamilyIdError::Empty);
        }
        Ok(Self(raw))
    }

    /// Returns the underlying string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for EventFamilyId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EventFamilyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Errors raised when constructing an [`EventFamilyId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventFamilyIdError {
    /// The supplied identifier was empty or whitespace.
    Empty,
}

impl std::fmt::Display for EventFamilyIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("event family id cannot be empty"),
        }
    }
}

impl std::error::Error for EventFamilyIdError {}

/// Whether an event family allows direct (non-service) client submission.
///
/// `AuthorizedClientAllowed` is reserved for ADR 0103 / TWREF-0103 direct
/// client attestation. All admission adapters return [`Self::ServiceOnly`]
/// until that work lands; current trellis-server still rejects appends that
/// carry `clientAttestation`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectSubmitPolicy {
    /// Only the service-authorized producer may submit this event family.
    ServiceOnly,
    /// A direct, client-attested submission is permitted (ADR 0103 follow-on).
    AuthorizedClientAllowed,
}

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
pub struct S3CompatibleArtifactStore {
    config: S3ObjectConfig,
    prefix: String,
    store: Mutex<Option<Arc<dyn object_store::ObjectStore + Send + Sync>>>,
}

impl std::fmt::Debug for S3CompatibleArtifactStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let initialized = self.store.lock().ok().map(|g| g.is_some()).unwrap_or(false);
        f.debug_struct("S3CompatibleArtifactStore")
            .field("config", &self.config)
            .field("prefix", &self.prefix)
            .field("store_initialized", &initialized)
            .finish()
    }
}

impl S3CompatibleArtifactStore {
    #[must_use]
    pub fn new(config: S3ObjectConfig, prefix: impl Into<String>) -> Self {
        Self {
            config,
            prefix: prefix.into(),
            store: Mutex::new(None),
        }
    }

    fn object_store(&self) -> Result<Arc<dyn object_store::ObjectStore + Send + Sync>, StackError> {
        let mut guard = self
            .store
            .lock()
            .map_err(|_| StackError::internal("object store mutex poisoned"))?;
        if let Some(existing) = guard.as_ref() {
            return Ok(Arc::clone(existing));
        }
        let built = Arc::new(stack_common_object_store::build_s3_store(&self.config)?)
            as Arc<dyn object_store::ObjectStore + Send + Sync>;
        *guard = Some(Arc::clone(&built));
        Ok(built)
    }

    /// Binds bucket/prefix semantics to an injected [`ObjectStore`] backend.
    ///
    /// Use [`Self::new`] in production so a lazy S3-compatible client is built from [`S3ObjectConfig`].
    ///
    /// This constructor is not `cfg(test)` because downstream workspaces (for example `formspec-server`
    /// integration tests) compile this crate without `cfg(test)` while still needing a shared in-memory
    /// backend for hermetic Trellis append + Formspec integrity verification.
    ///
    /// Prefer [`TrellisServerState::with_artifact_store`](https://docs.rs/trellis-server/latest/trellis_server/struct.TrellisServerState.html#method.with_artifact_store)
    /// on the Trellis side so append-side `put` bytes match verifier-side `get` paths for `s3://bucket/…` refs.
    #[must_use]
    pub fn from_object_store_for_test(
        config: S3ObjectConfig,
        prefix: impl Into<String>,
        store: Arc<dyn object_store::ObjectStore + Send + Sync>,
    ) -> Self {
        Self {
            config,
            prefix: prefix.into(),
            store: Mutex::new(Some(store)),
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
        stack_common_object_store::parse_s3_object_uri(&self.config, &uri)?;
        let store = self.object_store()?;
        let evidence =
            stack_common_object_store::write_object_bytes(store.as_ref(), &location, bytes).await?;
        Ok(ArtifactRef::with_evidence(uri, evidence))
    }

    async fn get(&self, artifact_ref: &ArtifactRef) -> Result<Option<Vec<u8>>, Self::Error> {
        let location =
            stack_common_object_store::parse_s3_object_uri(&self.config, &artifact_ref.uri)?;
        let store = self.object_store()?;
        let bytes = stack_common_object_store::read_object_bytes(store.as_ref(), &location).await?;
        Ok(Some(bytes))
    }
}

#[cfg(test)]
impl S3CompatibleArtifactStore {
    pub(crate) fn object_store_arc_for_test(
        &self,
    ) -> Result<Arc<dyn object_store::ObjectStore + Send + Sync>, StackError> {
        self.object_store()
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
///
/// `AdmissionEvent` deliberately carries only request facts (scope, event-type
/// literal, payload bytes). Semantic metadata used by generic Trellis code
/// arrives back through [`AdmittedEvent`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionEvent<'a> {
    pub scope: &'a [u8],
    pub event_type: &'a str,
    pub payload: &'a [u8],
}

/// Admitted event metadata returned by [`EventAdmissionPolicy`].
///
/// Carries the wire literal alongside neutral catalog metadata so receipts,
/// projection runtimes, and dispatch can consult a single source of truth
/// without re-parsing event-type prefixes in generic service code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedEvent {
    /// Wire/audit literal preserved verbatim.
    pub event_type: EventType,
    /// Logical event family used for dispatch and catalog routing.
    pub event_family: EventFamilyId,
    /// Validated event-type catalog reference.
    pub schema_ref: SchemaRef,
    /// Verification profile bound to this event family.
    pub profile_id: ProfileId,
    /// Whether direct (non-service) client submission is permitted.
    pub direct_submit: DirectSubmitPolicy,
}

/// Service-level event admission policy.
///
/// Admission is the source of neutral event metadata downstream consumers use
/// (receipts, event-type catalog projection, dispatch, authorization). The
/// returned [`AdmittedEvent`] is the only path that semantic metadata may
/// enter generic Trellis service code.
#[async_trait]
pub trait EventAdmissionPolicy: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Validates the submitted event and emits neutral metadata for the service path.
    ///
    /// # Errors
    /// Returns the implementor's error type when admission rejects the event.
    async fn admit(&self, event: &AdmissionEvent<'_>) -> Result<AdmittedEvent, Self::Error>;
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
    /// Claim names from the verified bearer JWT (`TrellisClaims.scopes`), when a token was presented.
    pub jwt_scopes: Option<&'a [String]>,
}

/// Scope authorization port.
#[async_trait]
pub trait ScopeAuthorizer: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn authorize(&self, request: &ScopeAuthorization<'_>) -> Result<(), Self::Error>;
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
///
/// **Naming note:** Trellis Core spec §14.3 defines a `RegistryBinding` type
/// in the byte-protocol export envelope that carries
/// `{registry_digest, registry_format, registry_version, bound_at_sequence}`.
/// This port-layer `RegistryBinding` is a different shape (service-side
/// event-type catalog binding for a scope at a sequence); the names overlap
/// only by coincidence. Do not assume the two structures share a wire shape.
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
        schema_ref: SchemaRef,
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
        schema_ref: SchemaRef,
        bound_at_sequence: u64,
    ) -> Result<RegistryBinding, Self::Error> {
        let binding = RegistryBinding {
            scope: scope.to_vec(),
            event_type: event_type.to_string(),
            schema_ref,
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
    use trellis_service_client as trellis_client;

    fn event(scope: &[u8], sequence: u64) -> StoredEvent {
        StoredEvent::new(scope.to_vec(), sequence, vec![sequence as u8], vec![0xaa])
    }

    #[test]
    fn given_compute_types_reexported_when_used_then_match_trellis_service_client() {
        fn assert_client(_: trellis_client::ComputeContext) {}

        let ctx = ComputeContext::no_delegated_compute("actor");
        assert_client(ctx);
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
    async fn given_repeated_puts_when_s3_artifact_store_then_reuses_object_store_client() {
        use object_store::memory::InMemory;

        let config = S3ObjectConfig {
            bucket: "proof-bundles".to_string(),
            endpoint: None,
            region: None,
        };
        let backend = Arc::new(InMemory::new()) as Arc<dyn object_store::ObjectStore + Send + Sync>;
        let store = S3CompatibleArtifactStore::from_object_store_for_test(config, "pfx/", backend);
        let first = store.object_store_arc_for_test().expect("store handle");
        store.put("a", b"1").await.expect("put");
        let second = store.object_store_arc_for_test().expect("store handle");
        assert!(Arc::ptr_eq(&first, &second));
        store.put("b", b"2").await.expect("put2");
        let third = store.object_store_arc_for_test().expect("store handle");
        assert!(Arc::ptr_eq(&first, &third));
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
        let schema_v1 = SchemaRef::new("schema:v1").expect("valid schema");
        let schema_v2 = SchemaRef::new("schema:v2").expect("valid schema");
        binder
            .bind_event_type(b"case-1", "wos.kernel.case_created", schema_v1, 2)
            .await
            .expect("bind v1");
        binder
            .bind_event_type(b"case-1", "wos.kernel.case_created", schema_v2, 5)
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
                .schema_ref
                .as_str(),
            "schema:v1"
        );
        assert_eq!(
            binder
                .resolve(b"case-1", "wos.kernel.case_created", 5)
                .await
                .expect("resolve")
                .expect("binding")
                .schema_ref
                .as_str(),
            "schema:v2"
        );
    }

    #[test]
    fn event_type_registry_requires_budget_review() {
        let mut registry = ReviewGateEventTypeRegistry::default();
        let schema = SchemaRef::new("schema:v1").expect("valid schema ref");

        let err = registry
            .register(EventTypeSpec {
                event_type: "wos.kernel.case_created".to_string(),
                schema_ref: schema.clone(),
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
                schema_ref: schema,
                budget_review: BudgetReviewRecord {
                    reviewer: "security-review".to_string(),
                    plaintext_fields: vec!["eventType".to_string()],
                    considered: true,
                },
            })
            .expect("register");
        assert_eq!(event_ref.schema_ref.as_str(), "schema:v1");
    }

    #[test]
    fn given_uri_like_schema_ref_when_parsed_then_round_trips() {
        let parsed = SchemaRef::new("wos-events://wos.kernel.case_created").expect("valid");
        assert_eq!(parsed.as_str(), "wos-events://wos.kernel.case_created");
        assert_eq!(
            parsed.to_string(),
            "wos-events://wos.kernel.case_created".to_string()
        );
    }

    #[test]
    fn given_empty_schema_ref_when_parsed_then_error() {
        assert_eq!(SchemaRef::new(""), Err(SchemaRefError::Empty));
        assert_eq!(SchemaRef::new("   "), Err(SchemaRefError::Empty));
    }

    #[test]
    fn given_schema_ref_without_scheme_when_parsed_then_error() {
        assert_eq!(
            SchemaRef::new("not-a-uri"),
            Err(SchemaRefError::MissingScheme)
        );
        assert_eq!(
            SchemaRef::new(":missing-scheme"),
            Err(SchemaRefError::MissingScheme)
        );
        assert_eq!(
            SchemaRef::new("missing-body:"),
            Err(SchemaRefError::MissingScheme)
        );
    }

    #[test]
    fn given_profile_id_constants_when_wrapped_then_round_trip_preserves_wire_int() {
        let wos = ProfileId::new(1);
        let formspec = ProfileId::new(2);
        assert_eq!(wos.get(), 1);
        assert_eq!(formspec.get(), 2);
        assert_ne!(wos, formspec);
    }

    #[test]
    fn given_event_family_id_when_built_then_rejects_empty() {
        assert_eq!(
            EventFamilyId::new(""),
            Err(EventFamilyIdError::Empty)
        );
        assert_eq!(
            EventFamilyId::new("   "),
            Err(EventFamilyIdError::Empty)
        );
        let family = EventFamilyId::new("wos.kernel").expect("non-empty");
        assert_eq!(family.as_str(), "wos.kernel");
    }

    #[test]
    fn given_admitted_event_when_constructed_then_carries_neutral_metadata() {
        let admitted = AdmittedEvent {
            event_type: "wos.kernel.case_created".to_string(),
            event_family: EventFamilyId::new("wos.kernel").expect("family"),
            schema_ref: SchemaRef::new("wos-events://wos.kernel.case_created").expect("schema"),
            profile_id: ProfileId::new(1),
            direct_submit: DirectSubmitPolicy::ServiceOnly,
        };
        assert_eq!(admitted.event_type, "wos.kernel.case_created");
        assert_eq!(admitted.event_family.as_str(), "wos.kernel");
        assert_eq!(admitted.profile_id.get(), 1);
        assert_eq!(admitted.direct_submit, DirectSubmitPolicy::ServiceOnly);
    }
}
