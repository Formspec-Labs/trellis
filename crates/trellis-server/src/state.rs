// Rust guideline compliant 2026-02-21
//! Cloneable Axum state, env bootstrap, and health probe (TWREF-086 `state` split).

use std::env;
use std::fs;
use std::sync::Arc;

use async_trait::async_trait;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use stack_common_auth::{JwtConfig, JwtVerifier};
use stack_common_error::{ErrorCode, StackError};
use stack_common_http::idempotency::{
    HttpIdempotencyState, IdempotencyCall, IdempotencyDecision, IdempotencyDriverError,
    IdempotencyFailure, IdempotencyOperation,
};
use stack_common_http::problem_response;
use stack_common_http::tenant::{
    HeaderConfig, TenantHeaderConfigProvider, TenantScope, extract_tenant,
    extract_tenant_multi_producer,
};
use stack_common_idempotency::{
    HttpReplayStore, InMemoryHttpReplayStore, ReplayOutcome, StoredResponse,
};
use stack_common_ops::{ComponentHealth, HealthProbe};
use trellis_export_writer::TrellisTimestamp;
use trellis_server_ports::{
    ArtifactStore, EventAdmissionPolicy, S3CompatibleArtifactStore, S3ObjectConfig, ScopeAuthorizer,
};

use crate::admission::{AllowAllScopeAuthorizer, ScopedAllowlistScopeAuthorizer};
use crate::append::{AppendRunner, DefaultAppendRunner};
use crate::artifacts::{BundleIndex, InMemoryArtifactStore, ScopeLocks};
use crate::composition::{EventTypeCatalog, default_admission_policy};
use crate::event_repository::{EventRepository, InMemoryEventRepository, PostgresEventRepository};
use crate::scope_startup::TrellisScopeAuthorizerStartupInputs;
use crate::{ServerSigningKey, TenantHeaderMode, TrellisClaims};

/// Cloneable Axum state for the Trellis service.
#[derive(Clone)]
pub struct TrellisServerState {
    pub(crate) repository: Arc<dyn EventRepository>,
    pub(crate) artifact_store: Arc<dyn ArtifactStore<Error = StackError>>,
    pub(crate) admission_policy: Arc<dyn EventAdmissionPolicy<Error = StackError>>,
    pub(crate) authorizer: Arc<dyn ScopeAuthorizer<Error = StackError>>,
    pub(crate) signing_key: ServerSigningKey,
    tenant_header_mode: TenantHeaderMode,
    replay_store: Arc<InMemoryHttpReplayStore>,
    pub(crate) bundles: Arc<BundleIndex>,
    pub(crate) scope_locks: Arc<ScopeLocks>,
    jwt_verifier: Option<Arc<JwtVerifier<TrellisClaims>>>,
    /// True when [`state_from_env`] used durable storage without `TRELLIS_PERMISSIVE_SCOPE_AUTH=1`.
    production_like_scope_posture: bool,
    /// True while the built-in [`AllowAllScopeAuthorizer`] from [`Self::new`] is still installed.
    scope_authorizer_allow_all: bool,
    pub(crate) append_runner: Arc<dyn AppendRunner>,
    /// Event-type catalog snapshot built from registered admission specs at
    /// startup; the catalog projection routes consult this and never re-parse
    /// literals or hand-build constants.
    pub(crate) event_type_catalog: Arc<EventTypeCatalog>,
}

impl TrellisServerState {
    #[must_use]
    pub fn new(
        repository: Arc<dyn EventRepository>,
        signing_key: ServerSigningKey,
        tenant_header_mode: TenantHeaderMode,
    ) -> Self {
        Self {
            repository,
            artifact_store: Arc::new(InMemoryArtifactStore::default()),
            admission_policy: default_admission_policy(),
            authorizer: Arc::new(AllowAllScopeAuthorizer),
            signing_key,
            tenant_header_mode,
            replay_store: Arc::new(InMemoryHttpReplayStore::new()),
            bundles: Arc::new(BundleIndex::default()),
            scope_locks: Arc::new(ScopeLocks::default()),
            jwt_verifier: None,
            production_like_scope_posture: false,
            scope_authorizer_allow_all: true,
            append_runner: Arc::new(DefaultAppendRunner),
            event_type_catalog: Arc::new(EventTypeCatalog::default_stack()),
        }
    }

    /// Test-only: replace the append runner (constructor injection for delegation proofs).
    #[cfg(test)]
    pub(crate) fn with_append_runner(mut self, runner: Arc<dyn AppendRunner>) -> Self {
        self.append_runner = runner;
        self
    }

    #[must_use]
    pub fn production_like_scope_posture(&self) -> bool {
        self.production_like_scope_posture
    }

    #[must_use]
    pub fn with_production_like_scope_posture(mut self, production_like: bool) -> Self {
        self.production_like_scope_posture = production_like;
        self
    }

    #[must_use]
    pub fn with_artifact_store(
        mut self,
        artifact_store: Arc<dyn ArtifactStore<Error = StackError>>,
    ) -> Self {
        self.artifact_store = artifact_store;
        self
    }

    #[must_use]
    pub fn with_jwt_verifier(mut self, verifier: JwtVerifier<TrellisClaims>) -> Self {
        self.jwt_verifier = Some(Arc::new(verifier));
        self
    }

    #[must_use]
    pub fn with_admission_policy(
        mut self,
        admission_policy: Arc<dyn EventAdmissionPolicy<Error = StackError>>,
    ) -> Self {
        self.admission_policy = admission_policy;
        self
    }

    #[must_use]
    pub fn with_scope_authorizer(
        mut self,
        authorizer: Arc<dyn ScopeAuthorizer<Error = StackError>>,
    ) -> Self {
        self.authorizer = authorizer;
        self.scope_authorizer_allow_all = false;
        self
    }

    /// Refuses misleading compositions: production-like posture must not run with allow-all scope auth.
    ///
    /// # Errors
    /// When the state would advertise production scope posture while still using dev-only authorization.
    pub fn ensure_serving_posture_twref022(&self) -> Result<(), StackError> {
        if !self.production_like_scope_posture {
            return Ok(());
        }
        if self.scope_authorizer_allow_all {
            return Err(StackError::bad_request(
                "trellis-server refuses to build router: production_like_scope_posture requires \
                 a scoped ScopeAuthorizer (JWT scopes allowlist), not AllowAll—set \
                 TRELLIS_PERMISSIVE_SCOPE_AUTH=1 for explicit dev bypass (TWREF-022).",
            ));
        }
        if self.jwt_verifier.is_none() {
            return Err(StackError::bad_request(
                "trellis-server refuses to build router: production_like_scope_posture requires \
                 TRELLIS_JWT_HS256_SECRET / jwt_verifier (TWREF-022).",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub(crate) fn append_coordinator(&self) -> crate::append::AppendCoordinator<'_> {
        crate::append::AppendCoordinator::new(self)
    }

    pub(crate) fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<TrellisClaims>, StackError> {
        let Some(verifier) = &self.jwt_verifier else {
            return Ok(None);
        };
        let token = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| {
                StackError::new(
                    ErrorCode::new("INFRA-4010").expect("static error code is valid"),
                    StatusCode::UNAUTHORIZED,
                    "missing bearer token",
                )
            })?;
        verifier.verify(token).map(Some)
    }
}

impl TenantHeaderConfigProvider for TrellisServerState {
    fn tenant_header_config(&self) -> HeaderConfig {
        match self.tenant_header_mode {
            TenantHeaderMode::Wos => HeaderConfig::wos(),
            TenantHeaderMode::Formspec => HeaderConfig::formspec(),
            TenantHeaderMode::MultiProducer => HeaderConfig::wos(),
        }
    }

    fn extract_tenant_scope(&self, headers: &HeaderMap) -> Result<TenantScope, StackError> {
        match self.tenant_header_mode {
            TenantHeaderMode::MultiProducer => extract_tenant_multi_producer(headers),
            TenantHeaderMode::Wos => extract_tenant(&HeaderConfig::wos(), headers),
            TenantHeaderMode::Formspec => extract_tenant(&HeaderConfig::formspec(), headers),
        }
    }
}

#[async_trait]
impl HttpIdempotencyState for TrellisServerState {
    type Error = StackError;

    async fn reserve_http_idempotency(
        &self,
        call: &IdempotencyCall,
    ) -> Result<IdempotencyDecision, IdempotencyDriverError<Self::Error>> {
        match self
            .replay_store
            .check(
                &tenant_replay_scope(call),
                &call.request.key,
                &call.request.request_hash,
            )
            .await
            .map_err(IdempotencyDriverError::store)?
        {
            ReplayOutcome::Fresh => Ok(IdempotencyDecision::Fresh),
            ReplayOutcome::Replay(response) => Ok(IdempotencyDecision::Replay(response)),
            ReplayOutcome::Conflict => Ok(IdempotencyDecision::Conflict),
        }
    }

    async fn record_http_idempotency_response(
        &self,
        call: &IdempotencyCall,
        response: StoredResponse,
    ) -> Result<(), IdempotencyDriverError<Self::Error>> {
        self.replay_store
            .record(
                &tenant_replay_scope(call),
                &call.request.key,
                &call.request.request_hash,
                response,
            )
            .await
            .map_err(IdempotencyDriverError::store)
    }

    fn idempotency_failure_response(&self, failure: IdempotencyFailure) -> Response {
        let error = match failure {
            IdempotencyFailure::MissingKey => StackError::bad_request("idempotency key required"),
            IdempotencyFailure::RequestBodyCaptureFailed => {
                StackError::bad_request("request body capture failed")
            }
            IdempotencyFailure::Conflict => {
                StackError::conflict("idempotency key reused with a different body")
            }
            IdempotencyFailure::ResponseBodyCaptureFailed => {
                StackError::internal("response body capture failed")
            }
        };
        problem_response(error)
    }

    fn idempotency_store_error_response(
        &self,
        _operation: IdempotencyOperation,
        error: Self::Error,
    ) -> Response {
        problem_response(error)
    }
}

fn tenant_replay_scope(call: &IdempotencyCall) -> String {
    let tenant = header_value(&call.headers, "x-wos-tenant-id")
        .or_else(|| header_value(&call.headers, "x-formspec-tenant-id"))
        .unwrap_or("unknown-tenant");
    format!("{tenant}:{}", call.request.scope)
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Builds a server state from environment variables.
///
/// Required unless `TRELLIS_STORAGE=memory`:
/// - `TRELLIS_DATABASE_URL`
///
/// Always required:
/// - `TRELLIS_SIGNING_KEY_COSE_PATH`
///
/// Optional:
/// - `TRELLIS_STORAGE=memory` (in-memory repository; skips `TRELLIS_DATABASE_URL`)
/// - `TRELLIS_PERMISSIVE_SCOPE_AUTH=1` (durable storage: keep `AllowAllScopeAuthorizer`; optional JWT)
/// - `TRELLIS_JWT_HS256_SECRET` (**required** for durable storage unless `TRELLIS_PERMISSIVE_SCOPE_AUTH=1`; optional otherwise)
/// - `TRELLIS_TENANT_HEADER_SET=wos|formspec|mixed`
/// - `TRELLIS_SIGNING_KEY_VALID_TO_UNIX_SECS`
/// - `TRELLIS_ARTIFACT_BUCKET`
/// - `TRELLIS_ARTIFACT_PREFIX`
/// - `TRELLIS_ARTIFACT_ENDPOINT`
/// - `TRELLIS_ARTIFACT_REGION`
///
/// # Errors
/// Returns an error when config is missing or backend setup fails.
pub async fn state_from_env() -> Result<TrellisServerState, StackError> {
    let scope_inputs = TrellisScopeAuthorizerStartupInputs::from_env();
    let trellis_storage_is_memory = scope_inputs.storage_is_memory;

    let signing_key_path = env::var("TRELLIS_SIGNING_KEY_COSE_PATH")
        .map_err(|_| StackError::bad_request("TRELLIS_SIGNING_KEY_COSE_PATH is required"))?;
    let signing_key_bytes = fs::read(&signing_key_path).map_err(|error| {
        StackError::bad_request(format!(
            "failed to read TRELLIS_SIGNING_KEY_COSE_PATH: {error}"
        ))
    })?;
    let signing_key_valid_to = env_optional_timestamp("TRELLIS_SIGNING_KEY_VALID_TO_UNIX_SECS")?;
    let signing_key =
        ServerSigningKey::from_cose_key_bytes(signing_key_bytes, TrellisTimestamp::new(0, 0)?)?
            .with_valid_to(signing_key_valid_to);

    let tenant_header_mode = match env::var("TRELLIS_TENANT_HEADER_SET")
        .unwrap_or_else(|_| "mixed".to_string())
        .as_str()
    {
        "wos" => TenantHeaderMode::Wos,
        "formspec" => TenantHeaderMode::Formspec,
        "mixed" => TenantHeaderMode::MultiProducer,
        other => {
            return Err(StackError::bad_request(format!(
                "unsupported TRELLIS_TENANT_HEADER_SET `{other}`"
            )));
        }
    };

    let repository: Arc<dyn EventRepository> = if trellis_storage_is_memory {
        Arc::new(InMemoryEventRepository::new())
    } else {
        let database_url = env::var("TRELLIS_DATABASE_URL")
            .map_err(|_| StackError::bad_request("TRELLIS_DATABASE_URL is required"))?;
        let pool = trellis_store_postgres_async::build_pool(&database_url, 10)
            .await
            .map_err(|error| StackError::unavailable(format!("postgres pool: {error}")))?;
        trellis_store_postgres_async::run_migrations(&pool)
            .await
            .map_err(|error| StackError::unavailable(format!("postgres migrations: {error}")))?;
        Arc::new(PostgresEventRepository::new(pool))
    };

    let mut state = TrellisServerState::new(repository, signing_key, tenant_header_mode);
    if let Some(artifact_store) = artifact_store_from_env() {
        state = state.with_artifact_store(artifact_store);
    }

    let jwt_secret = env::var("TRELLIS_JWT_HS256_SECRET")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    if trellis_storage_is_memory || scope_inputs.permissive_scope_auth {
        if let Some(secret) = jwt_secret {
            state = state.with_jwt_verifier(JwtVerifier::from_hs256(
                trellis_jwt_config(),
                secret.as_bytes(),
            ));
        }
        return Ok(state);
    }

    let Some(secret) = jwt_secret else {
        return Err(StackError::bad_request(
            "TRELLIS_JWT_HS256_SECRET is required when using durable storage without \
             TRELLIS_PERMISSIVE_SCOPE_AUTH=1 (TWREF-022). For dev/demo only, set \
             TRELLIS_PERMISSIVE_SCOPE_AUTH=1 to keep AllowAll scope authorization.",
        ));
    };

    state = state
        .with_jwt_verifier(JwtVerifier::from_hs256(
            trellis_jwt_config(),
            secret.as_bytes(),
        ))
        .with_scope_authorizer(Arc::new(ScopedAllowlistScopeAuthorizer));
    Ok(state.with_production_like_scope_posture(true))
}

#[must_use]
fn trellis_jwt_config() -> JwtConfig {
    JwtConfig {
        algorithm: jsonwebtoken::Algorithm::HS256,
        validate_exp: true,
        validate_iss: None,
        validate_aud: None,
        leeway_secs: 30,
    }
}

fn artifact_store_from_env() -> Option<Arc<dyn ArtifactStore<Error = StackError>>> {
    let bucket = env_optional("TRELLIS_ARTIFACT_BUCKET")?;
    let prefix = env_optional("TRELLIS_ARTIFACT_PREFIX").unwrap_or_else(|| "trellis".to_string());
    let config = S3ObjectConfig {
        bucket,
        endpoint: env_optional("TRELLIS_ARTIFACT_ENDPOINT"),
        region: env_optional("TRELLIS_ARTIFACT_REGION"),
    };
    Some(Arc::new(S3CompatibleArtifactStore::new(config, prefix)))
}

fn env_optional(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_optional_timestamp(name: &str) -> Result<Option<TrellisTimestamp>, StackError> {
    let Some(raw) = env_optional(name) else {
        return Ok(None);
    };
    let seconds: u64 = raw.parse().map_err(|error| {
        StackError::bad_request(format!("{name} must be a u64 unix timestamp: {error}"))
    })?;
    Ok(Some(TrellisTimestamp::new(seconds, 0)?))
}

#[derive(Clone)]
pub(crate) struct TrellisHealthProbe {
    state: TrellisServerState,
}

impl TrellisHealthProbe {
    pub(crate) fn new(state: TrellisServerState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl HealthProbe for TrellisHealthProbe {
    async fn check(&self) -> ComponentHealth {
        let mut issues = Vec::new();
        if let Err(error) = self.state.repository.list_scope(b"__healthz__").await {
            issues.push(format!("repository: {error}"));
        }
        let probe_key = "__healthz__/artifact-roundtrip";
        let probe_bytes = b"trellis-health-probe";
        match self.state.artifact_store.put(probe_key, probe_bytes).await {
            Ok(artifact_ref) => match self.state.artifact_store.get(&artifact_ref).await {
                Ok(Some(bytes)) if bytes == probe_bytes => {}
                Ok(Some(_)) => issues.push("artifact-store: roundtrip bytes mismatch".into()),
                Ok(None) => issues.push("artifact-store: stored object missing".into()),
                Err(error) => issues.push(format!("artifact-store read: {error}")),
            },
            Err(error) => issues.push(format!("artifact-store write: {error}")),
        }
        if issues.is_empty() {
            ComponentHealth::healthy("trellis-server", "repository and artifact store reachable")
        } else {
            ComponentHealth::degraded("trellis-server", issues.join("; "))
        }
    }
}
