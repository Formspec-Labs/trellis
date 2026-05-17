// Rust guideline compliant 2026-02-21
//! Shared Trellis service HTTP client contract.
//!
//! Applications append to Trellis through this crate instead of each carrying
//! a bespoke substrate dialect. The core surface ([`SubstrateClient`],
//! [`SubstrateAppendRequest`], wire DTOs) is intentionally WOS-agnostic.
//! Typed WOS producer ergonomics live in the [`wos_ext`] module behind D12's
//! "blessed helper client with containment" contract — no other producer
//! vocabulary belongs in this crate; future overlays ship their own
//! `<producer>-trellis-binding` crate.
//!
//! ## Append dialects (single HTTP route)
//!
//! All producers post to [`SubstrateClient::append_event`]
//! (`POST /v1/scopes/{scope}/events`). The Trellis admission composition root
//! (`trellis-server::composition::DefaultAdmissionPolicy`) routes the request
//! to one of two adapters before append commits:
//!
//! - **WOS provenance** — construct via [`wos_provenance_append_request`]
//!   (or the [`SubstrateClientExt::append_wos_provenance`] helper). The JSON
//!   body deserializes as `wos_events::ProvenanceRecord` and must agree with
//!   the canonical event literal carried in `event_type`.
//! - **Formspec substrate** — construct via [`SubstrateAppendRequest::new_json`]
//!   with Formspec's aggregate envelope (`aggregateType`, `aggregateId`,
//!   `payload`). Trellis routes Formspec admission only when `event_type`
//!   equals `substrate.append.response_submitted`. Additional Formspec literals
//!   require extending `trellis-admission-formspec` and the Trellis
//!   composition router alongside admission updates.
//!
//! ## Trust boundaries
//!
//! **Case scope versus URL scope (TWREF-005).** The `{scope}` path segment
//! names a Trellis deployment namespace (tenant/workspace routing), not a
//! governed WOS case identity by itself. Callers such as `wos-server` or
//! `formspec-server` map their product identifiers into that scope and tenant
//! headers. Trellis admission enforces event shape and registry literals for
//! whatever scope is supplied; it does not substitute WOS relationship checks
//! from other services.
//!
//! **Governance overlay versus substrate admission (TWREF-064).** A reference
//! WOS HTTP surface may publish only a subset of WOS event literals while
//! still delegating to Trellis for append. The Trellis `trellis-admission-wos`
//! adapter admits the full `wos-events` substrate registry for callers that
//! bear Trellis service credentials. Treat Trellis bearer scope plus
//! admission as the substrate trust root for vocabulary allowance; WOS HTTP
//! routing remains a narrower product gate until shared authorizers align.
//!
//! **Why WOS helpers share this crate (TWREF-065 / D12).** WOS provenance
//! JSON and Formspec aggregate JSON differ in payload shape but share one
//! HTTP route. The D12-blessed WOS helpers live in [`wos_ext`] to keep the
//! generic client free of producer dialects while still offering typed
//! convenience for the dominant first-party producer.

#![forbid(unsafe_code)]

mod wos_ext;

pub use wos_ext::{SubstrateClientExt, WosProvenanceAppend, wos_provenance_append_request};

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use stack_common_error::StackError;
use stack_common_http::idempotency::IDEMPOTENCY_KEY_HEADER;
use stack_common_http::tenant::{HeaderConfig, TenantScope};
use trellis_types::ArtifactType;
use utoipa::ToSchema;
use utoipa::openapi::schema::{ObjectBuilder, SchemaType, Type};
use utoipa::openapi::{RefOr, Schema};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Formspec aggregate append `eventType` literal admitted at the Trellis HTTP edge.
///
/// `trellis-server` re-exports this value as `FORMSPEC_RESPONSE_SUBMITTED`. The Trellis HTTP JSON
/// schema `$defs.EventType` enum must include the same literal (see `check-http-api-schema.py`).
pub const FORMSPEC_APPEND_EVENT_TYPE_LITERAL: &str = "substrate.append.response_submitted";

#[must_use]
fn trellis_admitted_event_type_openapi_schema() -> RefOr<Schema> {
    let mut values: Vec<String> = wos_ext::WOS_CANONICAL_EVENT_LITERALS
        .iter()
        .copied()
        .map(str::to_string)
        .collect();
    values.push(FORMSPEC_APPEND_EVENT_TYPE_LITERAL.to_string());
    values.sort();
    ObjectBuilder::new()
        .schema_type(SchemaType::new(Type::String))
        .enum_values(Some(values))
        .description(Some(
            "Admitted Trellis append literals: `wos-events` substrate registry plus Formspec append.",
        ))
        .into()
}

#[must_use]
fn artifact_type_openapi_schema() -> RefOr<Schema> {
    ObjectBuilder::new()
        .schema_type(SchemaType::new(Type::String))
        .enum_values(Some(["event", "checkpoint", "manifest"]))
        .description(Some(
            "Trellis substrate artifact type: event, checkpoint, or manifest.",
        ))
        .into()
}

/// Maximum Trellis HTTP error response body bytes folded into [`StackError`] text.
///
/// Reverse proxies often return HTML pages; cap inclusion so logs and downstream copies stay bounded.
const APPEND_HTTP_ERROR_BODY_PREVIEW_BYTES: usize = 8 * 1024;

#[must_use]
fn truncate_utf8_body_for_error_preview(mut body: String, max_bytes: usize) -> String {
    if body.len() <= max_bytes {
        return body;
    }
    let mut end = max_bytes;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    body.truncate(end);
    body.push_str("… (truncated)");
    body
}

/// Actor block carried by the Trellis append wire body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AppendActor {
    pub kind: String,
    pub subject: String,
}

impl AppendActor {
    #[must_use]
    pub fn service(subject: impl Into<String>) -> Self {
        Self {
            kind: "service".to_string(),
            subject: subject.into(),
        }
    }

    #[must_use]
    pub fn user(subject: impl Into<String>) -> Self {
        Self {
            kind: "user".to_string(),
            subject: subject.into(),
        }
    }
}

/// Sensitivity class disclosed for a producer's compute path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
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

/// Required delegated-compute disclosure context for append producers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ComputeContext {
    pub declaration_id: String,
    pub actor: String,
    pub sensitivity: ComputeSensitivity,
}

impl ComputeContext {
    #[must_use]
    pub fn new(
        declaration_id: impl Into<String>,
        actor: impl Into<String>,
        sensitivity: ComputeSensitivity,
    ) -> Self {
        Self {
            declaration_id: declaration_id.into(),
            actor: actor.into(),
            sensitivity,
        }
    }

    #[must_use]
    pub fn no_delegated_compute(actor: impl Into<String>) -> Self {
        let actor = actor.into();
        Self {
            declaration_id: format!("compute:{actor}:publicMetadata"),
            actor,
            sensitivity: ComputeSensitivity::PublicMetadata,
        }
    }
}

/// Optional direct-client attestation block.
///
/// **Trellis-server (2026-05-15):** Requests that include this field are rejected with
/// `400`; `cose_sign1` is not cryptographically verified yet. Omit the field until
/// verification lands (TWREF-0103). Durable deployments without `TRELLIS_PERMISSIVE_SCOPE_AUTH`
/// use the same HTTP admission as tests (TWREF-022 narrowing).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClientAttestation {
    pub kid: String,
    pub cose_sign1: String,
}

/// One append request against `POST /v1/scopes/{scope}/events`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubstrateAppendRequest {
    #[serde(skip)]
    pub scope: String,
    #[serde(skip)]
    pub tenant_scope: TenantScope,
    pub event_type: String,
    pub idempotency_key: String,
    pub actor: AppendActor,
    pub payload: serde_json::Value,
    pub compute_context: ComputeContext,
    /// Optional client attestation reserved for direct-signer flows — **omit** for
    /// `trellis-server` until verification is implemented (see [`ClientAttestation`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_attestation: Option<ClientAttestation>,
}

/// JSON body for `POST /v1/scopes/{scope}/events`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SubstrateAppendBody {
    #[schema(schema_with = trellis_admitted_event_type_openapi_schema)]
    pub event_type: String,
    pub idempotency_key: String,
    pub actor: AppendActor,
    pub payload: serde_json::Value,
    pub compute_context: ComputeContext,
    /// Optional client attestation reserved for direct-signer flows — **omit** for
    /// `trellis-server` until verification is implemented (see [`ClientAttestation`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_attestation: Option<ClientAttestation>,
}

impl SubstrateAppendRequest {
    /// Builds a request for an already-typed JSON event payload.
    ///
    /// # Errors
    /// Returns an error when required routing or event fields are empty.
    pub fn new_json(
        scope: impl Into<String>,
        tenant_scope: TenantScope,
        event_type: impl Into<String>,
        idempotency_key: impl Into<String>,
        actor: AppendActor,
        payload: serde_json::Value,
        compute_context: ComputeContext,
    ) -> Result<Self, StackError> {
        let request = Self {
            scope: scope.into(),
            tenant_scope,
            event_type: event_type.into(),
            idempotency_key: idempotency_key.into(),
            actor,
            payload,
            compute_context,
            client_attestation: None,
        };
        request.validate()?;
        Ok(request)
    }

    /// Attaches a direct-client attestation block.
    #[must_use]
    pub fn with_client_attestation(mut self, attestation: ClientAttestation) -> Self {
        self.client_attestation = Some(attestation);
        self
    }

    #[must_use]
    pub fn body(&self) -> SubstrateAppendBody {
        SubstrateAppendBody {
            event_type: self.event_type.clone(),
            idempotency_key: self.idempotency_key.clone(),
            actor: self.actor.clone(),
            payload: self.payload.clone(),
            compute_context: self.compute_context.clone(),
            client_attestation: self.client_attestation.clone(),
        }
    }

    fn validate(&self) -> Result<(), StackError> {
        validate_scope(&self.scope)?;
        self.body().validate()?;
        Ok(())
    }
}

impl SubstrateAppendBody {
    /// Validates route-independent append body fields.
    ///
    /// # Errors
    /// Returns an error when the body is missing load-bearing wire fields.
    pub fn validate(&self) -> Result<(), StackError> {
        validate_required("event_type", &self.event_type)?;
        validate_required("idempotency_key", &self.idempotency_key)?;
        validate_required("actor.kind", &self.actor.kind)?;
        validate_required("actor.subject", &self.actor.subject)?;
        validate_required(
            "compute_context.declaration_id",
            &self.compute_context.declaration_id,
        )?;
        validate_required("compute_context.actor", &self.compute_context.actor)?;
        if let Some(attestation) = &self.client_attestation {
            validate_required("client_attestation.kid", &attestation.kid)?;
            validate_required("client_attestation.cose_sign1", &attestation.cose_sign1)?;
        }
        Ok(())
    }
}

/// Substrate append HTTP/OpenAPI DTO: export verification summary for this append.
///
/// This is a **server projection** field on the JSON append response (`SubstrateAppendResult`),
/// not a Formspec/WOS spec-suite schema artifact. Formspec cryptographic receipts in authored
/// artifacts remain spec-defined; operators integrate Trellis using this DTO and the bundle ref.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReceipt {
    pub verified: bool,
    #[schema(schema_with = artifact_type_openapi_schema)]
    pub artifact_type: ArtifactType,
    pub event_type: String,
}

/// Append response returned by the Trellis service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SubstrateAppendResult {
    #[serde(alias = "substrateEventId")]
    pub event_id: String,
    pub sequence: u64,
    pub canonical_event_hash: String,
    #[serde(alias = "checkpointReference")]
    pub checkpoint_ref: String,
    #[serde(alias = "proofArtifactRef")]
    pub bundle_ref: String,
    pub verification_receipt: VerificationReceipt,
}

impl SubstrateAppendResult {
    fn validate_for(&self, scope: &str, event_type: &str) -> Result<(), StackError> {
        validate_required("event_id", &self.event_id)?;
        validate_required("canonical_event_hash", &self.canonical_event_hash)?;
        validate_required("checkpoint_ref", &self.checkpoint_ref)?;
        validate_required("bundle_ref", &self.bundle_ref)?;
        let checkpoint_prefix = format!("trellis://{scope}/checkpoints/");
        if !self.checkpoint_ref.starts_with(&checkpoint_prefix) {
            return Err(StackError::unavailable(
                "trellis append response checkpointRef is outside the requested scope",
            ));
        }
        if !self.verification_receipt.verified {
            return Err(StackError::unavailable(
                "trellis append response verification receipt is not verified",
            ));
        }
        if self.verification_receipt.event_type != event_type {
            return Err(StackError::unavailable(
                "trellis append response verification eventType does not match request",
            ));
        }
        Ok(())
    }
}

/// Core shared substrate client contract.
#[async_trait]
pub trait SubstrateClient: Send + Sync {
    /// Appends one event through the Trellis service.
    ///
    /// # Errors
    /// Returns an error if the request is invalid, the service rejects it, or
    /// the response cannot be decoded.
    async fn append_event(
        &self,
        request: SubstrateAppendRequest,
    ) -> Result<SubstrateAppendResult, StackError>;

    /// Fetches the current export bundle for `scope`.
    ///
    /// # Errors
    /// Returns an error if the service rejects the request.
    async fn head_bundle(
        &self,
        scope: &str,
        tenant_scope: &TenantScope,
    ) -> Result<Vec<u8>, StackError>;

    /// Fetches the export bundle pinned at `checkpoint_digest`.
    ///
    /// # Errors
    /// Returns an error if the service rejects the request.
    async fn bundle(
        &self,
        scope: &str,
        checkpoint_digest: &str,
        tenant_scope: &TenantScope,
    ) -> Result<Vec<u8>, StackError>;

    /// Fetches the current signing-key registry projection.
    ///
    /// # Errors
    /// Returns an error if the service rejects the request.
    async fn signing_key_registry(
        &self,
        scope: &str,
        tenant_scope: &TenantScope,
    ) -> Result<Vec<u8>, StackError>;

    /// Fetches the current event-type registry projection.
    ///
    /// # Errors
    /// Returns an error if the service rejects the request.
    async fn event_type_registry(
        &self,
        scope: &str,
        tenant_scope: &TenantScope,
    ) -> Result<serde_json::Value, StackError>;
}

/// Configures the concrete HTTP client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrellisServiceClientConfig {
    pub endpoint: String,
    pub service_bearer_token: Option<String>,
    pub tenant_headers: HeaderConfig,
    pub timeout: Duration,
}

impl TrellisServiceClientConfig {
    #[must_use]
    pub fn new(endpoint: impl Into<String>, tenant_headers: HeaderConfig) -> Self {
        Self {
            endpoint: endpoint.into(),
            service_bearer_token: None,
            tenant_headers,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    #[must_use]
    pub fn with_service_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.service_bearer_token = Some(token.into());
        self
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Reqwest-backed Trellis service client.
#[derive(Clone, Debug)]
pub struct TrellisServiceClient {
    config: TrellisServiceClientConfig,
    http: reqwest::Client,
}

impl TrellisServiceClient {
    /// Creates a concrete Trellis service client.
    ///
    /// # Errors
    /// Returns an error if endpoint is empty or the HTTP client cannot be
    /// constructed.
    pub fn new(config: TrellisServiceClientConfig) -> Result<Self, StackError> {
        validate_endpoint(&config.endpoint)?;
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|error| {
                StackError::internal(format!("failed to construct Trellis HTTP client: {error}"))
            })?;
        Ok(Self { config, http })
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.config.endpoint.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        tenant_scope: &TenantScope,
    ) -> reqwest::RequestBuilder {
        let mut request = self
            .http
            .request(method, self.url(path))
            .header(
                self.config.tenant_headers.tenant,
                tenant_scope.tenant.as_str(),
            )
            .header(
                self.config.tenant_headers.workspace,
                tenant_scope.workspace.as_str(),
            )
            .header(
                self.config.tenant_headers.environment,
                tenant_scope.environment.as_str(),
            )
            .header(self.config.tenant_headers.cell, tenant_scope.cell.as_str());
        if let Some(token) = &self.config.service_bearer_token {
            request = request.bearer_auth(token);
        }
        request
    }
}

#[async_trait]
impl SubstrateClient for TrellisServiceClient {
    async fn append_event(
        &self,
        request: SubstrateAppendRequest,
    ) -> Result<SubstrateAppendResult, StackError> {
        request.validate()?;
        let path = format!("/v1/scopes/{}/events", encode_path_segment(&request.scope));
        let response = self
            .request(reqwest::Method::POST, &path, &request.tenant_scope)
            .header(IDEMPOTENCY_KEY_HEADER, request.idempotency_key.as_str())
            .json(&request.body())
            .send()
            .await
            .map_err(|error| StackError::unavailable(format!("trellis append failed: {error}")))?;
        if !response.status().is_success() {
            let status = response.status();
            let body = truncate_utf8_body_for_error_preview(
                response.text().await.unwrap_or_default(),
                APPEND_HTTP_ERROR_BODY_PREVIEW_BYTES,
            );
            return Err(StackError::unavailable(format!(
                "trellis append returned HTTP {status}: {body}"
            )));
        }
        let result = response
            .json::<SubstrateAppendResult>()
            .await
            .map_err(|error| {
                StackError::unavailable(format!("trellis append response is invalid: {error}"))
            })?;
        result.validate_for(&request.scope, &request.event_type)?;
        Ok(result)
    }

    async fn head_bundle(
        &self,
        scope: &str,
        tenant_scope: &TenantScope,
    ) -> Result<Vec<u8>, StackError> {
        validate_scope(scope)?;
        self.bytes_get(
            &format!("/v1/scopes/{}/bundles/head", encode_path_segment(scope)),
            tenant_scope,
            "head bundle",
        )
        .await
    }

    async fn bundle(
        &self,
        scope: &str,
        checkpoint_digest: &str,
        tenant_scope: &TenantScope,
    ) -> Result<Vec<u8>, StackError> {
        validate_scope(scope)?;
        validate_required("checkpoint_digest", checkpoint_digest)?;
        self.bytes_get(
            &format!(
                "/v1/scopes/{}/bundles/{}",
                encode_path_segment(scope),
                encode_path_segment(checkpoint_digest)
            ),
            tenant_scope,
            "pinned bundle",
        )
        .await
    }

    async fn signing_key_registry(
        &self,
        scope: &str,
        tenant_scope: &TenantScope,
    ) -> Result<Vec<u8>, StackError> {
        validate_scope(scope)?;
        self.bytes_get(
            &format!(
                "/v1/scopes/{}/registries/signing-keys",
                encode_path_segment(scope)
            ),
            tenant_scope,
            "signing-key registry",
        )
        .await
    }

    async fn event_type_registry(
        &self,
        scope: &str,
        tenant_scope: &TenantScope,
    ) -> Result<serde_json::Value, StackError> {
        validate_scope(scope)?;
        let response = self
            .request(
                reqwest::Method::GET,
                &format!(
                    "/v1/scopes/{}/registries/event-types",
                    encode_path_segment(scope)
                ),
                tenant_scope,
            )
            .send()
            .await
            .map_err(|error| {
                StackError::unavailable(format!(
                    "trellis event-type registry fetch failed: {error}"
                ))
            })?;
        if !response.status().is_success() {
            return Err(StackError::unavailable(format!(
                "trellis event-type registry returned HTTP {}",
                response.status()
            )));
        }
        response.json::<serde_json::Value>().await.map_err(|error| {
            StackError::unavailable(format!(
                "trellis event-type registry response is invalid: {error}"
            ))
        })
    }
}

impl TrellisServiceClient {
    async fn bytes_get(
        &self,
        path: &str,
        tenant_scope: &TenantScope,
        label: &str,
    ) -> Result<Vec<u8>, StackError> {
        let response = self
            .request(reqwest::Method::GET, path, tenant_scope)
            .send()
            .await
            .map_err(|error| {
                StackError::unavailable(format!("trellis {label} fetch failed: {error}"))
            })?;
        if !response.status().is_success() {
            return Err(StackError::unavailable(format!(
                "trellis {label} returned HTTP {}",
                response.status()
            )));
        }
        response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|error| {
                StackError::unavailable(format!("trellis {label} response is invalid: {error}"))
            })
    }
}

fn validate_endpoint(endpoint: &str) -> Result<(), StackError> {
    validate_required("endpoint", endpoint)?;
    if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
        return Err(StackError::bad_request(
            "trellis endpoint must start with http:// or https://",
        ));
    }
    Ok(())
}

fn validate_scope(scope: &str) -> Result<(), StackError> {
    validate_required("scope", scope)?;
    if scope.contains('/') {
        return Err(StackError::bad_request(
            "trellis scope must be a single path segment",
        ));
    }
    Ok(())
}

fn validate_required(field: &str, value: &str) -> Result<(), StackError> {
    if value.trim().is_empty() {
        return Err(StackError::bad_request(format!("{field} is required")));
    }
    Ok(())
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
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use wos_events::{ProvenanceKind, ProvenanceRecord};

    use super::*;

    #[tokio::test]
    async fn append_wos_provenance_posts_shared_wire_shape() {
        let endpoint = test_server(|request| {
            assert!(
                request.starts_with("POST /v1/scopes/case_123/events "),
                "wrong request line: {request}"
            );
            assert!(request.contains("idempotency-key: idem-1\r\n"));
            assert!(request.contains("x-wos-tenant-id: tenant-a\r\n"));
            let body = request_body(&request);
            let value: serde_json::Value = serde_json::from_str(body).expect("append body is JSON");
            assert_eq!(value["eventType"], "wos.kernel.case_created");
            assert_eq!(value["idempotencyKey"], "idem-1");
            assert_eq!(value["actor"]["kind"], "service");
            assert_eq!(value["payload"]["recordKind"], "caseCreated");
            assert_eq!(value["computeContext"]["sensitivity"], "publicMetadata");
            response(
                "application/json",
                r#"{"eventId":"evt_1","sequence":7,"canonicalEventHash":"sha256:abc","checkpointRef":"trellis://case_123/checkpoints/cp_1","bundleRef":"s3://bucket/bundle.zip","verificationReceipt":{"verified":true,"artifactType":"event","eventType":"wos.kernel.case_created"}}"#,
            )
        });
        let client = TrellisServiceClient::new(TrellisServiceClientConfig::new(
            endpoint,
            HeaderConfig::wos(),
        ))
        .expect("client");
        let mut record = ProvenanceRecord::blank(ProvenanceKind::CaseCreated);
        record.id = "prov_1".to_string();

        let result = client
            .append_wos_provenance(WosProvenanceAppend {
                scope: "case_123".to_string(),
                tenant_scope: tenant_scope(),
                idempotency_key: "idem-1".to_string(),
                actor: AppendActor::service("wos-server"),
                record,
                compute_context: ComputeContext::no_delegated_compute("wos-server"),
            })
            .await
            .expect("append");

        assert_eq!(result.event_id, "evt_1");
        assert_eq!(result.sequence, 7);
    }

    #[tokio::test]
    async fn head_bundle_uses_v1_bundle_endpoint() {
        let endpoint = test_server(|request| {
            assert!(
                request.starts_with("GET /v1/scopes/case_123/bundles/head "),
                "wrong request line: {request}"
            );
            response("application/zip", "zip-bytes")
        });
        let client = TrellisServiceClient::new(TrellisServiceClientConfig::new(
            endpoint,
            HeaderConfig::wos(),
        ))
        .expect("client");

        let bytes = client
            .head_bundle("case_123", &tenant_scope())
            .await
            .expect("bundle");

        assert_eq!(bytes, b"zip-bytes");
    }

    #[test]
    fn append_result_rejects_unverified_receipts() {
        let result = SubstrateAppendResult {
            event_id: "evt_1".to_string(),
            sequence: 1,
            canonical_event_hash: "sha256:abc".to_string(),
            checkpoint_ref: "trellis://case_123/checkpoints/cp_1".to_string(),
            bundle_ref: "s3://bucket/bundle.zip".to_string(),
            verification_receipt: VerificationReceipt {
                verified: false,
                artifact_type: ArtifactType::Event,
                event_type: "wos.kernel.case_created".to_string(),
            },
        };

        assert!(
            result
                .validate_for("case_123", "wos.kernel.case_created")
                .is_err()
        );
    }

    #[test]
    fn path_segments_are_percent_encoded() {
        assert_eq!(encode_path_segment("case:123"), "case%3A123");
        assert_eq!(encode_path_segment("case_123"), "case_123");
    }

    fn tenant_scope() -> TenantScope {
        TenantScope {
            tenant: "tenant-a".to_string(),
            workspace: "workspace-a".to_string(),
            environment: "prod".to_string(),
            cell: "cell-a".to_string(),
        }
    }

    fn test_server(handler: impl FnOnce(String) -> String + Send + 'static) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock trellis");
        let address = listener.local_addr().expect("mock trellis address");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut buffer = [0_u8; 8192];
            let read = stream.read(&mut buffer).expect("read request");
            let request = String::from_utf8_lossy(&buffer[..read]).to_string();
            let response = handler(request);
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });
        format!("http://{address}")
    }

    fn request_body(request: &str) -> &str {
        request
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .expect("request has body")
    }

    fn response(content_type: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        )
    }
}
