// Rust guideline compliant 2026-02-21
//! WOS-typed extension helpers over the shared Trellis HTTP client (DI-004 / D12).
//!
//! D12 settled that producer-facing typed convenience for WOS provenance
//! events belongs in the shared `trellis-service-client` crate rather than a
//! separate WOS client dialect. This module is the **only** place
//! `trellis-service-client` is permitted to depend on `wos-events`: the core
//! `SubstrateClient` trait, `SubstrateAppendRequest`, response DTOs, and
//! generic constructors stay WOS-agnostic.
//!
//! Future overlay helpers (Formspec, other producers) should not live here —
//! they belong in their own binding crates (`formspec-trellis-binding`,
//! future `<producer>-trellis-binding`). See
//! `TRELLIS-DI-TOPOLOGY-TODO.md` DI-004 "Contain The D12 Shared Client
//! Surface".

use async_trait::async_trait;
use stack_common_error::StackError;
use stack_common_http::tenant::TenantScope;
use wos_events::ProvenanceRecord;
pub use wos_events::WOS_CANONICAL_EVENT_LITERALS;

use crate::{
    AppendActor, ComputeContext, SubstrateAppendRequest, SubstrateAppendResult, SubstrateClient,
};

/// Builds a typed WOS provenance append request from a [`ProvenanceRecord`].
///
/// Validates that the record carries (or resolves to) a canonical event literal
/// and serializes the JSON payload deterministically.
///
/// # Errors
/// Returns an error when the record kind has no Trellis event literal or the
/// record cannot serialize to JSON.
pub fn wos_provenance_append_request(
    scope: impl Into<String>,
    tenant_scope: TenantScope,
    idempotency_key: impl Into<String>,
    actor: AppendActor,
    record: ProvenanceRecord,
    compute_context: ComputeContext,
) -> Result<SubstrateAppendRequest, StackError> {
    let event_type = record
        .event
        .clone()
        .or_else(|| {
            record
                .record_kind
                .canonical_event_literal()
                .map(str::to_string)
        })
        .ok_or_else(|| {
            StackError::bad_request("WOS provenance record kind has no Trellis event literal")
        })?;
    let payload = serde_json::to_value(&record).map_err(|error| {
        StackError::bad_request(format!(
            "failed to serialize WOS provenance payload: {error}"
        ))
    })?;
    SubstrateAppendRequest::new_json(
        scope,
        tenant_scope,
        event_type,
        idempotency_key,
        actor,
        payload,
        compute_context,
    )
}

/// Producer-facing inputs for the typed WOS provenance helper.
#[derive(Clone, Debug)]
pub struct WosProvenanceAppend {
    pub scope: String,
    pub tenant_scope: TenantScope,
    pub idempotency_key: String,
    pub actor: AppendActor,
    pub record: ProvenanceRecord,
    pub compute_context: ComputeContext,
}

/// Ergonomic WOS-typed extensions layered over [`SubstrateClient`].
///
/// Blanket-implemented for every [`SubstrateClient`], so callers compose the
/// helper without owning the implementor type. The extension stays
/// WOS-specific by design (D12).
#[async_trait]
pub trait SubstrateClientExt: SubstrateClient {
    /// Builds and appends a typed WOS provenance record.
    ///
    /// # Errors
    /// Returns an error when request construction or append fails.
    async fn append_wos_provenance(
        &self,
        input: WosProvenanceAppend,
    ) -> Result<SubstrateAppendResult, StackError> {
        let request = wos_provenance_append_request(
            input.scope,
            input.tenant_scope,
            input.idempotency_key,
            input.actor,
            input.record,
            input.compute_context,
        )?;
        self.append_event(request).await
    }
}

impl<T> SubstrateClientExt for T where T: SubstrateClient + ?Sized {}
