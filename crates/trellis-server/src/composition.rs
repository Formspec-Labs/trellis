// Rust guideline compliant 2026-02-21
//! Composition root: the only Trellis-side module that wires concrete admission adapters.
//!
//! Generic Trellis service modules (`append`, `http`, `state`, the support
//! helpers in `lib.rs`) must not import this module. Only the crate root and
//! `state.rs` consume composition. New ecosystem overlays should be added by
//! introducing a `trellis-admission-*` adapter crate and registering it here.

use std::sync::Arc;

use async_trait::async_trait;
use stack_common_error::StackError;
use trellis_admission_formspec::{
    FORMSPEC_EVENT_FAMILY, FormspecAppendAdmissionPolicy, formspec_event_type_specs,
};
use trellis_admission_wos::{WosEventAdmissionPolicy, wos_event_family, wos_event_type_specs};
use trellis_server_ports::{
    AdmissionEvent, AdmittedEvent, EventAdmissionPolicy, EventTypeSpec,
};

/// Formspec intake-proof append literal admitted at the Trellis service edge.
///
/// Re-exported through the composition module so generic Trellis service
/// modules pull the literal through this single seam instead of depending on
/// `trellis-admission-formspec` directly (Boundary Gate).
pub use trellis_admission_formspec::FORMSPEC_RESPONSE_SUBMITTED;

/// Routed default admission policy: WOS for canonical WOS literals, Formspec for the
/// `substrate.append.response_submitted` aggregate literal.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultAdmissionPolicy {
    wos: WosEventAdmissionPolicy,
    formspec: FormspecAppendAdmissionPolicy,
}

impl DefaultAdmissionPolicy {
    /// Constructs the default routed admission policy.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            wos: WosEventAdmissionPolicy::new(),
            formspec: FormspecAppendAdmissionPolicy::new(),
        }
    }
}

#[async_trait]
impl EventAdmissionPolicy for DefaultAdmissionPolicy {
    type Error = StackError;

    async fn admit(&self, event: &AdmissionEvent<'_>) -> Result<AdmittedEvent, Self::Error> {
        if event.event_type == FORMSPEC_RESPONSE_SUBMITTED {
            self.formspec.admit(event).await
        } else {
            self.wos.admit(event).await
        }
    }
}

/// Builds the default admission policy wrapped in `Arc<dyn EventAdmissionPolicy>`.
#[must_use]
pub fn default_admission_policy() -> Arc<dyn EventAdmissionPolicy<Error = StackError>> {
    Arc::new(DefaultAdmissionPolicy::new())
}

/// Returns the combined event-type specifications the catalog projects.
///
/// Sourced from the admission adapters (`trellis-admission-wos`,
/// `trellis-admission-formspec`) so generic Trellis service code never hand-
/// builds vocabulary constants.
#[must_use]
pub fn default_event_type_specs() -> Vec<EventTypeSpec> {
    let mut specs = wos_event_type_specs();
    specs.extend(formspec_event_type_specs());
    specs
}

/// Derives the catalog binding family slug for a registered event-type literal.
///
/// Generic Trellis catalog projection consumes this so the catalog binding-
/// family column never re-parses literals on its own. The function is only
/// defined for literals produced by [`default_event_type_specs`] (i.e. WOS or
/// Formspec admission). Unregistered literals are surfaced as
/// [`BindingFamilyError`] so the caller can fail the projection cleanly
/// instead of crashing the process.
///
/// # Errors
/// Returns [`BindingFamilyError::Unregistered`] when `event_type` has no
/// admission adapter responsible for it.
pub fn binding_family_for(event_type: &str) -> Result<String, BindingFamilyError> {
    if event_type == FORMSPEC_RESPONSE_SUBMITTED {
        return Ok(FORMSPEC_EVENT_FAMILY.to_string());
    }
    if let Some(family) = wos_event_family(event_type) {
        return Ok(family.to_string());
    }
    Err(BindingFamilyError::Unregistered(event_type.to_string()))
}

/// Errors raised when [`binding_family_for`] cannot resolve a literal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingFamilyError {
    /// The literal is not registered by any admission adapter in this stack.
    Unregistered(String),
}

impl std::fmt::Display for BindingFamilyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unregistered(literal) => write!(
                f,
                "binding family for `{literal}` must come from a registered admission adapter; \
                 catalog projection received an unregistered literal"
            ),
        }
    }
}

impl std::error::Error for BindingFamilyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn given_default_policy_when_wos_literal_admits_then_wos_metadata() {
        let policy = DefaultAdmissionPolicy::new();
        let mut record = wos_events::ProvenanceRecord::blank(wos_events::ProvenanceKind::CaseCreated);
        record.id = "prov-default-route".to_string();
        let payload = serde_json::to_vec(&record).expect("serialize record");
        let event = AdmissionEvent {
            scope: b"case-1",
            event_type: "wos.kernel.case_created",
            payload: payload.as_slice(),
        };
        let admitted = policy.admit(&event).await.expect("wos branch admits");
        assert_eq!(admitted.profile_id.get(), integrity_verify::WOS_PROFILE_ID);
        assert_eq!(admitted.event_family.as_str(), "wos.kernel");
    }

    #[tokio::test]
    async fn given_default_policy_when_formspec_literal_admits_then_formspec_metadata() {
        let policy = DefaultAdmissionPolicy::new();
        let payload = br#"{"aggregateType":"t","aggregateId":"i","payload":{}}"#;
        let event = AdmissionEvent {
            scope: b"formspec",
            event_type: FORMSPEC_RESPONSE_SUBMITTED,
            payload,
        };
        let admitted = policy.admit(&event).await.expect("formspec branch admits");
        assert_eq!(
            admitted.profile_id.get(),
            integrity_verify::FORMSPEC_PROFILE_ID
        );
        assert_eq!(admitted.event_family.as_str(), "formspec.response");
    }

    #[test]
    fn given_event_type_specs_when_combined_then_include_wos_and_formspec_literals() {
        let specs = default_event_type_specs();
        assert!(specs.iter().any(|spec| spec.event_type == "wos.kernel.case_created"));
        assert!(specs.iter().any(|spec| spec.event_type == FORMSPEC_RESPONSE_SUBMITTED));
    }

    #[test]
    fn given_binding_family_when_resolved_then_distinguishes_namespaces() {
        assert_eq!(
            binding_family_for("wos.kernel.case_created").expect("known wos"),
            "wos.kernel"
        );
        assert_eq!(
            binding_family_for("wos.governance.amendment_authorized").expect("known governance"),
            "wos.governance"
        );
        assert_eq!(
            binding_family_for(FORMSPEC_RESPONSE_SUBMITTED).expect("known formspec"),
            "formspec.response"
        );
    }

    #[test]
    fn given_unregistered_literal_when_resolved_then_returns_error() {
        let err = binding_family_for("c2pa.assertion.created")
            .expect_err("unregistered literal must fail");
        assert!(matches!(err, BindingFamilyError::Unregistered(ref literal) if literal == "c2pa.assertion.created"));
        assert!(err.to_string().contains("c2pa.assertion.created"));
    }
}
