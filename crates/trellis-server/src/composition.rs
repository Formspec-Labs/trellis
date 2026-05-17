// Rust guideline compliant 2026-02-21
//! Composition root: the only Trellis-side module that wires concrete admission adapters.
//!
//! Generic Trellis service modules (`append`, `http`, `state`, the support
//! helpers in `lib.rs`) must not import this module. Only the crate root and
//! `state.rs` consume composition. New ecosystem overlays should be added by
//! introducing a `trellis-admission-*` adapter crate and registering it here.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use stack_common_error::StackError;
use trellis_admission_formspec::{FormspecAppendAdmissionPolicy, formspec_event_type_specs};
use trellis_admission_wos::{WosEventAdmissionPolicy, wos_event_type_specs};
use trellis_server_ports::{
    AdmissionEvent, AdmittedEvent, EventAdmissionPolicy, EventType, EventTypeRef,
    EventTypeRegistry, EventTypeSpec, ReviewGateEventTypeRegistry,
};
use wos_events::WOS_CANONICAL_EVENT_LITERALS;

/// Formspec intake-proof append literal admitted at the Trellis service edge.
///
/// Re-exported through the composition module so generic Trellis service
/// modules pull the literal through this single seam instead of depending on
/// `trellis-admission-formspec` directly (Boundary Gate).
pub use trellis_admission_formspec::FORMSPEC_RESPONSE_SUBMITTED;

/// Register-style admission router: each adapter declares which literals it
/// owns, and the router dispatches by literal lookup.
///
/// Adding a new ecosystem overlay (e.g. `trellis-admission-c2pa`) is one
/// `register_for_literals(...)` call against the default builder — no if-else
/// edits in this module, no struct-field churn. The router fails admission
/// for unregistered literals so unknown event types reject before append.
#[derive(Default, Clone)]
pub struct AdmissionRouter {
    by_literal: HashMap<EventType, Arc<dyn EventAdmissionPolicy<Error = StackError>>>,
}

impl std::fmt::Debug for AdmissionRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionRouter")
            .field("registered_literals", &self.by_literal.len())
            .finish()
    }
}

impl AdmissionRouter {
    /// Creates an empty router. Add adapters with [`Self::register_for_literals`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an adapter as the admission policy for every literal in `literals`.
    ///
    /// Later registrations for the same literal overwrite earlier ones, which
    /// gives composition the final word when a test substitutes a counting
    /// wrapper around an existing adapter.
    #[must_use]
    pub fn register_for_literals<I, S>(
        mut self,
        adapter: Arc<dyn EventAdmissionPolicy<Error = StackError>>,
        literals: I,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for literal in literals {
            self.by_literal.insert(literal.into(), Arc::clone(&adapter));
        }
        self
    }

    /// Returns true when a literal is registered.
    #[must_use]
    pub fn handles(&self, event_type: &str) -> bool {
        self.by_literal.contains_key(event_type)
    }
}

#[async_trait]
impl EventAdmissionPolicy for AdmissionRouter {
    type Error = StackError;

    async fn admit(&self, event: &AdmissionEvent<'_>) -> Result<AdmittedEvent, Self::Error> {
        let Some(adapter) = self.by_literal.get(event.event_type) else {
            return Err(StackError::bad_request(format!(
                "event type `{}` is not registered for admission",
                event.event_type
            )));
        };
        adapter.admit(event).await
    }
}

/// Builds the default admission policy by registering every shipped adapter
/// against the literals it owns. Adding a new overlay = one
/// `register_for_literals(...)` chain entry.
#[must_use]
pub fn default_admission_policy() -> Arc<dyn EventAdmissionPolicy<Error = StackError>> {
    let wos: Arc<dyn EventAdmissionPolicy<Error = StackError>> =
        Arc::new(WosEventAdmissionPolicy::new());
    let formspec: Arc<dyn EventAdmissionPolicy<Error = StackError>> =
        Arc::new(FormspecAppendAdmissionPolicy::new());
    Arc::new(
        AdmissionRouter::new()
            .register_for_literals(wos, WOS_CANONICAL_EVENT_LITERALS.iter().copied())
            .register_for_literals(formspec, [FORMSPEC_RESPONSE_SUBMITTED]),
    )
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

/// Read-side snapshot of the event-type catalog after every admission adapter
/// has registered its specs through the budget-review gate.
///
/// Generic Trellis service code (catalog projection, future dispatch) reads
/// from this snapshot — never from the parallel `default_event_type_specs()`
/// collection — so the registry trait is the single source of truth.
#[derive(Clone, Debug)]
pub struct EventTypeCatalog {
    entries: Vec<EventTypeRef>,
}

impl EventTypeCatalog {
    /// Builds the catalog by registering every default admission spec through
    /// the [`ReviewGateEventTypeRegistry`] budget gate at startup.
    ///
    /// # Panics
    /// Panics if any default admission spec fails the budget gate; the
    /// adapter implementations are owned by this crate and the contract is
    /// satisfied by construction.
    #[must_use]
    pub fn default_stack() -> Self {
        let mut registry = ReviewGateEventTypeRegistry::default();
        for spec in default_event_type_specs() {
            registry
                .register(spec)
                .expect("default admission specs satisfy the budget gate by construction");
        }
        Self {
            entries: registry.entries().cloned().collect(),
        }
    }

    /// Iterates registered event-type entries in event-type lexicographic order.
    pub fn entries(&self) -> impl Iterator<Item = &EventTypeRef> + '_ {
        self.entries.iter()
    }

    /// Looks up the registered entry for an event-type literal.
    #[must_use]
    pub fn get(&self, event_type: &str) -> Option<&EventTypeRef> {
        self.entries
            .iter()
            .find(|entry| entry.event_type == event_type)
    }

    /// Number of registered entries (for sizing tests + projection).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if no admission specs are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for EventTypeCatalog {
    fn default() -> Self {
        Self::default_stack()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn given_default_policy_when_wos_literal_admits_then_wos_metadata() {
        let policy = default_admission_policy();
        let mut record =
            wos_events::ProvenanceRecord::blank(wos_events::ProvenanceKind::CaseCreated);
        record.id = "prov-default-route".to_string();
        let payload = serde_json::to_vec(&record).expect("serialize record");
        let event = AdmissionEvent {
            scope: b"case-1",
            event_type: "wos.kernel.case_created",
            payload: payload.as_slice(),
        };
        let admitted = policy.admit(&event).await.expect("wos branch admits");
        assert_eq!(admitted.event_family.as_str(), "wos.kernel");
        assert_eq!(admitted.artifact_type, trellis_types::ArtifactType::Event);
    }

    #[tokio::test]
    async fn given_default_policy_when_formspec_literal_admits_then_formspec_metadata() {
        let policy = default_admission_policy();
        let payload = br#"{"aggregateType":"t","aggregateId":"i","payload":{}}"#;
        let event = AdmissionEvent {
            scope: b"formspec",
            event_type: FORMSPEC_RESPONSE_SUBMITTED,
            payload,
        };
        let admitted = policy.admit(&event).await.expect("formspec branch admits");
        assert_eq!(admitted.event_family.as_str(), "formspec.response");
        assert_eq!(admitted.artifact_type, trellis_types::ArtifactType::Event);
    }

    #[tokio::test]
    async fn given_unregistered_literal_when_default_policy_admits_then_rejects() {
        // Unknown literals (e.g., a hypothetical future overlay not yet
        // registered at composition) must reject at admission, never reach
        // append. This is the load-bearing dispatch contract.
        let policy = default_admission_policy();
        let event = AdmissionEvent {
            scope: b"unknown",
            event_type: "c2pa.assertion.created",
            payload: b"{}",
        };
        let err = policy
            .admit(&event)
            .await
            .expect_err("unregistered must reject");
        assert!(
            err.to_string().contains("not registered for admission"),
            "router must surface the registration gap; got: {err}"
        );
    }

    #[tokio::test]
    async fn given_router_when_new_adapter_registers_then_dispatches_without_editing_core() {
        // Demonstrates the plan-level criterion: adding an adapter is one
        // `register_for_literals` chain entry. The router exposes the
        // overlay through the EventAdmissionPolicy trait without editing
        // generic Trellis code.
        #[derive(Debug)]
        struct ConstantAdapter(AdmittedEvent);

        #[async_trait]
        impl EventAdmissionPolicy for ConstantAdapter {
            type Error = StackError;
            async fn admit(
                &self,
                _event: &AdmissionEvent<'_>,
            ) -> Result<AdmittedEvent, Self::Error> {
                Ok(self.0.clone())
            }
        }

        let adapter: Arc<dyn EventAdmissionPolicy<Error = StackError>> =
            Arc::new(ConstantAdapter(AdmittedEvent {
                event_type: "x-test.overlay.synthetic".to_string(),
                event_family: trellis_server_ports::EventFamilyId::new("x-test.overlay").unwrap(),
                schema_ref: trellis_server_ports::SchemaRef::new(
                    "x-test://x-test.overlay.synthetic",
                )
                .unwrap(),
                artifact_type: trellis_types::ArtifactType::Event,
                direct_submit: trellis_server_ports::DirectSubmitPolicy::ServiceOnly,
            }));

        let router =
            AdmissionRouter::new().register_for_literals(adapter, ["x-test.overlay.synthetic"]);
        assert!(router.handles("x-test.overlay.synthetic"));
        let admitted = router
            .admit(&AdmissionEvent {
                scope: b"x-test",
                event_type: "x-test.overlay.synthetic",
                payload: b"",
            })
            .await
            .expect("registered overlay admits");
        assert_eq!(admitted.artifact_type, trellis_types::ArtifactType::Event);
    }

    #[test]
    fn given_event_type_specs_when_combined_then_include_wos_and_formspec_literals() {
        let specs = default_event_type_specs();
        assert!(
            specs
                .iter()
                .any(|spec| spec.event_type == "wos.kernel.case_created")
        );
        assert!(
            specs
                .iter()
                .any(|spec| spec.event_type == FORMSPEC_RESPONSE_SUBMITTED)
        );
    }

    #[test]
    fn given_event_type_specs_when_collected_then_carry_family_artifact_and_direct_submit() {
        let specs = default_event_type_specs();
        let wos = specs
            .iter()
            .find(|spec| spec.event_type == "wos.kernel.case_created")
            .expect("WOS kernel spec");
        assert_eq!(wos.event_family.as_str(), "wos.kernel");
        assert_eq!(wos.artifact_type, trellis_types::ArtifactType::Event);
        assert_eq!(
            wos.direct_submit,
            trellis_server_ports::DirectSubmitPolicy::ServiceOnly
        );

        let governance = specs
            .iter()
            .find(|spec| spec.event_type == "wos.governance.amendment_authorized")
            .expect("WOS governance spec");
        assert_eq!(governance.event_family.as_str(), "wos.governance");

        let formspec = specs
            .iter()
            .find(|spec| spec.event_type == FORMSPEC_RESPONSE_SUBMITTED)
            .expect("Formspec spec");
        assert_eq!(formspec.event_family.as_str(), "formspec.response");
        assert_eq!(formspec.artifact_type, trellis_types::ArtifactType::Event);
    }
}
