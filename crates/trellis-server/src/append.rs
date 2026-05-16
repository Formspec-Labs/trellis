// Rust guideline compliant 2026-02-21
//! Append orchestration: admission, scope lock, core append, persistence, bundle publish.
//!
//! [`AppendCoordinator`] owns everything after HTTP validation/authentication passes:
//! admission, per-scope serialization, ledger key replay, canonical event construction via
//! `trellis_core`, repository append, deterministic export ZIP publication with independent
//! verification, and materialized substrate receipt fields. Bearer tokens, outer
//! `ScopeAuthorizer`, and HTTP body replay/idempotency live in the parent HTTP handlers and
//! middleware, not inside this module (TWREF-021).

use async_trait::async_trait;
use hkdf::Hkdf;
use integrity_cbor::{Value, domain_separated_sha256, json_to_dcbor_bytes};
use sha2::{Digest, Sha256};
use stack_common_error::StackError;
use trellis_core::{AuthoredEvent, LedgerStore};
use trellis_export_writer::PostureDeclaration as ExportPostureDeclaration;
use trellis_export_writer::TrellisTimestamp;
use trellis_server_ports::{
    AdmissionEvent, AdmittedEvent, AppendUnitOfWork, ComputeContext, ComputeSensitivity,
};
use trellis_service_client::{SubstrateAppendBody, SubstrateAppendResult};
use trellis_types::{CONTENT_DOMAIN, StoredEvent};

use crate::{
    TrellisServerState, append_result_for_event, event_hash, now_timestamp, publish_bundle,
    validate_existing_replay,
};

/// Command accepted by the append coordinator after HTTP validation and authorization.
#[derive(Clone, Debug)]
pub struct AppendCommand {
    pub scope: String,
    pub event_type: String,
    pub idempotency_key: String,
    pub payload: serde_json::Value,
    pub compute_context: ComputeContext,
}

/// Stored event plus wire result produced by one coordinator pass.
#[derive(Clone, Debug)]
pub struct AppendOutcome {
    pub result: SubstrateAppendResult,
    #[allow(dead_code)]
    pub stored: StoredEvent,
}

/// Runs append orchestration after HTTP validation and outer authorization (TWREF-021).
///
/// Production wiring delegates to [`AppendCoordinator`]; tests may substitute a recorder that
/// forwards to [`DefaultAppendRunner`] without monkeypatching globals.
#[async_trait]
pub(crate) trait AppendRunner: Send + Sync {
    async fn run_append(
        &self,
        state: &TrellisServerState,
        command: AppendCommand,
    ) -> Result<AppendOutcome, StackError>;
}

/// Production [`AppendRunner`] implementation (`AppendCoordinator::append`).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DefaultAppendRunner;

#[async_trait]
impl AppendRunner for DefaultAppendRunner {
    async fn run_append(
        &self,
        state: &TrellisServerState,
        command: AppendCommand,
    ) -> Result<AppendOutcome, StackError> {
        state.append_coordinator().append(command).await
    }
}

/// Owns the append transaction boundary: admission → lock → build → commit → publish.
#[derive(Clone, Copy)]
pub struct AppendCoordinator<'a> {
    state: &'a TrellisServerState,
}

impl<'a> AppendCoordinator<'a> {
    #[must_use]
    pub const fn new(state: &'a TrellisServerState) -> Self {
        Self { state }
    }

    /// Runs admission once, then either replays an idempotent commit or commits a new unit of work.
    ///
    /// # Errors
    /// Returns an error when admission, core append, persistence, or bundle publication fails.
    pub async fn append(&self, command: AppendCommand) -> Result<AppendOutcome, StackError> {
        if !self.state.signing_key.is_active_at(now_timestamp()?) {
            return Err(StackError::bad_request(
                "signing key inactive at append time",
            ));
        }
        let payload_json = serde_json::to_vec(&command.payload).map_err(|error| {
            StackError::bad_request(format!("payload JSON encode failed: {error}"))
        })?;
        let admitted = self
            .state
            .admission_policy
            .admit(&AdmissionEvent {
                scope: command.scope.as_bytes(),
                event_type: &command.event_type,
                payload: &payload_json,
            })
            .await?;

        let _scope_guard = self.state.scope_locks.lock(command.scope.as_bytes()).await;
        let mut events = self
            .state
            .repository
            .list_scope(command.scope.as_bytes())
            .await?;
        let content =
            EventContent::from_payload(&command.payload, command.idempotency_key.as_bytes())?;

        if let Some(existing) = events
            .iter()
            .find(|event| event.idempotency_key() == Some(command.idempotency_key.as_bytes()))
        {
            validate_existing_replay(existing, &command.event_type, content.content_hash)?;
            let replay_events = events
                .iter()
                .filter(|event| event.sequence() <= existing.sequence())
                .cloned()
                .collect::<Vec<_>>();
            let bundle = publish_bundle(
                self.state,
                command.scope.as_bytes(),
                &replay_events,
                false,
                &command.compute_context,
            )
            .await?;
            let result = append_result_for_event(
                &command.scope,
                existing,
                admitted.profile_id,
                &admitted.event_type,
                &bundle,
                true,
            )?;
            return Ok(AppendOutcome {
                result,
                stored: existing.clone(),
            });
        }

        let sequence = u64::try_from(events.len())
            .map_err(|_| StackError::internal("event count exceeds u64"))?;
        let prev_hash = events
            .last()
            .map(|event| event_hash(command.scope.as_bytes(), event))
            .transpose()?;
        let authored = build_authored_event(AuthoredEventInput {
            scope: command.scope.as_bytes(),
            sequence,
            prev_hash,
            event_type: &command.event_type,
            idempotency_key: command.idempotency_key.as_bytes(),
            content,
            authored_at: now_timestamp()?,
        })?;
        let mut capture = CapturingLedgerStore::default();
        let artifacts =
            trellis_core::append_event(&mut capture, &self.state.signing_key.core_key(), &authored)
                .map_err(|error| {
                    StackError::bad_request(format!("trellis append rejected: {error}"))
                })?;
        let stored = capture
            .take()
            .ok_or_else(|| StackError::internal("trellis core did not emit a stored event"))?
            .with_canonical_event_hash(Some(artifacts.canonical_event_hash));
        let unit = AppendUnitOfWork::new(stored, command.compute_context);
        self.commit_unit(&command.scope, &admitted, &mut events, unit, true)
            .await
    }

    async fn commit_unit(
        &self,
        scope: &str,
        admitted: &AdmittedEvent,
        events: &mut Vec<StoredEvent>,
        unit: AppendUnitOfWork,
        update_head: bool,
    ) -> Result<AppendOutcome, StackError> {
        let compute = unit.compute_context().clone();
        let stored = unit.event().clone();
        self.state.repository.append_event(stored.clone()).await?;
        events.push(stored.clone());
        let bundle =
            publish_bundle(self.state, scope.as_bytes(), events, update_head, &compute).await?;
        let result = append_result_for_event(
            scope,
            &stored,
            admitted.profile_id,
            &admitted.event_type,
            &bundle,
            true,
        )?;
        Ok(AppendOutcome { result, stored })
    }
}

/// Public-metadata posture used when republishing bundles outside an append receipt.
#[must_use]
pub fn default_public_compute_context() -> ComputeContext {
    ComputeContext {
        declaration_id: "compute:public-metadata:append".to_string(),
        actor: "trellis-server".to_string(),
        sensitivity: ComputeSensitivity::PublicMetadata,
    }
}

/// Maps append-time compute disclosure into the export manifest posture block.
#[must_use]
pub fn export_posture_from_compute(compute: &ComputeContext) -> ExportPostureDeclaration {
    let (provider_readable, reader_held, delegated_compute) = match compute.sensitivity {
        ComputeSensitivity::PublicMetadata => (true, false, false),
        ComputeSensitivity::ProviderReadable => (true, false, true),
        ComputeSensitivity::ReaderHeld => (false, true, false),
        ComputeSensitivity::Restricted => (false, true, false),
    };
    ExportPostureDeclaration {
        provider_readable,
        reader_held,
        delegated_compute,
        external_anchor_required: false,
        external_anchor_name: None,
        recovery_without_user: false,
        metadata_leakage_summary: format!(
            "{} ({})",
            compute.declaration_id,
            compute.sensitivity.as_str()
        ),
    }
}

/// Clones compute context from the shared wire DTO (`trellis-service-client`).
#[must_use]
pub fn port_compute_context(body: &SubstrateAppendBody) -> ComputeContext {
    body.compute_context.clone()
}

#[derive(Clone, Debug)]
struct EventContent {
    payload_bytes: Vec<u8>,
    content_hash: [u8; 32],
    nonce: [u8; 12],
}

impl EventContent {
    fn from_payload(
        payload: &serde_json::Value,
        idempotency_key: &[u8],
    ) -> Result<Self, StackError> {
        let payload_bytes = json_to_dcbor_bytes(payload, &[]).map_err(|error| {
            StackError::bad_request(format!("payload CBOR encode failed: {error}"))
        })?;
        let content_hash = domain_separated_sha256(CONTENT_DOMAIN, &payload_bytes);
        let nonce = derive_payload_inline_nonce(idempotency_key, &payload_bytes)?;
        Ok(Self {
            payload_bytes,
            content_hash,
            nonce,
        })
    }
}

fn derive_payload_inline_nonce(
    idempotency_key: &[u8],
    payload_bytes: &[u8],
) -> Result<[u8; 12], StackError> {
    // Core §9.4 / TR-CORE-144: nonce = HKDF-SHA256(
    //   salt = dCBOR(idempotency_key),
    //   ikm = SHA-256(payload_bytes),
    //   info = "trellis-payload-nonce-v1",
    //   L = 12
    // )
    let salt = integrity_cbor::encode_bstr(idempotency_key);
    let digest = Sha256::digest(payload_bytes);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), digest.as_slice());
    let mut nonce = [0u8; 12];
    hkdf.expand(b"trellis-payload-nonce-v1", &mut nonce)
        .map_err(|_| StackError::internal("payload nonce HKDF expand failed"))?;
    Ok(nonce)
}

struct AuthoredEventInput<'a> {
    scope: &'a [u8],
    sequence: u64,
    prev_hash: Option<[u8; 32]>,
    event_type: &'a str,
    idempotency_key: &'a [u8],
    content: EventContent,
    authored_at: TrellisTimestamp,
}

fn build_authored_event(input: AuthoredEventInput<'_>) -> Result<AuthoredEvent, StackError> {
    let header = crate::text_map(vec![
        (
            "event_type",
            Value::Bytes(input.event_type.as_bytes().to_vec()),
        ),
        ("authored_at", crate::timestamp_value(input.authored_at)),
        ("retention_tier", crate::uint(0)),
        (
            "classification",
            Value::Bytes(b"x-trellis-service/public-metadata".to_vec()),
        ),
        ("outcome_commitment", Value::Null),
        ("subject_ref_commitment", Value::Null),
        ("tag_commitment", Value::Null),
        ("witness_ref", Value::Null),
        ("extensions", Value::Null),
    ])?;
    let payload_ref = crate::text_map(vec![
        ("ref_type", Value::Text("inline".to_string())),
        ("ciphertext", Value::Bytes(input.content.payload_bytes)),
        ("nonce", Value::Bytes(input.content.nonce.to_vec())),
    ])?;
    let key_bag = crate::text_map(vec![("entries", Value::Array(Vec::new()))])?;
    let authored = crate::text_map(vec![
        ("version", crate::uint(1)),
        ("ledger_scope", Value::Bytes(input.scope.to_vec())),
        ("sequence", crate::uint(input.sequence)),
        (
            "prev_hash",
            input
                .prev_hash
                .map_or(Value::Null, |hash| Value::Bytes(hash.to_vec())),
        ),
        ("causal_deps", Value::Null),
        (
            "content_hash",
            Value::Bytes(input.content.content_hash.to_vec()),
        ),
        ("header", header),
        ("commitments", Value::Null),
        ("payload_ref", payload_ref),
        ("key_bag", key_bag),
        (
            "idempotency_key",
            Value::Bytes(input.idempotency_key.to_vec()),
        ),
        ("extensions", Value::Null),
    ])?;
    let bytes = crate::encode_value(&authored)?;
    Ok(AuthoredEvent::new(bytes))
}

#[derive(Default)]
struct CapturingLedgerStore {
    event: Option<StoredEvent>,
}

impl CapturingLedgerStore {
    fn take(&mut self) -> Option<StoredEvent> {
        self.event.take()
    }
}

impl LedgerStore for CapturingLedgerStore {
    type Error = StackError;

    fn append_event(&mut self, event: StoredEvent) -> Result<(), Self::Error> {
        if self.event.replace(event).is_some() {
            return Err(StackError::internal("multiple events captured"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServerSigningKey;
    use trellis_export_writer::TrellisTimestamp;

    fn fixture_payload_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vectors/_inputs/sample-payload-001.bin")
    }

    const APPEND_041_NONCE: [u8; 12] = *b"\xf2\x48\x1a\xd5\x81\x21\x4d\xf8\xe6\xda\x32\x54";
    const APPEND_042_NONCE: [u8; 12] = *b"\x90\xe4\x69\x49\xe5\x04\xf6\xce\xa0\x08\x55\x4b";

    #[test]
    fn given_provider_readable_compute_when_mapped_then_delegated_compute_is_true() {
        let compute = ComputeContext {
            declaration_id: "compute:provider-readable:test".to_string(),
            actor: "test-actor".to_string(),
            sensitivity: ComputeSensitivity::ProviderReadable,
        };
        let posture = export_posture_from_compute(&compute);
        assert!(posture.provider_readable);
        assert!(posture.delegated_compute);
        assert!(!posture.reader_held);
    }

    #[test]
    fn given_reader_held_compute_when_mapped_then_reader_held_is_true() {
        let compute = ComputeContext {
            declaration_id: "compute:reader-held:test".to_string(),
            actor: "test-actor".to_string(),
            sensitivity: ComputeSensitivity::ReaderHeld,
        };
        let posture = export_posture_from_compute(&compute);
        assert!(posture.reader_held);
        assert!(!posture.provider_readable);
        assert!(!posture.delegated_compute);
    }

    #[test]
    fn given_same_payload_and_different_idempotency_keys_when_deriving_inline_nonce_then_nonces_differ()
     {
        let payload = serde_json::json!({
            "kind": "test.event",
            "value": 42
        });
        let payload_bytes =
            json_to_dcbor_bytes(&payload, &[]).expect("encode deterministic payload bytes");
        let nonce_left = derive_payload_inline_nonce(b"idempotency-A", &payload_bytes)
            .expect("derive nonce for first key");
        let nonce_right = derive_payload_inline_nonce(b"idempotency-B", &payload_bytes)
            .expect("derive nonce for second key");
        assert_ne!(
            nonce_left, nonce_right,
            "different idempotency keys must produce different payload nonces"
        );
    }

    /// Given append/041 fixture inputs, when deriving the inline nonce, then
    /// output matches the vector generator's HKDF-SHA256 commitment.
    #[test]
    fn given_append_041_fixture_inputs_when_deriving_inline_nonce_then_matches_vector() {
        let payload_bytes = std::fs::read(fixture_payload_path()).expect("fixture payload");
        let nonce = derive_payload_inline_nonce(b"idemp-append-041", &payload_bytes)
            .expect("derive nonce for append/041");
        assert_eq!(
            nonce, APPEND_041_NONCE,
            "nonce must match append/041-aead-retry-determinism derivation"
        );
    }

    /// Given append/042 fixture inputs, when deriving the inline nonce, then
    /// output matches the vector generator's HKDF-SHA256 commitment.
    #[test]
    fn given_append_042_fixture_inputs_when_deriving_inline_nonce_then_matches_vector() {
        let payload_bytes = std::fs::read(fixture_payload_path()).expect("fixture payload");
        let nonce = derive_payload_inline_nonce(b"idemp-append-042", &payload_bytes)
            .expect("derive nonce for append/042");
        assert_eq!(
            nonce, APPEND_042_NONCE,
            "nonce must match append/042-idempotency-retry-noop derivation"
        );
    }

    #[test]
    fn given_expired_signing_key_when_checked_for_append_then_key_is_inactive() {
        let valid_from = TrellisTimestamp::new(1_700_000_000, 0).expect("valid from");
        let valid_to = TrellisTimestamp::new(1_700_000_010, 0).expect("valid to");
        let key_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vectors/_keys/issuer-001.cose_key");
        let key = std::fs::read(key_path).expect("fixture key");
        let signing_key = ServerSigningKey::from_cose_key_bytes(key, valid_from)
            .expect("parse signing key")
            .with_valid_to(Some(valid_to));
        let check_time = TrellisTimestamp::new(1_700_000_100, 0).expect("check time");
        assert!(
            !signing_key.is_active_at(check_time),
            "append path must reject signing keys after valid_to"
        );
    }
}
