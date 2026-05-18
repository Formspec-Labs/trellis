// Rust guideline compliant 2026-02-21
//! WOS-aware verification composed on Trellis integrity verification.
//!
//! Verification proves Trellis bundle structure, checkpoints, and signatures, then applies WOS-domain rules through
//! [`WosRecordValidator`]. The validator installs [`WosFormspecResolver`] so Formspec intake digest material carried
//! inside WOS-shaped provenance still participates in certificate / response-hash checks on the same export bundle
//! bytes (TWREF-025). Formspec producers append under `substrate.append.*` while WOS producers append under `wos.*`,
//! but both land in one ledger and one export ZIP interchange; this entry therefore remains the correct verifier for
//! Formspec-origin bundles unless a future split introduces a Formspec-only `RecordValidator` with different domain
//! findings. Operational `chain_hash` fields maintained inside `wos-server` projections are a separate diagnostic
//! surface from the Trellis proof chain this crate audits; documentation and APIs must not present them as
//! interchangeable legal-grade proof (TWREF-037).

#![forbid(unsafe_code)]

mod catalog;
mod certificate_resolver;
mod clock_semantics;
mod event_types;
mod findings;
mod policy_closure;
mod records;
mod rescission;
mod signed_acts;
mod validator;

#[cfg(test)]
mod tests;

pub use certificate_resolver::WosFormspecResolver;
pub use findings::{
    WosDomainReport, WosFinding, WosLayeredVerificationReport, WosRelyingPartyVerdict,
    WosVerificationReport,
};
pub use signed_acts::{derive_signed_acts_manifest_v1, encode_signed_acts_manifest_v1};
pub use validator::WosRecordValidator;

/// Verifies a Trellis export ZIP using structural Trellis checks plus WOS-domain validation.
///
/// Callers pass raw ZIP bytes as emitted by `trellis-export-writer`. The report bundles structural failures with
/// WOS-specific findings from [`WosRecordValidator`], including Formspec response digest resolution for applicable
/// payloads (TWREF-025). This is the verifier entry for stacks that delegate proof to Trellis: it does not consult
/// `wos-server` operational chain hashes, which track projection convenience rather than independent cryptographic
/// proof (TWREF-037).
#[must_use]
pub fn verify_export_zip(zip: &[u8]) -> WosVerificationReport {
    integrity_verify::trellis::verify_export_zip_with_validator(zip, &WosRecordValidator).into()
}

/// Verifies one WOS event.
///
/// # Errors
/// Returns an error when the signed bytes do not decode as a COSE_Sign1 item.
pub fn verify_single_event(
    public_key: [u8; 32],
    signed_event: &[u8],
) -> Result<WosVerificationReport, integrity_verify::trellis::VerifyError> {
    integrity_verify::trellis::verify_single_event_with_validator(
        public_key,
        signed_event,
        &WosRecordValidator,
    )
    .map(Into::into)
}

/// Verifies a WOS tamper-fixture ledger.
///
/// # Errors
/// Returns an error when the registry bytes cannot be decoded.
pub fn verify_tampered_ledger(
    signing_key_registry: &[u8],
    ledger: &[u8],
    initial_posture_declaration: Option<&[u8]>,
    posture_declaration: Option<&[u8]>,
) -> Result<WosVerificationReport, integrity_verify::trellis::VerifyError> {
    integrity_verify::trellis::verify_tampered_ledger_with_validator(
        signing_key_registry,
        ledger,
        initial_posture_declaration,
        posture_declaration,
        &WosRecordValidator,
    )
    .map(Into::into)
}
