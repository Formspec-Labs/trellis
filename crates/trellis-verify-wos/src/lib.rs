// Rust guideline compliant 2026-02-21
//! WOS-aware verification composed on Trellis integrity verification.

#![forbid(unsafe_code)]

mod catalog;
mod certificate_resolver;
mod clock_semantics;
mod event_types;
mod findings;
mod records;
mod rescission;
mod validator;

#[cfg(test)]
mod tests;

pub use certificate_resolver::WosFormspecResolver;
pub use findings::{WosFinding, WosVerificationReport};
pub use validator::WosRecordValidator;

/// Verifies a WOS export ZIP.
#[must_use]
pub fn verify_export_zip(zip: &[u8]) -> WosVerificationReport {
    trellis_verify::verify_export_zip_with_validator(zip, &WosRecordValidator).into()
}

/// Verifies one WOS event.
///
/// # Errors
/// Returns an error when the signed bytes do not decode as a COSE_Sign1 item.
pub fn verify_single_event(
    public_key: [u8; 32],
    signed_event: &[u8],
) -> Result<WosVerificationReport, trellis_verify::VerifyError> {
    trellis_verify::verify_single_event_with_validator(
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
) -> Result<WosVerificationReport, trellis_verify::VerifyError> {
    trellis_verify::verify_tampered_ledger_with_validator(
        signing_key_registry,
        ledger,
        initial_posture_declaration,
        posture_declaration,
        &WosRecordValidator,
    )
    .map(Into::into)
}
