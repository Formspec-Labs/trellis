use trellis_verify::certificate_proof::NoopResponseProofResolver;
use trellis_verify::{
    CertificateOfCompletionOutcome, CorrectionPreservationOutcome, ErasureEvidenceOutcome,
    InteropSidecarVerificationEntry, PostureTransitionOutcome, UserContentAttestationOutcome,
};

fn assert_exported<T>() {
    let _ = std::any::type_name::<T>();
}

#[test]
fn facade_preserves_legacy_root_type_exports() {
    assert_exported::<CertificateOfCompletionOutcome>();
    assert_exported::<CorrectionPreservationOutcome>();
    assert_exported::<ErasureEvidenceOutcome>();
    assert_exported::<InteropSidecarVerificationEntry>();
    assert_exported::<PostureTransitionOutcome>();
    assert_exported::<UserContentAttestationOutcome>();
}

#[test]
fn facade_preserves_certificate_proof_module_exports() {
    assert_exported::<NoopResponseProofResolver>();
}
