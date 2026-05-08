//! Trellis-COSE Formspec signature adapter.
//!
//! Implements `formspec_signature_port::Verifier` using `trellis-cose` primitives.
//! This is a consumer-owned adapter (NOT a Trellis center crate) per ADR-0086 D-7.
//! Same registry coverage as webcrypto/ring adapters; PQC suites composable as Trellis adds them.
//! Receipt signing uses Trellis-managed signing keys per ADR-0006 key-class taxonomy.

use ed25519_dalek::ed25519::signature::Verifier as Ed25519Verifier;
use ed25519_dalek::{Signature, VerifyingKey};
use formspec_signature_port::{
    AdapterInfo, KeyInfo, SignatureMethodRegistry, VerificationReceipt, VerificationResult,
    Verifier, VerifierError, VerifyRequest,
};

const ADAPTER_ID: &str = "urn:formspec:adapter:trellis-cose@1";
const ADAPTER_VERSION: &str = "0.1.0";

pub struct TrellisCoseVerifier {
    adapter_info: AdapterInfo,
}

impl TrellisCoseVerifier {
    pub fn new() -> Self {
        Self {
            adapter_info: AdapterInfo {
                id: ADAPTER_ID.into(),
                version: ADAPTER_VERSION.into(),
            },
        }
    }

    fn unsupported_receipt(
        &self,
        request: &VerifyRequest,
        registry: &SignatureMethodRegistry,
    ) -> VerificationReceipt {
        VerificationReceipt {
            result: VerificationResult::Unsupported,
            method: request.signature_method.clone(),
            method_registry_version: registry.version.clone(),
            adapter: self.adapter_info.clone(),
            key: KeyInfo {
                r#ref: request.key_ref.clone(),
                version: None,
                snapshot: None,
            },
            verified_at: chrono_now(),
            context: None,
            receipt_bytes: None,
        }
    }

    fn failed_receipt(
        &self,
        request: &VerifyRequest,
        registry: &SignatureMethodRegistry,
    ) -> VerificationReceipt {
        VerificationReceipt {
            result: VerificationResult::Failed,
            method: request.signature_method.clone(),
            method_registry_version: registry.version.clone(),
            adapter: self.adapter_info.clone(),
            key: KeyInfo {
                r#ref: request.key_ref.clone(),
                version: None,
                snapshot: None,
            },
            verified_at: chrono_now(),
            context: None,
            receipt_bytes: None,
        }
    }

    fn verified_receipt(
        &self,
        request: &VerifyRequest,
        registry: &SignatureMethodRegistry,
    ) -> VerificationReceipt {
        VerificationReceipt {
            result: VerificationResult::Verified,
            method: request.signature_method.clone(),
            method_registry_version: registry.version.clone(),
            adapter: self.adapter_info.clone(),
            key: KeyInfo {
                r#ref: request.key_ref.clone(),
                version: None,
                snapshot: None,
            },
            verified_at: chrono_now(),
            context: None,
            receipt_bytes: None,
        }
    }
}

impl Default for TrellisCoseVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Verifier for TrellisCoseVerifier {
    fn verify(
        &self,
        request: &VerifyRequest,
        registry: &SignatureMethodRegistry,
    ) -> Result<VerificationReceipt, VerifierError> {
        let entry = registry.resolve(&request.signature_method);
        let entry = match entry {
            Some(e) => e,
            None => {
                return Ok(self.unsupported_receipt(request, registry));
            }
        };

        if entry.status == "deprecated" {
            return Ok(self.unsupported_receipt(request, registry));
        }

        match entry.alg {
            Some(-8) => {
                let key_bytes = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    request.key_ref.as_str(),
                )
                .map_err(|error| VerifierError::Internal {
                    reason: format!("invalid base64 Ed25519 public key: {error}"),
                })?;
                let key_bytes: [u8; 32] =
                    key_bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| VerifierError::Internal {
                            reason: "Ed25519 public key must be 32 bytes".to_string(),
                        })?;
                let cose = formspec_signature_cose::decode_cose_sign1(&request.signature_bytes)
                    .map_err(|error| VerifierError::InvalidCoseEncoding {
                        reason: error.to_string(),
                    })?;
                if cose.alg() != entry.alg {
                    return Ok(self.failed_receipt(request, registry));
                }
                let payload = cose
                    .resolve_payload(&request.signed_bytes)
                    .map_err(|error| VerifierError::InvalidCoseEncoding {
                        reason: error.to_string(),
                    })?;
                let sig_structure =
                    formspec_signature_cose::sig_structure_bytes(cose.protected_header(), payload);
                let signature: [u8; 64] = cose.signature().try_into().map_err(|_| {
                    VerifierError::InvalidCoseEncoding {
                        reason: "Ed25519 COSE signature must be 64 bytes".to_string(),
                    }
                })?;
                let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|error| {
                    VerifierError::Internal {
                        reason: format!("invalid Ed25519 public key: {error}"),
                    }
                })?;
                let signature = Signature::from_bytes(&signature);
                if verifying_key.verify(&sig_structure, &signature).is_ok() {
                    Ok(self.verified_receipt(request, registry))
                } else {
                    Ok(self.failed_receipt(request, registry))
                }
            }
            Some(_) | None => Ok(self.unsupported_receipt(request, registry)),
        }
    }
}

/// RFC 3339 UTC timestamp from system clock using Hinnant civil_from_days algorithm.
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs() as i64;

    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }

    format!("{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use formspec_signature_port::RegistryEntry;

    fn test_registry() -> SignatureMethodRegistry {
        SignatureMethodRegistry {
            version: "1.0.0".into(),
            entries: vec![
                RegistryEntry {
                    id: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
                    suite: "Ed25519".to_string(),
                    wire: "COSE_Sign1 with alg = -8 (EdDSA)".to_string(),
                    alg: Some(-8),
                    status: "registered".to_string(),
                    deprecation_notice: None,
                },
                RegistryEntry {
                    id: "urn:formspec:sig-method:ml-dsa-65-cose-sign1@1".into(),
                    suite: "ML-DSA-65 (FIPS 204)".to_string(),
                    wire: "COSE_Sign1 with alg = TBD".to_string(),
                    alg: None,
                    status: "registered".to_string(),
                    deprecation_notice: None,
                },
            ],
        }
    }

    #[test]
    fn test_unsupported_for_unknown_method() {
        let verifier = TrellisCoseVerifier::new();
        let registry = test_registry();
        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes: vec![1, 2, 3],
                    signature_bytes: vec![4, 5, 6],
                    signature_method: "urn:formspec:sig-method:unknown@1".into(),
                    key_ref: "deadbeef".into(),
                },
                &registry,
            )
            .unwrap();
        assert_eq!(receipt.result.to_string(), "unsupported");
    }

    #[test]
    fn test_adapter_info() {
        let verifier = TrellisCoseVerifier::new();
        assert_eq!(
            verifier.adapter_info.id,
            "urn:formspec:adapter:trellis-cose@1"
        );
    }

    #[test]
    fn test_unsupported_for_null_alg() {
        let verifier = TrellisCoseVerifier::new();
        let registry = test_registry();
        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes: vec![1, 2, 3],
                    signature_bytes: vec![4, 5, 6],
                    signature_method: "urn:formspec:sig-method:ml-dsa-65-cose-sign1@1".into(),
                    key_ref: "deadbeef".into(),
                },
                &registry,
            )
            .unwrap();
        assert_eq!(receipt.result.to_string(), "unsupported");
    }

    #[test]
    fn test_known_method_with_malformed_cose_returns_error() {
        let verifier = TrellisCoseVerifier::new();
        let registry = test_registry();
        let key_ref = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 32]);
        let result = verifier.verify(
            &VerifyRequest {
                signed_bytes: vec![1, 2, 3],
                signature_bytes: vec![4, 5, 6],
                signature_method: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
                key_ref: key_ref.into(),
            },
            &registry,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            VerifierError::InvalidCoseEncoding { reason } => {
                assert!(
                    reason.contains("COSE_Sign1"),
                    "expected COSE decode message, got: {reason}"
                );
            }
            other => panic!("expected InvalidCoseEncoding error, got: {other}"),
        }
    }

    #[test]
    fn test_known_method_verifies_real_cose_sign1() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let signed_bytes = b"formspec signed payload".to_vec();
        let protected = formspec_signature_cose::protected_header_bytes(-8, Some(b"trellis-kid"));
        let sig_structure = formspec_signature_cose::sig_structure_bytes(&protected, &signed_bytes);
        let signature = signing_key.sign(&sig_structure);
        let signature_bytes =
            formspec_signature_cose::encode_cose_sign1(&protected, None, &signature.to_bytes());
        let key_ref = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            verifying_key.as_bytes(),
        );
        let verifier = TrellisCoseVerifier::new();
        let registry = test_registry();
        let receipt = verifier
            .verify(
                &VerifyRequest {
                    signed_bytes,
                    signature_bytes,
                    signature_method: "urn:formspec:sig-method:ed25519-cose-sign1@1".into(),
                    key_ref: key_ref.into(),
                },
                &registry,
            )
            .expect("verify");
        assert_eq!(receipt.result.to_string(), "verified");
    }

    #[test]
    fn test_chrono_now_produces_valid_rfc3339() {
        let ts = chrono_now();
        assert!(ts.ends_with('Z'), "must end with Z: {ts}");
        let parts: Vec<&str> = ts.split('T').collect();
        assert_eq!(parts.len(), 2, "must have date T time: {ts}");
        let date_parts: Vec<&str> = parts[0].split('-').collect();
        assert_eq!(date_parts.len(), 3, "date must be YYYY-MM-DD: {ts}");
        let year: i32 = date_parts[0].parse().expect("year must be numeric");
        assert!(
            (2020..=2100).contains(&year),
            "year must be plausible: {year}"
        );
    }
}
