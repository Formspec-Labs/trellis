// Rust guideline compliant 2026-02-21
//! WOS verification report types.

#![forbid(unsafe_code)]

pub type WosFinding = integrity_verify::trellis::DomainFinding;
pub type WosDomainReport = integrity_verify::trellis::DomainReport;
pub type WosLayeredVerificationReport = integrity_verify::trellis::LayeredVerificationReport;
pub type WosRelyingPartyVerdict = integrity_verify::trellis::RelyingPartyVerdict;

/// WOS verification report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WosVerificationReport {
    pub trellis: integrity_verify::trellis::VerificationReport,
    pub wos_findings: Vec<WosFinding>,
}

impl WosVerificationReport {
    /// Returns the substrate verification report.
    #[must_use]
    pub fn substrate(&self) -> &integrity_verify::trellis::VerificationReport {
        &self.trellis
    }

    /// Returns the WOS/domain verification report.
    #[must_use]
    pub fn domain_report(&self) -> WosDomainReport {
        WosDomainReport::new(self.wos_findings.clone())
    }

    /// Returns the relying-party verdict derived from substrate and domain results.
    #[must_use]
    pub fn verdict(&self) -> WosRelyingPartyVerdict {
        WosRelyingPartyVerdict::from_parts(&self.trellis, &self.wos_findings)
    }

    /// Returns the explicit two-tier report plus top-level verdict.
    #[must_use]
    pub fn layered_report(&self) -> WosLayeredVerificationReport {
        WosLayeredVerificationReport {
            verdict: self.verdict(),
            substrate: self.trellis.clone(),
            domain: self.domain_report(),
        }
    }

    /// Returns true only when the relying-party verdict is valid.
    #[must_use]
    pub fn relying_party_valid(&self) -> bool {
        self.verdict().relying_party_result == integrity_verify::trellis::RelyingPartyResult::Valid
    }
}

impl From<integrity_verify::trellis::VerificationWithDomain> for WosVerificationReport {
    fn from(value: integrity_verify::trellis::VerificationWithDomain) -> Self {
        Self {
            trellis: value.trellis,
            wos_findings: value.domain_findings,
        }
    }
}
