//! Export functionality for reports
//!
//! Provides PDF, CSV, and JSON export capabilities

pub mod csv;
pub mod json;
#[cfg(feature = "pdf-export")]
pub mod pdf;

#[cfg(not(feature = "pdf-export"))]
mod pdf {
    use anyhow::{Result, anyhow};

    use crate::database::NetworkStats;
    use crate::insights::SecurityReport;
    use crate::models::{HostInfo, ScanResult};

    pub fn generate_scan_report_pdf(
        _scan: &ScanResult,
        _devices: &[HostInfo],
        _stats: Option<&NetworkStats>,
    ) -> Result<Vec<u8>> {
        Err(anyhow!(
            "PDF export is disabled at compile time. Rebuild with --features pdf-export."
        ))
    }

    pub fn generate_network_health_pdf(_recommendations: &SecurityReport) -> Result<Vec<u8>> {
        Err(anyhow!(
            "PDF export is disabled at compile time. Rebuild with --features pdf-export."
        ))
    }
}

pub use csv::*;
pub use json::*;
pub use pdf::*;
