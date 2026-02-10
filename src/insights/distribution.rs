//! Device distribution statistics
//!
//! Analyzes device type breakdown for insights

use crate::HostInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Device distribution statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceDistribution {
    /// Total device count
    pub total: usize,
    /// Count by device type
    pub by_type: HashMap<String, usize>,
    /// Percentage breakdown
    pub percentages: HashMap<String, f32>,
    /// Dominant device type
    pub dominant_type: Option<String>,
    /// Summary text
    pub summary: String,
}

impl DeviceDistribution {
    /// Calculate distribution from scan results
    pub fn calculate(hosts: &[HostInfo]) -> Self {
        let total = hosts.len();

        if total == 0 {
            return Self::empty();
        }

        // Count by type
        let mut by_type: HashMap<String, usize> = HashMap::new();
        for host in hosts {
            *by_type.entry(host.device_type.clone()).or_insert(0) += 1;
        }

        // Calculate percentages
        let percentages: HashMap<String, f32> = by_type
            .iter()
            .map(|(k, v)| (k.clone(), (*v as f32 / total as f32) * 100.0))
            .collect();

        // Find dominant type
        let dominant_type = by_type
            .iter()
            .max_by_key(|(_, v)| *v)
            .map(|(k, _)| k.clone());

        // Generate summary
        let summary = Self::generate_summary(&by_type, total);

        Self {
            total,
            by_type,
            percentages,
            dominant_type,
            summary,
        }
    }

    fn generate_summary(by_type: &HashMap<String, usize>, total: usize) -> String {
        let router_count = *by_type.get("ROUTER").unwrap_or(&0);
        let mobile_count = *by_type.get("MOBILE").unwrap_or(&0);
        let pc_count = *by_type.get("PC").unwrap_or(&0);
        let unknown_count = *by_type.get("UNKNOWN").unwrap_or(&0);

        let mut parts = Vec::new();
        if router_count > 0 {
            parts.push(format!("{} router(s)", router_count));
        }
        if mobile_count > 0 {
            parts.push(format!("{} mobile(s)", mobile_count));
        }
        if pc_count > 0 {
            parts.push(format!("{} PC(s)", pc_count));
        }
        if unknown_count > 0 {
            parts.push(format!("{} unknown", unknown_count));
        }

        if parts.is_empty() {
            format!("{} devices total", total)
        } else {
            format!("{} devices: {}", total, parts.join(", "))
        }
    }

    fn empty() -> Self {
        Self {
            total: 0,
            by_type: HashMap::new(),
            percentages: HashMap::new(),
            dominant_type: None,
            summary: "No devices found".to_string(),
        }
    }
}

/// Vendor distribution statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorDistribution {
    pub total: usize,
    pub by_vendor: HashMap<String, usize>,
    pub top_vendors: Vec<(String, usize)>,
}

impl VendorDistribution {
    pub fn calculate(hosts: &[HostInfo]) -> Self {
        let total = hosts.len();
        let mut by_vendor: HashMap<String, usize> = HashMap::new();

        for host in hosts {
            let vendor = host.vendor.clone().unwrap_or_else(|| "Unknown".to_string());
            *by_vendor.entry(vendor).or_insert(0) += 1;
        }

        // Get top 5 vendors
        let mut top_vendors: Vec<_> = by_vendor.iter().map(|(k, v)| (k.clone(), *v)).collect();
        top_vendors.sort_by(|a, b| b.1.cmp(&a.1));
        top_vendors.truncate(5);

        Self {
            total,
            by_vendor,
            top_vendors,
        }
    }
}
