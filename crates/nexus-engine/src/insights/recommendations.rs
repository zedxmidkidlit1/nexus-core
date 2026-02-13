//! Security recommendations
//!
//! Generates actionable security advice based on scan results

use crate::HostInfo;
use serde::{Deserialize, Serialize};

/// Priority level for recommendations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Priority {
    pub fn as_str(&self) -> &'static str {
        match self {
            Priority::Critical => "CRITICAL",
            Priority::High => "HIGH",
            Priority::Medium => "MEDIUM",
            Priority::Low => "LOW",
            Priority::Info => "INFO",
        }
    }
}

/// A security recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub priority: Priority,
    pub category: String,
    pub title: String,
    pub description: String,
    pub affected_devices: Vec<String>,
}

/// Collection of recommendations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub recommendations: Vec<Recommendation>,
    pub critical_count: usize,
    pub high_count: usize,
    pub total_issues: usize,
    pub summary: String,
}

impl SecurityReport {
    /// Generate security recommendations from scan results
    pub fn generate(hosts: &[HostInfo]) -> Self {
        let mut recommendations = Vec::new();

        // Check for high-risk devices
        let high_risk: Vec<_> = hosts.iter().filter(|h| h.risk_score >= 50).collect();

        if !high_risk.is_empty() {
            recommendations.push(Recommendation {
                priority: Priority::High,
                category: "Risk Assessment".to_string(),
                title: "High-risk devices detected".to_string(),
                description: format!(
                    "{} device(s) have elevated risk scores. Review their security posture.",
                    high_risk.len()
                ),
                affected_devices: high_risk
                    .iter()
                    .map(|h| format!("{} ({})", h.ip, h.mac))
                    .collect(),
            });
        }

        // Check for insecure ports (Telnet)
        let telnet_hosts: Vec<_> = hosts
            .iter()
            .filter(|h| h.open_ports.contains(&23))
            .collect();

        if !telnet_hosts.is_empty() {
            recommendations.push(Recommendation {
                priority: Priority::Critical,
                category: "Insecure Services".to_string(),
                title: "Telnet (port 23) detected".to_string(),
                description:
                    "Telnet transmits data in plaintext. Consider disabling and using SSH instead."
                        .to_string(),
                affected_devices: telnet_hosts.iter().map(|h| h.ip.to_string()).collect(),
            });
        }

        // Check for FTP
        let ftp_hosts: Vec<_> = hosts
            .iter()
            .filter(|h| h.open_ports.contains(&21))
            .collect();

        if !ftp_hosts.is_empty() {
            recommendations.push(Recommendation {
                priority: Priority::High,
                category: "Insecure Services".to_string(),
                title: "FTP (port 21) detected".to_string(),
                description: "FTP is insecure. Consider using SFTP or FTPS.".to_string(),
                affected_devices: ftp_hosts.iter().map(|h| h.ip.to_string()).collect(),
            });
        }

        // Check for RDP
        let rdp_hosts: Vec<_> = hosts
            .iter()
            .filter(|h| h.open_ports.contains(&3389))
            .collect();

        if !rdp_hosts.is_empty() {
            recommendations.push(Recommendation {
                priority: Priority::Medium,
                category: "Remote Access".to_string(),
                title: "RDP (port 3389) exposed".to_string(),
                description: "RDP can be a target for attacks. Ensure strong authentication and consider VPN.".to_string(),
                affected_devices: rdp_hosts.iter()
                    .map(|h| h.ip.to_string())
                    .collect(),
            });
        }

        // Check for randomized MACs (potential rogue devices)
        let randomized: Vec<_> = hosts.iter().filter(|h| h.is_randomized).collect();

        if !randomized.is_empty() {
            recommendations.push(Recommendation {
                priority: Priority::Low,
                category: "Device Tracking".to_string(),
                title: "Randomized MAC addresses detected".to_string(),
                description: format!(
                    "{} device(s) using randomized MACs. These may be harder to track consistently.",
                    randomized.len()
                ),
                affected_devices: randomized.iter()
                    .map(|h| format!("{} ({})", h.ip, h.mac))
                    .collect(),
            });
        }

        // Check for unknown device types
        let unknown: Vec<_> = hosts
            .iter()
            .filter(|h| h.device_type == "UNKNOWN")
            .collect();

        if !unknown.is_empty() {
            recommendations.push(Recommendation {
                priority: Priority::Info,
                category: "Device Classification".to_string(),
                title: "Unidentified devices".to_string(),
                description: format!(
                    "{} device(s) could not be classified. Consider investigating these.",
                    unknown.len()
                ),
                affected_devices: unknown
                    .iter()
                    .map(|h| {
                        format!(
                            "{} ({})",
                            h.ip,
                            h.vendor.as_deref().unwrap_or("Unknown vendor")
                        )
                    })
                    .collect(),
            });
        }

        // If no issues, add positive note
        if recommendations.is_empty() {
            recommendations.push(Recommendation {
                priority: Priority::Info,
                category: "General".to_string(),
                title: "No major issues detected".to_string(),
                description: "Your network appears to be well-configured.".to_string(),
                affected_devices: vec![],
            });
        }

        // Count by priority
        let critical_count = recommendations
            .iter()
            .filter(|r| matches!(r.priority, Priority::Critical))
            .count();
        let high_count = recommendations
            .iter()
            .filter(|r| matches!(r.priority, Priority::High))
            .count();
        let total_issues = recommendations.len();

        // Generate summary
        let summary = if critical_count > 0 {
            format!(
                "⚠️ {} critical issue(s) require immediate attention",
                critical_count
            )
        } else if high_count > 0 {
            format!("⚡ {} high-priority recommendation(s)", high_count)
        } else {
            "✅ No critical security issues found".to_string()
        };

        Self {
            recommendations,
            critical_count,
            high_count,
            total_issues,
            summary,
        }
    }
}
