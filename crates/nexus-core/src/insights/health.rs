//! Network health scoring
//!
//! Calculates overall network security health score

use crate::HostInfo;
use serde::{Deserialize, Serialize};

/// Network health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHealth {
    /// Overall health score (0-100)
    pub score: u8,
    /// Health status label
    pub status: String,
    /// Letter grade (A, B, C, D, F)
    pub grade: char,
    /// Breakdown of score components
    pub breakdown: HealthBreakdown,
    /// Summary insights
    pub insights: Vec<String>,
}

/// Score breakdown by category
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthBreakdown {
    /// Security score component (0-40 points)
    pub security: u8,
    /// Network stability component (0-30 points)
    pub stability: u8,
    /// Device compliance component (0-30 points)
    pub compliance: u8,
}

impl NetworkHealth {
    /// Calculate network health from scan results
    pub fn calculate(hosts: &[HostInfo]) -> Self {
        let total = hosts.len();
        if total == 0 {
            return Self::empty();
        }

        // Calculate security score (0-40 points)
        let high_risk_count = hosts.iter().filter(|h| h.risk_score >= 50).count();
        let medium_risk_count = hosts
            .iter()
            .filter(|h| h.risk_score >= 25 && h.risk_score < 50)
            .count();

        let security = if high_risk_count == 0 && medium_risk_count == 0 {
            40
        } else {
            let penalty = (high_risk_count * 15 + medium_risk_count * 5) as u8;
            40u8.saturating_sub(penalty)
        };

        // Calculate stability score (0-30 points)
        let responsive_count = hosts
            .iter()
            .filter(|h| h.response_time_ms.is_some())
            .count();
        let response_rate = responsive_count as f32 / total as f32;
        let stability = (response_rate * 30.0) as u8;

        // Calculate compliance score (0-30 points)
        let randomized_count = hosts.iter().filter(|h| h.is_randomized).count();
        let unknown_count = hosts.iter().filter(|h| h.device_type == "UNKNOWN").count();
        let compliance_penalty = (randomized_count * 3 + unknown_count * 2) as u8;
        let compliance = 30u8.saturating_sub(compliance_penalty);

        // Total score
        let score = security + stability + compliance;

        // Determine grade
        let grade = match score {
            90..=100 => 'A',
            80..=89 => 'B',
            70..=79 => 'C',
            60..=69 => 'D',
            _ => 'F',
        };

        // Determine status
        let status = match score {
            80..=100 => "Excellent".to_string(),
            60..=79 => "Good".to_string(),
            40..=59 => "Fair".to_string(),
            20..=39 => "Poor".to_string(),
            _ => "Critical".to_string(),
        };

        // Generate insights
        let mut insights = Vec::new();
        insights.push(format!("{} devices scanned", total));

        if high_risk_count > 0 {
            insights.push(format!("⚠️ {} high-risk devices detected", high_risk_count));
        }
        if randomized_count > 0 {
            insights.push(format!(
                "🔒 {} devices using randomized MACs",
                randomized_count
            ));
        }
        if unknown_count > 0 {
            insights.push(format!("❓ {} unidentified device types", unknown_count));
        }
        if score >= 80 {
            insights.push("✅ Network health is good".to_string());
        }

        Self {
            score,
            status,
            grade,
            breakdown: HealthBreakdown {
                security,
                stability,
                compliance,
            },
            insights,
        }
    }

    fn empty() -> Self {
        Self {
            score: 0,
            status: "No Data".to_string(),
            grade: 'N',
            breakdown: HealthBreakdown {
                security: 0,
                stability: 0,
                compliance: 0,
            },
            insights: vec!["No devices scanned".to_string()],
        }
    }
}
