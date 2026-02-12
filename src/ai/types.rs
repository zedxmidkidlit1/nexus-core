use serde::{Deserialize, Serialize};

use crate::{DeviceDistribution, NetworkHealth, SecurityReport, VendorDistribution};

/// AI routing mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiMode {
    Disabled,
    Local,
    Cloud,
    HybridAuto,
}

impl AiMode {
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "disabled" => Some(Self::Disabled),
            "local" => Some(Self::Local),
            "cloud" => Some(Self::Cloud),
            "hybrid" | "hybrid_auto" | "auto" => Some(Self::HybridAuto),
            _ => None,
        }
    }
}

/// LLM-generated overlay over rule-based insights.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AiInsightOverlay {
    pub executive_summary: String,
    pub top_risks: Vec<String>,
    pub immediate_actions: Vec<String>,
    pub follow_up_actions: Vec<String>,
}

/// Final insights response preserving deterministic base output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridInsightsResult {
    pub health: NetworkHealth,
    pub security: SecurityReport,
    pub device_distribution: DeviceDistribution,
    pub vendor_distribution: VendorDistribution,
    pub ai_overlay: Option<AiInsightOverlay>,
    pub ai_provider: Option<String>,
    pub ai_model: Option<String>,
    pub ai_error: Option<String>,
}

/// Provider connectivity/model check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiProviderCheck {
    pub provider: String,
    pub configured: bool,
    pub reachable: bool,
    pub model: Option<String>,
    pub model_available: Option<bool>,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// End-to-end AI readiness report for current runtime settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiCheckReport {
    pub ai_enabled: bool,
    pub mode: AiMode,
    pub timeout_ms: u64,
    pub local: Option<AiProviderCheck>,
    pub cloud: Option<AiProviderCheck>,
    pub overall_ok: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AiInputDigest {
    pub total_hosts: usize,
    pub health_score: u8,
    pub health_grade: char,
    pub health_status: String,
    pub critical_issues: usize,
    pub high_priority_issues: usize,
    pub total_recommendations: usize,
    pub top_device_types: Vec<(String, usize)>,
    pub top_vendors: Vec<(String, usize)>,
    pub high_risk_hosts: Vec<AiHostDigest>,
    pub recommendation_titles: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AiHostDigest {
    pub id: String,
    pub device_type: String,
    pub risk_score: u8,
    pub open_ports: Vec<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ai_mode_parse_accepts_aliases() {
        assert_eq!(AiMode::parse("hybrid"), Some(AiMode::HybridAuto));
        assert_eq!(AiMode::parse("auto"), Some(AiMode::HybridAuto));
        assert_eq!(AiMode::parse("local"), Some(AiMode::Local));
        assert_eq!(AiMode::parse("bad"), None);
    }
}
