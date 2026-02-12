//! Hybrid AI insights orchestration.
//!
//! This module keeps rule-based insights as source of truth and optionally
//! augments them with LLM-generated narrative/actions via:
//! - Local Ollama
//! - Cloud Gemini API
//! - Hybrid auto routing

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

use crate::{DeviceDistribution, HostInfo, NetworkHealth, SecurityReport, VendorDistribution};

const DEFAULT_AI_TIMEOUT_MS: u64 = 8000;
const DEFAULT_OLLAMA_ENDPOINT: &str = "http://127.0.0.1:11434";
const DEFAULT_OLLAMA_MODEL: &str = "qwen3:8b";
const DEFAULT_GEMINI_ENDPOINT: &str = "https://generativelanguage.googleapis.com";
const DEFAULT_GEMINI_MODEL: &str = "gemini-2.5-flash";

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
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "disabled" => Some(Self::Disabled),
            "local" => Some(Self::Local),
            "cloud" => Some(Self::Cloud),
            "hybrid" | "hybrid_auto" | "auto" => Some(Self::HybridAuto),
            _ => None,
        }
    }
}

/// Runtime AI settings (env-driven).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSettings {
    pub enabled: bool,
    pub mode: AiMode,
    pub timeout_ms: u64,
    pub ollama_endpoint: String,
    pub ollama_model: String,
    pub gemini_endpoint: String,
    pub gemini_model: String,
    pub gemini_api_key: Option<String>,
    /// If false, cloud calls redact IP/MAC/hostnames by default.
    pub cloud_allow_sensitive: bool,
}

impl Default for AiSettings {
    fn default() -> Self {
        Self::from_env()
    }
}

impl AiSettings {
    pub fn from_env() -> Self {
        let enabled = env_parse_bool("NEXUS_AI_ENABLED", false);
        let mode = if enabled {
            env_var("NEXUS_AI_MODE")
                .and_then(|v| AiMode::parse(&v))
                .unwrap_or(AiMode::Local)
        } else {
            AiMode::Disabled
        };

        Self {
            enabled,
            mode,
            timeout_ms: env_parse_u64("NEXUS_AI_TIMEOUT_MS", DEFAULT_AI_TIMEOUT_MS, 500, 60_000),
            ollama_endpoint: env_var("NEXUS_AI_ENDPOINT")
                .unwrap_or_else(|| DEFAULT_OLLAMA_ENDPOINT.to_string()),
            ollama_model: env_var("NEXUS_AI_MODEL")
                .unwrap_or_else(|| DEFAULT_OLLAMA_MODEL.to_string()),
            gemini_endpoint: env_var("NEXUS_AI_GEMINI_ENDPOINT")
                .unwrap_or_else(|| DEFAULT_GEMINI_ENDPOINT.to_string()),
            gemini_model: env_var("NEXUS_AI_GEMINI_MODEL")
                .unwrap_or_else(|| DEFAULT_GEMINI_MODEL.to_string()),
            gemini_api_key: env_var("NEXUS_AI_GEMINI_API_KEY"),
            cloud_allow_sensitive: env_parse_bool("NEXUS_AI_CLOUD_ALLOW_SENSITIVE", false),
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
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

#[derive(Debug, Clone, Serialize)]
struct AiInputDigest {
    total_hosts: usize,
    health_score: u8,
    health_grade: char,
    health_status: String,
    critical_issues: usize,
    high_priority_issues: usize,
    total_recommendations: usize,
    top_device_types: Vec<(String, usize)>,
    top_vendors: Vec<(String, usize)>,
    high_risk_hosts: Vec<AiHostDigest>,
    recommendation_titles: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct AiHostDigest {
    id: String,
    device_type: String,
    risk_score: u8,
    open_ports: Vec<u16>,
}

pub async fn generate_hybrid_insights(hosts: &[HostInfo]) -> HybridInsightsResult {
    let health = NetworkHealth::calculate(hosts);
    let security = SecurityReport::generate(hosts);
    let device_distribution = DeviceDistribution::calculate(hosts);
    let vendor_distribution = VendorDistribution::calculate(hosts);

    let mut result = HybridInsightsResult {
        health,
        security,
        device_distribution,
        vendor_distribution,
        ai_overlay: None,
        ai_provider: None,
        ai_model: None,
        ai_error: None,
    };

    let settings = AiSettings::from_env();
    if !settings.enabled || settings.mode == AiMode::Disabled {
        return result;
    }

    let client = match Client::builder().timeout(settings.timeout()).build() {
        Ok(c) => c,
        Err(e) => {
            result.ai_error = Some(format!("AI client init failed: {}", e));
            return result;
        }
    };

    let local_input = build_ai_input_digest(
        hosts,
        &result.health,
        &result.security,
        &result.device_distribution,
        &result.vendor_distribution,
        false,
    );

    match settings.mode {
        AiMode::Local => match call_ollama(&client, &settings, &local_input).await {
            Ok(overlay) => {
                result.ai_overlay = Some(overlay);
                result.ai_provider = Some("ollama".to_string());
                result.ai_model = Some(settings.ollama_model.clone());
            }
            Err(e) => result.ai_error = Some(format!("Local AI failed: {}", e)),
        },
        AiMode::Cloud => match call_gemini_with_policy(&client, &settings, hosts, &result).await {
            Ok(overlay) => {
                result.ai_overlay = Some(overlay);
                result.ai_provider = Some("gemini".to_string());
                result.ai_model = Some(settings.gemini_model.clone());
            }
            Err(e) => result.ai_error = Some(format!("Cloud AI failed: {}", e)),
        },
        AiMode::HybridAuto => match call_ollama(&client, &settings, &local_input).await {
            Ok(overlay) => {
                result.ai_overlay = Some(overlay);
                result.ai_provider = Some("ollama".to_string());
                result.ai_model = Some(settings.ollama_model.clone());
            }
            Err(local_err) => {
                tracing::warn!(
                    "Local AI failed in hybrid mode, trying cloud: {}",
                    local_err
                );
                match call_gemini_with_policy(&client, &settings, hosts, &result).await {
                    Ok(overlay) => {
                        result.ai_overlay = Some(overlay);
                        result.ai_provider = Some("gemini".to_string());
                        result.ai_model = Some(settings.gemini_model.clone());
                    }
                    Err(cloud_err) => {
                        result.ai_error = Some(format!(
                            "Hybrid AI failed. local={}, cloud={}",
                            local_err, cloud_err
                        ));
                    }
                }
            }
        },
        AiMode::Disabled => {}
    }

    result
}

async fn call_gemini_with_policy(
    client: &Client,
    settings: &AiSettings,
    hosts: &[HostInfo],
    base: &HybridInsightsResult,
) -> Result<AiInsightOverlay> {
    if settings.gemini_api_key.is_none() {
        return Err(anyhow!(
            "NEXUS_AI_GEMINI_API_KEY is required for cloud/hybrid cloud fallback"
        ));
    }

    let input = build_ai_input_digest(
        hosts,
        &base.health,
        &base.security,
        &base.device_distribution,
        &base.vendor_distribution,
        !settings.cloud_allow_sensitive,
    );

    call_gemini(client, settings, &input).await
}

fn build_ai_input_digest(
    hosts: &[HostInfo],
    health: &NetworkHealth,
    security: &SecurityReport,
    device_distribution: &DeviceDistribution,
    vendor_distribution: &VendorDistribution,
    redact_sensitive: bool,
) -> AiInputDigest {
    let mut high_risk_hosts: Vec<&HostInfo> = hosts.iter().filter(|h| h.risk_score >= 50).collect();
    high_risk_hosts.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));

    let high_risk_hosts = high_risk_hosts
        .into_iter()
        .take(10)
        .enumerate()
        .map(|(idx, host)| AiHostDigest {
            id: if redact_sensitive {
                format!("host_{}", idx + 1)
            } else {
                format!(
                    "{} ({})",
                    host.ip,
                    host.hostname
                        .as_deref()
                        .filter(|name| !name.is_empty())
                        .unwrap_or("unknown")
                )
            },
            device_type: host.device_type.clone(),
            risk_score: host.risk_score,
            open_ports: host.open_ports.clone(),
        })
        .collect();

    let mut top_types: Vec<(String, usize)> = device_distribution
        .by_type
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    top_types.sort_by(|a, b| b.1.cmp(&a.1));
    top_types.truncate(5);

    let mut top_vendors = vendor_distribution.top_vendors.clone();
    top_vendors.truncate(5);

    AiInputDigest {
        total_hosts: hosts.len(),
        health_score: health.score,
        health_grade: health.grade,
        health_status: health.status.clone(),
        critical_issues: security.critical_count,
        high_priority_issues: security.high_count,
        total_recommendations: security.total_issues,
        top_device_types: top_types,
        top_vendors,
        high_risk_hosts,
        recommendation_titles: security
            .recommendations
            .iter()
            .take(8)
            .map(|r| format!("[{}] {}", r.priority.as_str(), r.title))
            .collect(),
    }
}

fn build_prompt(input: &AiInputDigest) -> Result<String> {
    let digest_json =
        serde_json::to_string_pretty(input).context("Failed to serialize AI input digest")?;
    Ok(format!(
        "You are a network security assistant for a CLI engine.\n\
Return ONLY valid JSON with this exact schema:\n\
{{\n\
  \"executive_summary\": \"string\",\n\
  \"top_risks\": [\"string\", \"string\"],\n\
  \"immediate_actions\": [\"string\", \"string\"],\n\
  \"follow_up_actions\": [\"string\", \"string\"]\n\
}}\n\
Rules:\n\
- Keep recommendations concrete and prioritized.\n\
- Do not invent unsupported facts.\n\
- Mention uncertainty briefly when needed.\n\
- Keep each list item concise.\n\
\n\
Input digest:\n{}",
        digest_json
    ))
}

async fn call_ollama(
    client: &Client,
    settings: &AiSettings,
    input: &AiInputDigest,
) -> Result<AiInsightOverlay> {
    let prompt = build_prompt(input)?;
    let endpoint = settings.ollama_endpoint.trim_end_matches('/');
    let url = format!("{}/api/generate", endpoint);

    let response = client
        .post(url)
        .json(&json!({
            "model": settings.ollama_model,
            "prompt": prompt,
            "stream": false,
            "format": "json"
        }))
        .send()
        .await
        .context("Failed to call Ollama generate endpoint")?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("Ollama request failed with {}: {}", status, body));
    }

    let payload: serde_json::Value = response
        .json()
        .await
        .context("Failed to parse Ollama response JSON")?;
    let text = payload
        .get("response")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Ollama response missing 'response' field"))?;

    parse_overlay_json(text)
}

async fn call_gemini(
    client: &Client,
    settings: &AiSettings,
    input: &AiInputDigest,
) -> Result<AiInsightOverlay> {
    let prompt = build_prompt(input)?;
    let api_key = settings
        .gemini_api_key
        .as_ref()
        .ok_or_else(|| anyhow!("Gemini API key is not configured"))?;

    let endpoint = settings.gemini_endpoint.trim_end_matches('/');
    let url = format!(
        "{}/v1beta/models/{}:generateContent?key={}",
        endpoint, settings.gemini_model, api_key
    );

    let response = client
        .post(url)
        .json(&json!({
            "contents": [{
                "role": "user",
                "parts": [{ "text": prompt }]
            }],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json"
            }
        }))
        .send()
        .await
        .context("Failed to call Gemini generateContent endpoint")?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("Gemini request failed with {}: {}", status, body));
    }

    let payload: serde_json::Value = response
        .json()
        .await
        .context("Failed to parse Gemini response JSON")?;

    let text = payload
        .get("candidates")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|candidate| candidate.get("content"))
        .and_then(|content| content.get("parts"))
        .and_then(|parts| parts.as_array())
        .and_then(|parts| parts.first())
        .and_then(|part| part.get("text"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Gemini response missing candidates[0].content.parts[0].text"))?;

    parse_overlay_json(text)
}

fn parse_overlay_json(raw: &str) -> Result<AiInsightOverlay> {
    let trimmed = raw.trim();
    let normalized = if trimmed.starts_with("```") {
        extract_json_object(trimmed).unwrap_or(trimmed).to_string()
    } else {
        trimmed.to_string()
    };

    let json_slice = extract_json_object(&normalized).unwrap_or(normalized.as_str());
    let overlay: AiInsightOverlay =
        serde_json::from_str(json_slice).context("Failed to parse AI overlay JSON body")?;

    if overlay.executive_summary.trim().is_empty() {
        return Err(anyhow!("AI overlay executive_summary is empty"));
    }
    if overlay.top_risks.is_empty() {
        return Err(anyhow!("AI overlay top_risks is empty"));
    }
    if overlay.immediate_actions.is_empty() {
        return Err(anyhow!("AI overlay immediate_actions is empty"));
    }

    Ok(overlay)
}

fn extract_json_object(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end <= start {
        return None;
    }
    Some(&text[start..=end])
}

fn env_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn env_parse_bool(name: &str, default: bool) -> bool {
    match env_var(name) {
        Some(value) => {
            let normalized = value.to_ascii_lowercase();
            match normalized.as_str() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                _ => default,
            }
        }
        None => default,
    }
}

fn env_parse_u64(name: &str, default: u64, min: u64, max: u64) -> u64 {
    match env_var(name).and_then(|v| v.parse::<u64>().ok()) {
        Some(v) => v.clamp(min, max),
        None => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insights::{HealthBreakdown, Priority, Recommendation};

    fn sample_hosts() -> Vec<HostInfo> {
        vec![
            HostInfo {
                ip: "192.168.1.10".to_string(),
                mac: "AA:BB:CC:DD:EE:10".to_string(),
                vendor: Some("Vendor".to_string()),
                is_randomized: false,
                response_time_ms: Some(5),
                ttl: Some(64),
                os_guess: Some("Linux".to_string()),
                device_type: "ROUTER".to_string(),
                risk_score: 65,
                open_ports: vec![23, 80],
                discovery_method: "ARP+ICMP+TCP".to_string(),
                hostname: Some("router".to_string()),
                system_description: None,
                uptime_seconds: None,
                neighbors: vec![],
                vulnerabilities: vec![],
                port_warnings: vec![],
                security_grade: String::new(),
            },
            HostInfo {
                ip: "192.168.1.20".to_string(),
                mac: "AA:BB:CC:DD:EE:20".to_string(),
                vendor: Some("Vendor2".to_string()),
                is_randomized: true,
                response_time_ms: Some(12),
                ttl: Some(64),
                os_guess: Some("Linux".to_string()),
                device_type: "UNKNOWN".to_string(),
                risk_score: 20,
                open_ports: vec![3389],
                discovery_method: "ARP+ICMP".to_string(),
                hostname: Some("unknown".to_string()),
                system_description: None,
                uptime_seconds: None,
                neighbors: vec![],
                vulnerabilities: vec![],
                port_warnings: vec![],
                security_grade: String::new(),
            },
        ]
    }

    fn sample_result() -> HybridInsightsResult {
        HybridInsightsResult {
            health: NetworkHealth {
                score: 72,
                status: "Good".to_string(),
                grade: 'C',
                breakdown: HealthBreakdown {
                    security: 30,
                    stability: 20,
                    compliance: 22,
                },
                insights: vec!["2 devices scanned".to_string()],
            },
            security: SecurityReport {
                recommendations: vec![Recommendation {
                    priority: Priority::High,
                    category: "Risk".to_string(),
                    title: "High risk detected".to_string(),
                    description: "Act now".to_string(),
                    affected_devices: vec!["192.168.1.10".to_string()],
                }],
                critical_count: 0,
                high_count: 1,
                total_issues: 1,
                summary: "One high priority issue".to_string(),
            },
            device_distribution: DeviceDistribution {
                by_type: std::collections::HashMap::from([
                    ("ROUTER".to_string(), 1),
                    ("UNKNOWN".to_string(), 1),
                ]),
                percentages: std::collections::HashMap::new(),
                total: 2,
                dominant_type: Some("ROUTER".to_string()),
                summary: "Summary".to_string(),
            },
            vendor_distribution: VendorDistribution {
                by_vendor: std::collections::HashMap::from([
                    ("Vendor".to_string(), 1),
                    ("Vendor2".to_string(), 1),
                ]),
                top_vendors: vec![("Vendor".to_string(), 1), ("Vendor2".to_string(), 1)],
                total: 2,
            },
            ai_overlay: None,
            ai_provider: None,
            ai_model: None,
            ai_error: None,
        }
    }

    #[test]
    fn parse_overlay_json_handles_code_fence() {
        let raw = "```json\n{\"executive_summary\":\"ok\",\"top_risks\":[\"r1\"],\"immediate_actions\":[\"a1\"],\"follow_up_actions\":[\"f1\"]}\n```";
        let parsed = parse_overlay_json(raw).expect("overlay should parse");
        assert_eq!(parsed.executive_summary, "ok");
        assert_eq!(parsed.top_risks.len(), 1);
    }

    #[test]
    fn build_digest_redacts_host_ids_for_cloud() {
        let hosts = sample_hosts();
        let base = sample_result();
        let digest = build_ai_input_digest(
            &hosts,
            &base.health,
            &base.security,
            &base.device_distribution,
            &base.vendor_distribution,
            true,
        );
        assert!(
            digest
                .high_risk_hosts
                .iter()
                .all(|h| h.id.starts_with("host_"))
        );
    }

    #[test]
    fn ai_mode_parse_accepts_aliases() {
        assert_eq!(AiMode::parse("hybrid"), Some(AiMode::HybridAuto));
        assert_eq!(AiMode::parse("auto"), Some(AiMode::HybridAuto));
        assert_eq!(AiMode::parse("local"), Some(AiMode::Local));
        assert_eq!(AiMode::parse("bad"), None);
    }
}
