use reqwest::Client;
use std::time::Instant;

use crate::{DeviceDistribution, HostInfo, NetworkHealth, SecurityReport, VendorDistribution};

use crate::ai::config::AiSettings;
use crate::ai::provider::AiProvider;
use crate::ai::providers::{gemini::GeminiProvider, ollama::OllamaProvider};
use crate::ai::redaction::build_ai_input_digest;
use crate::ai::types::{AiCheckReport, AiMode, AiProviderCheck, HybridInsightsResult};

pub async fn generate_hybrid_insights(hosts: &[HostInfo]) -> HybridInsightsResult {
    let settings = AiSettings::from_env();
    generate_hybrid_insights_with_settings(hosts, &settings).await
}

pub(crate) async fn generate_hybrid_insights_with_settings(
    hosts: &[HostInfo],
    settings: &AiSettings,
) -> HybridInsightsResult {
    let mut result = build_base_result(hosts);

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

    let local_provider = OllamaProvider::new(
        settings.ollama_endpoint.clone(),
        settings.ollama_model.clone(),
    );

    match settings.mode {
        AiMode::Local => {
            apply_provider_result(&mut result, &local_provider, &client, &local_input).await;
        }
        AiMode::Cloud => {
            let cloud_input = build_ai_input_digest(
                hosts,
                &result.health,
                &result.security,
                &result.device_distribution,
                &result.vendor_distribution,
                !settings.cloud_allow_sensitive,
            );
            match build_gemini_provider(settings) {
                Ok(cloud_provider) => {
                    apply_provider_result(&mut result, &cloud_provider, &client, &cloud_input).await
                }
                Err(e) => result.ai_error = Some(format!("Cloud AI failed: {}", e)),
            }
        }
        AiMode::HybridAuto => match local_provider.generate_overlay(&client, &local_input).await {
            Ok(overlay) => {
                result.ai_overlay = Some(overlay);
                result.ai_provider = Some(local_provider.provider_id().to_string());
                result.ai_model = Some(local_provider.model_name().to_string());
            }
            Err(local_err) => {
                tracing::warn!(
                    "Local AI failed in hybrid mode, trying cloud: {}",
                    local_err
                );
                let cloud_input = build_ai_input_digest(
                    hosts,
                    &result.health,
                    &result.security,
                    &result.device_distribution,
                    &result.vendor_distribution,
                    !settings.cloud_allow_sensitive,
                );
                match build_gemini_provider(settings) {
                    Ok(cloud_provider) => {
                        match cloud_provider.generate_overlay(&client, &cloud_input).await {
                            Ok(overlay) => {
                                result.ai_overlay = Some(overlay);
                                result.ai_provider = Some(cloud_provider.provider_id().to_string());
                                result.ai_model = Some(cloud_provider.model_name().to_string());
                            }
                            Err(cloud_err) => {
                                result.ai_error = Some(format!(
                                    "Hybrid AI failed. local={}, cloud={}",
                                    local_err, cloud_err
                                ));
                            }
                        }
                    }
                    Err(cloud_cfg_err) => {
                        result.ai_error = Some(format!(
                            "Hybrid AI failed. local={}, cloud-config={}",
                            local_err, cloud_cfg_err
                        ));
                    }
                }
            }
        },
        AiMode::Disabled => {}
    }

    result
}

pub async fn run_ai_check() -> AiCheckReport {
    let settings = AiSettings::from_env();
    run_ai_check_with_settings(&settings).await
}

pub(crate) async fn run_ai_check_with_settings(settings: &AiSettings) -> AiCheckReport {
    let mut report = AiCheckReport {
        ai_enabled: settings.enabled,
        mode: settings.mode,
        timeout_ms: settings.timeout_ms,
        local: None,
        cloud: None,
        overall_ok: !settings.enabled || settings.mode == AiMode::Disabled,
    };

    let client = match Client::builder().timeout(settings.timeout()).build() {
        Ok(c) => c,
        Err(e) => {
            let err = Some(format!("AI client init failed: {}", e));
            match settings.mode {
                AiMode::Local => {
                    report.local = Some(AiProviderCheck {
                        provider: "ollama".to_string(),
                        configured: settings.enabled,
                        reachable: false,
                        model: Some(settings.ollama_model.clone()),
                        model_available: None,
                        latency_ms: None,
                        error: err.clone(),
                    });
                }
                AiMode::Cloud => {
                    report.cloud = Some(AiProviderCheck {
                        provider: "gemini".to_string(),
                        configured: settings.gemini_api_key.is_some(),
                        reachable: false,
                        model: Some(settings.gemini_model.clone()),
                        model_available: None,
                        latency_ms: None,
                        error: err.clone(),
                    });
                }
                AiMode::HybridAuto => {
                    report.local = Some(AiProviderCheck {
                        provider: "ollama".to_string(),
                        configured: settings.enabled,
                        reachable: false,
                        model: Some(settings.ollama_model.clone()),
                        model_available: None,
                        latency_ms: None,
                        error: err.clone(),
                    });
                    report.cloud = Some(AiProviderCheck {
                        provider: "gemini".to_string(),
                        configured: settings.gemini_api_key.is_some(),
                        reachable: false,
                        model: Some(settings.gemini_model.clone()),
                        model_available: None,
                        latency_ms: None,
                        error: err,
                    });
                }
                AiMode::Disabled => {}
            }
            return report;
        }
    };

    match settings.mode {
        AiMode::Disabled => {}
        AiMode::Local => {
            report.local = Some(check_ollama(&client, settings).await);
        }
        AiMode::Cloud => {
            report.cloud = Some(check_gemini(&client, settings).await);
        }
        AiMode::HybridAuto => {
            report.local = Some(check_ollama(&client, settings).await);
            report.cloud = Some(check_gemini(&client, settings).await);
        }
    }

    report.overall_ok = match settings.mode {
        AiMode::Disabled => true,
        AiMode::Local => report
            .local
            .as_ref()
            .is_some_and(|c| c.reachable && c.model_available.unwrap_or(false)),
        AiMode::Cloud => report
            .cloud
            .as_ref()
            .is_some_and(|c| c.reachable && c.model_available.unwrap_or(false)),
        AiMode::HybridAuto => {
            let local_ok = report
                .local
                .as_ref()
                .is_some_and(|c| c.reachable && c.model_available.unwrap_or(false));
            let cloud_ok = report
                .cloud
                .as_ref()
                .is_some_and(|c| c.reachable && c.model_available.unwrap_or(false));
            local_ok || cloud_ok
        }
    };

    report
}

async fn check_ollama(client: &Client, settings: &AiSettings) -> AiProviderCheck {
    let start = Instant::now();
    let endpoint = settings.ollama_endpoint.trim_end_matches('/');
    let url = format!("{}/api/tags", endpoint);

    let mut out = AiProviderCheck {
        provider: "ollama".to_string(),
        configured: settings.enabled,
        reachable: false,
        model: Some(settings.ollama_model.clone()),
        model_available: None,
        latency_ms: None,
        error: None,
    };

    match client.get(url).send().await {
        Ok(resp) => {
            out.latency_ms = Some(start.elapsed().as_millis() as u64);
            let status = resp.status();
            if !status.is_success() {
                out.error = Some(format!("Ollama tags request failed with {}", status));
                return out;
            }
            out.reachable = true;
            match resp.json::<serde_json::Value>().await {
                Ok(payload) => {
                    let available = payload
                        .get("models")
                        .and_then(|v| v.as_array())
                        .map(|models| {
                            models.iter().any(|m| {
                                m.get("name").and_then(|v| v.as_str()).is_some_and(|name| {
                                    model_name_matches(&settings.ollama_model, name)
                                })
                            })
                        })
                        .unwrap_or(false);
                    out.model_available = Some(available);
                    if !available {
                        out.error = Some(format!(
                            "Configured model '{}' not found in Ollama local tags",
                            settings.ollama_model
                        ));
                    }
                }
                Err(e) => {
                    out.error = Some(format!("Failed to parse Ollama tags response: {}", e));
                }
            }
        }
        Err(e) => {
            out.error = Some(format!("Failed to reach Ollama endpoint: {}", e));
        }
    }

    out
}

async fn check_gemini(client: &Client, settings: &AiSettings) -> AiProviderCheck {
    let start = Instant::now();
    let mut out = AiProviderCheck {
        provider: "gemini".to_string(),
        configured: settings.gemini_api_key.is_some(),
        reachable: false,
        model: Some(settings.gemini_model.clone()),
        model_available: None,
        latency_ms: None,
        error: None,
    };

    let api_key = match settings.gemini_api_key.as_ref() {
        Some(k) => k,
        None => {
            out.error = Some("NEXUS_AI_GEMINI_API_KEY is not configured".to_string());
            return out;
        }
    };

    let endpoint = settings.gemini_endpoint.trim_end_matches('/');
    let url = format!("{}/v1beta/models?key={}", endpoint, api_key);

    match client.get(url).send().await {
        Ok(resp) => {
            out.latency_ms = Some(start.elapsed().as_millis() as u64);
            let status = resp.status();
            if !status.is_success() {
                out.error = Some(format!("Gemini models request failed with {}", status));
                return out;
            }
            out.reachable = true;
            match resp.json::<serde_json::Value>().await {
                Ok(payload) => {
                    let available = payload
                        .get("models")
                        .and_then(|v| v.as_array())
                        .map(|models| {
                            models.iter().any(|m| {
                                m.get("name").and_then(|v| v.as_str()).is_some_and(|name| {
                                    model_name_matches(&settings.gemini_model, name)
                                })
                            })
                        })
                        .unwrap_or(false);
                    out.model_available = Some(available);
                    if !available {
                        out.error = Some(format!(
                            "Configured model '{}' not listed by Gemini models API",
                            settings.gemini_model
                        ));
                    }
                }
                Err(e) => {
                    out.error = Some(format!("Failed to parse Gemini models response: {}", e));
                }
            }
        }
        Err(e) => {
            out.error = Some(format!("Failed to reach Gemini endpoint: {}", e));
        }
    }

    out
}

fn model_name_matches(configured: &str, available: &str) -> bool {
    available == configured
        || available.ends_with(configured)
        || available
            .strip_prefix("models/")
            .is_some_and(|name| name == configured)
}

async fn apply_provider_result<P: AiProvider>(
    result: &mut HybridInsightsResult,
    provider: &P,
    client: &Client,
    input: &crate::ai::types::AiInputDigest,
) {
    match provider.generate_overlay(client, input).await {
        Ok(overlay) => {
            result.ai_overlay = Some(overlay);
            result.ai_provider = Some(provider.provider_id().to_string());
            result.ai_model = Some(provider.model_name().to_string());
        }
        Err(e) => {
            let label = provider.provider_id();
            let capitalized = match label {
                "ollama" => "Local",
                "gemini" => "Cloud",
                _ => "AI",
            };
            result.ai_error = Some(format!("{} AI failed: {}", capitalized, e));
        }
    }
}

fn build_gemini_provider(settings: &AiSettings) -> anyhow::Result<GeminiProvider> {
    let api_key = settings.gemini_api_key.clone().ok_or_else(|| {
        anyhow::anyhow!("NEXUS_AI_GEMINI_API_KEY is required for cloud/hybrid cloud fallback")
    })?;

    Ok(GeminiProvider::new(
        settings.gemini_endpoint.clone(),
        settings.gemini_model.clone(),
        api_key,
    ))
}

fn build_base_result(hosts: &[HostInfo]) -> HybridInsightsResult {
    let health = NetworkHealth::calculate(hosts);
    let security = SecurityReport::generate(hosts);
    let device_distribution = DeviceDistribution::calculate(hosts);
    let vendor_distribution = VendorDistribution::calculate(hosts);

    HybridInsightsResult {
        health,
        security,
        device_distribution,
        vendor_distribution,
        ai_overlay: None,
        ai_provider: None,
        ai_model: None,
        ai_error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::Method::{GET, POST};
    use httpmock::MockServer;
    use serde_json::json;

    fn sample_hosts() -> Vec<HostInfo> {
        let mut host = HostInfo::new(
            "192.168.1.10".to_string(),
            "AA:BB:CC:DD:EE:10".to_string(),
            "UNKNOWN".to_string(),
            "ARP".to_string(),
        );
        host.risk_score = 55;
        host.open_ports = vec![23];
        vec![host]
    }

    fn test_settings() -> AiSettings {
        AiSettings {
            enabled: true,
            mode: AiMode::Local,
            timeout_ms: 3_000,
            ollama_endpoint: "http://127.0.0.1:1".to_string(),
            ollama_model: "qwen3:8b".to_string(),
            gemini_endpoint: "http://127.0.0.1:1".to_string(),
            gemini_model: "gemini-test".to_string(),
            gemini_api_key: None,
            cloud_allow_sensitive: false,
        }
    }

    #[tokio::test]
    async fn local_mode_uses_ollama_provider_successfully() {
        let ollama = MockServer::start();
        ollama.mock(|when, then| {
            when.method(POST).path("/api/generate");
            then.status(200).json_body(json!({
                "response": "{\"executive_summary\":\"Local summary\",\"top_risks\":[\"r1\"],\"immediate_actions\":[\"a1\"],\"follow_up_actions\":[\"f1\"]}"
            }));
        });

        let mut settings = test_settings();
        settings.mode = AiMode::Local;
        settings.ollama_endpoint = ollama.base_url();

        let result = generate_hybrid_insights_with_settings(&sample_hosts(), &settings).await;
        assert_eq!(result.ai_provider.as_deref(), Some("ollama"));
        assert_eq!(result.ai_model.as_deref(), Some("qwen3:8b"));
        assert!(result.ai_overlay.is_some());
        assert!(result.ai_error.is_none());
    }

    #[tokio::test]
    async fn hybrid_mode_falls_back_to_gemini_when_local_fails() {
        let ollama = MockServer::start();
        ollama.mock(|when, then| {
            when.method(POST).path("/api/generate");
            then.status(500).body("local failure");
        });

        let gemini = MockServer::start();
        gemini.mock(|when, then| {
            when.method(POST)
                .path("/v1beta/models/gemini-test:generateContent");
            then.status(200).json_body(json!({
                "candidates": [{
                    "content": {
                        "parts": [{
                            "text": "{\"executive_summary\":\"Cloud summary\",\"top_risks\":[\"r1\"],\"immediate_actions\":[\"a1\"],\"follow_up_actions\":[\"f1\"]}"
                        }]
                    }
                }]
            }));
        });

        let mut settings = test_settings();
        settings.mode = AiMode::HybridAuto;
        settings.ollama_endpoint = ollama.base_url();
        settings.gemini_endpoint = gemini.base_url();
        settings.gemini_api_key = Some("test-key".to_string());

        let result = generate_hybrid_insights_with_settings(&sample_hosts(), &settings).await;
        assert_eq!(result.ai_provider.as_deref(), Some("gemini"));
        assert_eq!(result.ai_model.as_deref(), Some("gemini-test"));
        assert!(result.ai_overlay.is_some());
        assert!(result.ai_error.is_none());
    }

    #[tokio::test]
    async fn ai_check_local_reports_missing_model() {
        let ollama = MockServer::start();
        ollama.mock(|when, then| {
            when.method(GET).path("/api/tags");
            then.status(200)
                .json_body(json!({ "models": [{ "name": "other:1b" }] }));
        });

        let mut settings = test_settings();
        settings.mode = AiMode::Local;
        settings.ollama_endpoint = ollama.base_url();
        settings.ollama_model = "qwen3:8b".to_string();

        let report = run_ai_check_with_settings(&settings).await;
        assert!(!report.overall_ok);
        let local = report.local.expect("local report should exist");
        assert!(local.reachable);
        assert_eq!(local.model_available, Some(false));
        assert!(local.error.unwrap_or_default().contains("not found"));
    }

    #[tokio::test]
    async fn ai_check_hybrid_succeeds_if_cloud_available() {
        let gemini = MockServer::start();
        gemini.mock(|when, then| {
            when.method(GET).path("/v1beta/models");
            then.status(200)
                .json_body(json!({ "models": [{ "name": "models/gemini-test" }] }));
        });

        let mut settings = test_settings();
        settings.mode = AiMode::HybridAuto;
        settings.ollama_endpoint = "http://127.0.0.1:9".to_string();
        settings.gemini_endpoint = gemini.base_url();
        settings.gemini_api_key = Some("test-key".to_string());

        let report = run_ai_check_with_settings(&settings).await;
        assert!(report.overall_ok);
        let local = report.local.expect("local report should exist");
        assert!(!local.reachable);
        let cloud = report.cloud.expect("cloud report should exist");
        assert!(cloud.reachable);
        assert_eq!(cloud.model_available, Some(true));
    }
}
