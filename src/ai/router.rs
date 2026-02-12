use reqwest::Client;

use crate::{DeviceDistribution, HostInfo, NetworkHealth, SecurityReport, VendorDistribution};

use crate::ai::config::AiSettings;
use crate::ai::provider::AiProvider;
use crate::ai::providers::{gemini::GeminiProvider, ollama::OllamaProvider};
use crate::ai::redaction::build_ai_input_digest;
use crate::ai::types::{AiMode, HybridInsightsResult};

pub async fn generate_hybrid_insights(hosts: &[HostInfo]) -> HybridInsightsResult {
    let mut result = build_base_result(hosts);

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
            match build_gemini_provider(&settings) {
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
                match build_gemini_provider(&settings) {
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
