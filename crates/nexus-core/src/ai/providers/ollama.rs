use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde_json::json;
use std::future::Future;
use std::pin::Pin;

use crate::ai::prompt::build_prompt;
use crate::ai::provider::{AiProvider, parse_overlay_json};
use crate::ai::types::{AiInputDigest, AiInsightOverlay};

#[derive(Debug, Clone)]
pub struct OllamaProvider {
    endpoint: String,
    model: String,
}

impl OllamaProvider {
    pub fn new(endpoint: String, model: String) -> Self {
        Self { endpoint, model }
    }
}

impl AiProvider for OllamaProvider {
    fn provider_id(&self) -> &'static str {
        "ollama"
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    fn generate_overlay<'a>(
        &'a self,
        client: &'a Client,
        input: &'a AiInputDigest,
    ) -> Pin<Box<dyn Future<Output = Result<AiInsightOverlay>> + Send + 'a>> {
        Box::pin(async move {
            let prompt = build_prompt(input)?;
            let endpoint = self.endpoint.trim_end_matches('/');
            let url = format!("{}/api/generate", endpoint);

            let response = client
                .post(url)
                .json(&json!({
                    "model": self.model,
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
        })
    }
}
