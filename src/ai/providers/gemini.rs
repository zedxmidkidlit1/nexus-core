use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde_json::json;
use std::future::Future;
use std::pin::Pin;

use crate::ai::prompt::build_prompt;
use crate::ai::provider::{AiProvider, parse_overlay_json};
use crate::ai::types::{AiInputDigest, AiInsightOverlay};

#[derive(Debug, Clone)]
pub struct GeminiProvider {
    endpoint: String,
    model: String,
    api_key: String,
}

impl GeminiProvider {
    pub fn new(endpoint: String, model: String, api_key: String) -> Self {
        Self {
            endpoint,
            model,
            api_key,
        }
    }
}

impl AiProvider for GeminiProvider {
    fn provider_id(&self) -> &'static str {
        "gemini"
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
            let url = format!(
                "{}/v1beta/models/{}:generateContent?key={}",
                endpoint, self.model, self.api_key
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
                .ok_or_else(|| {
                    anyhow!("Gemini response missing candidates[0].content.parts[0].text")
                })?;

            parse_overlay_json(text)
        })
    }
}
