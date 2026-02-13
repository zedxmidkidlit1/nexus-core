use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use std::future::Future;
use std::pin::Pin;

use crate::ai::types::{AiInputDigest, AiInsightOverlay};

pub(crate) trait AiProvider: Send + Sync {
    fn provider_id(&self) -> &'static str;
    fn model_name(&self) -> &str;
    fn generate_overlay<'a>(
        &'a self,
        client: &'a Client,
        input: &'a AiInputDigest,
    ) -> Pin<Box<dyn Future<Output = Result<AiInsightOverlay>> + Send + 'a>>;
}

pub(crate) fn parse_overlay_json(raw: &str) -> Result<AiInsightOverlay> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_overlay_json_handles_code_fence() {
        let raw = "```json\n{\"executive_summary\":\"ok\",\"top_risks\":[\"r1\"],\"immediate_actions\":[\"a1\"],\"follow_up_actions\":[\"f1\"]}\n```";
        let parsed = parse_overlay_json(raw).expect("overlay should parse");
        assert_eq!(parsed.executive_summary, "ok");
        assert_eq!(parsed.top_risks.len(), 1);
    }
}
