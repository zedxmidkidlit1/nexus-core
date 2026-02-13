use anyhow::{Context, Result};

use crate::ai::types::AiInputDigest;

pub(crate) fn build_prompt(input: &AiInputDigest) -> Result<String> {
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
