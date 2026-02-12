use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::ai::types::AiMode;

const DEFAULT_AI_TIMEOUT_MS: u64 = 8000;
const DEFAULT_OLLAMA_ENDPOINT: &str = "http://127.0.0.1:11434";
const DEFAULT_OLLAMA_MODEL: &str = "qwen3:8b";
const DEFAULT_GEMINI_ENDPOINT: &str = "https://generativelanguage.googleapis.com";
const DEFAULT_GEMINI_MODEL: &str = "gemini-2.5-flash";

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

    pub(crate) fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
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
