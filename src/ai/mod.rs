//! Dedicated AI integration module.

pub mod config;
mod prompt;
mod provider;
mod providers;
mod redaction;
mod router;
pub mod types;

pub use config::AiSettings;
pub use router::generate_hybrid_insights;
pub use types::{AiInsightOverlay, AiMode, HybridInsightsResult};
