//! AI Insights module
//!
//! Rule-based network analysis and recommendations

pub mod distribution;
pub mod health;
pub mod recommendations;
pub mod security;
pub mod vulnerability_filter;

pub use crate::ai::{
    AiCheckReport, AiInsightOverlay, AiMode, AiProviderCheck, AiSettings, HybridInsightsResult,
    generate_hybrid_insights, run_ai_check,
};
pub use distribution::*;
pub use health::*;
pub use recommendations::*;
pub use security::*;
pub use vulnerability_filter::*;
