//! Real-time network monitoring module
//!
//! Provides background scanning and live event emission

pub mod events;
pub mod passive_integration;
pub mod watcher;

pub use events::*;
pub use passive_integration::*;
pub use watcher::*;
