//! Database module for storing scan history and device data
//!
//! Provides SQLite storage for:
//! - Scan history
//! - Device tracking
//! - Alerts

pub mod connection;
pub mod encryption;
pub mod models;
pub mod queries;
pub mod schema;
pub mod seed_cves;

pub use connection::Database;
pub use models::*;
pub use queries::*;

#[cfg(test)]
mod encryption_tests;
