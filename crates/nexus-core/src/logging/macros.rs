//! Common logging macros for Network Topology Mapper
//!
//! Provides convenient macros for structured logging throughout the codebase.

/// Log an informational message
///
/// Replacement for `eprintln!` with structured logging support.
/// Uses tracing's info! macro internally.
#[macro_export]
macro_rules! log_stderr {
    ($($arg:tt)*) => {
        tracing::info!($($arg)*);
    };
}

/// Log a debug message
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        tracing::debug!($($arg)*);
    };
}

/// Log a warning message
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        tracing::warn!($($arg)*);
    };
}

/// Log an error message
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        tracing::error!($($arg)*);
    };
}
