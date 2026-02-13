//! Structured logging module for Network Topology Mapper
//!
//! Provides file-based logging with rotation and structured log output.
//! Logs are written to: %APPDATA%/netmapper/logs/

pub mod macros;

use std::path::PathBuf;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize the logging system
///
/// Creates log directory and sets up daily rotating log files.
/// Logs are written to: `%APPDATA%/netmapper/logs/netmapper-YYYY-MM-DD.log`
///
/// # Log Levels
/// - ERROR: Critical errors that need immediate attention
/// - WARN: Warning conditions
/// - INFO: Informational messages (default)
/// - DEBUG: Detailed information for debugging
/// - TRACE: Very detailed trace information
///
/// Set `RUST_LOG` environment variable to control log level:
/// - `RUST_LOG=debug` for debug level
/// - `RUST_LOG=trace` for trace level
pub fn init_logging() -> Result<PathBuf, Box<dyn std::error::Error>> {
    // Get log directory path
    let log_dir = get_log_directory()?;

    // Ensure log directory exists
    std::fs::create_dir_all(&log_dir)?;

    // Create file appender with daily rotation
    let file_appender = RollingFileAppender::new(Rotation::DAILY, &log_dir, "netmapper.log");

    // Create console layer (for stderr)
    let console_layer = fmt::layer()
        .with_target(false)
        .with_thread_ids(true)
        .with_line_number(true)
        .compact();

    // Create file layer
    let file_layer = fmt::layer()
        .with_writer(file_appender)
        .with_ansi(false) // No ANSI colors in file
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_file(true)
        .json(); // JSON format for easier parsing

    // Set up filter (default to INFO level unless RUST_LOG is set)
    let filter = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info"))?;

    // Initialize subscriber with both layers
    let init_result = tracing_subscriber::registry()
        .with(filter)
        .with(console_layer)
        .with(file_layer)
        .try_init();

    if let Err(e) = init_result {
        // Avoid panicking when another subsystem/test already installed a global subscriber.
        if e.to_string().contains("already been set") {
            return Ok(log_dir);
        }
        return Err(Box::new(e));
    }

    tracing::info!("Logging initialized. Log directory: {}", log_dir.display());

    Ok(log_dir)
}

/// Get log directory path
///
/// Returns: `%APPDATA%/netmapper/logs` on Windows
///          `~/.config/netmapper/logs` on Linux/macOS
fn get_log_directory() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let base_dir = if cfg!(target_os = "windows") {
        // Windows: %APPDATA%/netmapper
        dirs::data_local_dir()
            .ok_or("Could not find APPDATA directory")?
            .join("netmapper")
    } else {
        // Linux/macOS: ~/.config/netmapper
        dirs::config_dir()
            .ok_or("Could not find config directory")?
            .join("netmapper")
    };

    Ok(base_dir.join("logs"))
}

/// Get current log file path (for UI display)
pub fn get_current_log_file() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let log_dir = get_log_directory()?;
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    Ok(log_dir.join(format!("netmapper.log.{}", today)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_directory_exists() {
        let log_dir = get_log_directory().expect("Should get log directory");
        assert!(log_dir.to_string_lossy().contains("netmapper"));
        assert!(log_dir.to_string_lossy().contains("logs"));
    }
}
