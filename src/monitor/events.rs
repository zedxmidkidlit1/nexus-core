//! Network monitoring events
//!
//! Event types for real-time UI updates

use serde::{Deserialize, Serialize};

/// Network monitoring events emitted to frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum NetworkEvent {
    /// Monitoring session started
    MonitoringStarted { interval_seconds: u64 },

    /// Monitoring session stopped
    MonitoringStopped,

    /// Scan cycle started
    ScanStarted { scan_number: u32 },

    /// Scan progress update
    ScanProgress {
        phase: String,
        percent: u8,
        message: String,
    },

    /// Scan cycle completed
    ScanCompleted {
        scan_number: u32,
        hosts_found: usize,
        duration_ms: u64,
    },

    /// New device discovered on network
    NewDeviceDiscovered {
        ip: String,
        mac: String,
        hostname: Option<String>,
        device_type: String,
    },

    /// Device went offline
    DeviceWentOffline {
        mac: String,
        last_ip: String,
        hostname: Option<String>,
    },

    /// Device came back online  
    DeviceCameOnline {
        mac: String,
        ip: String,
        hostname: Option<String>,
    },

    /// Device IP address changed
    DeviceIpChanged {
        mac: String,
        old_ip: String,
        new_ip: String,
    },

    /// Error during monitoring
    MonitoringError { message: String },
}

/// Monitoring status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringStatus {
    pub is_running: bool,
    pub interval_seconds: u64,
    pub scan_count: u32,
    pub last_scan_time: Option<String>,
    pub devices_online: usize,
    pub devices_total: usize,
}

impl Default for MonitoringStatus {
    fn default() -> Self {
        Self {
            is_running: false,
            interval_seconds: 60,
            scan_count: 0,
            last_scan_time: None,
            devices_online: 0,
            devices_total: 0,
        }
    }
}

/// Simple device info for events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSnapshot {
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub device_type: String,
    pub is_online: bool,
}
