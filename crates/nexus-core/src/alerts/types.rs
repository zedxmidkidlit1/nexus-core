//! Alert types for network monitoring
//!
//! Defines alert categories and severity levels

use serde::{Deserialize, Serialize};

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl AlertSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertSeverity::Low => "LOW",
            AlertSeverity::Medium => "MEDIUM",
            AlertSeverity::High => "HIGH",
            AlertSeverity::Critical => "CRITICAL",
        }
    }
}

/// Types of alerts that can be generated
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertType {
    /// New device discovered on network
    NewDeviceDiscovered,
    /// Known device went offline
    DeviceWentOffline,
    /// Device came back online
    DeviceCameOnline,
    /// High risk device detected
    HighRiskDetected,
    /// Unusual/suspicious port detected
    UnusualPort,
    /// Device IP address changed
    IpChanged,
}

impl AlertType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertType::NewDeviceDiscovered => "NEW_DEVICE",
            AlertType::DeviceWentOffline => "DEVICE_OFFLINE",
            AlertType::DeviceCameOnline => "DEVICE_ONLINE",
            AlertType::HighRiskDetected => "HIGH_RISK",
            AlertType::UnusualPort => "UNUSUAL_PORT",
            AlertType::IpChanged => "IP_CHANGED",
        }
    }

    pub fn severity(&self) -> AlertSeverity {
        match self {
            AlertType::NewDeviceDiscovered => AlertSeverity::Medium,
            AlertType::DeviceWentOffline => AlertSeverity::Low,
            AlertType::DeviceCameOnline => AlertSeverity::Low,
            AlertType::HighRiskDetected => AlertSeverity::High,
            AlertType::UnusualPort => AlertSeverity::High,
            AlertType::IpChanged => AlertSeverity::Low,
        }
    }
}

/// A generated alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub alert_type: AlertType,
    pub device_mac: Option<String>,
    pub device_ip: Option<String>,
    pub message: String,
    pub severity: AlertSeverity,
}

impl Alert {
    pub fn new(alert_type: AlertType, message: impl Into<String>) -> Self {
        let severity = alert_type.severity();
        Self {
            alert_type,
            device_mac: None,
            device_ip: None,
            message: message.into(),
            severity,
        }
    }

    pub fn with_device(mut self, mac: impl Into<String>, ip: impl Into<String>) -> Self {
        self.device_mac = Some(mac.into());
        self.device_ip = Some(ip.into());
        self
    }

    pub fn with_severity(mut self, severity: AlertSeverity) -> Self {
        self.severity = severity;
        self
    }
}

/// Suspicious ports that should trigger alerts
pub const SUSPICIOUS_PORTS: &[u16] = &[
    23,    // Telnet (insecure)
    21,    // FTP (insecure)
    3389,  // RDP (potential attack vector)
    5900,  // VNC (potential attack vector)
    8080,  // Alternate HTTP
    8443,  // Alternate HTTPS
    1433,  // MSSQL
    3306,  // MySQL
    5432,  // PostgreSQL
    27017, // MongoDB
];

/// High risk threshold
pub const HIGH_RISK_THRESHOLD: u32 = 50;
