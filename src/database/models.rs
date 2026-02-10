//! Database models
//!
//! Structs for database records with serialization support

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Scan record from database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: i64,
    pub scan_time: DateTime<Utc>,
    pub interface_name: String,
    pub local_ip: String,
    pub local_mac: String,
    pub subnet: String,
    pub scan_method: String,
    pub arp_discovered: i32,
    pub icmp_discovered: i32,
    pub total_hosts: i32,
    pub duration_ms: i64,
}

/// Device record from database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: i64,
    pub mac: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub last_ip: Option<String>,
    pub vendor: Option<String>,
    pub device_type: Option<String>,
    pub hostname: Option<String>,
    pub os_guess: Option<String>,
    pub custom_name: Option<String>,
    pub notes: Option<String>,
    pub security_grade: Option<String>,
}

/// Device history entry (per-scan snapshot)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceHistoryRecord {
    pub id: i64,
    pub scan_id: i64,
    pub device_id: i64,
    pub ip: String,
    pub response_time_ms: Option<i64>,
    pub ttl: Option<i32>,
    pub risk_score: i32,
    pub is_online: bool,
    pub discovery_method: Option<String>,
    pub open_ports: Vec<u16>,
}

/// Alert record from database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub alert_type: AlertType,
    pub device_id: Option<i64>,
    pub device_mac: Option<String>,
    pub device_ip: Option<String>,
    pub message: String,
    pub severity: AlertSeverity,
    pub is_read: bool,
}

/// Alert types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AlertType {
    NewDevice,
    DeviceOffline,
    DeviceOnline,
    HighRisk,
    PortChange,
    IpChange,
    Custom,
}

impl std::fmt::Display for AlertType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertType::NewDevice => write!(f, "new_device"),
            AlertType::DeviceOffline => write!(f, "device_offline"),
            AlertType::DeviceOnline => write!(f, "device_online"),
            AlertType::HighRisk => write!(f, "high_risk"),
            AlertType::PortChange => write!(f, "port_change"),
            AlertType::IpChange => write!(f, "ip_change"),
            AlertType::Custom => write!(f, "custom"),
        }
    }
}

impl std::str::FromStr for AlertType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "new_device" => Ok(AlertType::NewDevice),
            "device_offline" => Ok(AlertType::DeviceOffline),
            "device_online" => Ok(AlertType::DeviceOnline),
            "high_risk" => Ok(AlertType::HighRisk),
            "port_change" => Ok(AlertType::PortChange),
            "ip_change" => Ok(AlertType::IpChange),
            "custom" => Ok(AlertType::Custom),
            _ => Err(format!("Unknown alert type: {}", s)),
        }
    }
}

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Info => write!(f, "info"),
            AlertSeverity::Warning => write!(f, "warning"),
            AlertSeverity::Error => write!(f, "error"),
            AlertSeverity::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for AlertSeverity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "info" => Ok(AlertSeverity::Info),
            "warning" => Ok(AlertSeverity::Warning),
            "error" => Ok(AlertSeverity::Error),
            "critical" => Ok(AlertSeverity::Critical),
            _ => Err(format!("Unknown severity: {}", s)),
        }
    }
}

/// Summary statistics for dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub total_devices: i64,
    pub online_devices: i64,
    pub offline_devices: i64,
    pub new_devices_24h: i64,
    pub high_risk_devices: i64,
    pub total_scans: i64,
    pub last_scan_time: Option<DateTime<Utc>>,
}
