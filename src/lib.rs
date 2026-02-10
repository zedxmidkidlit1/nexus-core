//! NEXUS Core Engine — Network Discovery, Security Analysis & Health Monitoring
//!
//! This crate provides network scanning capabilities:
//! - Active ARP scanning for Layer 2 discovery
//! - ICMP ping for latency measurement
//! - TCP port probing for service detection
//! - SNMP enrichment for device details (optional)
//! - SQLite database for historical data storage
//! - Real-time network monitoring
//! - Alert detection and notifications
//! - AI-powered network insights

pub mod alerts;
pub mod config;
pub mod database;
pub mod exports;
pub mod insights;
pub mod logging;
pub mod models;
pub mod monitor;
pub mod network;
pub mod scanner;

pub use alerts::{detect_alerts, detect_alerts_without_baseline, has_high_priority_alerts, Alert};
pub use config::*;
pub use database::{
    AlertRecord, AlertSeverity, AlertType, Database, DeviceRecord, NetworkStats, ScanRecord,
};
pub use exports::{
    export_devices_csv, export_hosts_csv, export_scan_result_json, export_topology_json,
    generate_network_health_pdf, generate_scan_report_pdf,
};
pub use insights::{
    DeviceDistribution, NetworkHealth, Recommendation, SecurityReport, VendorDistribution,
};
pub use models::*;
pub use monitor::{BackgroundMonitor, MonitoringStatus, NetworkEvent};
pub use network::{
    calculate_risk_score, calculate_subnet_ips, dns_scan, find_valid_interface, infer_device_type,
    is_local_subnet, is_special_address, list_valid_interfaces, lookup_vendor, lookup_vendor_info,
    DeviceType,
};
pub use scanner::{
    active_arp_scan, guess_os_from_ttl, icmp_scan, snmp_enrich, tcp_probe_scan, IcmpResult,
    SnmpData, SnmpNeighbor,
};

// Re-export logging macros for use across crate
pub use crate::logging::macros;
