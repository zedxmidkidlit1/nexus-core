//! JSON export functionality
//!
//! Export scan results and topology data to JSON format

use crate::models::{HostInfo, ScanResult};
use anyhow::Result;
use serde::Serialize;
use serde_json;

/// Topology export format
#[derive(Debug, Serialize)]
pub struct TopologyExport {
    pub export_date: String,
    pub network: String,
    pub total_devices: usize,
    pub devices: Vec<DeviceNode>,
    pub connections: Vec<Connection>,
}

/// Device node for topology
#[derive(Debug, Serialize)]
pub struct DeviceNode {
    pub id: String, // MAC address
    pub ip: String,
    pub mac: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub device_type: String,
    pub os: Option<String>,
    pub risk_score: u8,
    pub open_ports: Vec<u16>,
    pub is_randomized: bool,
}

/// Connection between devices
#[derive(Debug, Serialize)]
pub struct Connection {
    pub source: String, // MAC address
    pub target: String, // MAC address
    pub connection_type: String,
}

fn is_router(device_type: &str) -> bool {
    device_type.eq_ignore_ascii_case("ROUTER") || device_type.eq_ignore_ascii_case("Router")
}

/// Export topology data to JSON
pub fn export_topology_json(hosts: &[HostInfo], network: &str) -> Result<String> {
    let devices: Vec<DeviceNode> = hosts
        .iter()
        .map(|h| DeviceNode {
            id: h.mac.clone(),
            ip: h.ip.clone(),
            mac: h.mac.clone(),
            hostname: h.hostname.clone(),
            vendor: h.vendor.clone(),
            device_type: h.device_type.clone(),
            os: h.os_guess.clone(),
            risk_score: h.risk_score,
            open_ports: h.open_ports.clone(),
            is_randomized: h.is_randomized,
        })
        .collect();

    // Infer connections (router to all devices)
    let router = hosts.iter().find(|h| is_router(&h.device_type));
    let connections: Vec<Connection> = if let Some(router_device) = router {
        hosts
            .iter()
            .filter(|h| h.mac != router_device.mac)
            .map(|h| Connection {
                source: router_device.mac.clone(),
                target: h.mac.clone(),
                connection_type: "ethernet".to_string(),
            })
            .collect()
    } else {
        vec![]
    };

    let export = TopologyExport {
        export_date: chrono::Utc::now().to_rfc3339(),
        network: network.to_string(),
        total_devices: devices.len(),
        devices,
        connections,
    };

    let json = serde_json::to_string_pretty(&export)?;
    Ok(json)
}

/// Export full scan result to JSON
pub fn export_scan_result_json(scan: &ScanResult) -> Result<String> {
    let json = serde_json::to_string_pretty(scan)?;
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_topology_json() {
        let hosts = vec![
            HostInfo {
                ip: "192.168.1.1".to_string(),
                mac: "aa:bb:cc:dd:ee:ff".to_string(),
                hostname: Some("router".to_string()),
                vendor: Some("TP-Link".to_string()),
                device_type: "ROUTER".to_string(),
                os_guess: Some("Linux".to_string()),
                risk_score: 15,
                open_ports: vec![80, 443],
                response_time_ms: Some(5),
                is_randomized: false,
                ttl: Some(64),
                discovery_method: "ARP+ICMP+TCP".to_string(),
                system_description: None,
                uptime_seconds: None,
                neighbors: vec![],
                vulnerabilities: vec![],
                port_warnings: vec![],
                security_grade: String::new(),
            },
            HostInfo {
                ip: "192.168.1.10".to_string(),
                mac: "11:22:33:44:55:66".to_string(),
                hostname: Some("laptop".to_string()),
                vendor: Some("Apple".to_string()),
                device_type: "PC".to_string(),
                os_guess: Some("macOS".to_string()),
                risk_score: 5,
                open_ports: vec![],
                response_time_ms: Some(2),
                is_randomized: false,
                ttl: Some(64),
                discovery_method: "ARP+ICMP".to_string(),
                system_description: None,
                uptime_seconds: None,
                neighbors: vec![],
                vulnerabilities: vec![],
                port_warnings: vec![],
                security_grade: String::new(),
            },
        ];

        let json = export_topology_json(&hosts, "192.168.1.0/24").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let connection_count = parsed["connections"]
            .as_array()
            .map(|v| v.len())
            .unwrap_or(0);

        assert!(json.contains("192.168.1.1"));
        assert!(json.contains("router"));
        assert!(json.contains("connections"));
        assert!(connection_count > 0);
    }
}
