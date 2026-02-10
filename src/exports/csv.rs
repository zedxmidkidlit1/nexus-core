//! CSV export functionality
//!
//! Export device lists and scan history to CSV format

use crate::database::DeviceRecord;
use crate::models::HostInfo;
use anyhow::Result;
use chrono::{DateTime, Utc};
use csv::Writer;

/// Export devices to CSV format
pub fn export_devices_csv(devices: &[DeviceRecord]) -> Result<String> {
    let mut writer = Writer::from_writer(vec![]);

    // Write header
    writer.write_record([
        "IP Address",
        "MAC Address",
        "Hostname",
        "Custom Name",
        "Vendor",
        "Device Type",
        "Operating System",
        "Risk Score",
        "First Seen",
        "Last Seen",
        "Status",
    ])?;

    // Write device records
    for device in devices {
        let status = if is_recently_seen(&device.last_seen.to_rfc3339()) {
            "Online"
        } else {
            "Offline"
        };

        writer.write_record([
            device.last_ip.as_deref().unwrap_or("N/A"),
            &device.mac,
            device.hostname.as_deref().unwrap_or("N/A"),
            device.custom_name.as_deref().unwrap_or(""),
            device.vendor.as_deref().unwrap_or("Unknown"),
            device.device_type.as_deref().unwrap_or("Unknown"),
            device.os_guess.as_deref().unwrap_or("Unknown"),
            "0", // Risk score not stored in DeviceRecord
            &device.first_seen.to_rfc3339(),
            &device.last_seen.to_rfc3339(),
            status,
        ])?;
    }

    let csv_data = String::from_utf8(writer.into_inner()?)?;
    Ok(csv_data)
}

/// Export host info list to CSV (for current scan results)
pub fn export_hosts_csv(hosts: &[HostInfo]) -> Result<String> {
    let mut writer = Writer::from_writer(vec![]);

    // Write header
    writer.write_record([
        "IP Address",
        "MAC Address",
        "Hostname",
        "Vendor",
        "Device Type",
        "Operating System",
        "Risk Score",
        "Open Ports",
        "Latency (ms)",
        "Is Randomized MAC",
    ])?;

    // Write host records
    for host in hosts {
        let open_ports = host
            .open_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(";");

        let latency = host
            .response_time_ms
            .map(|l| l.to_string())
            .unwrap_or_else(|| "N/A".to_string());

        writer.write_record([
            &host.ip,
            &host.mac,
            host.hostname.as_deref().unwrap_or("N/A"),
            host.vendor.as_deref().unwrap_or("Unknown"),
            &host.device_type,
            host.os_guess.as_deref().unwrap_or("Unknown"),
            &host.risk_score.to_string(),
            &open_ports,
            &latency,
            &host.is_randomized.to_string(),
        ])?;
    }

    let csv_data = String::from_utf8(writer.into_inner()?)?;
    Ok(csv_data)
}

/// Helper: Check if device was seen recently (within last hour)
fn is_recently_seen(last_seen: &str) -> bool {
    if let Ok(dt) = DateTime::parse_from_rfc3339(last_seen) {
        let utc_dt: DateTime<Utc> = dt.into();
        let now = Utc::now();
        let duration = now.signed_duration_since(utc_dt);
        duration.num_hours() < 1
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_hosts_csv() {
        let hosts = vec![HostInfo {
            ip: "192.168.1.1".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            hostname: Some("router".to_string()),
            vendor: Some("TP-Link".to_string()),
            device_type: "Router".to_string(),
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
        }];

        let csv = export_hosts_csv(&hosts).unwrap();
        assert!(csv.contains("192.168.1.1"));
        assert!(csv.contains("router"));
        assert!(csv.contains("TP-Link"));
    }
}
