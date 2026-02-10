//! Alert detection logic
//!
//! Compares scan results to detect changes and generate alerts

use std::collections::HashMap;

use super::types::{Alert, AlertSeverity, AlertType, HIGH_RISK_THRESHOLD, SUSPICIOUS_PORTS};
use crate::database::DeviceRecord;
use crate::HostInfo;

fn append_security_alerts(current_hosts: &[HostInfo], alerts: &mut Vec<Alert>) {
    // Check for high risk devices
    for host in current_hosts {
        if host.risk_score >= HIGH_RISK_THRESHOLD as u8 {
            let hostname_str = host.hostname.as_deref().unwrap_or("Unknown");
            alerts.push(
                Alert::new(
                    AlertType::HighRiskDetected,
                    format!(
                        "High risk device detected: {} ({}) - Score: {}",
                        host.ip, hostname_str, host.risk_score
                    ),
                )
                .with_device(&host.mac, &host.ip)
                .with_severity(AlertSeverity::High),
            );
        }
    }

    // Check for suspicious ports
    for host in current_hosts {
        for port in &host.open_ports {
            if SUSPICIOUS_PORTS.contains(port) {
                let hostname_str = host.hostname.as_deref().unwrap_or("Unknown");
                alerts.push(
                    Alert::new(
                        AlertType::UnusualPort,
                        format!(
                            "Suspicious port {} open on {} ({})",
                            port, host.ip, hostname_str
                        ),
                    )
                    .with_device(&host.mac, &host.ip)
                    .with_severity(AlertSeverity::High),
                );
            }
        }
    }
}

/// Detect baseline-independent security alerts when known-device baseline is unavailable.
pub fn detect_alerts_without_baseline(current_hosts: &[HostInfo]) -> Vec<Alert> {
    let mut alerts = Vec::new();
    append_security_alerts(current_hosts, &mut alerts);
    alerts
}

/// Detect alerts by comparing current scan with known devices
pub fn detect_alerts(known_devices: &[DeviceRecord], current_hosts: &[HostInfo]) -> Vec<Alert> {
    let mut alerts = Vec::new();

    // Build lookup maps
    let known_macs: HashMap<&str, &DeviceRecord> =
        known_devices.iter().map(|d| (d.mac.as_str(), d)).collect();

    let current_macs: HashMap<&str, &HostInfo> =
        current_hosts.iter().map(|h| (h.mac.as_str(), h)).collect();

    // Check for new devices
    for host in current_hosts {
        if !known_macs.contains_key(host.mac.as_str()) {
            let hostname_str = host.hostname.as_deref().unwrap_or("Unknown");
            alerts.push(
                Alert::new(
                    AlertType::NewDeviceDiscovered,
                    format!("New device discovered: {} ({})", host.ip, hostname_str),
                )
                .with_device(&host.mac, &host.ip),
            );
        }
    }

    // Check for offline devices (was online, now not in scan)
    for device in known_devices {
        if !current_macs.contains_key(device.mac.as_str()) {
            let last_ip = device.last_ip.as_deref().unwrap_or("Unknown");
            let hostname = device.hostname.as_deref().unwrap_or("Unknown");
            alerts.push(
                Alert::new(
                    AlertType::DeviceWentOffline,
                    format!("Device went offline: {} ({})", last_ip, hostname),
                )
                .with_device(&device.mac, last_ip),
            );
        }
    }

    append_security_alerts(current_hosts, &mut alerts);

    // Check for IP changes
    for host in current_hosts {
        if let Some(known) = known_macs.get(host.mac.as_str()) {
            if let Some(ref last_ip) = known.last_ip {
                if last_ip != &host.ip {
                    let hostname_str = host.hostname.as_deref().unwrap_or("Unknown");
                    alerts.push(
                        Alert::new(
                            AlertType::IpChanged,
                            format!(
                                "Device {} changed IP: {} → {}",
                                hostname_str, last_ip, host.ip
                            ),
                        )
                        .with_device(&host.mac, &host.ip),
                    );
                }
            }
        }
    }

    alerts
}

/// Quick check if any alerts are high priority
pub fn has_high_priority_alerts(alerts: &[Alert]) -> bool {
    alerts
        .iter()
        .any(|a| matches!(a.severity, AlertSeverity::High | AlertSeverity::Critical))
}

/// Count alerts by type
pub fn count_alerts_by_type(alerts: &[Alert]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for alert in alerts {
        *counts
            .entry(alert.alert_type.as_str().to_string())
            .or_insert(0) += 1;
    }
    counts
}
