//! Passive Discovery Integration Helper
//!
//! This module provides helper functions to integrate passive discovery
//! into the background monitor

use crate::monitor::events::{DeviceSnapshot, NetworkEvent};
use crate::scanner::passive::mdns::PassiveDevice;
use crate::scanner::passive::{ArpEvent, ArpMonitor, PassiveScanner};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Start passive discovery listeners
///
/// Returns channels for mDNS and ARP events
pub async fn start_passive_listeners() -> Result<
    (
        mpsc::Receiver<PassiveDevice>,
        Option<mpsc::Receiver<ArpEvent>>,
    ),
    Box<dyn std::error::Error>,
> {
    // mDNS listener
    let (mdns_tx, mdns_rx) = mpsc::channel(100);
    let mdns_scanner = PassiveScanner::new()?;

    tokio::spawn(async move {
        if let Err(e) = mdns_scanner.start_listening(mdns_tx).await {
            tracing::error!("mDNS listener error: {}", e);
        }
    });

    // ARP monitor (optional - requires admin on Windows)
    let arp_rx = match try_start_arp_monitor().await {
        Ok(rx) => Some(rx),
        Err(e) => {
            tracing::warn!("ARP monitoring disabled: {}", e);
            None
        }
    };

    Ok((mdns_rx, arp_rx))
}

/// Try to start ARP monitor (may fail without admin privileges)
async fn try_start_arp_monitor() -> Result<mpsc::Receiver<ArpEvent>, Box<dyn std::error::Error>> {
    use pnet::datalink;

    // Find suitable interface
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| !iface.is_loopback() && iface.is_up() && !iface.ips.is_empty())
        .ok_or("No suitable network interface")?;

    let (tx, rx) = mpsc::channel(100);
    let monitor = ArpMonitor::new(interface);

    tokio::spawn(async move {
        if let Err(e) = monitor.start_monitoring(tx).await {
            tracing::error!("ARP monitor error: {}", e);
        }
    });

    Ok(rx)
}

/// Convert PassiveDevice to DeviceSnapshot
pub fn passive_device_to_snapshot(device: PassiveDevice) -> DeviceSnapshot {
    // Use device type hint if available, otherwise default to "Unknown"
    let device_type = device
        .device_type_hint
        .unwrap_or_else(|| "Unknown".to_string());

    DeviceSnapshot {
        mac: device
            .mac
            .unwrap_or_else(|| format!("unknown_{}", device.ip)),
        ip: device.ip,
        hostname: Some(device.hostname),
        device_type,
        is_online: true,
    }
}

/// Handle passive mDNS discovery event
pub fn handle_mdns_device<F>(device: PassiveDevice, callback: &Arc<F>)
where
    F: Fn(NetworkEvent) + Send + Sync,
{
    let device_type = device
        .device_type_hint
        .clone()
        .unwrap_or_else(|| "Unknown".to_string());

    tracing::info!(
        "🎧 Passive discovery: {} at {} via mDNS (type: {})",
        device.hostname,
        device.ip,
        device_type
    );

    // Emit as new device discovered (matching existing NetworkEvent structure)
    callback(NetworkEvent::NewDeviceDiscovered {
        ip: device.ip.clone(),
        mac: device
            .mac
            .unwrap_or_else(|| format!("unknown_{}", device.ip)),
        hostname: Some(device.hostname),
        device_type,
    });
}

/// Enrich device with ARP data (MAC address)
pub fn enrich_with_arp(device_ip: &str, arp_event: &ArpEvent) -> Option<String> {
    if arp_event.sender_ip == device_ip {
        Some(arp_event.sender_mac.clone())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passive_device_conversion() {
        let device = PassiveDevice {
            hostname: "test-device.local".to_string(),
            ip: "192.168.1.100".to_string(),
            mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            services: vec!["_http._tcp".to_string()],
            discovered_at: chrono::Utc::now(),
            device_type_hint: Some("Web Server".to_string()),
        };

        let snapshot = passive_device_to_snapshot(device);
        assert_eq!(snapshot.ip, "192.168.1.100");
        assert_eq!(snapshot.hostname, Some("test-device.local".to_string()));
        assert!(snapshot.is_online);
    }
}
