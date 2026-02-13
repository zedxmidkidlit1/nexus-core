//! Test the alerts detection system

use chrono::Utc;
use nexus_core::{HostInfo, database::DeviceRecord, detect_alerts, has_high_priority_alerts};

fn main() {
    println!("=== Alerts System Test ===\n");

    let now = Utc::now();

    // Simulate known devices from database
    let known_devices = vec![
        DeviceRecord {
            id: 1,
            mac: "AA:BB:CC:DD:EE:01".to_string(),
            first_seen: now,
            last_seen: now,
            last_ip: Some("192.168.1.100".to_string()),
            vendor: Some("Apple Inc".to_string()),
            risk_score: 10,
            device_type: Some("MOBILE".to_string()),
            hostname: Some("iphone".to_string()),
            os_guess: None,
            custom_name: None,
            notes: None,
            security_grade: None,
        },
        DeviceRecord {
            id: 2,
            mac: "AA:BB:CC:DD:EE:02".to_string(),
            first_seen: now,
            last_seen: now,
            last_ip: Some("192.168.1.101".to_string()),
            vendor: Some("Samsung".to_string()),
            risk_score: 8,
            device_type: Some("MOBILE".to_string()),
            hostname: Some("galaxy".to_string()),
            os_guess: None,
            custom_name: None,
            notes: None,
            security_grade: None,
        },
    ];

    // Simulate current scan results
    let current_hosts = vec![
        // Device 1 still online but with different IP (IP change alert)
        HostInfo {
            ip: "192.168.1.150".to_string(), // Changed from .100
            mac: "AA:BB:CC:DD:EE:01".to_string(),
            vendor: Some("Apple Inc".to_string()),
            is_randomized: false,
            response_time_ms: Some(5),
            ttl: Some(64),
            os_guess: Some("iOS".to_string()),
            device_type: "MOBILE".to_string(),
            risk_score: 10,
            open_ports: vec![],
            discovery_method: "ARP+ICMP".to_string(),
            hostname: Some("iphone".to_string()),
            system_description: None,
            uptime_seconds: None,
            neighbors: vec![],
            vulnerabilities: vec![],
            port_warnings: vec![],
            security_grade: String::new(),
        },
        // NEW device (new device alert)
        HostInfo {
            ip: "192.168.1.200".to_string(),
            mac: "FF:FF:FF:00:00:01".to_string(),
            vendor: Some("Unknown".to_string()),
            is_randomized: true,
            response_time_ms: Some(10),
            ttl: Some(64),
            os_guess: None,
            device_type: "UNKNOWN".to_string(),
            risk_score: 60,                 // High risk!
            open_ports: vec![22, 23, 3389], // Has Telnet and RDP!
            discovery_method: "ARP".to_string(),
            hostname: None,
            system_description: None,
            uptime_seconds: None,
            neighbors: vec![],
            vulnerabilities: vec![],
            port_warnings: vec![],
            security_grade: String::new(),
        },
    ];
    // Note: Device 2 (galaxy) is NOT in current scan - it went offline

    println!("Known devices: {}", known_devices.len());
    for d in &known_devices {
        println!(
            "  - {} ({}) - Last IP: {:?}",
            d.mac,
            d.hostname.as_deref().unwrap_or("?"),
            d.last_ip
        );
    }

    println!("\nCurrent scan hosts: {}", current_hosts.len());
    for h in &current_hosts {
        println!(
            "  - {} ({}) - Risk: {}, Ports: {:?}",
            h.ip, h.mac, h.risk_score, h.open_ports
        );
    }

    // Run alert detection
    println!("\n=== Running Alert Detection ===\n");
    let alerts = detect_alerts(&known_devices, &current_hosts);

    println!("Alerts generated: {}\n", alerts.len());

    for alert in &alerts {
        let icon = match alert.alert_type.as_str() {
            "NEW_DEVICE" => "🆕",
            "DEVICE_OFFLINE" => "📴",
            "HIGH_RISK" => "⚠️",
            "UNUSUAL_PORT" => "🚨",
            "IP_CHANGED" => "🔄",
            _ => "📌",
        };

        println!("{} [{}] {}", icon, alert.severity.as_str(), alert.message);
        if let (Some(mac), Some(ip)) = (&alert.device_mac, &alert.device_ip) {
            println!("   Device: {} ({})", mac, ip);
        }
        println!();
    }

    // Check priority
    if has_high_priority_alerts(&alerts) {
        println!("⚡ HIGH PRIORITY ALERTS DETECTED!");
    } else {
        println!("✅ No high priority alerts");
    }

    println!("\n=== Test Complete ===");
}
