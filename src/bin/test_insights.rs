//! Test the AI insights system

use nexus_core::{DeviceDistribution, HostInfo, NetworkHealth, SecurityReport, VendorDistribution};

fn main() {
    println!("=== AI Insights Test ===\n");

    // Simulate scan results
    let hosts = vec![
        HostInfo {
            ip: "192.168.1.1".to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            vendor: Some("Cisco".to_string()),
            is_randomized: false,
            response_time_ms: Some(5),
            ttl: Some(64),
            os_guess: Some("Linux".to_string()),
            device_type: "ROUTER".to_string(),
            risk_score: 15,
            open_ports: vec![22, 80, 443],
            discovery_method: "ARP+ICMP".to_string(),
            hostname: Some("router".to_string()),
            system_description: None,
            uptime_seconds: None,
            neighbors: vec![],
            vulnerabilities: vec![],
            port_warnings: vec![],
            security_grade: String::new(),
        },
        HostInfo {
            ip: "192.168.1.100".to_string(),
            mac: "AA:BB:CC:DD:EE:01".to_string(),
            vendor: Some("Apple".to_string()),
            is_randomized: false,
            response_time_ms: Some(10),
            ttl: Some(64),
            os_guess: Some("macOS".to_string()),
            device_type: "PC".to_string(),
            risk_score: 10,
            open_ports: vec![],
            discovery_method: "ARP+ICMP".to_string(),
            hostname: Some("macbook".to_string()),
            system_description: None,
            uptime_seconds: None,
            neighbors: vec![],
            vulnerabilities: vec![],
            port_warnings: vec![],
            security_grade: String::new(),
        },
        HostInfo {
            ip: "192.168.1.101".to_string(),
            mac: "FF:FF:FF:00:00:01".to_string(),
            vendor: Some("Unknown".to_string()),
            is_randomized: true,
            response_time_ms: Some(15),
            ttl: Some(64),
            os_guess: None,
            device_type: "UNKNOWN".to_string(),
            risk_score: 55,             // High risk!
            open_ports: vec![23, 3389], // Telnet + RDP
            discovery_method: "ARP".to_string(),
            hostname: None,
            system_description: None,
            uptime_seconds: None,
            neighbors: vec![],
            vulnerabilities: vec![],
            port_warnings: vec![],
            security_grade: String::new(),
        },
        HostInfo {
            ip: "192.168.1.102".to_string(),
            mac: "11:22:33:44:55:66".to_string(),
            vendor: Some("Samsung".to_string()),
            is_randomized: true,
            response_time_ms: Some(8),
            ttl: Some(64),
            os_guess: Some("Android".to_string()),
            device_type: "MOBILE".to_string(),
            risk_score: 20,
            open_ports: vec![],
            discovery_method: "ARP+ICMP".to_string(),
            hostname: Some("galaxy-s21".to_string()),
            system_description: None,
            uptime_seconds: None,
            neighbors: vec![],
            vulnerabilities: vec![],
            port_warnings: vec![],
            security_grade: String::new(),
        },
    ];

    // 1. Network Health
    println!("━━━ Network Health ━━━");
    let health = NetworkHealth::calculate(&hosts);
    println!("Score: {}/100 (Grade: {})", health.score, health.grade);
    println!("Status: {}", health.status);
    println!("Breakdown:");
    println!("  Security:   {}/40", health.breakdown.security);
    println!("  Stability:  {}/30", health.breakdown.stability);
    println!("  Compliance: {}/30", health.breakdown.compliance);
    println!("\nInsights:");
    for insight in &health.insights {
        println!("  • {}", insight);
    }

    // 2. Device Distribution
    println!("\n━━━ Device Distribution ━━━");
    let distribution = DeviceDistribution::calculate(&hosts);
    println!("Summary: {}", distribution.summary);
    println!("By Type:");
    for (dtype, count) in &distribution.by_type {
        let pct = distribution.percentages.get(dtype).unwrap_or(&0.0);
        println!("  {} : {} ({:.1}%)", dtype, count, pct);
    }

    // 3. Vendor Distribution
    println!("\n━━━ Vendor Distribution ━━━");
    let vendors = VendorDistribution::calculate(&hosts);
    println!("Top Vendors:");
    for (vendor, count) in &vendors.top_vendors {
        println!("  {} : {}", vendor, count);
    }

    // 4. Security Recommendations
    println!("\n━━━ Security Report ━━━");
    let report = SecurityReport::generate(&hosts);
    println!("Summary: {}", report.summary);
    println!(
        "Critical: {} | High: {} | Total: {}",
        report.critical_count, report.high_count, report.total_issues
    );
    println!("\nRecommendations:");
    for rec in &report.recommendations {
        println!(
            "\n[{}] {} - {}",
            rec.priority.as_str(),
            rec.category,
            rec.title
        );
        println!("  {}", rec.description);
        if !rec.affected_devices.is_empty() {
            println!("  Affected: {:?}", rec.affected_devices);
        }
    }

    println!("\n=== Test Complete ===");
}
