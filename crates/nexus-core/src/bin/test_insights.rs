//! Test the AI insights system

use nexus_core::{HostInfo, generate_hybrid_insights};

#[tokio::main]
async fn main() {
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

    let result = generate_hybrid_insights(&hosts).await;

    // 1. Network Health
    println!("━━━ Network Health ━━━");
    println!(
        "Score: {}/100 (Grade: {})",
        result.health.score, result.health.grade
    );
    println!("Status: {}", result.health.status);
    println!("Breakdown:");
    println!("  Security:   {}/40", result.health.breakdown.security);
    println!("  Stability:  {}/30", result.health.breakdown.stability);
    println!("  Compliance: {}/30", result.health.breakdown.compliance);
    println!("\nInsights:");
    for insight in &result.health.insights {
        println!("  • {}", insight);
    }

    // 2. Device Distribution
    println!("\n━━━ Device Distribution ━━━");
    println!("Summary: {}", result.device_distribution.summary);
    println!("By Type:");
    for (dtype, count) in &result.device_distribution.by_type {
        let pct = result
            .device_distribution
            .percentages
            .get(dtype)
            .unwrap_or(&0.0);
        println!("  {} : {} ({:.1}%)", dtype, count, pct);
    }

    // 3. Vendor Distribution
    println!("\n━━━ Vendor Distribution ━━━");
    println!("Top Vendors:");
    for (vendor, count) in &result.vendor_distribution.top_vendors {
        println!("  {} : {}", vendor, count);
    }

    // 4. Security Recommendations
    println!("\n━━━ Security Report ━━━");
    println!("Summary: {}", result.security.summary);
    println!(
        "Critical: {} | High: {} | Total: {}",
        result.security.critical_count, result.security.high_count, result.security.total_issues
    );
    println!("\nRecommendations:");
    for rec in &result.security.recommendations {
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

    // 5. Optional AI overlay (policy-driven: local/cloud/hybrid)
    println!("\n━━━ AI Overlay (Optional) ━━━");
    match (&result.ai_overlay, &result.ai_provider, &result.ai_model) {
        (Some(ai), Some(provider), Some(model)) => {
            println!("Provider: {} ({})", provider, model);
            println!("Executive Summary: {}", ai.executive_summary);
            println!("Top Risks:");
            for risk in &ai.top_risks {
                println!("  - {}", risk);
            }
            println!("Immediate Actions:");
            for action in &ai.immediate_actions {
                println!("  - {}", action);
            }
            if !ai.follow_up_actions.is_empty() {
                println!("Follow-up Actions:");
                for action in &ai.follow_up_actions {
                    println!("  - {}", action);
                }
            }
        }
        _ => {
            println!("AI overlay not available (disabled or provider call failed).");
            if let Some(err) = &result.ai_error {
                println!("Reason: {}", err);
            } else {
                println!("Enable with env vars, e.g. NEXUS_AI_ENABLED=true NEXUS_AI_MODE=local.");
            }
        }
    }

    println!("\n=== Test Complete ===");
}
