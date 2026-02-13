//! Security grading and vulnerability assessment
//!
//! Calculates security grades (A-F) for network devices

use crate::models::HostInfo;

/// Calculate security grade for a host based on vulnerabilities and risk factors
///
/// Grade Scale:
/// - A (0-10 penalty): Excellent security posture
/// - B (11-25 penalty): Good security, minor issues
/// - C (26-45 penalty): Fair security, some concerns
/// - D (46-70 penalty): Poor security, multiple issues
/// - F (71+ penalty): Critical security risks
pub fn calculate_security_grade(host: &HostInfo) -> String {
    let mut penalty = 0;

    // Vulnerability penalties based on severity
    for vuln in &host.vulnerabilities {
        penalty += match vuln.severity.to_uppercase().as_str() {
            "CRITICAL" => 25,
            "HIGH" => 15,
            "MEDIUM" => 7,
            "LOW" => 3,
            _ => 0,
        };
    }

    // Port warning penalties
    for warning in &host.port_warnings {
        penalty += match warning.severity.to_uppercase().as_str() {
            "CRITICAL" => 20,
            "HIGH" => 12,
            "MEDIUM" => 6,
            "LOW" => 2,
            _ => 0,
        };
    }

    // Base risk score penalty (0-100 risk score contributes 0-20 penalty)
    penalty += (host.risk_score as i32) / 5;

    // Randomized MAC penalty (potential security concern)
    if host.is_randomized {
        penalty += 5;
    }

    // Convert penalty to letter grade
    match penalty {
        0..=10 => "A".to_string(),
        11..=25 => "B".to_string(),
        26..=45 => "C".to_string(),
        46..=70 => "D".to_string(),
        _ => "F".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{PortWarning, VulnerabilityInfo};

    #[test]
    fn test_grade_a_no_issues() {
        let host = HostInfo {
            ip: "192.168.1.1".to_string(),
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            vendor: Some("TestVendor".to_string()),
            is_randomized: false,
            response_time_ms: Some(10),
            ttl: Some(64),
            os_guess: Some("Linux".to_string()),
            device_type: "ROUTER".to_string(),
            risk_score: 0,
            open_ports: vec![],
            discovery_method: "ARP".to_string(),
            hostname: None,
            system_description: None,
            uptime_seconds: None,
            neighbors: vec![],
            vulnerabilities: vec![],
            port_warnings: vec![],
            security_grade: String::new(),
        };

        assert_eq!(calculate_security_grade(&host), "A");
    }

    #[test]
    fn test_grade_f_critical_vulns() {
        let mut host = HostInfo {
            ip: "192.168.1.1".to_string(),
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            vendor: Some("TestVendor".to_string()),
            is_randomized: false,
            response_time_ms: Some(10),
            ttl: Some(64),
            os_guess: Some("Linux".to_string()),
            device_type: "ROUTER".to_string(),
            risk_score: 50,
            open_ports: vec![23, 21],
            discovery_method: "ARP".to_string(),
            hostname: None,
            system_description: None,
            uptime_seconds: None,
            neighbors: vec![],
            vulnerabilities: vec![],
            port_warnings: vec![],
            security_grade: String::new(),
        };

        // Add critical vulnerabilities
        host.vulnerabilities.push(VulnerabilityInfo {
            cve_id: "CVE-2023-1234".to_string(),
            description: "Critical vulnerability".to_string(),
            severity: "CRITICAL".to_string(),
            cvss_score: Some(9.8),
        });

        host.port_warnings.push(PortWarning {
            port: 23,
            service: "Telnet".to_string(),
            warning: "Unencrypted protocol".to_string(),
            severity: "CRITICAL".to_string(),
            recommendation: Some("Use SSH".to_string()),
        });

        let grade = calculate_security_grade(&host);
        assert_eq!(grade, "D");
    }
}
