use crate::{DeviceDistribution, HostInfo, NetworkHealth, SecurityReport, VendorDistribution};

use crate::ai::types::{AiHostDigest, AiInputDigest};

pub(crate) fn build_ai_input_digest(
    hosts: &[HostInfo],
    health: &NetworkHealth,
    security: &SecurityReport,
    device_distribution: &DeviceDistribution,
    vendor_distribution: &VendorDistribution,
    redact_sensitive: bool,
) -> AiInputDigest {
    let mut high_risk_hosts: Vec<&HostInfo> = hosts.iter().filter(|h| h.risk_score >= 50).collect();
    high_risk_hosts.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));

    let high_risk_hosts = high_risk_hosts
        .into_iter()
        .take(10)
        .enumerate()
        .map(|(idx, host)| AiHostDigest {
            id: if redact_sensitive {
                format!("host_{}", idx + 1)
            } else {
                format!(
                    "{} ({})",
                    host.ip,
                    host.hostname
                        .as_deref()
                        .filter(|name| !name.is_empty())
                        .unwrap_or("unknown")
                )
            },
            device_type: host.device_type.clone(),
            risk_score: host.risk_score,
            open_ports: host.open_ports.clone(),
        })
        .collect();

    let mut top_types: Vec<(String, usize)> = device_distribution
        .by_type
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    top_types.sort_by(|a, b| b.1.cmp(&a.1));
    top_types.truncate(5);

    let mut top_vendors = vendor_distribution.top_vendors.clone();
    top_vendors.truncate(5);

    AiInputDigest {
        total_hosts: hosts.len(),
        health_score: health.score,
        health_grade: health.grade,
        health_status: health.status.clone(),
        critical_issues: security.critical_count,
        high_priority_issues: security.high_count,
        total_recommendations: security.total_issues,
        top_device_types: top_types,
        top_vendors,
        high_risk_hosts,
        recommendation_titles: security
            .recommendations
            .iter()
            .take(8)
            .map(|r| format!("[{}] {}", r.priority.as_str(), r.title))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::types::HybridInsightsResult;
    use crate::insights::{HealthBreakdown, Priority, Recommendation};

    fn sample_hosts() -> Vec<HostInfo> {
        vec![
            HostInfo {
                ip: "192.168.1.10".to_string(),
                mac: "AA:BB:CC:DD:EE:10".to_string(),
                vendor: Some("Vendor".to_string()),
                is_randomized: false,
                response_time_ms: Some(5),
                ttl: Some(64),
                os_guess: Some("Linux".to_string()),
                device_type: "ROUTER".to_string(),
                risk_score: 65,
                open_ports: vec![23, 80],
                discovery_method: "ARP+ICMP+TCP".to_string(),
                hostname: Some("router".to_string()),
                system_description: None,
                uptime_seconds: None,
                neighbors: vec![],
                vulnerabilities: vec![],
                port_warnings: vec![],
                security_grade: String::new(),
            },
            HostInfo {
                ip: "192.168.1.20".to_string(),
                mac: "AA:BB:CC:DD:EE:20".to_string(),
                vendor: Some("Vendor2".to_string()),
                is_randomized: true,
                response_time_ms: Some(12),
                ttl: Some(64),
                os_guess: Some("Linux".to_string()),
                device_type: "UNKNOWN".to_string(),
                risk_score: 20,
                open_ports: vec![3389],
                discovery_method: "ARP+ICMP".to_string(),
                hostname: Some("unknown".to_string()),
                system_description: None,
                uptime_seconds: None,
                neighbors: vec![],
                vulnerabilities: vec![],
                port_warnings: vec![],
                security_grade: String::new(),
            },
        ]
    }

    fn sample_result() -> HybridInsightsResult {
        HybridInsightsResult {
            health: NetworkHealth {
                score: 72,
                status: "Good".to_string(),
                grade: 'C',
                breakdown: HealthBreakdown {
                    security: 30,
                    stability: 20,
                    compliance: 22,
                },
                insights: vec!["2 devices scanned".to_string()],
            },
            security: SecurityReport {
                recommendations: vec![Recommendation {
                    priority: Priority::High,
                    category: "Risk".to_string(),
                    title: "High risk detected".to_string(),
                    description: "Act now".to_string(),
                    affected_devices: vec!["192.168.1.10".to_string()],
                }],
                critical_count: 0,
                high_count: 1,
                total_issues: 1,
                summary: "One high priority issue".to_string(),
            },
            device_distribution: DeviceDistribution {
                by_type: std::collections::HashMap::from([
                    ("ROUTER".to_string(), 1),
                    ("UNKNOWN".to_string(), 1),
                ]),
                percentages: std::collections::HashMap::new(),
                total: 2,
                dominant_type: Some("ROUTER".to_string()),
                summary: "Summary".to_string(),
            },
            vendor_distribution: VendorDistribution {
                by_vendor: std::collections::HashMap::from([
                    ("Vendor".to_string(), 1),
                    ("Vendor2".to_string(), 1),
                ]),
                top_vendors: vec![("Vendor".to_string(), 1), ("Vendor2".to_string(), 1)],
                total: 2,
            },
            ai_overlay: None,
            ai_provider: None,
            ai_model: None,
            ai_error: None,
        }
    }

    #[test]
    fn build_digest_redacts_host_ids_for_cloud() {
        let hosts = sample_hosts();
        let base = sample_result();
        let digest = build_ai_input_digest(
            &hosts,
            &base.health,
            &base.security,
            &base.device_distribution,
            &base.vendor_distribution,
            true,
        );
        assert!(
            digest
                .high_risk_hosts
                .iter()
                .all(|h| h.id.starts_with("host_"))
        );
    }
}
