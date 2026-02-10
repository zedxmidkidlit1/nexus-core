//! NEXUS Core Engine — Network Discovery CLI
//!
//! Production-grade network scanner with:
//! - Active ARP scanning (Layer 2)
//! - ICMP ping (latency measurement)
//! - TCP port probing (service detection)
//! - SNMP enrichment (optional)

use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::time::Instant;

use nexus_core::{
    active_arp_scan, calculate_risk_score, calculate_subnet_ips, dns_scan, find_valid_interface,
    guess_os_from_ttl, icmp_scan, infer_device_type, lookup_vendor_info, snmp_enrich,
    tcp_probe_scan, HostInfo, InterfaceInfo, NeighborInfo, ScanResult, SNMP_ENABLED,
};

/// Logs a message to stderr
macro_rules! log_stderr {
    ($($arg:tt)*) => {
        eprintln!("[INFO] {}", format!($($arg)*));
    };
}

/// Logs an error message to stderr
macro_rules! log_error {
    ($($arg:tt)*) => {
        eprintln!("[ERROR] {}", format!($($arg)*));
    };
}

/// Performs the complete network scan
async fn scan_network(interface: &InterfaceInfo) -> Result<ScanResult> {
    let start_time = Instant::now();
    let (subnet, ips) = calculate_subnet_ips(interface)?;

    log_stderr!("Starting Active ARP + ICMP scan on subnet {}...", subnet);
    log_stderr!("================================================");

    // Phase 1: Active ARP Scan
    let arp_hosts = tokio::task::spawn_blocking({
        let interface = interface.clone();
        let ips = ips.clone();
        move || active_arp_scan(&interface, &ips, &subnet)
    })
    .await
    .context("ARP scan task failed")??;

    let arp_count = arp_hosts.len();

    // Phase 2 & 3: Run ICMP ping and TCP probe in parallel for faster scanning
    let (response_times_result, port_results_result) =
        tokio::join!(icmp_scan(&arp_hosts), tcp_probe_scan(&arp_hosts));

    let response_times = response_times_result?;
    let icmp_count = response_times.len();
    let port_results = port_results_result?;

    // Phase 4: SNMP enrichment (if enabled)
    let host_ips: Vec<Ipv4Addr> = arp_hosts
        .keys()
        .filter(|ip| **ip != interface.ip)
        .copied()
        .collect();

    let snmp_data = if SNMP_ENABLED {
        snmp_enrich(&host_ips).await.unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    };

    // Phase 5: DNS reverse lookup
    let dns_hostnames = dns_scan(&host_ips).await;

    // Build results (exclude local machine from ARP - we add it separately)
    let mut active_hosts: Vec<HostInfo> = arp_hosts
        .iter()
        .filter(|(ip, _)| **ip != interface.ip)
        .map(|(ip, mac)| {
            let icmp_result = response_times.get(ip);
            let response_time = icmp_result.map(|r| r.duration.as_millis() as u64);
            let ttl = icmp_result.and_then(|r| r.ttl);
            let os_guess = ttl.map(guess_os_from_ttl);
            let open_ports = port_results.get(ip).cloned().unwrap_or_default();
            let snmp = snmp_data.get(ip);

            let mut method = match (response_time.is_some(), !open_ports.is_empty()) {
                (true, true) => "ARP+ICMP+TCP",
                (true, false) => "ARP+ICMP",
                (false, true) => "ARP+TCP",
                (false, false) => "ARP",
            }
            .to_string();

            if snmp.is_some() {
                method.push_str("+SNMP");
            }

            let mac_str = format!("{}", mac);
            let vendor_info = lookup_vendor_info(&mac_str);

            // Infer device type and calculate risk score
            // Gateway detection: typically ends in .1 or has web interface on port 80
            let is_gateway = ip.octets()[3] == 1 || open_ports.contains(&80);
            let device_type = infer_device_type(
                vendor_info.vendor.as_deref(),
                dns_hostnames.get(ip).map(|s| s.as_str()),
                &open_ports,
                is_gateway,
            );
            let risk_score =
                calculate_risk_score(device_type, &open_ports, vendor_info.is_randomized);

            let mut host = HostInfo::new(
                ip.to_string(),
                mac_str,
                device_type.as_str().to_string(),
                method,
            );
            host.vendor = vendor_info.vendor;
            host.is_randomized = vendor_info.is_randomized;
            host.response_time_ms = response_time;
            host.ttl = ttl;
            host.os_guess = os_guess;
            host.risk_score = risk_score;
            host.open_ports = open_ports;
            // DNS hostname takes precedence, fallback to SNMP hostname
            host.hostname = dns_hostnames
                .get(ip)
                .cloned()
                .or_else(|| snmp.and_then(|s| s.hostname.clone()));
            host.system_description = snmp.and_then(|s| s.system_description.clone());
            host.uptime_seconds = snmp.and_then(|s| s.uptime_seconds);
            host.neighbors = snmp
                .map(|s| {
                    s.neighbors
                        .iter()
                        .map(|n| NeighborInfo {
                            local_port: n.local_port.clone(),
                            remote_device: n.remote_device.clone(),
                            remote_port: n.remote_port.clone(),
                            remote_ip: n.remote_ip.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            host
        })
        .collect();

    // Add local machine to results
    let local_mac = format!("{}", interface.mac);
    let local_vendor_info = lookup_vendor_info(&local_mac);
    let local_device_type =
        infer_device_type(local_vendor_info.vendor.as_deref(), None, &[], false);
    let mut local_host = HostInfo::new(
        interface.ip.to_string(),
        local_mac,
        local_device_type.as_str().to_string(),
        "LOCAL".to_string(),
    );
    local_host.vendor = local_vendor_info.vendor;
    local_host.is_randomized = local_vendor_info.is_randomized;
    local_host.response_time_ms = Some(0);
    active_hosts.push(local_host);

    // Sort by IP
    active_hosts.sort_by(|a, b| {
        let ip_a: Ipv4Addr = a.ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
        let ip_b: Ipv4Addr = b.ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
        ip_a.cmp(&ip_b)
    });

    let total_hosts = active_hosts.len();
    let scan_duration = start_time.elapsed();

    log_stderr!("================================================");
    log_stderr!(
        "Scan complete: {} hosts found ({} ARP, {} ICMP responsive) in {:.2}s",
        total_hosts,
        arp_count,
        icmp_count,
        scan_duration.as_secs_f64()
    );

    let scan_method = if SNMP_ENABLED {
        "Active ARP + ICMP + TCP + SNMP".to_string()
    } else {
        "Active ARP + ICMP + TCP".to_string()
    };

    Ok(ScanResult {
        interface_name: interface.name.clone(),
        local_ip: interface.ip.to_string(),
        local_mac: format!("{}", interface.mac),
        subnet: subnet.to_string(),
        scan_method,
        arp_discovered: arp_count,
        icmp_discovered: icmp_count,
        total_hosts,
        scan_duration_ms: scan_duration.as_millis() as u64,
        active_hosts,
    })
}

#[tokio::main]
async fn main() {
    match run().await {
        Ok(result) => {
            match serde_json::to_string_pretty(&result) {
                Ok(json) => println!("{}", json),
                Err(e) => {
                    log_error!("Failed to serialize scan result to JSON: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            log_error!("{:#}", e);
            std::process::exit(1);
        }
    }
}

/// Main entry point
async fn run() -> Result<ScanResult> {
    log_stderr!("NEXUS Core Engine — Network Discovery v0.4.0-dev");
    log_stderr!("Active ARP + ICMP + TCP Scanning Mode");
    log_stderr!("================================================");

    log_stderr!("Detecting network interfaces...");
    let interface = find_valid_interface()?;

    scan_network(&interface).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_result_serialization() {
        let result = ScanResult {
            interface_name: "eth0".to_string(),
            local_ip: "192.168.1.100".to_string(),
            local_mac: "00:11:22:33:44:55".to_string(),
            subnet: "192.168.1.0/24".to_string(),
            scan_method: "Active ARP + ICMP".to_string(),
            arp_discovered: 5,
            icmp_discovered: 3,
            total_hosts: 5,
            scan_duration_ms: 1000,
            active_hosts: vec![{
                let mut host = HostInfo::new(
                    "192.168.1.1".to_string(),
                    "AA:BB:CC:DD:EE:FF".to_string(),
                    "UNKNOWN".to_string(),
                    "ARP+ICMP+TCP".to_string(),
                );
                host.response_time_ms = Some(10);
                host.open_ports = vec![80];
                host
            }],
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"interface_name\":\"eth0\""));
        assert!(json.contains("\"open_ports\":[80]"));
    }
}
