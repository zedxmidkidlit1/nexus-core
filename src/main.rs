//! NEXUS Core Engine — Network Discovery CLI
//!
//! Production-grade network scanner with:
//! - Active ARP scanning (Layer 2)
//! - ICMP ping (latency measurement)
//! - TCP port probing (service detection)
//! - SNMP enrichment (optional)

use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use nexus_core::{
    HostInfo, InterfaceInfo, NeighborInfo, SNMP_ENABLED, ScanResult, active_arp_scan,
    calculate_risk_score, calculate_subnet_ips, dns_scan, find_interface_by_name,
    find_valid_interface, guess_os_from_ttl, icmp_scan, infer_device_type, list_valid_interfaces,
    lookup_vendor_info, snmp_enrich, tcp_probe_scan,
};

/// Logs a message to stderr
macro_rules! log_stderr {
    ($($arg:tt)*) => {
        nexus_core::log_stderr!($($arg)*);
    };
}

/// Logs an error message to stderr
macro_rules! log_error {
    ($($arg:tt)*) => {
        nexus_core::log_error!($($arg)*);
    };
}

const ARP_PHASE_TIMEOUT_SECS: u64 = 15;

#[derive(Debug, PartialEq, Eq)]
enum CliCommand {
    Scan { interface: Option<String> },
    Interfaces,
    Help,
    Version,
}

fn version_text() -> String {
    format!("nexus-core {}", env!("CARGO_PKG_VERSION"))
}

fn usage_text() -> String {
    format!(
        "{version}
NEXUS Core Engine — Network Discovery CLI

Usage:
  nexus-core [scan] [--interface <NAME>]
  nexus-core interfaces
  nexus-core --help
  nexus-core --version

Options:
  -i, --interface <NAME>  Select network interface by exact name
  -h, --help              Show this help text
  -V, --version           Show version",
        version = version_text()
    )
}

fn parse_cli_args<I, S>(args: I) -> Result<CliCommand>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut iter = args.into_iter();
    let _program_name = iter.next();

    let mut command: Option<String> = None;
    let mut interface: Option<String> = None;

    while let Some(arg) = iter.next() {
        let arg = arg.as_ref();
        match arg {
            "-h" | "--help" => return Ok(CliCommand::Help),
            "-V" | "--version" => return Ok(CliCommand::Version),
            "scan" | "interfaces" => {
                if command.as_deref().is_some_and(|existing| existing != arg) {
                    return Err(anyhow::anyhow!(
                        "Multiple commands provided. Use only one command.\n\n{}",
                        usage_text()
                    ));
                }
                command = Some(arg.to_string());
            }
            "-i" | "--interface" => {
                let value = iter.next().ok_or_else(|| {
                    anyhow::anyhow!("Missing value for --interface.\n\n{}", usage_text())
                })?;
                interface = Some(value.as_ref().to_string());
            }
            _ if arg.starts_with("--interface=") => {
                let value = arg.split_once('=').map(|(_, v)| v).unwrap_or_default();
                if value.is_empty() {
                    return Err(anyhow::anyhow!(
                        "Missing value for --interface.\n\n{}",
                        usage_text()
                    ));
                }
                interface = Some(value.to_string());
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Unknown argument: {arg}\n\n{}",
                    usage_text()
                ));
            }
        }
    }

    match command.as_deref().unwrap_or("scan") {
        "scan" => Ok(CliCommand::Scan { interface }),
        "interfaces" => {
            if interface.is_some() {
                return Err(anyhow::anyhow!(
                    "--interface is only valid with scan.\n\n{}",
                    usage_text()
                ));
            }
            Ok(CliCommand::Interfaces)
        }
        _ => unreachable!(),
    }
}

/// Performs the complete network scan
async fn scan_network(interface: &InterfaceInfo) -> Result<ScanResult> {
    let start_time = Instant::now();
    let (subnet, ips) = calculate_subnet_ips(interface)?;

    log_stderr!("Starting Active ARP + ICMP scan on subnet {}...", subnet);
    log_stderr!("================================================");

    // Phase 1: Active ARP Scan
    let arp_scan_handle = tokio::task::spawn_blocking({
        let interface = interface.clone();
        let ips = ips.clone();
        move || active_arp_scan(&interface, &ips, &subnet)
    });

    let arp_hosts =
        match tokio::time::timeout(Duration::from_secs(ARP_PHASE_TIMEOUT_SECS), arp_scan_handle)
            .await
        {
            Ok(joined) => joined.context("ARP scan task failed")??,
            Err(_) => {
                log_error!(
                    "ARP phase exceeded {}s timeout; continuing with empty ARP host set",
                    ARP_PHASE_TIMEOUT_SECS
                );
                std::collections::HashMap::new()
            }
        };

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
        match snmp_enrich(&host_ips).await {
            Ok(data) => data,
            Err(e) => {
                log_error!(
                    "SNMP enrichment failed; continuing without SNMP data: {}",
                    e
                );
                std::collections::HashMap::new()
            }
        }
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
    if let Err(e) = nexus_core::logging::init_logging() {
        eprintln!("[WARN] Failed to initialize structured logging: {}", e);
    }

    match run(std::env::args()).await {
        Ok(()) => {}
        Err(e) => {
            log_error!("{:#}", e);
            std::process::exit(1);
        }
    }
}

/// Main entry point
async fn run<I, S>(args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    match parse_cli_args(args)? {
        CliCommand::Help => {
            println!("{}", usage_text());
            Ok(())
        }
        CliCommand::Version => {
            println!("{}", version_text());
            Ok(())
        }
        CliCommand::Interfaces => {
            let interfaces = list_valid_interfaces();
            if interfaces.is_empty() {
                println!("No valid IPv4 network interfaces found.");
            } else {
                for interface in interfaces {
                    println!("{}", interface);
                }
            }
            Ok(())
        }
        CliCommand::Scan { interface } => {
            log_stderr!(
                "NEXUS Core Engine — Network Discovery v{}",
                env!("CARGO_PKG_VERSION")
            );
            log_stderr!("Active ARP + ICMP + TCP Scanning Mode");
            log_stderr!("================================================");

            let selected_interface = match interface {
                Some(name) => {
                    log_stderr!("Using requested interface: {}", name);
                    find_interface_by_name(&name)?
                }
                None => {
                    log_stderr!("Detecting network interfaces...");
                    find_valid_interface()?
                }
            };

            let result = scan_network(&selected_interface).await?;
            let json =
                serde_json::to_string_pretty(&result).context("Failed to serialize scan result")?;
            println!("{}", json);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_help_flag() {
        let args = ["nexus-core", "--help"];
        let parsed = parse_cli_args(args).expect("help args should parse");
        assert_eq!(parsed, CliCommand::Help);
    }

    #[test]
    fn parse_version_flag() {
        let args = ["nexus-core", "--version"];
        let parsed = parse_cli_args(args).expect("version args should parse");
        assert_eq!(parsed, CliCommand::Version);
    }

    #[test]
    fn parse_default_scan_command() {
        let args = ["nexus-core"];
        let parsed = parse_cli_args(args).expect("default args should parse");
        assert_eq!(parsed, CliCommand::Scan { interface: None });
    }

    #[test]
    fn parse_scan_with_interface_flag() {
        let args = ["nexus-core", "scan", "--interface", "Ethernet"];
        let parsed = parse_cli_args(args).expect("scan with interface should parse");
        assert_eq!(
            parsed,
            CliCommand::Scan {
                interface: Some("Ethernet".to_string())
            }
        );
    }

    #[test]
    fn parse_interfaces_command() {
        let args = ["nexus-core", "interfaces"];
        let parsed = parse_cli_args(args).expect("interfaces command should parse");
        assert_eq!(parsed, CliCommand::Interfaces);
    }

    #[test]
    fn parse_unknown_argument_errors() {
        let args = ["nexus-core", "--unknown"];
        let err = parse_cli_args(args).expect_err("unknown flag should fail");
        let message = err.to_string();
        assert!(message.contains("Unknown argument"));
    }

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
