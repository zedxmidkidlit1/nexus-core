use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::app::{AppContext, AppEvent, LoadTestSummary};
use crate::{
    HostInfo, InterfaceInfo, NeighborInfo, ScanResult, active_arp_scan, calculate_risk_score,
    calculate_subnet_ips, dns_scan, guess_os_from_ttl, icmp_scan, infer_device_type,
    lookup_vendor_info, snmp_enabled, snmp_enrich, tcp_probe_scan,
};

const ARP_PHASE_TIMEOUT_SECS: u64 = 15;

#[derive(Debug, Clone)]
pub(crate) struct PersistedScan {
    pub scan_id: i64,
    pub path: String,
}

pub(crate) async fn run_load_test(
    interface: &InterfaceInfo,
    iterations: u32,
    concurrency: usize,
) -> Result<LoadTestSummary> {
    let started = Instant::now();
    let mut remaining = iterations;
    let mut successful_scans: u32 = 0;
    let mut failed_scans: u32 = 0;
    let mut scan_durations: Vec<u64> = Vec::new();
    let mut host_counts: Vec<usize> = Vec::new();

    while remaining > 0 {
        let batch_size = std::cmp::min(remaining as usize, concurrency);
        let mut batch = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            let iface = interface.clone();
            batch.push(tokio::spawn(
                async move { scan_network(&iface, None).await },
            ));
        }

        for result in batch {
            match result.await {
                Ok(Ok(scan)) => {
                    successful_scans += 1;
                    scan_durations.push(scan.scan_duration_ms);
                    host_counts.push(scan.total_hosts);
                }
                Ok(Err(_)) | Err(_) => {
                    failed_scans += 1;
                }
            }
        }

        remaining -= batch_size as u32;
    }

    let wall_time_ms = started.elapsed().as_millis() as u64;
    let avg_scan_duration_ms = if scan_durations.is_empty() {
        0.0
    } else {
        scan_durations.iter().sum::<u64>() as f64 / scan_durations.len() as f64
    };
    let min_scan_duration_ms = scan_durations.iter().copied().min().unwrap_or(0);
    let max_scan_duration_ms = scan_durations.iter().copied().max().unwrap_or(0);
    let avg_hosts_found = if host_counts.is_empty() {
        0.0
    } else {
        host_counts.iter().sum::<usize>() as f64 / host_counts.len() as f64
    };

    Ok(LoadTestSummary {
        interface_name: interface.name.clone(),
        iterations,
        concurrency,
        successful_scans,
        failed_scans,
        wall_time_ms,
        avg_scan_duration_ms,
        min_scan_duration_ms,
        max_scan_duration_ms,
        avg_hosts_found,
    })
}

pub(crate) fn persist_scan_result(result: &ScanResult, db_path: &Path) -> Result<PersistedScan> {
    let db = crate::database::Database::new(db_path.to_path_buf())
        .context("Failed to open local database for scan persistence")?;
    let db_path = db.path().clone();
    let conn = db.connection();
    let conn = conn
        .lock()
        .map_err(|_| anyhow::anyhow!("Database connection lock poisoned"))?;
    let scan_id = crate::database::queries::insert_scan(&conn, result)
        .context("Failed to persist scan result")?;
    crate::log_stderr!(
        "Persisted scan {} to {}",
        scan_id,
        db_path.to_string_lossy()
    );
    Ok(PersistedScan {
        scan_id,
        path: db_path.to_string_lossy().to_string(),
    })
}

pub(crate) async fn scan_network(
    interface: &InterfaceInfo,
    context: Option<&AppContext>,
) -> Result<ScanResult> {
    let start_time = Instant::now();
    emit_scan_phase(context, "init", 5);
    let (subnet, ips) = calculate_subnet_ips(interface)?;

    crate::log_stderr!("Starting Active ARP + ICMP scan on subnet {}...", subnet);
    crate::log_stderr!("================================================");

    // Phase 1: Active ARP Scan
    emit_scan_phase(context, "arp", 20);
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
                crate::log_error!(
                    "ARP phase exceeded {}s timeout; continuing with empty ARP host set",
                    ARP_PHASE_TIMEOUT_SECS
                );
                if let Some(ctx) = context {
                    ctx.emit_event(AppEvent::Warn {
                        message: format!(
                            "ARP phase exceeded {}s timeout; continuing with empty ARP host set",
                            ARP_PHASE_TIMEOUT_SECS
                        ),
                    });
                }
                std::collections::HashMap::new()
            }
        };

    let arp_count = arp_hosts.len();

    // Phase 2 & 3: Run ICMP ping and TCP probe in parallel for faster scanning
    emit_scan_phase(context, "tcp", 50);
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

    let snmp_is_enabled = snmp_enabled();
    let snmp_data = if snmp_is_enabled {
        emit_scan_phase(context, "snmp", 65);
        match snmp_enrich(&host_ips).await {
            Ok(data) => data,
            Err(e) => {
                crate::log_error!(
                    "SNMP enrichment failed; continuing without SNMP data: {}",
                    e
                );
                if let Some(ctx) = context {
                    ctx.emit_event(AppEvent::Warn {
                        message: format!(
                            "SNMP enrichment failed; continuing without SNMP data: {}",
                            e
                        ),
                    });
                }
                std::collections::HashMap::new()
            }
        }
    } else {
        std::collections::HashMap::new()
    };

    // Phase 5: DNS reverse lookup
    emit_scan_phase(context, "dns", 80);
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

    crate::log_stderr!("================================================");
    crate::log_stderr!(
        "Scan complete: {} hosts found ({} ARP, {} ICMP responsive) in {:.2}s",
        total_hosts,
        arp_count,
        icmp_count,
        scan_duration.as_secs_f64()
    );
    emit_scan_phase(context, "complete", 100);

    let scan_method = if snmp_is_enabled {
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

fn emit_scan_phase(context: Option<&AppContext>, phase: &str, progress_pct: u8) {
    if let Some(ctx) = context {
        ctx.emit_event(AppEvent::ScanPhase {
            phase: phase.to_string(),
            progress_pct,
        });
    }
}
