//! TCP port probing

use anyhow::Result;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

use crate::config::{max_concurrent_pings, tcp_probe_ports, tcp_probe_timeout};

/// Logs a message to stderr
macro_rules! log_stderr {
    ($($arg:tt)*) => {
        tracing::info!($($arg)*);
    };
}

/// Logs a warning to stderr
macro_rules! log_warn {
    ($($arg:tt)*) => {
        tracing::warn!($($arg)*);
    };
}

/// Probes a single host for open ports
async fn probe_host_ports(ip: Ipv4Addr, ports: &[u16], timeout: std::time::Duration) -> Vec<u16> {
    let mut open_ports = Vec::new();

    for &port in ports {
        let addr = std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port);

        if let Ok(Ok(_)) = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await
        {
            open_ports.push(port);
        }
    }

    open_ports
}

/// Performs TCP probe scan on discovered hosts
pub async fn tcp_probe_scan(
    hosts: &HashMap<Ipv4Addr, MacAddr>,
) -> Result<HashMap<Ipv4Addr, Vec<u16>>> {
    let ports = Arc::new(tcp_probe_ports());
    let timeout = tcp_probe_timeout();
    let concurrency = max_concurrent_pings();

    log_stderr!(
        "Phase 3: TCP probing {} hosts ({} ports each)...",
        hosts.len(),
        ports.len()
    );

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let port_results: Arc<Mutex<HashMap<Ipv4Addr, Vec<u16>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let mut handles = Vec::new();

    for &ip in hosts.keys() {
        let semaphore = Arc::clone(&semaphore);
        let port_results = Arc::clone(&port_results);
        let ports = Arc::clone(&ports);

        let handle = tokio::spawn(async move {
            let _permit = match semaphore.acquire().await {
                Ok(permit) => permit,
                Err(e) => {
                    log_warn!("TCP semaphore acquire failed for {}: {}", ip, e);
                    return;
                }
            };

            let open_ports = probe_host_ports(ip, &ports, timeout).await;
            if !open_ports.is_empty() {
                let mut results = port_results.lock().await;
                results.insert(ip, open_ports);
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        if let Err(e) = handle.await {
            log_warn!("TCP probe task failed: {}", e);
        }
    }

    let results = port_results.lock().await;
    let hosts_with_ports = results.len();
    let total_ports: usize = results.values().map(|v| v.len()).sum();

    log_stderr!(
        "Phase 3 complete: {} hosts with open ports ({} ports total)",
        hosts_with_ports,
        total_ports
    );

    Ok(results.clone())
}
