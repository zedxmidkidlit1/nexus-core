//! ICMP ping scanning with TTL-based OS fingerprinting

use anyhow::Result;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use surge_ping::{Client, Config, IcmpPacket, PingIdentifier, PingSequence};
use tokio::sync::{Mutex, Semaphore};

use crate::config::{MAX_CONCURRENT_PINGS, PING_RETRIES, PING_TIMEOUT};

/// Logs a message to stderr
macro_rules! log_stderr {
    ($($arg:tt)*) => {
        eprintln!("[INFO] {}", format!($($arg)*));
    };
}

/// Logs a warning to stderr
macro_rules! log_warn {
    ($($arg:tt)*) => {
        eprintln!("[WARN] {}", format!($($arg)*));
    };
}

/// Result of an ICMP ping including TTL for OS fingerprinting
#[derive(Debug, Clone)]
pub struct IcmpResult {
    pub duration: Duration,
    pub ttl: Option<u8>,
}

/// Generates a random ping identifier
fn rand_id() -> u16 {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    ((duration.as_nanos() % 0xFFFF) as u16).wrapping_add(1)
}

/// Guess the operating system based on TTL value
///
/// Common default TTL values:
/// - Linux/Unix/macOS: 64
/// - Windows: 128
/// - Cisco/Network devices: 255
pub fn guess_os_from_ttl(ttl: u8) -> String {
    match ttl {
        1..=64 => "Linux/Unix/macOS".to_string(),
        65..=128 => "Windows".to_string(),
        129..=255 => "Network Device (Router/Switch)".to_string(),
        0 => "Unknown".to_string(),
    }
}

/// Pings a single IP address with retries, returns duration and TTL
async fn ping_host_with_retries(client: &Client, ip: Ipv4Addr) -> Option<IcmpResult> {
    let payload = [0u8; 56];

    for attempt in 0..PING_RETRIES {
        let start = Instant::now();
        match client
            .pinger(IpAddr::V4(ip), PingIdentifier(rand_id()))
            .await
            .timeout(PING_TIMEOUT)
            .ping(PingSequence(attempt as u16), &payload)
            .await
        {
            Ok((packet, _rtt)) => {
                let ttl = match packet {
                    IcmpPacket::V4(p) => p.get_ttl(),
                    IcmpPacket::V6(_) => None,
                };
                return Some(IcmpResult {
                    duration: start.elapsed(),
                    ttl,
                });
            }
            Err(_) => continue,
        }
    }
    None
}

/// Performs ICMP scan on discovered hosts to get response times and TTL
pub async fn icmp_scan(
    arp_hosts: &HashMap<Ipv4Addr, MacAddr>,
) -> Result<HashMap<Ipv4Addr, IcmpResult>> {
    if arp_hosts.is_empty() {
        return Ok(HashMap::new());
    }

    log_stderr!(
        "Phase 2: ICMP scanning {} hosts for response times...",
        arp_hosts.len()
    );

    let config = Config::default();
    let client = match Client::new(&config) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            log_warn!(
                "ICMP client unavailable ({}), skipping latency measurement",
                e
            );
            return Ok(HashMap::new());
        }
    };

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_PINGS));
    let results = Arc::new(Mutex::new(HashMap::new()));

    let mut handles = Vec::new();

    for &ip in arp_hosts.keys() {
        let client = Arc::clone(&client);
        let semaphore = Arc::clone(&semaphore);
        let results = Arc::clone(&results);

        let handle = tokio::spawn(async move {
            let _permit = match semaphore.acquire().await {
                Ok(permit) => permit,
                Err(e) => {
                    log_warn!("ICMP semaphore acquire failed for {}: {}", ip, e);
                    return;
                }
            };

            if let Some(icmp_result) = ping_host_with_retries(&client, ip).await {
                let mut res = results.lock().await;
                res.insert(ip, icmp_result);
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        if let Err(e) = handle.await {
            log_warn!("ICMP scan task failed: {}", e);
        }
    }

    let res = results.lock().await;
    log_stderr!("Phase 2 complete: {} hosts responded to ICMP", res.len());

    Ok(res.clone())
}
