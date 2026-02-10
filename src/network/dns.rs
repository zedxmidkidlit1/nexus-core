//! DNS Reverse Lookup for hostname resolution
//!
//! Resolves IP addresses to hostnames using reverse DNS queries.

use dns_lookup::lookup_addr;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::Semaphore;

/// Maximum concurrent DNS lookups
const MAX_CONCURRENT_DNS: usize = 10;

/// DNS lookup timeout (synchronous, so we use spawn_blocking)
const DNS_TIMEOUT_MS: u64 = 2000;

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

/// Perform reverse DNS lookup for a single IP address
pub fn reverse_lookup(ip: Ipv4Addr) -> Option<String> {
    let ip_addr = IpAddr::V4(ip);
    match lookup_addr(&ip_addr) {
        Ok(hostname) => {
            // Don't return if hostname is just the IP address
            if hostname != ip.to_string() {
                Some(hostname)
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

/// Perform reverse DNS lookup for multiple IP addresses concurrently
pub async fn dns_scan(ips: &[Ipv4Addr]) -> HashMap<Ipv4Addr, String> {
    if ips.is_empty() {
        return HashMap::new();
    }

    log_stderr!("Phase 5: DNS reverse lookup for {} hosts...", ips.len());

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_DNS));
    let results = Arc::new(Mutex::new(HashMap::new()));

    let mut handles = Vec::new();

    for &ip in ips {
        let semaphore = Arc::clone(&semaphore);
        let results = Arc::clone(&results);

        let handle = tokio::spawn(async move {
            let _permit = match semaphore.acquire().await {
                Ok(permit) => permit,
                Err(e) => {
                    log_warn!("DNS semaphore acquire failed for {}: {}", ip, e);
                    return;
                }
            };

            // Run DNS lookup in blocking thread with timeout
            let lookup_result = tokio::time::timeout(
                Duration::from_millis(DNS_TIMEOUT_MS),
                tokio::task::spawn_blocking(move || reverse_lookup(ip)),
            )
            .await;

            match lookup_result {
                Ok(Ok(Some(hostname))) => {
                    let mut res = results.lock().await;
                    res.insert(ip, hostname);
                }
                Ok(Ok(None)) => {}
                Ok(Err(e)) => {
                    log_warn!("DNS worker join failed for {}: {}", ip, e);
                }
                Err(_) => {}
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        if let Err(e) = handle.await {
            log_warn!("DNS scan task failed: {}", e);
        }
    }

    let res = results.lock().await;
    log_stderr!("Phase 5 complete: {} hostnames resolved", res.len());

    res.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reverse_lookup_localhost() {
        let result = reverse_lookup(Ipv4Addr::new(127, 0, 0, 1));
        println!("Localhost reverse lookup: {:?}", result);
        // Usually returns "localhost" or similar
    }
}
