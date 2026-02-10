//! Network interface detection and selection

use anyhow::{anyhow, Result};
use pnet::datalink;
use pnet::util::MacAddr;
use std::net::{IpAddr, Ipv4Addr};

use crate::models::InterfaceInfo;

/// Logs a message using structured tracing.
macro_rules! log_debug {
    ($($arg:tt)*) => {
        tracing::debug!("{}", format!($($arg)*));
    };
}

fn is_virtual_adapter_name(name_lower: &str) -> bool {
    name_lower.contains("hyper-v")
        || name_lower.contains("vmware")
        || name_lower.contains("virtualbox")
        || name_lower.contains("docker")
        || name_lower.contains("vethernet")
        || name_lower.contains("wsl")
}

fn collect_candidate_interfaces(
    pnet_interfaces: &[datalink::NetworkInterface],
    verbose: bool,
) -> Vec<InterfaceInfo> {
    let mut candidates: Vec<InterfaceInfo> = Vec::new();

    for pnet_if in pnet_interfaces {
        // Skip loopback interfaces.
        if pnet_if.is_loopback() {
            continue;
        }

        // On Windows/Npcap, `is_up()` can be false even for usable adapters.
        // Keep strict behavior on other OSes, but allow Windows adapters that
        // clearly have a non-zero IPv4 assignment.
        let has_usable_ipv4 = pnet_if.ips.iter().any(|ip_network| match ip_network.ip() {
            IpAddr::V4(ipv4) => {
                !ipv4.is_unspecified()
                    && ip_network.prefix() > 0
                    && !(ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254)
            }
            IpAddr::V6(_) => false,
        });
        if !pnet_if.is_up() && !(cfg!(target_os = "windows") && has_usable_ipv4) {
            if verbose {
                log_debug!("Skipping down adapter: {}", pnet_if.name);
            }
            continue;
        }

        // Skip interfaces without MAC
        let mac = match pnet_if.mac {
            Some(m) if m != MacAddr::zero() => m,
            _ => continue,
        };

        // Skip known virtual adapter patterns (Windows/macOS/Linux)
        let name_lower = pnet_if.name.to_lowercase();
        if is_virtual_adapter_name(&name_lower) {
            if verbose {
                log_debug!("Skipping virtual adapter: {}", pnet_if.name);
            }
            continue;
        }

        // Find IPv4 addresses
        for ip_network in &pnet_if.ips {
            if let IpAddr::V4(ipv4) = ip_network.ip() {
                // Skip unassigned placeholder addresses.
                if ipv4.is_unspecified() || ip_network.prefix() == 0 {
                    continue;
                }

                // Skip link-local (169.254.x.x)
                if ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254 {
                    continue;
                }

                let prefix_len = ip_network.prefix();

                if verbose {
                    log_debug!(
                        "Found candidate interface: {} (IP: {}/{}, MAC: {})",
                        pnet_if.name,
                        ipv4,
                        prefix_len,
                        mac
                    );
                }

                candidates.push(InterfaceInfo {
                    name: pnet_if.name.clone(),
                    ip: ipv4,
                    mac,
                    prefix_len,
                    pnet_interface: pnet_if.clone(),
                });
            }
        }
    }

    candidates
}

/// Finds the first valid IPv4 network interface with MAC address
/// Prefers physical adapters over virtual ones (Hyper-V, VMware, etc.)
pub fn find_valid_interface() -> Result<InterfaceInfo> {
    let pnet_interfaces = datalink::interfaces();

    log_debug!("Scanning {} network interfaces...", pnet_interfaces.len());

    let mut candidates = collect_candidate_interfaces(&pnet_interfaces, true);

    // Sort candidates: prefer 192.168.x.x, then 10.x.x.x, then others
    candidates.sort_by(|a, b| {
        let score_a = interface_score(&a.ip);
        let score_b = interface_score(&b.ip);
        score_b.cmp(&score_a)
    });

    if let Some(best) = candidates.into_iter().next() {
        log_debug!(
            "Selected interface: {} (IP: {}/{}, MAC: {})",
            best.name,
            best.ip,
            best.prefix_len,
            best.mac
        );
        return Ok(best);
    }

    // Debug output if no interface found
    tracing::warn!("No valid interface found. Available interfaces:");
    for pnet_if in &pnet_interfaces {
        tracing::warn!(
            "  - {} (loopback: {}, mac: {:?}, ips: {:?})",
            pnet_if.name,
            pnet_if.is_loopback(),
            pnet_if.mac,
            pnet_if.ips
        );
    }

    Err(anyhow!(
        "No valid IPv4 network interface found.\n\
         Ensure you have an active network connection."
    ))
}

/// List valid interface names in priority order.
pub fn list_valid_interfaces() -> Vec<String> {
    let pnet_interfaces = datalink::interfaces();
    let mut candidates = collect_candidate_interfaces(&pnet_interfaces, false);

    candidates.sort_by(|a, b| {
        let score_a = interface_score(&a.ip);
        let score_b = interface_score(&b.ip);
        score_b.cmp(&score_a)
    });

    let mut names = Vec::new();
    for candidate in candidates {
        if !names.iter().any(|n: &String| n == &candidate.name) {
            names.push(candidate.name);
        }
    }
    names
}

/// Scores an IP address for interface selection priority
pub fn interface_score(ip: &Ipv4Addr) -> u32 {
    let octets = ip.octets();
    match octets[0] {
        192 if octets[1] == 168 => 100, // 192.168.x.x - typical home/office LAN
        10 => 90,                       // 10.x.x.x - typical office LAN
        172 if octets[1] >= 16 && octets[1] <= 31 => 50, // 172.16-31.x.x - could be virtual
        _ => 70,                        // Other private IPs
    }
}
