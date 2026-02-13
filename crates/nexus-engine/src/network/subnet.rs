//! Subnet calculation and utilities

use anyhow::{Context, Result};
use ipnetwork::Ipv4Network;
use std::net::Ipv4Addr;

use crate::config::max_scan_hosts;
use crate::models::InterfaceInfo;

/// Prefix lengths below this threshold are treated as large subnets.
const LARGE_SUBNET_PREFIX_THRESHOLD: u8 = 24;
/// Hard cap for large subnets to keep scans responsive.
const LARGE_SUBNET_MAX_HOSTS: usize = 32;

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

/// Checks if an IP address is a network or broadcast address
pub fn is_special_address(ip: Ipv4Addr, subnet: &Ipv4Network) -> bool {
    ip == subnet.network() || ip == subnet.broadcast()
}

/// Checks if a target IP is in the same subnet as the local interface (L2 reachable)
/// Returns true if target is local (ARP will work), false if remote (needs L3 routing)
pub fn is_local_subnet(target_ip: Ipv4Addr, local_interface: &InterfaceInfo) -> bool {
    if let Ok(local_network) = Ipv4Network::new(local_interface.ip, local_interface.prefix_len) {
        local_network.contains(target_ip)
    } else {
        false
    }
}

/// Calculates the subnet range and generates the list of target IPs
/// Applies runtime host caps to prevent scanning huge subnets.
pub fn calculate_subnet_ips(interface: &InterfaceInfo) -> Result<(Ipv4Network, Vec<Ipv4Addr>)> {
    let network = Ipv4Network::new(interface.ip, interface.prefix_len)
        .context("Failed to create network from interface IP and prefix")?;

    let subnet = Ipv4Network::new(network.network(), interface.prefix_len)
        .context("Failed to create subnet network")?;

    // Exclude network and broadcast addresses
    let all_ips: Vec<Ipv4Addr> = subnet
        .iter()
        .filter(|ip| !is_special_address(*ip, &subnet))
        .collect();

    // Limit host count for performance. Large subnets get a tighter cap to keep
    // scan latency bounded on slow virtual adapters.
    let host_cap = if interface.prefix_len < LARGE_SUBNET_PREFIX_THRESHOLD {
        LARGE_SUBNET_MAX_HOSTS
    } else {
        max_scan_hosts()
    };

    let ips = if all_ips.len() > host_cap {
        log_warn!(
            "Subnet {} has {} hosts, limiting scan to {} hosts",
            subnet,
            all_ips.len(),
            host_cap
        );
        // Center the scan window around the local IP index within the subnet host list.
        let center_index = all_ips
            .iter()
            .position(|ip| *ip == interface.ip)
            .unwrap_or(all_ips.len() / 2);
        let half_window = host_cap / 2;

        let mut start = center_index.saturating_sub(half_window);
        if start + host_cap > all_ips.len() {
            start = all_ips.len().saturating_sub(host_cap);
        }

        all_ips.into_iter().skip(start).take(host_cap).collect()
    } else {
        all_ips
    };

    log_stderr!(
        "Calculated subnet: {} with {} scannable hosts",
        subnet,
        ips.len()
    );

    Ok((subnet, ips))
}

#[cfg(test)]
#[path = "subnet_tests.rs"]
mod subnet_tests;
