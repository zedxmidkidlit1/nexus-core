//! Configuration constants for the Network Topology Mapper

use std::time::Duration;

/// Maximum concurrent ping operations (increased for speed)
pub const MAX_CONCURRENT_PINGS: usize = 200;

/// Timeout for each ICMP ping request (reduced from 2s)
pub const PING_TIMEOUT: Duration = Duration::from_millis(800);

/// Number of ping retries per host (reduced from 2)
pub const PING_RETRIES: u8 = 1;

/// Default subnet prefix length when interface doesn't provide one
pub const DEFAULT_PREFIX_LEN: u8 = 24;

/// Maximum hosts to scan (prevent scanning huge /20 subnets)
/// Set to 254 for typical /24 subnet, or 512 for /23
pub const MAX_SCAN_HOSTS: usize = 254;

// ====== ARP Adaptive Scan Configuration ======

/// Maximum total wait time for ARP replies (ms) - reduced
pub const ARP_MAX_WAIT_MS: u64 = 1200;

/// Interval to check for new hosts (ms)
pub const ARP_CHECK_INTERVAL_MS: u64 = 150;

/// Stop early if no new hosts for this duration (ms)
pub const ARP_IDLE_TIMEOUT_MS: u64 = 300;

/// Number of ARP scan rounds (reduced to 1 for speed)
pub const ARP_ROUNDS: u8 = 1;

/// TCP probe timeout (reduced from 500ms)
pub const TCP_PROBE_TIMEOUT: Duration = Duration::from_millis(300);

/// Common ports to probe for host detection (reduced list for speed)
/// Full list: [22, 80, 443, 445, 8080, 3389, 5353, 62078]
pub const TCP_PROBE_PORTS: &[u16] = &[22, 80, 443, 445, 3389];

// ====== SNMP Configuration (Optional Feature) ======

/// Enable SNMP enrichment for discovered hosts (disabled by default)
pub const SNMP_ENABLED: bool = false;

/// SNMP community string for v1/v2c
pub const SNMP_COMMUNITY: &str = "public";

/// SNMP query timeout
pub const SNMP_TIMEOUT: Duration = Duration::from_secs(1);

/// SNMP port
pub const SNMP_PORT: u16 = 161;

// ====== Monitoring Configuration ======

/// Default monitoring interval in seconds
pub const DEFAULT_MONITOR_INTERVAL: u64 = 60;

/// Minimum monitoring interval in seconds
pub const MIN_MONITOR_INTERVAL: u64 = 10;

/// Maximum monitoring interval in seconds
pub const MAX_MONITOR_INTERVAL: u64 = 3600;

/// Minutes without sightings before a known device is considered "came back online" when seen again.
pub const CAME_ONLINE_STALE_MINUTES: i64 = 30;

fn env_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn env_parse_u64(name: &str, default: u64, min: u64, max: u64) -> u64 {
    match env_var(name).and_then(|v| v.parse::<u64>().ok()) {
        Some(v) => v.clamp(min, max),
        None => default,
    }
}

fn env_parse_usize(name: &str, default: usize, min: usize, max: usize) -> usize {
    match env_var(name).and_then(|v| v.parse::<usize>().ok()) {
        Some(v) => v.clamp(min, max),
        None => default,
    }
}

fn env_parse_u16(name: &str, default: u16, min: u16, max: u16) -> u16 {
    match env_var(name).and_then(|v| v.parse::<u16>().ok()) {
        Some(v) => v.clamp(min, max),
        None => default,
    }
}

fn env_parse_u8(name: &str, default: u8, min: u8, max: u8) -> u8 {
    match env_var(name).and_then(|v| v.parse::<u8>().ok()) {
        Some(v) => v.clamp(min, max),
        None => default,
    }
}

fn env_parse_i64(name: &str, default: i64, min: i64, max: i64) -> i64 {
    match env_var(name).and_then(|v| v.parse::<i64>().ok()) {
        Some(v) => v.clamp(min, max),
        None => default,
    }
}

fn env_parse_bool(name: &str, default: bool) -> bool {
    match env_var(name) {
        Some(value) => {
            let normalized = value.to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
        }
        None => default,
    }
}

/// Runtime-tunable max concurrent probe/ping tasks.
/// Env: `NEXUS_MAX_CONCURRENT_PINGS`
pub fn max_concurrent_pings() -> usize {
    env_parse_usize("NEXUS_MAX_CONCURRENT_PINGS", MAX_CONCURRENT_PINGS, 8, 4096)
}

/// Runtime-tunable ICMP timeout.
/// Env: `NEXUS_PING_TIMEOUT_MS`
pub fn ping_timeout() -> Duration {
    Duration::from_millis(env_parse_u64(
        "NEXUS_PING_TIMEOUT_MS",
        PING_TIMEOUT.as_millis() as u64,
        50,
        10_000,
    ))
}

/// Runtime-tunable ICMP retry count.
/// Env: `NEXUS_PING_RETRIES`
pub fn ping_retries() -> u8 {
    env_parse_u8("NEXUS_PING_RETRIES", PING_RETRIES, 1, 5)
}

/// Runtime-tunable host cap for active scan target generation.
/// Env: `NEXUS_MAX_SCAN_HOSTS`
pub fn max_scan_hosts() -> usize {
    env_parse_usize("NEXUS_MAX_SCAN_HOSTS", MAX_SCAN_HOSTS, 8, 4096)
}

/// Runtime-tunable max ARP receive wait.
/// Env: `NEXUS_ARP_MAX_WAIT_MS`
pub fn arp_max_wait_ms() -> u64 {
    env_parse_u64("NEXUS_ARP_MAX_WAIT_MS", ARP_MAX_WAIT_MS, 100, 30_000)
}

/// Runtime-tunable ARP receiver poll interval.
/// Env: `NEXUS_ARP_CHECK_INTERVAL_MS`
pub fn arp_check_interval_ms() -> u64 {
    env_parse_u64(
        "NEXUS_ARP_CHECK_INTERVAL_MS",
        ARP_CHECK_INTERVAL_MS,
        10,
        5_000,
    )
}

/// Runtime-tunable ARP idle early-exit threshold.
/// Env: `NEXUS_ARP_IDLE_TIMEOUT_MS`
pub fn arp_idle_timeout_ms() -> u64 {
    env_parse_u64("NEXUS_ARP_IDLE_TIMEOUT_MS", ARP_IDLE_TIMEOUT_MS, 10, 10_000)
}

/// Runtime-tunable ARP round count.
/// Env: `NEXUS_ARP_ROUNDS`
pub fn arp_rounds() -> u8 {
    env_parse_u8("NEXUS_ARP_ROUNDS", ARP_ROUNDS, 1, 5)
}

/// Runtime-tunable TCP connect timeout.
/// Env: `NEXUS_TCP_PROBE_TIMEOUT_MS`
pub fn tcp_probe_timeout() -> Duration {
    Duration::from_millis(env_parse_u64(
        "NEXUS_TCP_PROBE_TIMEOUT_MS",
        TCP_PROBE_TIMEOUT.as_millis() as u64,
        50,
        10_000,
    ))
}

/// Runtime-tunable TCP probe port list.
/// Env: `NEXUS_TCP_PROBE_PORTS` (comma-separated, e.g. `22,80,443`)
pub fn tcp_probe_ports() -> Vec<u16> {
    if let Some(raw) = env_var("NEXUS_TCP_PROBE_PORTS") {
        let ports: Vec<u16> = raw
            .split(',')
            .filter_map(|p| p.trim().parse::<u16>().ok())
            .filter(|p| *p > 0)
            .collect();
        if !ports.is_empty() {
            return ports;
        }
    }
    TCP_PROBE_PORTS.to_vec()
}

/// Runtime-tunable SNMP feature switch.
/// Env: `NEXUS_SNMP_ENABLED`
pub fn snmp_enabled() -> bool {
    env_parse_bool("NEXUS_SNMP_ENABLED", SNMP_ENABLED)
}

/// Runtime-tunable SNMP community.
/// Env: `NEXUS_SNMP_COMMUNITY`
pub fn snmp_community() -> String {
    env_var("NEXUS_SNMP_COMMUNITY").unwrap_or_else(|| SNMP_COMMUNITY.to_string())
}

/// Runtime-tunable SNMP timeout.
/// Env: `NEXUS_SNMP_TIMEOUT_MS`
pub fn snmp_timeout() -> Duration {
    Duration::from_millis(env_parse_u64(
        "NEXUS_SNMP_TIMEOUT_MS",
        SNMP_TIMEOUT.as_millis() as u64,
        100,
        10_000,
    ))
}

/// Runtime-tunable SNMP port.
/// Env: `NEXUS_SNMP_PORT`
pub fn snmp_port() -> u16 {
    env_parse_u16("NEXUS_SNMP_PORT", SNMP_PORT, 1, u16::MAX)
}

/// Runtime-tunable default monitor interval.
/// Env: `NEXUS_DEFAULT_MONITOR_INTERVAL`
pub fn default_monitor_interval() -> u64 {
    env_parse_u64(
        "NEXUS_DEFAULT_MONITOR_INTERVAL",
        DEFAULT_MONITOR_INTERVAL,
        5,
        86_400,
    )
}

/// Runtime-tunable minimum monitor interval.
/// Env: `NEXUS_MIN_MONITOR_INTERVAL`
pub fn min_monitor_interval() -> u64 {
    env_parse_u64(
        "NEXUS_MIN_MONITOR_INTERVAL",
        MIN_MONITOR_INTERVAL,
        1,
        86_400,
    )
}

/// Runtime-tunable maximum monitor interval.
/// Env: `NEXUS_MAX_MONITOR_INTERVAL`
pub fn max_monitor_interval() -> u64 {
    env_parse_u64(
        "NEXUS_MAX_MONITOR_INTERVAL",
        MAX_MONITOR_INTERVAL,
        1,
        86_400,
    )
}

/// Runtime-tunable "came online" stale threshold in minutes.
/// Env: `NEXUS_CAME_ONLINE_STALE_MINUTES`
pub fn came_online_stale_minutes() -> i64 {
    env_parse_i64(
        "NEXUS_CAME_ONLINE_STALE_MINUTES",
        CAME_ONLINE_STALE_MINUTES,
        1,
        10_080,
    )
}
