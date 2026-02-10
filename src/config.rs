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
