//! Background network watcher
//!
//! Provides continuous network scanning in background thread
//! Uses callbacks for event notification (Tauri-agnostic)

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use super::events::{DeviceSnapshot, MonitoringStatus, NetworkEvent};
use super::passive_integration::{passive_device_to_snapshot, start_passive_listeners};
use crate::config::{DEFAULT_MONITOR_INTERVAL, MAX_MONITOR_INTERVAL, MIN_MONITOR_INTERVAL};
use crate::{
    InterfaceInfo, active_arp_scan, calculate_subnet_ips, dns_scan, find_interface_by_name,
    find_valid_interface, infer_device_type, lookup_vendor_info, tcp_probe_scan,
};

const OFFLINE_RETENTION_SECS: u64 = 3600;
const BACKGROUND_ARP_PHASE_TIMEOUT_SECS: u64 = 15;

#[derive(Debug, Clone)]
struct OfflineDeviceSnapshot {
    device: DeviceSnapshot,
    since: Instant,
}

/// Event callback type
pub type EventCallback = Arc<dyn Fn(NetworkEvent) + Send + Sync>;

/// Background network monitor
pub struct BackgroundMonitor {
    is_running: Arc<AtomicBool>,
    interval_seconds: Arc<Mutex<u64>>,
    scan_count: Arc<AtomicU32>,
    last_scan_time: Arc<Mutex<Option<String>>>,
    /// Current online devices from previous scan (MAC -> DeviceSnapshot)
    previous_devices: Arc<Mutex<HashMap<String, DeviceSnapshot>>>,
    /// Recently-offline devices for "came online" event correlation.
    offline_devices: Arc<Mutex<HashMap<String, OfflineDeviceSnapshot>>>,
    /// Live passive discoveries from mDNS/ARP listeners.
    passive_devices: Arc<Mutex<HashMap<String, DeviceSnapshot>>>,
    /// Session-wide unique device identities seen across all scans.
    unique_devices_seen: Arc<Mutex<HashSet<String>>>,
    /// Active interface selected for the current monitor session.
    selected_interface_name: Arc<Mutex<Option<String>>>,
}

impl BackgroundMonitor {
    pub fn new() -> Self {
        Self {
            is_running: Arc::new(AtomicBool::new(false)),
            interval_seconds: Arc::new(Mutex::new(DEFAULT_MONITOR_INTERVAL)),
            scan_count: Arc::new(AtomicU32::new(0)),
            last_scan_time: Arc::new(Mutex::new(None)),
            previous_devices: Arc::new(Mutex::new(HashMap::new())),
            offline_devices: Arc::new(Mutex::new(HashMap::new())),
            passive_devices: Arc::new(Mutex::new(HashMap::new())),
            unique_devices_seen: Arc::new(Mutex::new(HashSet::new())),
            selected_interface_name: Arc::new(Mutex::new(None)),
        }
    }

    /// Start background monitoring with event callback
    pub async fn start<F>(&self, callback: F, interval: Option<u64>) -> Result<(), String>
    where
        F: Fn(NetworkEvent) + Send + Sync + 'static,
    {
        self.start_with_interface(callback, interval, None).await
    }

    /// Start background monitoring pinned to a single interface.
    ///
    /// If `interface_name` is `None`, the best valid interface is selected once
    /// at start time and reused for the full monitoring session.
    pub async fn start_with_interface<F>(
        &self,
        callback: F,
        interval: Option<u64>,
        interface_name: Option<String>,
    ) -> Result<(), String>
    where
        F: Fn(NetworkEvent) + Send + Sync + 'static,
    {
        let requested_interval = interval
            .unwrap_or(DEFAULT_MONITOR_INTERVAL)
            .clamp(MIN_MONITOR_INTERVAL, MAX_MONITOR_INTERVAL);

        if self.is_running.load(Ordering::SeqCst) {
            // Idempotent start: keep current loop and optionally update interval.
            *self.interval_seconds.lock().await = requested_interval;
            if let Some(requested) = interface_name.as_deref()
                && let Some(current) = self.selected_interface_name.lock().await.clone()
                && !current.eq_ignore_ascii_case(requested)
            {
                return Err(format!(
                    "Monitoring is already running on interface '{}'. Stop it before switching to '{}'.",
                    current, requested
                ));
            }
            return Ok(());
        }

        let interval_secs = requested_interval;
        let selected_interface = resolve_monitor_interface(interface_name.as_deref())?;

        *self.interval_seconds.lock().await = interval_secs;
        *self.selected_interface_name.lock().await = Some(selected_interface.name.clone());
        self.is_running.store(true, Ordering::SeqCst);
        self.scan_count.store(0, Ordering::SeqCst);
        self.unique_devices_seen.lock().await.clear();
        self.previous_devices.lock().await.clear();
        self.offline_devices.lock().await.clear();
        self.passive_devices.lock().await.clear();

        // Wrap callback in Arc
        let callback = Arc::new(callback);

        // Emit monitoring started event
        callback(NetworkEvent::MonitoringStarted {
            interval_seconds: interval_secs,
        });

        // Clone Arc references for the spawned task
        let is_running = Arc::clone(&self.is_running);
        let scan_count = Arc::clone(&self.scan_count);
        let last_scan_time = Arc::clone(&self.last_scan_time);
        let previous_devices = Arc::clone(&self.previous_devices);
        let offline_devices = Arc::clone(&self.offline_devices);
        let passive_devices = Arc::clone(&self.passive_devices);
        let unique_devices_seen = Arc::clone(&self.unique_devices_seen);
        let interval_seconds = Arc::clone(&self.interval_seconds);
        let selected_interface_name = Arc::clone(&self.selected_interface_name);
        let scan_interface = selected_interface.clone();
        let cb = Arc::clone(&callback);

        // Start passive listeners (best-effort) and merge into the monitor state.
        let is_running_for_passive = Arc::clone(&self.is_running);
        let passive_map = Arc::clone(&self.passive_devices);
        let unique_for_passive = Arc::clone(&self.unique_devices_seen);
        let cb_passive = Arc::clone(&callback);

        match start_passive_listeners(&scan_interface.pnet_interface).await {
            Ok((mut mdns_rx, mut arp_rx_opt)) => {
                tokio::spawn(async move {
                    let mut arp_ip_to_mac: HashMap<String, String> = HashMap::new();

                    tracing::info!("[MONITOR] Passive listener bridge started");

                    while is_running_for_passive.load(Ordering::SeqCst) {
                        tokio::select! {
                            mdns_device = mdns_rx.recv() => {
                                match mdns_device {
                                    Some(device) => {
                                        let mut snapshot = passive_device_to_snapshot(device);
                                        if let Some(mac) = arp_ip_to_mac.get(&snapshot.ip) {
                                            snapshot.mac = mac.clone();
                                        }
                                        upsert_passive_device(
                                            &passive_map,
                                            &unique_for_passive,
                                            snapshot,
                                            &*cb_passive,
                                        )
                                        .await;
                                    }
                                    None => break,
                                }
                            }
                            arp_event = async {
                                if let Some(rx) = arp_rx_opt.as_mut() {
                                    rx.recv().await
                                } else {
                                    tokio::time::sleep(Duration::from_millis(500)).await;
                                    None
                                }
                            } => {
                                if let Some(event) = arp_event {
                                    arp_ip_to_mac.insert(event.sender_ip.clone(), event.sender_mac.clone());
                                    apply_arp_enrichment(
                                        &passive_map,
                                        &unique_for_passive,
                                        &event.sender_ip,
                                        &event.sender_mac,
                                    )
                                    .await;
                                } else if arp_rx_opt.is_some() {
                                    tracing::warn!("[MONITOR] ARP passive channel closed");
                                    arp_rx_opt = None;
                                }
                            }
                            _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                        }
                    }

                    tracing::info!("[MONITOR] Passive listener bridge stopped");
                });
            }
            Err(e) => {
                tracing::warn!("[MONITOR] Passive listeners unavailable: {}", e);
            }
        }

        // Spawn background scanning task
        tokio::spawn(async move {
            tracing::info!(
                "[MONITOR] Background monitoring started (interval: {}s)",
                interval_secs
            );

            while is_running.load(Ordering::SeqCst) {
                let current_scan = scan_count.fetch_add(1, Ordering::SeqCst) + 1;
                let interval = *interval_seconds.lock().await;

                // Emit scan started
                (*cb)(NetworkEvent::ScanStarted {
                    scan_number: current_scan,
                });

                tracing::debug!("[MONITOR] Starting scan #{}", current_scan);
                let start = Instant::now();

                // Run the actual scan
                match run_background_scan(&*cb, &scan_interface).await {
                    Ok(devices) => {
                        let merged_devices =
                            merge_active_and_passive_devices(devices, &passive_devices).await;
                        let duration = start.elapsed().as_millis() as u64;

                        // Update last scan time
                        *last_scan_time.lock().await = Some(chrono::Utc::now().to_rfc3339());

                        // Detect changes
                        let mut prev = previous_devices.lock().await;
                        let mut offline = offline_devices.lock().await;
                        let mut unique = unique_devices_seen.lock().await;
                        detect_and_emit_changes(
                            &*cb,
                            &mut prev,
                            &mut offline,
                            &mut unique,
                            &merged_devices,
                        );

                        // Emit scan completed
                        (*cb)(NetworkEvent::ScanCompleted {
                            scan_number: current_scan,
                            hosts_found: merged_devices.len(),
                            duration_ms: duration,
                        });

                        tracing::debug!(
                            "[MONITOR] Scan #{} complete: {} hosts in {}ms",
                            current_scan,
                            merged_devices.len(),
                            duration
                        );
                    }
                    Err(e) => {
                        tracing::warn!("[MONITOR] Scan #{} failed: {}", current_scan, e);
                        (*cb)(NetworkEvent::MonitoringError { message: e });
                    }
                }

                // Wait for next interval (check every second to allow quick stop)
                for _ in 0..interval {
                    if !is_running.load(Ordering::SeqCst) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }

            tracing::info!("[MONITOR] Background monitoring stopped");
            *selected_interface_name.lock().await = None;
            (*cb)(NetworkEvent::MonitoringStopped);
        });

        Ok(())
    }

    /// Stop background monitoring
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);
    }

    /// Get current monitoring status
    pub async fn status(&self) -> MonitoringStatus {
        let online_count = self.previous_devices.lock().await.len();
        let total_seen = self.unique_devices_seen.lock().await.len();

        MonitoringStatus {
            is_running: self.is_running.load(Ordering::SeqCst),
            interval_seconds: *self.interval_seconds.lock().await,
            scan_count: self.scan_count.load(Ordering::SeqCst),
            last_scan_time: self.last_scan_time.lock().await.clone(),
            devices_online: online_count,
            devices_total: total_seen,
        }
    }

    /// Check if monitoring is running
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    /// Selected monitor interface name for current session (if running).
    pub async fn selected_interface(&self) -> Option<String> {
        self.selected_interface_name.lock().await.clone()
    }
}

impl Default for BackgroundMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Run a background scan and return device snapshots
fn resolve_monitor_interface(interface_name: Option<&str>) -> Result<InterfaceInfo, String> {
    if let Some(name) = interface_name {
        find_interface_by_name(name)
            .map_err(|e| format!("Requested interface '{}' is unavailable: {}", name, e))
    } else {
        find_valid_interface().map_err(|e| format!("Interface error: {}", e))
    }
}

async fn run_background_scan<F>(
    callback: &F,
    interface: &InterfaceInfo,
) -> Result<Vec<DeviceSnapshot>, String>
where
    F: Fn(NetworkEvent),
{
    // Emit progress: Finding interface
    callback(NetworkEvent::ScanProgress {
        phase: "INIT".to_string(),
        percent: 5,
        message: format!("Using interface {} ({})", interface.name, interface.ip),
    });

    let (subnet, ips) =
        calculate_subnet_ips(interface).map_err(|e| format!("Subnet error: {}", e))?;

    // Emit progress: ARP scan
    callback(NetworkEvent::ScanProgress {
        phase: "ARP".to_string(),
        percent: 20,
        message: format!("ARP scanning {} hosts...", ips.len()),
    });

    let arp_scan_handle = {
        let interface_clone = interface.clone();
        let ips_clone = ips.clone();
        let subnet_clone = subnet;

        tokio::task::spawn_blocking(move || {
            active_arp_scan(&interface_clone, &ips_clone, &subnet_clone)
        })
    };

    let arp_hosts = match tokio::time::timeout(
        Duration::from_secs(BACKGROUND_ARP_PHASE_TIMEOUT_SECS),
        arp_scan_handle,
    )
    .await
    {
        Ok(joined) => joined
            .map_err(|e| format!("ARP task error: {}", e))?
            .map_err(|e| format!("ARP scan error: {}", e))?,
        Err(_) => {
            tracing::warn!(
                "[MONITOR] ARP phase exceeded {}s timeout; continuing with empty ARP host set",
                BACKGROUND_ARP_PHASE_TIMEOUT_SECS
            );
            HashMap::new()
        }
    };

    // Emit progress: TCP scan
    callback(NetworkEvent::ScanProgress {
        phase: "TCP".to_string(),
        percent: 50,
        message: format!("TCP probing {} hosts...", arp_hosts.len()),
    });

    let port_results = tcp_probe_scan(&arp_hosts)
        .await
        .map_err(|e| format!("TCP scan error: {}", e))?;

    // Emit progress: DNS lookup
    callback(NetworkEvent::ScanProgress {
        phase: "DNS".to_string(),
        percent: 80,
        message: "Resolving hostnames...".to_string(),
    });

    let host_ips: Vec<std::net::Ipv4Addr> = arp_hosts
        .keys()
        .filter(|ip| **ip != interface.ip)
        .copied()
        .collect();

    let dns_hostnames = dns_scan(&host_ips).await;

    // Build device snapshots
    callback(NetworkEvent::ScanProgress {
        phase: "COMPLETE".to_string(),
        percent: 100,
        message: "Scan complete".to_string(),
    });

    let devices: Vec<DeviceSnapshot> = arp_hosts
        .iter()
        .filter(|(ip, _)| **ip != interface.ip)
        .map(|(ip, mac)| {
            let mac_str = format!("{}", mac);
            let vendor_info = lookup_vendor_info(&mac_str);
            let open_ports = port_results.get(ip).cloned().unwrap_or_default();
            let is_gateway = ip.octets()[3] == 1 || open_ports.contains(&80);

            let device_type = infer_device_type(
                vendor_info.vendor.as_deref(),
                dns_hostnames.get(ip).map(|s| s.as_str()),
                &open_ports,
                is_gateway,
            );

            DeviceSnapshot {
                mac: mac_str,
                ip: ip.to_string(),
                hostname: dns_hostnames.get(ip).cloned(),
                device_type: device_type.as_str().to_string(),
                is_online: true,
            }
        })
        .collect();

    Ok(devices)
}

fn is_unknown_passive_mac(mac: &str) -> bool {
    mac.starts_with("unknown_")
}

async fn upsert_passive_device<F>(
    passive_devices: &Arc<Mutex<HashMap<String, DeviceSnapshot>>>,
    unique_devices_seen: &Arc<Mutex<HashSet<String>>>,
    snapshot: DeviceSnapshot,
    callback: &F,
) where
    F: Fn(NetworkEvent),
{
    let key = snapshot.mac.clone();

    let mut map = passive_devices.lock().await;
    let is_new = !map.contains_key(&key);
    map.insert(key, snapshot.clone());
    drop(map);
    let should_emit_new = unique_devices_seen
        .lock()
        .await
        .insert(snapshot.mac.clone());

    if is_new && should_emit_new {
        callback(NetworkEvent::NewDeviceDiscovered {
            ip: snapshot.ip,
            mac: snapshot.mac,
            hostname: snapshot.hostname,
            device_type: snapshot.device_type,
        });
    }
}

async fn apply_arp_enrichment(
    passive_devices: &Arc<Mutex<HashMap<String, DeviceSnapshot>>>,
    unique_devices_seen: &Arc<Mutex<HashSet<String>>>,
    sender_ip: &str,
    sender_mac: &str,
) {
    let mut map = passive_devices.lock().await;
    let matching_keys: Vec<(String, bool)> = map
        .iter()
        .filter(|(_, snapshot)| snapshot.ip == sender_ip && snapshot.mac != sender_mac)
        .map(|(key, _)| (key.clone(), is_unknown_passive_mac(key)))
        .collect();

    let mut replaced_unknown_keys = Vec::new();
    for (old_key, was_unknown) in matching_keys {
        if let Some(mut snapshot) = map.remove(&old_key) {
            if was_unknown {
                replaced_unknown_keys.push(old_key.clone());
            }
            snapshot.mac = sender_mac.to_string();
            if let Some(existing) = map.get_mut(sender_mac) {
                if existing.hostname.is_none() {
                    existing.hostname = snapshot.hostname.take();
                }
                if existing.device_type.eq_ignore_ascii_case("unknown")
                    && !snapshot.device_type.eq_ignore_ascii_case("unknown")
                {
                    existing.device_type = snapshot.device_type;
                }
            } else {
                map.insert(snapshot.mac.clone(), snapshot);
            }
        }
    }
    drop(map);

    if !replaced_unknown_keys.is_empty() {
        let mut unique = unique_devices_seen.lock().await;
        for old_key in replaced_unknown_keys {
            unique.remove(&old_key);
        }
        unique.insert(sender_mac.to_string());
    }
}

async fn merge_active_and_passive_devices(
    active_devices: Vec<DeviceSnapshot>,
    passive_devices: &Arc<Mutex<HashMap<String, DeviceSnapshot>>>,
) -> Vec<DeviceSnapshot> {
    let passive = passive_devices.lock().await;
    let mut merged = active_devices;

    let mut seen_macs: HashSet<String> = merged.iter().map(|d| d.mac.clone()).collect();
    let mut seen_ips: HashSet<String> = merged.iter().map(|d| d.ip.clone()).collect();

    for snapshot in passive.values() {
        if seen_macs.contains(&snapshot.mac) {
            continue;
        }

        // Unknown passive MACs are treated as soft identities; skip them when active scan already has same IP.
        if is_unknown_passive_mac(&snapshot.mac) && seen_ips.contains(&snapshot.ip) {
            continue;
        }

        merged.push(snapshot.clone());
        seen_macs.insert(snapshot.mac.clone());
        seen_ips.insert(snapshot.ip.clone());
    }

    merged
}

/// Detect changes between scans and emit events
fn detect_and_emit_changes<F>(
    callback: &F,
    previous_online: &mut HashMap<String, DeviceSnapshot>,
    offline_devices: &mut HashMap<String, OfflineDeviceSnapshot>,
    unique_devices_seen: &mut HashSet<String>,
    current: &[DeviceSnapshot],
) where
    F: Fn(NetworkEvent),
{
    let now = Instant::now();
    offline_devices
        .retain(|_, snap| now.duration_since(snap.since).as_secs() <= OFFLINE_RETENTION_SECS);

    let current_macs: HashMap<String, &DeviceSnapshot> =
        current.iter().map(|d| (d.mac.clone(), d)).collect();

    // Check for offline devices (known online previously, now missing).
    for (mac, prev_device) in previous_online.iter() {
        if !current_macs.contains_key(mac) {
            tracing::debug!("[MONITOR] Device offline: {} ({})", prev_device.ip, mac);
            callback(NetworkEvent::DeviceWentOffline {
                mac: mac.clone(),
                last_ip: prev_device.ip.clone(),
                hostname: prev_device.hostname.clone(),
            });
            offline_devices.insert(
                mac.clone(),
                OfflineDeviceSnapshot {
                    device: prev_device.clone(),
                    since: now,
                },
            );
        }
    }

    // Build next online device map while emitting change events.
    let mut next_online: HashMap<String, DeviceSnapshot> = HashMap::with_capacity(current.len());

    for device in current {
        if let Some(prev_device) = previous_online.get(&device.mac) {
            if prev_device.ip != device.ip {
                tracing::debug!(
                    "[MONITOR] IP changed: {} -> {} ({})",
                    prev_device.ip,
                    device.ip,
                    device.mac
                );
                callback(NetworkEvent::DeviceIpChanged {
                    mac: device.mac.clone(),
                    old_ip: prev_device.ip.clone(),
                    new_ip: device.ip.clone(),
                });
            }
        } else if let Some(was_offline) = offline_devices.remove(&device.mac) {
            tracing::debug!(
                "[MONITOR] Device back online: {} ({})",
                device.ip,
                device.mac
            );
            callback(NetworkEvent::DeviceCameOnline {
                mac: device.mac.clone(),
                ip: device.ip.clone(),
                hostname: device.hostname.clone(),
            });

            if was_offline.device.ip != device.ip {
                tracing::debug!(
                    "[MONITOR] IP changed while offline: {} -> {} ({})",
                    was_offline.device.ip,
                    device.ip,
                    device.mac
                );
                callback(NetworkEvent::DeviceIpChanged {
                    mac: device.mac.clone(),
                    old_ip: was_offline.device.ip,
                    new_ip: device.ip.clone(),
                });
            }
        } else if unique_devices_seen.insert(device.mac.clone()) {
            tracing::debug!("[MONITOR] New device: {} ({})", device.ip, device.mac);
            callback(NetworkEvent::NewDeviceDiscovered {
                ip: device.ip.clone(),
                mac: device.mac.clone(),
                hostname: device.hostname.clone(),
                device_type: device.device_type.clone(),
            });
        }

        unique_devices_seen.insert(device.mac.clone());
        next_online.insert(device.mac.clone(), device.clone());
    }

    *previous_online = next_online;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc as StdArc, Mutex as StdMutex};

    #[test]
    fn detect_changes_skips_duplicate_new_event_for_already_seen_mac() {
        let events: StdArc<StdMutex<Vec<NetworkEvent>>> = StdArc::new(StdMutex::new(Vec::new()));
        let events_capture = StdArc::clone(&events);
        let callback = move |event: NetworkEvent| {
            events_capture.lock().expect("event lock").push(event);
        };

        let current = vec![DeviceSnapshot {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            ip: "192.168.1.50".to_string(),
            hostname: Some("passive-device".to_string()),
            device_type: "UNKNOWN".to_string(),
            is_online: true,
        }];

        let mut previous_online: HashMap<String, DeviceSnapshot> = HashMap::new();
        let mut offline_devices: HashMap<String, OfflineDeviceSnapshot> = HashMap::new();
        let mut unique_devices_seen: HashSet<String> =
            HashSet::from(["AA:BB:CC:DD:EE:FF".to_string()]);

        detect_and_emit_changes(
            &callback,
            &mut previous_online,
            &mut offline_devices,
            &mut unique_devices_seen,
            &current,
        );

        let events = events.lock().expect("event lock");
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, NetworkEvent::NewDeviceDiscovered { .. })),
            "new-device event should be deduped when MAC is already seen"
        );
    }

    #[tokio::test]
    async fn arp_enrichment_reconciles_unknown_identity_in_unique_set() {
        let passive_devices = Arc::new(Mutex::new(HashMap::from([(
            "unknown_192.168.1.77".to_string(),
            DeviceSnapshot {
                mac: "unknown_192.168.1.77".to_string(),
                ip: "192.168.1.77".to_string(),
                hostname: Some("mdns-device".to_string()),
                device_type: "Unknown".to_string(),
                is_online: true,
            },
        )])));
        let unique_devices_seen = Arc::new(Mutex::new(HashSet::from([
            "unknown_192.168.1.77".to_string()
        ])));

        apply_arp_enrichment(
            &passive_devices,
            &unique_devices_seen,
            "192.168.1.77",
            "AA:BB:CC:DD:EE:77",
        )
        .await;

        let map = passive_devices.lock().await;
        assert!(map.contains_key("AA:BB:CC:DD:EE:77"));
        assert!(!map.contains_key("unknown_192.168.1.77"));
        drop(map);

        let unique = unique_devices_seen.lock().await;
        assert!(unique.contains("AA:BB:CC:DD:EE:77"));
        assert!(!unique.contains("unknown_192.168.1.77"));
    }
}
