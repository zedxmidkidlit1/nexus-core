//! Active ARP scanning with adaptive timing

use anyhow::{anyhow, Result};
use ipnetwork::Ipv4Network;
use pnet::datalink::{self, Channel};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{ARP_CHECK_INTERVAL_MS, ARP_IDLE_TIMEOUT_MS, ARP_MAX_WAIT_MS, ARP_ROUNDS};
use crate::models::InterfaceInfo;
use crate::network::is_special_address;

/// Broadcast MAC address for ARP requests
const BROADCAST_MAC: MacAddr = MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

/// Logs a message to stderr
macro_rules! log_stderr {
    ($($arg:tt)*) => {
        tracing::info!($($arg)*);
    };
}

/// Creates an ARP request packet
fn create_arp_request(
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; 42];

    // Build Ethernet frame
    {
        let mut ethernet_packet = MutableEthernetPacket::new(&mut buffer[..14])
            .ok_or_else(|| anyhow!("Failed to construct Ethernet packet buffer"))?;
        ethernet_packet.set_destination(BROADCAST_MAC);
        ethernet_packet.set_source(source_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);
    }

    // Build ARP packet
    {
        let mut arp_packet = MutableArpPacket::new(&mut buffer[14..42])
            .ok_or_else(|| anyhow!("Failed to construct ARP packet buffer"))?;
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(source_mac);
        arp_packet.set_sender_proto_addr(source_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip);
    }

    Ok(buffer)
}

/// Performs Adaptive ARP scan with early termination
pub fn active_arp_scan(
    interface: &InterfaceInfo,
    target_ips: &[Ipv4Addr],
    subnet: &Ipv4Network,
) -> Result<HashMap<Ipv4Addr, MacAddr>> {
    log_stderr!(
        "Phase 1: Active ARP scanning {} hosts (adaptive timing)...",
        target_ips.len()
    );

    // Open datalink channel
    let (mut tx, mut rx) = match datalink::channel(&interface.pnet_interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(anyhow!("Unsupported channel type")),
        Err(e) => {
            let error_msg = format!("{}", e);
            if error_msg.contains("requires")
                || error_msg.contains("permission")
                || error_msg.contains("Access")
                || error_msg.contains("Npcap")
                || error_msg.contains("WinPcap")
            {
                return Err(anyhow!(
                    "Failed to open network interface for ARP scanning.\n\n\
                     On Windows, this requires Npcap to be installed:\n\
                     1. Download from: https://npcap.com/#download\n\
                     2. Install with 'WinPcap API-compatible Mode' checked\n\
                     3. Run this program as Administrator\n\n\
                     Original error: {}",
                    e
                ));
            }
            return Err(anyhow!("Failed to open datalink channel: {}", e));
        }
    };

    let discovered: Arc<std::sync::Mutex<HashMap<Ipv4Addr, MacAddr>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));
    let host_count = Arc::new(AtomicUsize::new(0));
    let scan_start = Instant::now();

    // Calculate total timeout for receiver thread (all rounds + buffer)
    let total_timeout = Duration::from_millis(ARP_MAX_WAIT_MS * ARP_ROUNDS as u64 + 500);

    let discovered_clone = Arc::clone(&discovered);
    let host_count_clone = Arc::clone(&host_count);
    let subnet_clone = *subnet;

    // Start receiver thread
    let receiver_handle = std::thread::spawn(move || {
        let deadline = Instant::now() + total_timeout;

        while Instant::now() < deadline {
            match rx.next() {
                Ok(packet) => {
                    if let Some(ethernet) = EthernetPacket::new(packet) {
                        if ethernet.get_ethertype() == EtherTypes::Arp {
                            if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                                if arp.get_operation() == ArpOperations::Reply {
                                    let sender_ip = arp.get_sender_proto_addr();
                                    let sender_mac = arp.get_sender_hw_addr();

                                    if subnet_clone.contains(sender_ip)
                                        && !is_special_address(sender_ip, &subnet_clone)
                                    {
                                        let mut map = match discovered_clone.lock() {
                                            Ok(map) => map,
                                            Err(_) => {
                                                log_stderr!(
                                                    "ARP receiver map lock poisoned; stopping receiver thread"
                                                );
                                                break;
                                            }
                                        };
                                        if let std::collections::hash_map::Entry::Vacant(e) =
                                            map.entry(sender_ip)
                                        {
                                            e.insert(sender_mac);
                                            host_count_clone.fetch_add(1, Ordering::SeqCst);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    std::thread::sleep(Duration::from_micros(50));
                }
            }
        }
    });

    // Give receiver time to start
    std::thread::sleep(Duration::from_millis(10));

    // Adaptive ARP scan rounds
    for round in 1..=ARP_ROUNDS {
        let round_start = Instant::now();
        let initial_count = host_count.load(Ordering::SeqCst);

        // Get remaining IPs to scan
        let remaining: Vec<Ipv4Addr> = {
            let discovered_map = discovered
                .lock()
                .map_err(|_| anyhow!("ARP discovered-host map lock poisoned"))?;
            target_ips
                .iter()
                .filter(|ip| !discovered_map.contains_key(ip))
                .copied()
                .collect()
        };

        if remaining.is_empty() {
            log_stderr!("Round {}/{}: All hosts found, skipping", round, ARP_ROUNDS);
            break;
        }

        log_stderr!(
            "Round {}/{}: Blasting {} requests ({} already found)...",
            round,
            ARP_ROUNDS,
            remaining.len(),
            initial_count
        );

        // BLAST: Send all requests as fast as possible
        for target_ip in &remaining {
            match create_arp_request(interface.mac, interface.ip, *target_ip) {
                Ok(packet) => {
                    let _ = tx.send_to(&packet, None);
                }
                Err(e) => {
                    log_stderr!("Failed to create ARP request for {}: {}", target_ip, e);
                }
            }
        }

        // ADAPTIVE WAIT: Check periodically, stop early if idle
        let max_wait = Duration::from_millis(ARP_MAX_WAIT_MS);
        let check_interval = Duration::from_millis(ARP_CHECK_INTERVAL_MS);
        let idle_timeout = Duration::from_millis(ARP_IDLE_TIMEOUT_MS);

        let mut last_count = host_count.load(Ordering::SeqCst);
        let mut last_change = Instant::now();

        while round_start.elapsed() < max_wait {
            std::thread::sleep(check_interval);

            let current_count = host_count.load(Ordering::SeqCst);

            if current_count > last_count {
                // New hosts found, reset idle timer
                last_count = current_count;
                last_change = Instant::now();
            } else if last_change.elapsed() >= idle_timeout {
                // No new hosts for idle_timeout, stop early
                log_stderr!(
                    "Round {} early exit: no new hosts for {}ms",
                    round,
                    ARP_IDLE_TIMEOUT_MS
                );
                break;
            }
        }

        let final_count = host_count.load(Ordering::SeqCst);
        log_stderr!(
            "Round {} complete: {} hosts found ({} new) in {:?}",
            round,
            final_count,
            final_count - initial_count,
            round_start.elapsed()
        );
    }

    // Wait for receiver to finish
    if receiver_handle.join().is_err() {
        return Err(anyhow!("ARP receiver thread panicked"));
    }

    let map = discovered
        .lock()
        .map_err(|_| anyhow!("ARP discovered-host map lock poisoned"))?;
    for (ip, mac) in map.iter() {
        log_stderr!("[ARP] Found: {} -> {}", ip, mac);
    }

    log_stderr!(
        "Phase 1 complete: {} hosts found in {:?}",
        map.len(),
        scan_start.elapsed()
    );

    Ok(map.clone())
}
