//! ARP passive monitoring
//!
//! Listens to ARP broadcasts without sending packets
//! Captures MAC addresses and IP assignments

use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::Packet;
use std::time::Duration;
use tokio::sync::mpsc;

/// ARP event captured from network
#[derive(Debug, Clone)]
pub struct ArpEvent {
    pub sender_mac: String,
    pub sender_ip: String,
    pub target_ip: String,
    pub is_request: bool,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// ARP monitor for passive device discovery
pub struct ArpMonitor {
    interface: NetworkInterface,
}

impl ArpMonitor {
    /// Create a new ARP monitor for the given interface
    pub fn new(interface: NetworkInterface) -> Self {
        Self { interface }
    }

    /// Start monitoring ARP traffic (passive listening)
    ///
    /// Sends captured ARP events through the channel
    pub async fn start_monitoring(
        &self,
        tx: mpsc::Sender<ArpEvent>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let interface_name = self.interface.name.clone();
        let interface = self.interface.clone();

        tracing::info!("🎧 Started ARP monitoring on interface: {}", interface_name);

        // Run packet capture in a blocking worker thread to avoid stalling Tokio runtime workers.
        let worker_result = tokio::task::spawn_blocking(move || -> Result<(), String> {
            // Create datalink channel in non-promiscuous mode
            let channel =
                datalink::channel(&interface, Default::default()).map_err(|e| e.to_string())?;

            let mut rx = match channel {
                Channel::Ethernet(_, rx) => rx,
                _ => return Err("Unsupported channel type".to_string()),
            };

            // Listen for ARP packets
            loop {
                match rx.next() {
                    Ok(packet) => {
                        // Parse Ethernet frame
                        if let Some(ethernet) = EthernetPacket::new(packet) {
                            // Check if it's an ARP packet
                            if ethernet.get_ethertype() == EtherTypes::Arp {
                                if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                                    let event = ArpEvent {
                                        sender_mac: format!(
                                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                            arp.get_sender_hw_addr().0,
                                            arp.get_sender_hw_addr().1,
                                            arp.get_sender_hw_addr().2,
                                            arp.get_sender_hw_addr().3,
                                            arp.get_sender_hw_addr().4,
                                            arp.get_sender_hw_addr().5,
                                        ),
                                        sender_ip: arp.get_sender_proto_addr().to_string(),
                                        target_ip: arp.get_target_proto_addr().to_string(),
                                        is_request: arp.get_operation() == ArpOperations::Request,
                                        timestamp: chrono::Utc::now(),
                                    };

                                    tracing::debug!(
                                        "🎧 ARP: {} ({}) {} {}",
                                        event.sender_ip,
                                        event.sender_mac,
                                        if event.is_request { "→" } else { "←" },
                                        event.target_ip
                                    );

                                    // Send event from blocking thread.
                                    if tx.blocking_send(event).is_err() {
                                        tracing::warn!("ARP monitoring channel closed");
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("ARP monitoring error: {}", e);
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }

            Ok(())
        })
        .await
        .map_err(|e| std::io::Error::other(format!("ARP monitor worker join error: {}", e)))?;

        if let Err(e) = worker_result {
            return Err(std::io::Error::other(e).into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_event_creation() {
        let event = ArpEvent {
            sender_mac: "aa:bb:cc:dd:ee:ff".to_string(),
            sender_ip: "192.168.1.100".to_string(),
            target_ip: "192.168.1.1".to_string(),
            is_request: true,
            timestamp: chrono::Utc::now(),
        };

        assert_eq!(event.sender_mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(event.sender_ip, "192.168.1.100");
        assert!(event.is_request);
    }
}
