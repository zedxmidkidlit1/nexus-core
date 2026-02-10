//! ARP passive monitoring
//!
//! Listens to ARP broadcasts without sending packets
//! Captures MAC addresses and IP assignments

use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::Packet;
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

        // Create datalink channel in non-promiscuous mode
        let channel = datalink::channel(&self.interface, Default::default())?;

        let mut rx = match channel {
            Channel::Ethernet(_, rx) => rx,
            _ => return Err("Unsupported channel type".into()),
        };

        tracing::info!("🎧 Started ARP monitoring on interface: {}", interface_name);

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

                                // Send event
                                if tx.send(event).await.is_err() {
                                    tracing::warn!("ARP monitoring channel closed");
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("ARP monitoring error: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
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
