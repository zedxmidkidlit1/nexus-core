//! Passive network discovery module
//!
//! Discovers devices without sending packets:
//! - mDNS/DNS-SD: Listen for service announcements
//! - ARP monitoring: Observe ARP traffic
//! - DHCP snooping: Capture DHCP requests

pub mod arp;
pub mod mdns;

pub use arp::{ArpEvent, ArpMonitor};
pub use mdns::PassiveScanner;
