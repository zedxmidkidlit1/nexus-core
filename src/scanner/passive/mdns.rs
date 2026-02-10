//! mDNS/DNS-SD passive discovery
//!
//! Listens for multicast DNS service announcements without sending packets

use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::time::Duration;
use tokio::sync::mpsc;

/// Discovered device from passive scanning
#[derive(Debug, Clone)]
pub struct PassiveDevice {
    pub hostname: String,
    pub ip: String,
    pub mac: Option<String>,
    pub services: Vec<String>,
    pub discovered_at: chrono::DateTime<chrono::Utc>,
    pub device_type_hint: Option<String>,
}

/// Passive network scanner using mDNS
pub struct PassiveScanner {
    mdns: ServiceDaemon,
}

impl PassiveScanner {
    /// Create a new passive scanner
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mdns = ServiceDaemon::new()?;

        tracing::info!("Passive scanner initialized (mDNS/DNS-SD)");

        Ok(Self { mdns })
    }

    /// Start listening for mDNS service announcements
    ///
    /// Sends discovered devices through the provided channel
    pub async fn start_listening(
        &self,
        tx: mpsc::Sender<PassiveDevice>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Browse for all DNS-SD services
        let receiver = self.mdns.browse("_services._dns-sd._udp.local")?;

        tracing::info!("🎧 Started mDNS listening on 224.0.0.251:5353");

        // Process service discovery events
        loop {
            tokio::select! {
                event = receiver.recv_async() => {
                    match event {
                        Ok(ServiceEvent::ServiceResolved(info)) => {
                            let device = self.parse_mdns_service(&info);

                            tracing::info!(
                                "🎧 Passive discovery: {} at {} (services: {:?})",
                                device.hostname,
                                device.ip,
                                device.services
                            );

                            // Send to monitoring system
                            if tx.send(device).await.is_err() {
                                tracing::warn!("Passive discovery channel closed");
                                break;
                            }
                        }
                        Ok(ServiceEvent::ServiceRemoved(type_name, full_name)) => {
                            tracing::debug!(
                                "Service removed: {} ({})",
                                full_name,
                                type_name
                            );
                        }
                        Err(e) => {
                            tracing::error!("mDNS error: {}", e);
                        }
                        _ => {}
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    // Periodic check to keep the loop going
                }
            }
        }

        Ok(())
    }

    /// Parse mDNS service info into PassiveDevice
    fn parse_mdns_service(&self, info: &mdns_sd::ServiceInfo) -> PassiveDevice {
        let hostname = info.get_hostname().trim_end_matches('.').to_string();

        // Get first available IP address
        let ip = info
            .get_addresses()
            .iter()
            .next()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Infer device type from service type
        let service_type = info.get_type();
        let device_type_hint = match service_type {
            t if t.contains("_airplay") => Some("Apple TV / iOS Device".to_string()),
            t if t.contains("_raop") => Some("AirPlay Speaker".to_string()),
            t if t.contains("_homekit") => Some("HomeKit Device".to_string()),
            t if t.contains("_printer") || t.contains("_ipp") => {
                Some("Network Printer".to_string())
            }
            t if t.contains("_ssh") => Some("SSH Server".to_string()),
            t if t.contains("_smb") => Some("SMB File Server".to_string()),
            t if t.contains("_http") => Some("Web Server".to_string()),
            t if t.contains("_spotify") => Some("Spotify Connect".to_string()),
            t if t.contains("_googlecast") => Some("Chromecast".to_string()),
            _ => None,
        };

        PassiveDevice {
            hostname,
            ip,
            mac: None, // Will be enriched by ARP monitoring
            services: vec![service_type.to_string()],
            discovered_at: chrono::Utc::now(),
            device_type_hint,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_passive_scanner_creation() {
        let scanner = PassiveScanner::new();
        assert!(scanner.is_ok());
    }
}
