//! NEXUS Core Engine — Network Discovery CLI
//!
//! Production-grade network scanner with:
//! - Active ARP scanning (Layer 2)
//! - ICMP ping (latency measurement)
//! - TCP port probing (service detection)
//! - SNMP enrichment (optional)

#[tokio::main]
async fn main() {
    if let Err(e) = nexus_core::logging::init_logging() {
        eprintln!("[WARN] Failed to initialize structured logging: {}", e);
    }

    match nexus_core::app::run(std::env::args()).await {
        Ok(()) => {}
        Err(e) => {
            nexus_core::log_error!("{:#}", e);
            std::process::exit(1);
        }
    }
}
