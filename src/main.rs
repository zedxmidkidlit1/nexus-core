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

    let context = nexus_core::AppContext::from_env();
    let cancel_context = context.clone();
    let signal_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel_context.cancel();
            nexus_core::log_stderr!(
                "Cancellation requested (Ctrl+C). Stopping after current scan phase..."
            );
        }
    });

    let run_result = nexus_core::app::run_with_context(std::env::args(), &context).await;
    signal_task.abort();

    match run_result {
        Ok(()) => {}
        Err(e) => {
            nexus_core::log_error!("{:#}", e);
            std::process::exit(1);
        }
    }
}
