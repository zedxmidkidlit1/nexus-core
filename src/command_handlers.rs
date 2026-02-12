use anyhow::Result;

use crate::ai::{generate_hybrid_insights_with_settings, run_ai_check_with_settings};
use crate::app::{AppContext, LoadTestSummary, ScanWithAi};
use crate::scan_workflow::{persist_scan_result, run_load_test, scan_network};
use crate::{find_interface_by_name, find_valid_interface, list_valid_interfaces};

pub(crate) fn collect_interfaces() -> Vec<String> {
    list_valid_interfaces()
}

pub(crate) async fn ai_check_report(context: &AppContext) -> Result<crate::AiCheckReport> {
    Ok(run_ai_check_with_settings(context.ai_settings()).await)
}

pub(crate) async fn ai_insights_result(
    context: &AppContext,
) -> Result<crate::HybridInsightsResult> {
    let db = crate::database::Database::new(context.db_path().to_path_buf()).map_err(|e| {
        anyhow::anyhow!(
            "Failed to open database. Run a scan first to create baseline data: {}",
            e
        )
    })?;

    let hosts = {
        let conn = db.connection();
        let conn = conn
            .lock()
            .map_err(|_| anyhow::anyhow!("Database connection lock poisoned"))?;
        crate::database::queries::get_latest_scan_hosts(&conn)
            .map_err(|e| anyhow::anyhow!("Failed to load hosts from latest scan history: {}", e))?
    };

    if hosts.is_empty() {
        return Err(anyhow::anyhow!(
            "No hosts found in latest persisted scan. Run `nexus-core scan` with persistence workflow first."
        ));
    }

    Ok(generate_hybrid_insights_with_settings(&hosts, context.ai_settings()).await)
}

pub(crate) async fn scan_with_ai(
    interface: Option<String>,
    context: &AppContext,
) -> Result<ScanWithAi> {
    crate::log_stderr!(
        "NEXUS Core Engine — Network Discovery v{}",
        env!("CARGO_PKG_VERSION")
    );
    crate::log_stderr!("Active ARP + ICMP + TCP Scanning Mode");
    crate::log_stderr!("================================================");

    let selected_interface = select_interface(interface)?;
    let result = scan_network(&selected_interface).await?;

    if let Err(e) = persist_scan_result(&result, context.db_path()) {
        crate::log_error!(
            "Scan persistence failed (continuing with JSON output): {}",
            e
        );
    }

    let ai_result = if context.ai_settings().enabled {
        Some(
            generate_hybrid_insights_with_settings(&result.active_hosts, context.ai_settings())
                .await,
        )
    } else {
        None
    };

    Ok(ScanWithAi {
        scan: result,
        ai: ai_result,
    })
}

pub(crate) async fn load_test_summary(
    interface: Option<String>,
    iterations: u32,
    concurrency: usize,
    _context: &AppContext,
) -> Result<LoadTestSummary> {
    crate::log_stderr!(
        "NEXUS Core Engine — Load Test v{} (iterations={}, concurrency={})",
        env!("CARGO_PKG_VERSION"),
        iterations,
        concurrency
    );

    let selected_interface = select_interface(interface)?;
    run_load_test(&selected_interface, iterations, concurrency).await
}

fn select_interface(interface: Option<String>) -> Result<crate::InterfaceInfo> {
    match interface {
        Some(name) => {
            crate::log_stderr!("Using requested interface: {}", name);
            find_interface_by_name(&name)
        }
        None => {
            crate::log_stderr!("Detecting network interfaces...");
            find_valid_interface()
        }
    }
}
