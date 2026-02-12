use anyhow::{Context, Result};

use crate::scan_workflow::{persist_scan_result, run_load_test, scan_network};

use crate::{
    AiSettings, export_scan_result_with_ai_json, find_interface_by_name, find_valid_interface,
    generate_hybrid_insights, list_valid_interfaces, run_ai_check,
};

pub(crate) async fn handle_interfaces() -> Result<()> {
    let interfaces = list_valid_interfaces();
    if interfaces.is_empty() {
        println!("No valid IPv4 network interfaces found.");
    } else {
        for interface in interfaces {
            println!("{}", interface);
        }
    }
    Ok(())
}

pub(crate) async fn handle_ai_check() -> Result<()> {
    let report = run_ai_check().await;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).context("Failed to serialize ai-check report")?
    );
    Ok(())
}

pub(crate) async fn handle_ai_insights() -> Result<()> {
    let db = crate::database::Database::new(crate::database::Database::default_path())
        .context("Failed to open database. Run a scan first to create baseline data")?;

    let hosts = {
        let conn = db.connection();
        let conn = conn
            .lock()
            .map_err(|_| anyhow::anyhow!("Database connection lock poisoned"))?;
        crate::database::queries::get_latest_scan_hosts(&conn)
            .context("Failed to load hosts from latest scan history")?
    };

    if hosts.is_empty() {
        return Err(anyhow::anyhow!(
            "No hosts found in latest persisted scan. Run `nexus-core scan` with persistence workflow first."
        ));
    }

    let result = generate_hybrid_insights(&hosts).await;
    println!(
        "{}",
        serde_json::to_string_pretty(&result).context("Failed to serialize ai-insights output")?
    );
    Ok(())
}

pub(crate) async fn handle_scan(interface: Option<String>) -> Result<()> {
    crate::log_stderr!(
        "NEXUS Core Engine — Network Discovery v{}",
        env!("CARGO_PKG_VERSION")
    );
    crate::log_stderr!("Active ARP + ICMP + TCP Scanning Mode");
    crate::log_stderr!("================================================");

    let selected_interface = select_interface(interface)?;
    let result = scan_network(&selected_interface).await?;

    if let Err(e) = persist_scan_result(&result) {
        crate::log_error!(
            "Scan persistence failed (continuing with JSON output): {}",
            e
        );
    }

    let ai_settings = AiSettings::from_env();
    let ai_result = if ai_settings.enabled {
        Some(generate_hybrid_insights(&result.active_hosts).await)
    } else {
        None
    };

    let ai_ref = ai_result.as_ref().and_then(|ai| {
        if ai.ai_overlay.is_some()
            || ai.ai_provider.is_some()
            || ai.ai_model.is_some()
            || ai.ai_error.is_some()
        {
            Some(ai)
        } else {
            None
        }
    });

    let json = export_scan_result_with_ai_json(&result, ai_ref)
        .context("Failed to serialize scan result JSON")?;
    println!("{}", json);
    Ok(())
}

pub(crate) async fn handle_load_test(
    interface: Option<String>,
    iterations: u32,
    concurrency: usize,
) -> Result<()> {
    crate::log_stderr!(
        "NEXUS Core Engine — Load Test v{} (iterations={}, concurrency={})",
        env!("CARGO_PKG_VERSION"),
        iterations,
        concurrency
    );

    let selected_interface = select_interface(interface)?;
    let summary = run_load_test(&selected_interface, iterations, concurrency).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&summary).context("Failed to serialize load-test summary")?
    );
    Ok(())
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
