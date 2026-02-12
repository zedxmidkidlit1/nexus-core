//! NEXUS Core Engine — Network Discovery CLI
//!
//! Production-grade network scanner with:
//! - Active ARP scanning (Layer 2)
//! - ICMP ping (latency measurement)
//! - TCP port probing (service detection)
//! - SNMP enrichment (optional)

use anyhow::{Context, Result};

mod cli;
mod scan_workflow;

use crate::cli::{CliCommand, parse_cli_args, usage_text, version_text};
use crate::scan_workflow::{persist_scan_result, run_load_test, scan_network};

use nexus_core::{
    AiSettings, export_scan_result_with_ai_json, find_interface_by_name, find_valid_interface,
    generate_hybrid_insights, list_valid_interfaces, run_ai_check,
};
#[cfg(test)]
use nexus_core::{HostInfo, ScanResult};

/// Logs a message to stderr
macro_rules! log_stderr {
    ($($arg:tt)*) => {
        nexus_core::log_stderr!($($arg)*);
    };
}

/// Logs an error message to stderr
macro_rules! log_error {
    ($($arg:tt)*) => {
        nexus_core::log_error!($($arg)*);
    };
}

#[tokio::main]
async fn main() {
    if let Err(e) = nexus_core::logging::init_logging() {
        eprintln!("[WARN] Failed to initialize structured logging: {}", e);
    }

    match run(std::env::args()).await {
        Ok(()) => {}
        Err(e) => {
            log_error!("{:#}", e);
            std::process::exit(1);
        }
    }
}

/// Main entry point
async fn run<I, S>(args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    match parse_cli_args(args)? {
        CliCommand::Help => {
            println!("{}", usage_text());
            Ok(())
        }
        CliCommand::Version => {
            println!("{}", version_text());
            Ok(())
        }
        CliCommand::Interfaces => {
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
        CliCommand::AiCheck => {
            let report = run_ai_check().await;
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .context("Failed to serialize ai-check report")?
            );
            Ok(())
        }
        CliCommand::AiInsights => {
            let db =
                nexus_core::database::Database::new(nexus_core::database::Database::default_path())
                    .context("Failed to open database. Run a scan first to create baseline data")?;

            let hosts = {
                let conn = db.connection();
                let conn = conn
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Database connection lock poisoned"))?;
                nexus_core::database::queries::get_latest_scan_hosts(&conn)
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
                serde_json::to_string_pretty(&result)
                    .context("Failed to serialize ai-insights output")?
            );
            Ok(())
        }
        CliCommand::Scan { interface } => {
            log_stderr!(
                "NEXUS Core Engine — Network Discovery v{}",
                env!("CARGO_PKG_VERSION")
            );
            log_stderr!("Active ARP + ICMP + TCP Scanning Mode");
            log_stderr!("================================================");

            let selected_interface = match interface {
                Some(name) => {
                    log_stderr!("Using requested interface: {}", name);
                    find_interface_by_name(&name)?
                }
                None => {
                    log_stderr!("Detecting network interfaces...");
                    find_valid_interface()?
                }
            };

            let result = scan_network(&selected_interface).await?;
            if let Err(e) = persist_scan_result(&result) {
                log_error!(
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
        CliCommand::LoadTest {
            interface,
            iterations,
            concurrency,
        } => {
            log_stderr!(
                "NEXUS Core Engine — Load Test v{} (iterations={}, concurrency={})",
                env!("CARGO_PKG_VERSION"),
                iterations,
                concurrency
            );

            let selected_interface = match interface {
                Some(name) => {
                    log_stderr!("Using requested interface: {}", name);
                    find_interface_by_name(&name)?
                }
                None => {
                    log_stderr!("Detecting network interfaces...");
                    find_valid_interface()?
                }
            };

            let summary = run_load_test(&selected_interface, iterations, concurrency).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&summary)
                    .context("Failed to serialize load-test summary")?
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_result_serialization() {
        let result = ScanResult {
            interface_name: "eth0".to_string(),
            local_ip: "192.168.1.100".to_string(),
            local_mac: "00:11:22:33:44:55".to_string(),
            subnet: "192.168.1.0/24".to_string(),
            scan_method: "Active ARP + ICMP".to_string(),
            arp_discovered: 5,
            icmp_discovered: 3,
            total_hosts: 5,
            scan_duration_ms: 1000,
            active_hosts: vec![{
                let mut host = HostInfo::new(
                    "192.168.1.1".to_string(),
                    "AA:BB:CC:DD:EE:FF".to_string(),
                    "UNKNOWN".to_string(),
                    "ARP+ICMP+TCP".to_string(),
                );
                host.response_time_ms = Some(10);
                host.open_ports = vec![80];
                host
            }],
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"interface_name\":\"eth0\""));
        assert!(json.contains("\"open_ports\":[80]"));
    }
}
