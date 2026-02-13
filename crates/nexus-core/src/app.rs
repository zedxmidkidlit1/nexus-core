use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::cli::{usage_text, version_text};
use crate::command::AppCommand;
use crate::command_handlers::{
    ai_check_report, ai_insights_result, collect_interfaces, load_test_summary, scan_with_ai,
};
use crate::export_scan_result_with_ai_json;

pub type OutputHook = Arc<dyn Fn(&str) + Send + Sync>;
pub type EventHook = Arc<dyn Fn(&AppEvent) + Send + Sync>;

#[derive(Clone)]
pub struct AppContext {
    db_path: PathBuf,
    ai_settings: crate::AiSettings,
    output_hook: OutputHook,
    event_hook: EventHook,
    cancel_flag: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AppEvent {
    Info { message: String },
    Warn { message: String },
    Error { message: String },
    ScanPhase { phase: String, progress_pct: u8 },
    ScanPersisted { scan_id: i64, path: String },
    Cancelled { stage: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanWithAi {
    pub scan: crate::ScanResult,
    pub ai: Option<crate::HybridInsightsResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoadTestSummary {
    pub interface_name: String,
    pub iterations: u32,
    pub concurrency: usize,
    pub successful_scans: u32,
    pub failed_scans: u32,
    pub wall_time_ms: u64,
    pub avg_scan_duration_ms: f64,
    pub min_scan_duration_ms: u64,
    pub max_scan_duration_ms: u64,
    pub avg_hosts_found: f64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum AppCommandResult {
    HelpText(String),
    VersionText(String),
    Interfaces(Vec<String>),
    AiCheck(crate::AiCheckReport),
    AiInsights(crate::HybridInsightsResult),
    Scan(ScanWithAi),
    LoadTest(LoadTestSummary),
}

impl Default for AppContext {
    fn default() -> Self {
        Self::from_env()
    }
}

impl AppContext {
    pub fn from_env() -> Self {
        Self {
            db_path: crate::database::Database::default_path(),
            ai_settings: crate::AiSettings::from_env(),
            output_hook: Arc::new(|line| println!("{}", line)),
            event_hook: Arc::new(|_| {}),
            cancel_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_db_path(mut self, db_path: PathBuf) -> Self {
        self.db_path = db_path;
        self
    }

    pub fn with_ai_settings(mut self, ai_settings: crate::AiSettings) -> Self {
        self.ai_settings = ai_settings;
        self
    }

    pub fn with_output_hook(mut self, output_hook: OutputHook) -> Self {
        self.output_hook = output_hook;
        self
    }

    pub fn with_event_hook(mut self, event_hook: EventHook) -> Self {
        self.event_hook = event_hook;
        self
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn ai_settings(&self) -> &crate::AiSettings {
        &self.ai_settings
    }

    pub fn emit_line(&self, line: &str) {
        (self.output_hook)(line);
    }

    pub fn emit_event(&self, event: AppEvent) {
        (self.event_hook)(&event);
    }

    pub fn cancel(&self) {
        self.cancel_flag.store(true, Ordering::Relaxed);
    }

    pub fn reset_cancel(&self) {
        self.cancel_flag.store(false, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel_flag.load(Ordering::Relaxed)
    }
}

/// Compatibility wrapper for CLI adapter entrypoint.
pub async fn run<I, S>(args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    crate::cli_adapter::run(args).await
}

/// Compatibility wrapper for CLI adapter entrypoint.
pub async fn run_with_ctrl_c<I, S>(args: I, context: &AppContext) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    crate::cli_adapter::run_with_ctrl_c(args, context).await
}

/// Compatibility wrapper for CLI adapter entrypoint.
pub async fn run_with_context<I, S>(args: I, context: &AppContext) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    crate::cli_adapter::run_with_context(args, context).await
}

/// Execute a pre-parsed command. This is reusable for non-CLI entrypoints.
pub async fn execute_command(command: AppCommand) -> Result<()> {
    let context = AppContext::from_env();
    execute_command_with_context(command, &context).await
}

/// Execute a pre-parsed command with an explicit execution context.
pub async fn execute_command_with_context(command: AppCommand, context: &AppContext) -> Result<()> {
    let result = execute_command_typed(command, context).await?;
    emit_command_result(&result, context)
}

/// Execute a pre-parsed command and return a strongly-typed result payload.
pub async fn execute_command_typed(
    command: AppCommand,
    context: &AppContext,
) -> Result<AppCommandResult> {
    match command {
        AppCommand::Help => Ok(AppCommandResult::HelpText(usage_text())),
        AppCommand::Version => Ok(AppCommandResult::VersionText(version_text())),
        AppCommand::Interfaces => Ok(AppCommandResult::Interfaces(collect_interfaces())),
        AppCommand::AiCheck => Ok(AppCommandResult::AiCheck(ai_check_report(context).await?)),
        AppCommand::AiInsights => Ok(AppCommandResult::AiInsights(
            ai_insights_result(context).await?,
        )),
        AppCommand::Scan { interface } => Ok(AppCommandResult::Scan(
            scan_with_ai(interface, context).await?,
        )),
        AppCommand::LoadTest {
            interface,
            iterations,
            concurrency,
        } => Ok(AppCommandResult::LoadTest(
            load_test_summary(interface, iterations, concurrency, context).await?,
        )),
    }
}

fn emit_command_result(result: &AppCommandResult, context: &AppContext) -> Result<()> {
    match result {
        AppCommandResult::HelpText(text) => {
            context.emit_line(text);
            Ok(())
        }
        AppCommandResult::VersionText(text) => {
            context.emit_line(text);
            Ok(())
        }
        AppCommandResult::Interfaces(interfaces) => {
            if interfaces.is_empty() {
                context.emit_line("No valid IPv4 network interfaces found.");
            } else {
                for interface in interfaces {
                    context.emit_line(interface);
                }
            }
            Ok(())
        }
        AppCommandResult::AiCheck(report) => {
            let output = serde_json::to_string_pretty(report)
                .context("Failed to serialize ai-check report")?;
            context.emit_line(&output);
            Ok(())
        }
        AppCommandResult::AiInsights(result) => {
            let output = serde_json::to_string_pretty(result)
                .context("Failed to serialize ai-insights output")?;
            context.emit_line(&output);
            Ok(())
        }
        AppCommandResult::Scan(result) => {
            let ai_ref = ai_payload_for_export(result);
            let json = export_scan_result_with_ai_json(&result.scan, ai_ref)
                .context("Failed to serialize scan result JSON")?;
            context.emit_line(&json);
            Ok(())
        }
        AppCommandResult::LoadTest(summary) => {
            let output = serde_json::to_string_pretty(summary)
                .context("Failed to serialize load-test summary")?;
            context.emit_line(&output);
            Ok(())
        }
    }
}

fn ai_payload_for_export(scan: &ScanWithAi) -> Option<&crate::HybridInsightsResult> {
    scan.ai.as_ref().and_then(|ai| {
        if ai.ai_overlay.is_some()
            || ai.ai_provider.is_some()
            || ai.ai_model.is_some()
            || ai.ai_error.is_some()
        {
            Some(ai)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use crate::{AppCommand, HostInfo, ScanResult};
    use std::sync::{Arc, Mutex};

    use super::{AppCommandResult, AppContext, AppEvent, execute_command_typed};

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

    #[tokio::test]
    async fn execute_command_typed_help_returns_help_variant() {
        let context = AppContext::from_env();
        let result = execute_command_typed(AppCommand::Help, &context)
            .await
            .expect("typed command execution should succeed");

        assert!(matches!(result, AppCommandResult::HelpText(text) if text.contains("Usage:")));
    }

    #[test]
    fn context_event_hook_receives_emitted_event() {
        let events: Arc<Mutex<Vec<AppEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        let context = AppContext::from_env().with_event_hook(Arc::new(move |event| {
            sink.lock()
                .expect("event lock should not be poisoned")
                .push(event.clone());
        }));

        context.emit_event(AppEvent::Info {
            message: "hello".to_string(),
        });

        let captured = events.lock().expect("event lock should not be poisoned");
        assert_eq!(captured.len(), 1);
        assert_eq!(
            captured[0],
            AppEvent::Info {
                message: "hello".to_string()
            }
        );
    }

    #[test]
    fn context_cancel_flag_can_be_set_and_reset() {
        let context = AppContext::from_env();
        assert!(!context.is_cancelled());
        context.cancel();
        assert!(context.is_cancelled());
        context.reset_cancel();
        assert!(!context.is_cancelled());
    }
}
