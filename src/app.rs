use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::cli::{CliCommand, parse_cli_args, usage_text, version_text};
use crate::command_handlers::{
    handle_ai_check, handle_ai_insights, handle_interfaces, handle_load_test, handle_scan,
};

pub type OutputHook = Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Clone)]
pub struct AppContext {
    db_path: PathBuf,
    ai_settings: crate::AiSettings,
    output_hook: OutputHook,
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

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn ai_settings(&self) -> &crate::AiSettings {
        &self.ai_settings
    }

    pub fn emit_line(&self, line: &str) {
        (self.output_hook)(line);
    }
}

/// Run the app by parsing CLI-style args and dispatching the command.
pub async fn run<I, S>(args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let context = AppContext::from_env();
    run_with_context(args, &context).await
}

/// Run the app with an explicit context (db path, AI settings, and output hooks).
pub async fn run_with_context<I, S>(args: I, context: &AppContext) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let command = parse_cli_args(args)?;
    execute_command_with_context(command, context).await
}

/// Execute a pre-parsed command. This is reusable for non-CLI entrypoints.
pub async fn execute_command(command: CliCommand) -> Result<()> {
    let context = AppContext::from_env();
    execute_command_with_context(command, &context).await
}

/// Execute a pre-parsed command with an explicit execution context.
pub async fn execute_command_with_context(command: CliCommand, context: &AppContext) -> Result<()> {
    match command {
        CliCommand::Help => {
            context.emit_line(&usage_text());
            Ok(())
        }
        CliCommand::Version => {
            context.emit_line(&version_text());
            Ok(())
        }
        CliCommand::Interfaces => handle_interfaces(context).await,
        CliCommand::AiCheck => handle_ai_check(context).await,
        CliCommand::AiInsights => handle_ai_insights(context).await,
        CliCommand::Scan { interface } => handle_scan(interface, context).await,
        CliCommand::LoadTest {
            interface,
            iterations,
            concurrency,
        } => handle_load_test(interface, iterations, concurrency, context).await,
    }
}

#[cfg(test)]
mod tests {
    use crate::{HostInfo, ScanResult};

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
