use anyhow::Result;

use crate::cli::{CliCommand, parse_cli_args, usage_text, version_text};
use crate::command_handlers::{
    handle_ai_check, handle_ai_insights, handle_interfaces, handle_load_test, handle_scan,
};

/// Run the app by parsing CLI-style args and dispatching the command.
pub async fn run<I, S>(args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let command = parse_cli_args(args)?;
    execute_command(command).await
}

/// Execute a pre-parsed command. This is reusable for non-CLI entrypoints.
pub async fn execute_command(command: CliCommand) -> Result<()> {
    match command {
        CliCommand::Help => {
            println!("{}", usage_text());
            Ok(())
        }
        CliCommand::Version => {
            println!("{}", version_text());
            Ok(())
        }
        CliCommand::Interfaces => handle_interfaces().await,
        CliCommand::AiCheck => handle_ai_check().await,
        CliCommand::AiInsights => handle_ai_insights().await,
        CliCommand::Scan { interface } => handle_scan(interface).await,
        CliCommand::LoadTest {
            interface,
            iterations,
            concurrency,
        } => handle_load_test(interface, iterations, concurrency).await,
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
