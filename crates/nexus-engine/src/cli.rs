use crate::command::AppCommand;
use anyhow::Result;

const DEFAULT_LOAD_TEST_ITERATIONS: u32 = 5;
const DEFAULT_LOAD_TEST_CONCURRENCY: usize = 1;

pub type CliCommand = AppCommand;

pub fn version_text() -> String {
    format!("nexus-core {}", env!("CARGO_PKG_VERSION"))
}

pub fn banner_text() -> &'static str {
    r#" _   _ _______  __ _   _ ____    ____ _     ___
| \ | | ____\ \/ /| | | / ___|  / ___| |   |_ _|
|  \| |  _|  \  / | | | \___ \ | |   | |    | |
| |\  | |___ /  \ | |_| |___) || |___| |___ | |
|_| \_|_____/_/\_\ \___/|____/  \____|_____|___|"#
}

pub fn usage_text() -> String {
    format!(
        "{banner}
{version}
NEXUS Core Engine — Network Discovery CLI

Usage:
  nexus-core scan [--interface <NAME>]
  nexus-core load-test [--interface <NAME>] [--iterations <N>] [--concurrency <N>]
  nexus-core ai-check
  nexus-core ai-insights
  nexus-core interfaces
  nexus-core --help
  nexus-core --version

Options:
  -i, --interface <NAME>  Select network interface by exact name
      --iterations <N>    Load-test: number of scans to run (default: {default_iterations})
      --concurrency <N>   Load-test: concurrent scans per batch (default: {default_concurrency})
  -h, --help              Show this help text
  -V, --version           Show version

Notes:
  - Running with no arguments shows this help screen.
  - Use explicit commands for actions, e.g. `nexus-core scan`.",
        banner = banner_text(),
        version = version_text(),
        default_iterations = DEFAULT_LOAD_TEST_ITERATIONS,
        default_concurrency = DEFAULT_LOAD_TEST_CONCURRENCY
    )
}

fn parse_u32_arg(flag: &str, raw: &str) -> Result<u32> {
    raw.parse::<u32>().ok().filter(|v| *v > 0).ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid value for {}: '{}'. Expected a positive integer.\n\n{}",
            flag,
            raw,
            usage_text()
        )
    })
}

fn parse_usize_arg(flag: &str, raw: &str) -> Result<usize> {
    raw.parse::<usize>().ok().filter(|v| *v > 0).ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid value for {}: '{}'. Expected a positive integer.\n\n{}",
            flag,
            raw,
            usage_text()
        )
    })
}

pub fn parse_cli_args<I, S>(args: I) -> Result<AppCommand>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut iter = args.into_iter();
    let _program_name = iter.next();

    let mut command: Option<String> = None;
    let mut interface: Option<String> = None;
    let mut iterations: Option<u32> = None;
    let mut concurrency: Option<usize> = None;

    while let Some(arg) = iter.next() {
        let arg = arg.as_ref();
        match arg {
            "-h" | "--help" => return Ok(AppCommand::Help),
            "-V" | "--version" => return Ok(AppCommand::Version),
            "scan" | "interfaces" | "load-test" | "ai-check" | "ai-insights" => {
                if command.as_deref().is_some_and(|existing| existing != arg) {
                    return Err(anyhow::anyhow!(
                        "Multiple commands provided. Use only one command.\n\n{}",
                        usage_text()
                    ));
                }
                command = Some(arg.to_string());
            }
            "-i" | "--interface" => {
                let value = iter.next().ok_or_else(|| {
                    anyhow::anyhow!("Missing value for --interface.\n\n{}", usage_text())
                })?;
                interface = Some(value.as_ref().to_string());
            }
            "--iterations" => {
                let value = iter.next().ok_or_else(|| {
                    anyhow::anyhow!("Missing value for --iterations.\n\n{}", usage_text())
                })?;
                iterations = Some(parse_u32_arg("--iterations", value.as_ref())?);
            }
            "--concurrency" => {
                let value = iter.next().ok_or_else(|| {
                    anyhow::anyhow!("Missing value for --concurrency.\n\n{}", usage_text())
                })?;
                concurrency = Some(parse_usize_arg("--concurrency", value.as_ref())?);
            }
            _ if arg.starts_with("--interface=") => {
                let value = arg.split_once('=').map(|(_, v)| v).unwrap_or_default();
                if value.is_empty() {
                    return Err(anyhow::anyhow!(
                        "Missing value for --interface.\n\n{}",
                        usage_text()
                    ));
                }
                interface = Some(value.to_string());
            }
            _ if arg.starts_with("--iterations=") => {
                let value = arg.split_once('=').map(|(_, v)| v).unwrap_or_default();
                if value.is_empty() {
                    return Err(anyhow::anyhow!(
                        "Missing value for --iterations.\n\n{}",
                        usage_text()
                    ));
                }
                iterations = Some(parse_u32_arg("--iterations", value)?);
            }
            _ if arg.starts_with("--concurrency=") => {
                let value = arg.split_once('=').map(|(_, v)| v).unwrap_or_default();
                if value.is_empty() {
                    return Err(anyhow::anyhow!(
                        "Missing value for --concurrency.\n\n{}",
                        usage_text()
                    ));
                }
                concurrency = Some(parse_usize_arg("--concurrency", value)?);
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Unknown argument: {arg}\n\n{}",
                    usage_text()
                ));
            }
        }
    }

    let selected = command.as_deref();
    if selected.is_none() {
        if interface.is_none() && iterations.is_none() && concurrency.is_none() {
            return Ok(AppCommand::Help);
        }
        return Err(anyhow::anyhow!(
            "Missing command. Use one of: scan, load-test, ai-check, ai-insights, interfaces.\n\n{}",
            usage_text()
        ));
    }

    match selected.unwrap_or_default() {
        "scan" => {
            if iterations.is_some() || concurrency.is_some() {
                return Err(anyhow::anyhow!(
                    "--iterations/--concurrency are only valid with load-test.\n\n{}",
                    usage_text()
                ));
            }
            Ok(AppCommand::Scan { interface })
        }
        "load-test" => Ok(AppCommand::LoadTest {
            interface,
            iterations: iterations.unwrap_or(DEFAULT_LOAD_TEST_ITERATIONS),
            concurrency: concurrency.unwrap_or(DEFAULT_LOAD_TEST_CONCURRENCY),
        }),
        "interfaces" => {
            if interface.is_some() || iterations.is_some() || concurrency.is_some() {
                return Err(anyhow::anyhow!(
                    "--interface/--iterations/--concurrency are only valid with scan or load-test.\n\n{}",
                    usage_text()
                ));
            }
            Ok(AppCommand::Interfaces)
        }
        "ai-check" => {
            if interface.is_some() || iterations.is_some() || concurrency.is_some() {
                return Err(anyhow::anyhow!(
                    "--interface/--iterations/--concurrency are not valid with ai-check.\n\n{}",
                    usage_text()
                ));
            }
            Ok(AppCommand::AiCheck)
        }
        "ai-insights" => {
            if interface.is_some() || iterations.is_some() || concurrency.is_some() {
                return Err(anyhow::anyhow!(
                    "--interface/--iterations/--concurrency are not valid with ai-insights.\n\n{}",
                    usage_text()
                ));
            }
            Ok(AppCommand::AiInsights)
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_help_flag() {
        let args = ["nexus-core", "--help"];
        let parsed = parse_cli_args(args).expect("help args should parse");
        assert_eq!(parsed, CliCommand::Help);
    }

    #[test]
    fn parse_version_flag() {
        let args = ["nexus-core", "--version"];
        let parsed = parse_cli_args(args).expect("version args should parse");
        assert_eq!(parsed, CliCommand::Version);
    }

    #[test]
    fn parse_default_no_args_shows_help() {
        let args = ["nexus-core"];
        let parsed = parse_cli_args(args).expect("default args should parse");
        assert_eq!(parsed, CliCommand::Help);
    }

    #[test]
    fn parse_scan_with_interface_flag() {
        let args = ["nexus-core", "scan", "--interface", "Ethernet"];
        let parsed = parse_cli_args(args).expect("scan with interface should parse");
        assert_eq!(
            parsed,
            CliCommand::Scan {
                interface: Some("Ethernet".to_string())
            }
        );
    }

    #[test]
    fn parse_interfaces_command() {
        let args = ["nexus-core", "interfaces"];
        let parsed = parse_cli_args(args).expect("interfaces command should parse");
        assert_eq!(parsed, CliCommand::Interfaces);
    }

    #[test]
    fn parse_ai_check_command() {
        let args = ["nexus-core", "ai-check"];
        let parsed = parse_cli_args(args).expect("ai-check command should parse");
        assert_eq!(parsed, CliCommand::AiCheck);
    }

    #[test]
    fn parse_ai_insights_command() {
        let args = ["nexus-core", "ai-insights"];
        let parsed = parse_cli_args(args).expect("ai-insights command should parse");
        assert_eq!(parsed, CliCommand::AiInsights);
    }

    #[test]
    fn parse_load_test_command_with_options() {
        let args = [
            "nexus-core",
            "load-test",
            "--interface",
            "Ethernet",
            "--iterations",
            "10",
            "--concurrency",
            "2",
        ];
        let parsed = parse_cli_args(args).expect("load-test command should parse");
        assert_eq!(
            parsed,
            CliCommand::LoadTest {
                interface: Some("Ethernet".to_string()),
                iterations: 10,
                concurrency: 2
            }
        );
    }

    #[test]
    fn parse_scan_rejects_load_test_options() {
        let args = ["nexus-core", "scan", "--iterations", "3"];
        let err = parse_cli_args(args).expect_err("scan should reject load-test-only options");
        let msg = err.to_string();
        assert!(msg.contains("--iterations/--concurrency are only valid with load-test"));
    }

    #[test]
    fn parse_ai_check_rejects_scan_flags() {
        let args = ["nexus-core", "ai-check", "--interface", "Ethernet"];
        let err = parse_cli_args(args).expect_err("ai-check should reject scan flags");
        assert!(err.to_string().contains("not valid with ai-check"));
    }

    #[test]
    fn parse_ai_insights_rejects_scan_flags() {
        let args = ["nexus-core", "ai-insights", "--interface", "Ethernet"];
        let err = parse_cli_args(args).expect_err("ai-insights should reject scan flags");
        assert!(err.to_string().contains("not valid with ai-insights"));
    }

    #[test]
    fn parse_unknown_argument_errors() {
        let args = ["nexus-core", "--unknown"];
        let err = parse_cli_args(args).expect_err("unknown flag should fail");
        let message = err.to_string();
        assert!(message.contains("Unknown argument"));
    }

    #[test]
    fn parse_no_command_with_scan_flags_errors() {
        let args = ["nexus-core", "--interface", "Ethernet"];
        let err = parse_cli_args(args).expect_err("flags without command should fail");
        let message = err.to_string();
        assert!(message.contains("Missing command"));
    }
}
