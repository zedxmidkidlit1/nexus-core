use anyhow::Result;

use crate::app::{AppContext, execute_command_with_context};
use crate::cli::parse_cli_args;

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

/// Run the app with Ctrl+C cancellation wired into the provided context.
/// This is intended for CLI-style entrypoints.
pub async fn run_with_ctrl_c<I, S>(args: I, context: &AppContext) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let cancel_context = context.clone();
    let signal_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel_context.cancel();
            crate::log_stderr!(
                "Cancellation requested (Ctrl+C). Stopping after current scan phase..."
            );
        }
    });

    let run_result = run_with_context(args, context).await;
    signal_task.abort();
    run_result
}
