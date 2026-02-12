use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use nexus_core::database::{Database, queries::insert_scan};
use nexus_core::{
    AiMode, AiSettings, AppContext, CliCommand, HostInfo, OutputHook, ScanResult,
    execute_command_with_context,
};

fn disabled_ai_settings() -> AiSettings {
    AiSettings {
        enabled: false,
        mode: AiMode::Disabled,
        timeout_ms: 1000,
        ollama_endpoint: "http://127.0.0.1:11434".to_string(),
        ollama_model: "qwen3:8b".to_string(),
        gemini_endpoint: "https://generativelanguage.googleapis.com".to_string(),
        gemini_model: "gemini-2.5-flash".to_string(),
        gemini_api_key: None,
        cloud_allow_sensitive: false,
    }
}

fn make_test_context(db_path: Option<PathBuf>) -> (AppContext, Arc<Mutex<Vec<String>>>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    let output_hook: OutputHook = Arc::new(move |line| {
        sink.lock()
            .expect("output lock should not be poisoned")
            .push(line.to_string());
    });

    let mut context = AppContext::from_env()
        .with_ai_settings(disabled_ai_settings())
        .with_output_hook(output_hook);
    if let Some(path) = db_path {
        context = context.with_db_path(path);
    }

    (context, lines)
}

fn unique_temp_db_path(prefix: &str) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{}_{}.db", prefix, timestamp))
}

#[tokio::test]
async fn help_command_writes_usage_to_output_hook() {
    let (context, lines) = make_test_context(None);

    execute_command_with_context(CliCommand::Help, &context)
        .await
        .expect("help command should succeed");

    let output = lines
        .lock()
        .expect("output lock should not be poisoned")
        .join("\n");
    assert!(output.contains("Usage:"));
    assert!(output.contains("nexus-core ai-check"));
}

#[tokio::test]
async fn ai_check_uses_context_settings_and_outputs_json() {
    let (context, lines) = make_test_context(None);

    execute_command_with_context(CliCommand::AiCheck, &context)
        .await
        .expect("ai-check should succeed");

    let output = lines
        .lock()
        .expect("output lock should not be poisoned")
        .join("\n");
    let parsed: serde_json::Value =
        serde_json::from_str(&output).expect("ai-check output should be valid JSON");

    assert_eq!(parsed["ai_enabled"], serde_json::Value::Bool(false));
    assert_eq!(
        parsed["mode"],
        serde_json::Value::String("disabled".to_string())
    );
    assert_eq!(parsed["overall_ok"], serde_json::Value::Bool(true));
}

#[tokio::test]
async fn ai_insights_reads_from_context_db_path_and_outputs_json() {
    let db_path = unique_temp_db_path("nexus_ai_insights_dispatch");

    let db = Database::new(db_path.clone()).expect("db should initialize");
    {
        let conn = db.connection();
        let conn = conn
            .lock()
            .expect("database lock should not be poisoned for insert");

        let mut host = HostInfo::new(
            "192.168.50.10".to_string(),
            "AA:BB:CC:DD:EE:10".to_string(),
            "UNKNOWN".to_string(),
            "ARP+ICMP".to_string(),
        );
        host.risk_score = 10;
        host.open_ports = vec![80];

        let scan = ScanResult {
            interface_name: "eth0".to_string(),
            local_ip: "192.168.50.1".to_string(),
            local_mac: "00:11:22:33:44:55".to_string(),
            subnet: "192.168.50.0/24".to_string(),
            scan_method: "Active ARP + ICMP + TCP".to_string(),
            arp_discovered: 1,
            icmp_discovered: 1,
            total_hosts: 1,
            scan_duration_ms: 1200,
            active_hosts: vec![host],
        };
        insert_scan(&conn, &scan).expect("test scan should persist");
    }
    drop(db);

    let (context, lines) = make_test_context(Some(db_path.clone()));
    execute_command_with_context(CliCommand::AiInsights, &context)
        .await
        .expect("ai-insights should succeed with stored scan data");

    let output = lines
        .lock()
        .expect("output lock should not be poisoned")
        .join("\n");
    let parsed: serde_json::Value =
        serde_json::from_str(&output).expect("ai-insights output should be valid JSON");
    assert!(parsed.get("health").is_some());
    assert!(parsed.get("security").is_some());
    assert!(parsed.get("device_distribution").is_some());

    let _ = std::fs::remove_file(db_path);
}
