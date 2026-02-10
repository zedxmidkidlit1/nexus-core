use nexus_core::database::{
    AlertSeverity as DbAlertSeverity, AlertType as DbAlertType, Database, queries,
};
use nexus_core::{Alert as RuntimeAlert, HostInfo, ScanResult, detect_alerts};

fn map_runtime_alert(alert: &RuntimeAlert) -> (DbAlertType, DbAlertSeverity) {
    let alert_type = match alert.alert_type.as_str() {
        "NEW_DEVICE" => DbAlertType::NewDevice,
        "DEVICE_OFFLINE" => DbAlertType::DeviceOffline,
        "DEVICE_ONLINE" => DbAlertType::DeviceOnline,
        "HIGH_RISK" => DbAlertType::HighRisk,
        "UNUSUAL_PORT" => DbAlertType::PortChange,
        "IP_CHANGED" => DbAlertType::IpChange,
        _ => DbAlertType::Custom,
    };

    let severity = match alert.severity.as_str() {
        "CRITICAL" => DbAlertSeverity::Critical,
        "HIGH" => DbAlertSeverity::Error,
        "MEDIUM" => DbAlertSeverity::Warning,
        "LOW" => DbAlertSeverity::Info,
        _ => DbAlertSeverity::Info,
    };

    (alert_type, severity)
}

fn extract_port_from_alert_message(message: &str) -> Option<u16> {
    message
        .split(|c: char| !c.is_ascii_digit())
        .find_map(|chunk| chunk.parse::<u16>().ok())
}

fn dedupe_key(alert: &RuntimeAlert) -> String {
    let mac = alert.device_mac.as_deref().unwrap_or("unknown-mac");
    let ip = alert.device_ip.as_deref().unwrap_or("unknown-ip");
    match alert.alert_type.as_str() {
        "NEW_DEVICE" => format!("new-device:{mac}"),
        "DEVICE_OFFLINE" => format!("device-offline:{mac}"),
        "DEVICE_ONLINE" => format!("device-online:{mac}"),
        "HIGH_RISK" => format!("high-risk:{mac}"),
        "UNUSUAL_PORT" => {
            let port = extract_port_from_alert_message(&alert.message)
                .map(|p| p.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            format!("unusual-port:{mac}:{port}")
        }
        "IP_CHANGED" => format!("ip-changed:{mac}:{ip}"),
        _ => format!("custom:{mac}:{ip}"),
    }
}

fn persist_alerts(conn: &rusqlite::Connection, alerts: &[RuntimeAlert]) -> usize {
    let mut inserted = 0usize;

    for alert in alerts {
        let (alert_type, severity) = map_runtime_alert(alert);
        let key = dedupe_key(alert);
        let alert_insert = queries::AlertInsert {
            alert_type,
            device_id: None,
            device_mac: alert.device_mac.as_deref(),
            device_ip: alert.device_ip.as_deref(),
            dedupe_key: None,
            message: &alert.message,
            severity,
        };
        let result = queries::insert_alert_if_not_exists(conn, &alert_insert, &key, 30)
            .expect("alert insert should succeed");

        if result.is_some() {
            inserted += 1;
        }
    }

    inserted
}

fn build_host() -> HostInfo {
    let mut host = HostInfo::new(
        "192.168.1.50".to_string(),
        "AA:BB:CC:DD:EE:FF".to_string(),
        "UNKNOWN".to_string(),
        "ARP+TCP".to_string(),
    );
    host.hostname = Some("suspicious-host".to_string());
    host.risk_score = 80;
    host.open_ports = vec![23];
    host
}

fn build_scan(host: HostInfo, duration_ms: u64) -> ScanResult {
    ScanResult {
        interface_name: "eth0".to_string(),
        local_ip: "192.168.1.10".to_string(),
        local_mac: "00:11:22:33:44:55".to_string(),
        subnet: "192.168.1.0/24".to_string(),
        scan_method: "Active ARP + ICMP + TCP".to_string(),
        arp_discovered: 1,
        icmp_discovered: 0,
        total_hosts: 1,
        scan_duration_ms: duration_ms,
        active_hosts: vec![host],
    }
}

#[test]
fn test_alert_generation_and_dedupe_across_two_consecutive_scans() {
    let db = Database::in_memory().expect("in-memory db should initialize");
    let conn = db.connection();
    let conn = conn.lock().expect("connection lock should not be poisoned");

    let scan1 = build_scan(build_host(), 1200);
    let known_first = queries::get_all_devices(&conn).expect("query should work");
    assert!(
        known_first.is_empty(),
        "first scan should start with no known devices"
    );

    let alerts_first = detect_alerts(&known_first, &scan1.active_hosts);
    assert!(
        alerts_first
            .iter()
            .any(|a| a.alert_type.as_str() == "HIGH_RISK"),
        "first scan must generate high-risk alert"
    );
    assert!(
        alerts_first
            .iter()
            .any(|a| a.alert_type.as_str() == "UNUSUAL_PORT"),
        "first scan must generate unusual-port alert"
    );

    queries::insert_scan(&conn, &scan1).expect("first scan insert should succeed");
    let inserted_first = persist_alerts(&conn, &alerts_first);
    assert!(
        inserted_first >= 2,
        "first scan should persist at least high-risk and unusual-port alerts"
    );

    let scan2 = build_scan(build_host(), 900);
    let known_second = queries::get_all_devices(&conn).expect("query should work");
    assert_eq!(
        known_second.len(),
        1,
        "device from first scan should be known in second scan"
    );

    let alerts_second = detect_alerts(&known_second, &scan2.active_hosts);
    assert!(
        !alerts_second
            .iter()
            .any(|a| a.alert_type.as_str() == "NEW_DEVICE"),
        "second scan should not flag known device as new"
    );
    assert!(
        alerts_second
            .iter()
            .any(|a| a.alert_type.as_str() == "HIGH_RISK"),
        "second scan still generates recurring high-risk alert before dedupe"
    );

    queries::insert_scan(&conn, &scan2).expect("second scan insert should succeed");
    let inserted_second = persist_alerts(&conn, &alerts_second);
    assert_eq!(
        inserted_second, 0,
        "second scan alerts should be deduped within the dedupe window"
    );

    let unread = queries::get_unread_alerts(&conn).expect("unread query should work");
    let new_device_count = unread
        .iter()
        .filter(|a| a.alert_type == DbAlertType::NewDevice)
        .count();
    let high_risk_count = unread
        .iter()
        .filter(|a| a.alert_type == DbAlertType::HighRisk)
        .count();
    let unusual_port_count = unread
        .iter()
        .filter(|a| a.alert_type == DbAlertType::PortChange)
        .count();

    assert_eq!(
        new_device_count, 1,
        "new-device alert should appear only once"
    );
    assert_eq!(high_risk_count, 1, "high-risk alert should be deduped");
    assert_eq!(
        unusual_port_count, 1,
        "unusual-port alert should be deduped"
    );
}
