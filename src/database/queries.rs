//! Database query functions
//!
//! CRUD operations for scans, devices, and alerts

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};

use super::models::*;
use crate::models::{HostInfo, ScanResult};

/// Parameters used to insert an alert record.
pub struct AlertInsert<'a> {
    pub alert_type: AlertType,
    pub device_id: Option<i64>,
    pub device_mac: Option<&'a str>,
    pub device_ip: Option<&'a str>,
    pub dedupe_key: Option<&'a str>,
    pub message: &'a str,
    pub severity: AlertSeverity,
}

/// Insert a scan result into the database
pub fn insert_scan(conn: &Connection, result: &ScanResult) -> Result<i64> {
    conn.execute_batch("SAVEPOINT insert_scan")
        .context("Failed to start insert_scan transaction")?;

    let insert_result = (|| -> Result<i64> {
        conn.execute(
            r#"
            INSERT INTO scans (
                interface_name, local_ip, local_mac, subnet, scan_method,
                arp_discovered, icmp_discovered, total_hosts, duration_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                result.interface_name,
                result.local_ip,
                result.local_mac,
                result.subnet,
                result.scan_method,
                result.arp_discovered as i32,
                result.icmp_discovered as i32,
                result.total_hosts as i32,
                result.scan_duration_ms as i64,
            ],
        )
        .context("Failed to insert scan")?;

        let scan_id = conn.last_insert_rowid();

        // Insert/update each discovered host
        for host in &result.active_hosts {
            upsert_device_from_host(conn, host, scan_id)?;
        }

        Ok(scan_id)
    })();

    match insert_result {
        Ok(scan_id) => {
            conn.execute_batch("RELEASE SAVEPOINT insert_scan")
                .context("Failed to commit insert_scan transaction")?;
            Ok(scan_id)
        }
        Err(e) => {
            let _ = conn.execute_batch(
                "ROLLBACK TO SAVEPOINT insert_scan; RELEASE SAVEPOINT insert_scan",
            );
            Err(e)
        }
    }
}

/// Insert or update a device from scan result
fn upsert_device_from_host(conn: &Connection, host: &HostInfo, scan_id: i64) -> Result<i64> {
    // Try to get existing device
    let device_id: Option<i64> = conn
        .query_row(
            "SELECT id FROM devices WHERE mac = ?1",
            params![&host.mac],
            |row| row.get(0),
        )
        .ok();

    let device_id = if let Some(id) = device_id {
        // Update existing device
        conn.execute(
            r#"
            UPDATE devices SET
                last_seen = datetime('now'),
                last_ip = ?2,
                vendor = COALESCE(?3, vendor),
                is_randomized = ?4,
                risk_score = ?5,
                device_type = COALESCE(?6, device_type),
                hostname = COALESCE(?7, hostname),
                os_guess = COALESCE(?8, os_guess)
            WHERE id = ?1
            "#,
            params![
                id,
                &host.ip,
                &host.vendor,
                if host.is_randomized { 1 } else { 0 },
                host.risk_score as i32,
                &host.device_type,
                &host.hostname,
                &host.os_guess,
            ],
        )
        .context("Failed to update device")?;
        id
    } else {
        // Insert new device
        conn.execute(
            r#"
            INSERT INTO devices (
                mac, last_ip, vendor, is_randomized, risk_score, device_type, hostname, os_guess
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                &host.mac,
                &host.ip,
                &host.vendor,
                if host.is_randomized { 1 } else { 0 },
                host.risk_score as i32,
                &host.device_type,
                &host.hostname,
                &host.os_guess,
            ],
        )
        .context("Failed to insert device")?;
        conn.last_insert_rowid()
    };

    // Insert device history for this scan
    let open_ports_str = host
        .open_ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");

    conn.execute(
        r#"
        INSERT INTO device_history (
            scan_id, device_id, ip, response_time_ms, ttl, risk_score, is_randomized,
            security_grade, is_online, discovery_method, open_ports
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#,
        params![
            scan_id,
            device_id,
            &host.ip,
            host.response_time_ms.map(|t| t as i64),
            host.ttl.map(|t| t as i32),
            host.risk_score as i32,
            if host.is_randomized { 1 } else { 0 },
            &host.security_grade,
            true,
            &host.discovery_method,
            open_ports_str,
        ],
    )
    .context("Failed to insert device history")?;

    Ok(device_id)
}

/// Get recent scans
pub fn get_recent_scans(conn: &Connection, limit: i32) -> Result<Vec<ScanRecord>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT id, scan_time, interface_name, local_ip, local_mac, subnet,
               scan_method, arp_discovered, icmp_discovered, total_hosts, duration_ms
        FROM scans
        ORDER BY scan_time DESC
        LIMIT ?1
        "#,
    )?;

    let scans = stmt
        .query_map(params![limit], |row| {
            Ok(ScanRecord {
                id: row.get(0)?,
                scan_time: parse_datetime_column(row.get::<_, String>(1)?, 1)?,
                interface_name: row.get(2)?,
                local_ip: row.get(3)?,
                local_mac: row.get(4)?,
                subnet: row.get(5)?,
                scan_method: row.get(6)?,
                arp_discovered: row.get(7)?,
                icmp_discovered: row.get(8)?,
                total_hosts: row.get(9)?,
                duration_ms: row.get(10)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(scans)
}

/// Get all devices
pub fn get_all_devices(conn: &Connection) -> Result<Vec<DeviceRecord>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT id, mac, first_seen, last_seen, last_ip, vendor, risk_score,
               device_type, hostname, os_guess, custom_name, notes
        FROM devices
        ORDER BY last_seen DESC
        "#,
    )?;

    let devices = stmt
        .query_map([], |row| {
            Ok(DeviceRecord {
                id: row.get(0)?,
                mac: row.get(1)?,
                first_seen: parse_datetime_column(row.get::<_, String>(2)?, 2)?,
                last_seen: parse_datetime_column(row.get::<_, String>(3)?, 3)?,
                last_ip: row.get(4)?,
                vendor: row.get(5)?,
                risk_score: row.get(6)?,
                device_type: row.get(7)?,
                hostname: row.get(8)?,
                os_guess: row.get(9)?,
                custom_name: row.get(10)?,
                notes: row.get(11)?,
                security_grade: None,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(devices)
}

/// Get device by MAC address
pub fn get_device_by_mac(conn: &Connection, mac: &str) -> Result<Option<DeviceRecord>> {
    let result = conn.query_row(
        r#"
        SELECT id, mac, first_seen, last_seen, last_ip, vendor, risk_score,
               device_type, hostname, os_guess, custom_name, notes
        FROM devices WHERE mac = ?1
        "#,
        params![mac],
        |row| {
            Ok(DeviceRecord {
                id: row.get(0)?,
                mac: row.get(1)?,
                first_seen: parse_datetime_column(row.get::<_, String>(2)?, 2)?,
                last_seen: parse_datetime_column(row.get::<_, String>(3)?, 3)?,
                last_ip: row.get(4)?,
                vendor: row.get(5)?,
                risk_score: row.get(6)?,
                device_type: row.get(7)?,
                hostname: row.get(8)?,
                os_guess: row.get(9)?,
                custom_name: row.get(10)?,
                notes: row.get(11)?,
                security_grade: None,
            })
        },
    );

    match result {
        Ok(device) => Ok(Some(device)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Update device custom name
pub fn update_device_name(conn: &Connection, mac: &str, custom_name: &str) -> Result<()> {
    conn.execute(
        "UPDATE devices SET custom_name = ?2 WHERE mac = ?1",
        params![mac, custom_name],
    )
    .context("Failed to update device name")?;
    Ok(())
}

/// Get device history for a specific device
pub fn get_device_history(
    conn: &Connection,
    device_id: i64,
    limit: i32,
) -> Result<Vec<DeviceHistoryRecord>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT id, scan_id, device_id, ip, response_time_ms, ttl,
               risk_score, is_online, discovery_method, open_ports
        FROM device_history
        WHERE device_id = ?1
        ORDER BY id DESC
        LIMIT ?2
        "#,
    )?;

    let history = stmt
        .query_map(params![device_id, limit], |row| {
            let ports_str: String = row.get::<_, Option<String>>(9)?.unwrap_or_default();
            let open_ports: Vec<u16> = ports_str
                .split(',')
                .filter_map(|s| s.parse().ok())
                .collect();

            Ok(DeviceHistoryRecord {
                id: row.get(0)?,
                scan_id: row.get(1)?,
                device_id: row.get(2)?,
                ip: row.get(3)?,
                response_time_ms: row.get(4)?,
                ttl: row.get(5)?,
                risk_score: row.get(6)?,
                is_online: row.get::<_, i32>(7)? == 1,
                discovery_method: row.get(8)?,
                open_ports,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(history)
}

/// Insert an alert
pub fn insert_alert(
    conn: &Connection,
    alert_type: AlertType,
    device_id: Option<i64>,
    device_mac: Option<&str>,
    device_ip: Option<&str>,
    message: &str,
    severity: AlertSeverity,
) -> Result<i64> {
    let alert = AlertInsert {
        alert_type,
        device_id,
        device_mac,
        device_ip,
        dedupe_key: None,
        message,
        severity,
    };
    insert_alert_with_dedupe_key(conn, &alert)
}

/// Insert an alert with an optional semantic dedupe key.
pub fn insert_alert_with_dedupe_key(conn: &Connection, alert: &AlertInsert<'_>) -> Result<i64> {
    conn.execute(
        r#"
        INSERT INTO alerts (
            alert_type, device_id, device_mac, device_ip, dedupe_key, message, severity
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
        params![
            alert.alert_type.to_string(),
            alert.device_id,
            alert.device_mac,
            alert.device_ip,
            alert.dedupe_key,
            alert.message,
            alert.severity.to_string(),
        ],
    )
    .context("Failed to insert alert")?;

    Ok(conn.last_insert_rowid())
}

/// Insert alert only if a matching unread alert does not already exist recently.
pub fn insert_alert_if_not_exists(
    conn: &Connection,
    alert: &AlertInsert<'_>,
    dedupe_key: &str,
    dedupe_window_minutes: i64,
) -> Result<Option<i64>> {
    let window_minutes = dedupe_window_minutes.max(1);
    let window_expr = format!("-{} minutes", window_minutes);

    let existing: Option<i64> = conn
        .query_row(
            r#"
            SELECT id
            FROM alerts
            WHERE alert_type = ?1
              AND COALESCE(device_mac, '') = COALESCE(?2, '')
              AND COALESCE(dedupe_key, '') = ?3
              AND is_read = 0
              AND created_at >= datetime('now', ?4)
            ORDER BY id DESC
            LIMIT 1
            "#,
            params![
                alert.alert_type.to_string(),
                alert.device_mac,
                dedupe_key,
                window_expr
            ],
            |row| row.get(0),
        )
        .optional()?;

    if existing.is_some() {
        return Ok(None);
    }

    let deduped_alert = AlertInsert {
        alert_type: alert.alert_type.clone(),
        device_id: alert.device_id,
        device_mac: alert.device_mac,
        device_ip: alert.device_ip,
        dedupe_key: Some(dedupe_key),
        message: alert.message,
        severity: alert.severity.clone(),
    };

    let id = insert_alert_with_dedupe_key(conn, &deduped_alert)?;
    Ok(Some(id))
}

/// Get unread alerts
pub fn get_unread_alerts(conn: &Connection) -> Result<Vec<AlertRecord>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT id, created_at, alert_type, device_id, device_mac, device_ip,
               message, severity, is_read
        FROM alerts
        WHERE is_read = 0
        ORDER BY created_at DESC
        "#,
    )?;

    let alerts = stmt
        .query_map([], |row| {
            let alert_type_str: String = row.get(2)?;
            let severity_str: String = row.get(7)?;

            Ok(AlertRecord {
                id: row.get(0)?,
                created_at: parse_datetime_column(row.get::<_, String>(1)?, 1)?,
                alert_type: parse_alert_type_or_default(&alert_type_str),
                device_id: row.get(3)?,
                device_mac: row.get(4)?,
                device_ip: row.get(5)?,
                message: row.get(6)?,
                severity: parse_alert_severity_or_default(&severity_str),
                is_read: row.get::<_, i32>(8)? == 1,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(alerts)
}

/// Mark alert as read
pub fn mark_alert_read(conn: &Connection, alert_id: i64) -> Result<()> {
    conn.execute(
        "UPDATE alerts SET is_read = 1 WHERE id = ?1",
        params![alert_id],
    )
    .context("Failed to mark alert read")?;
    Ok(())
}

/// Mark all alerts as read
pub fn mark_all_alerts_read(conn: &Connection) -> Result<()> {
    conn.execute("UPDATE alerts SET is_read = 1", [])
        .context("Failed to mark all alerts read")?;
    Ok(())
}

/// Clear all alerts
pub fn clear_all_alerts(conn: &Connection) -> Result<()> {
    conn.execute("DELETE FROM alerts", [])
        .context("Failed to clear all alerts")?;
    Ok(())
}

/// Get host-like records from the latest scan for insight calculations.
pub fn get_latest_scan_hosts(conn: &Connection) -> Result<Vec<HostInfo>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT
            d.last_ip,
            d.mac,
            d.vendor,
            d.device_type,
            d.hostname,
            dh.response_time_ms,
            dh.risk_score,
            dh.is_randomized,
            dh.open_ports
        FROM device_history dh
        JOIN devices d ON d.id = dh.device_id
        WHERE dh.scan_id = (SELECT MAX(id) FROM scans)
        ORDER BY d.mac
        "#,
    )?;

    let hosts = stmt
        .query_map([], |row| {
            let ip = row
                .get::<_, Option<String>>(0)?
                .unwrap_or_else(|| "0.0.0.0".to_string());
            let mac: String = row.get(1)?;
            let vendor: Option<String> = row.get(2)?;
            let device_type = row
                .get::<_, Option<String>>(3)?
                .unwrap_or_else(|| "UNKNOWN".to_string());
            let hostname: Option<String> = row.get(4)?;
            let response_time_ms = row.get::<_, Option<i64>>(5)?.map(|v| v as u64);
            let raw_risk_score: i32 = row.get(6)?;
            let risk_score = if raw_risk_score < 0 {
                tracing::warn!("Negative risk_score {} found in database; clamping to 0", raw_risk_score);
                0
            } else if raw_risk_score > 100 {
                tracing::warn!("Out-of-range risk_score {} found in database; clamping to 100", raw_risk_score);
                100
            } else {
                raw_risk_score as u8
            };
            let is_randomized = row.get::<_, i32>(7)? == 1;
            let ports_str = row.get::<_, Option<String>>(8)?.unwrap_or_default();

            let mut host = HostInfo::new(ip, mac, device_type, "DATABASE".to_string());
            host.vendor = vendor;
            host.hostname = hostname;
            host.response_time_ms = response_time_ms;
            host.risk_score = risk_score;
            host.is_randomized = is_randomized;
            host.open_ports = ports_str
                .split(',')
                .filter(|p| !p.is_empty())
                .filter_map(|p| p.parse::<u16>().ok())
                .collect();
            Ok(host)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(hosts)
}

/// Get network statistics
pub fn get_network_stats(conn: &Connection) -> Result<NetworkStats> {
    let total_devices: i64 =
        conn.query_row("SELECT COUNT(*) FROM devices", [], |row| row.get(0))?;

    // Devices seen in last scan (online)
    let online_devices: i64 = conn
        .query_row(
            r#"
        SELECT COUNT(DISTINCT device_id) FROM device_history
        WHERE scan_id = (SELECT MAX(id) FROM scans)
        "#,
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let offline_devices = total_devices - online_devices;

    // New devices in last 24 hours
    let new_devices_24h: i64 = conn.query_row(
        r#"
        SELECT COUNT(*) FROM devices
        WHERE first_seen >= datetime('now', '-24 hours')
        "#,
        [],
        |row| row.get(0),
    )?;

    // High risk devices (risk_score > 70)
    let high_risk_devices: i64 = conn
        .query_row(
            r#"
        SELECT COUNT(DISTINCT device_id) FROM device_history
        WHERE scan_id = (SELECT MAX(id) FROM scans) AND risk_score > 70
        "#,
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let total_scans: i64 = conn.query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))?;

    let last_scan_time_raw: Option<String> = conn
        .query_row(
            "SELECT scan_time FROM scans ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;

    let last_scan_time = match last_scan_time_raw {
        Some(raw) => Some(parse_datetime(raw)?),
        None => None,
    };

    Ok(NetworkStats {
        total_devices,
        online_devices,
        offline_devices,
        new_devices_24h,
        high_risk_devices,
        total_scans,
        last_scan_time,
    })
}

/// Helper: Parse SQLite datetime string to chrono DateTime
fn parse_datetime(s: String) -> Result<DateTime<Utc>> {
    DateTime::parse_from_str(&format!("{} +0000", s), "%Y-%m-%d %H:%M:%S %z")
        .map(|dt| dt.with_timezone(&Utc))
        .with_context(|| format!("Invalid datetime value in database: {}", s))
}

fn parse_datetime_column(s: String, column: usize) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_str(&format!("{} +0000", s), "%Y-%m-%d %H:%M:%S %z")
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(column, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn parse_alert_type_or_default(s: &str) -> AlertType {
    match s.parse() {
        Ok(value) => value,
        Err(_) => {
            tracing::warn!("Unknown alert type in database: {}", s);
            AlertType::Custom
        }
    }
}

fn parse_alert_severity_or_default(s: &str) -> AlertSeverity {
    match s.parse() {
        Ok(value) => value,
        Err(_) => {
            tracing::warn!("Unknown alert severity in database: {}", s);
            AlertSeverity::Info
        }
    }
}

/// Lookup vulnerabilities for a vendor from CVE cache
pub fn lookup_vulnerabilities(
    conn: &Connection,
    vendor: &str,
) -> Result<Vec<crate::models::VulnerabilityInfo>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT cve_id, description, severity, cvss_score
        FROM cve_cache
        WHERE LOWER(vendor) = LOWER(?1) OR vendor = '*'
        ORDER BY cvss_score DESC NULLS LAST
        "#,
    )?;

    let vulns = stmt
        .query_map(params![vendor], |row| {
            Ok(crate::models::VulnerabilityInfo {
                cve_id: row.get(0)?,
                description: row.get(1)?,
                severity: row.get(2)?,
                cvss_score: row.get(3)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(vulns)
}

/// Lookup port warnings for given ports
pub fn lookup_port_warnings(
    conn: &Connection,
    ports: &[u16],
) -> Result<Vec<crate::models::PortWarning>> {
    if ports.is_empty() {
        return Ok(Vec::new());
    }

    let placeholders = ports.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let query = format!(
        "SELECT port, service, warning, severity, recommendation FROM port_warnings WHERE port IN ({})",
        placeholders
    );

    let mut stmt = conn.prepare(&query)?;
    let params: Vec<&dyn rusqlite::ToSql> =
        ports.iter().map(|p| p as &dyn rusqlite::ToSql).collect();

    let warnings = stmt
        .query_map(params.as_slice(), |row| {
            Ok(crate::models::PortWarning {
                port: row.get::<_, i64>(0)? as u16,
                service: row.get(1)?,
                warning: row.get(2)?,
                severity: row.get(3)?,
                recommendation: row.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;

    #[test]
    fn test_insert_and_get_scan() {
        let db = Database::in_memory().unwrap();
        let conn = db.connection();
        let conn = conn.lock().unwrap();

        let result = ScanResult {
            interface_name: "eth0".to_string(),
            local_ip: "192.168.1.1".to_string(),
            local_mac: "AA:BB:CC:DD:EE:FF".to_string(),
            subnet: "192.168.1.0/24".to_string(),
            scan_method: "arp+icmp".to_string(),
            arp_discovered: 5,
            icmp_discovered: 3,
            total_hosts: 5,
            scan_duration_ms: 1500,
            active_hosts: vec![],
        };

        let scan_id = insert_scan(&conn, &result).unwrap();
        assert!(scan_id > 0);

        let scans = get_recent_scans(&conn, 10).unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].interface_name, "eth0");
    }

    #[test]
    fn test_network_stats() {
        let db = Database::in_memory().unwrap();
        let conn = db.connection();
        let conn = conn.lock().unwrap();

        let stats = get_network_stats(&conn).unwrap();
        assert_eq!(stats.total_devices, 0);
        assert_eq!(stats.total_scans, 0);
    }

    #[test]
    fn test_insert_scan_is_atomic_on_host_failure() {
        let db = Database::in_memory().unwrap();
        let conn = db.connection();
        let conn = conn.lock().unwrap();

        // Force device persistence failure after scan row insert.
        conn.execute_batch(
            r#"
            CREATE TRIGGER fail_device_insert
            AFTER INSERT ON devices
            BEGIN
                SELECT RAISE(FAIL, 'forced device insert failure');
            END;
            "#,
        )
        .unwrap();

        let host = HostInfo::new(
            "192.168.1.10".to_string(),
            "AA:BB:CC:DD:EE:01".to_string(),
            "UNKNOWN".to_string(),
            "ARP".to_string(),
        );

        let result = ScanResult {
            interface_name: "eth0".to_string(),
            local_ip: "192.168.1.1".to_string(),
            local_mac: "AA:BB:CC:DD:EE:FF".to_string(),
            subnet: "192.168.1.0/24".to_string(),
            scan_method: "arp+icmp".to_string(),
            arp_discovered: 1,
            icmp_discovered: 0,
            total_hosts: 1,
            scan_duration_ms: 1500,
            active_hosts: vec![host],
        };

        assert!(insert_scan(&conn, &result).is_err());

        let scan_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))
            .unwrap();
        assert_eq!(scan_count, 0, "scan row must rollback on host failure");
    }
}
