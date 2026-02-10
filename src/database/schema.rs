//! Database schema definitions
//!
//! Creates and manages the SQLite tables

use anyhow::{Context, Result};
use rusqlite::Connection;

/// Create all database tables
pub fn create_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        -- Scans table: stores each scan session
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time TEXT NOT NULL DEFAULT (datetime('now')),
            interface_name TEXT NOT NULL,
            local_ip TEXT NOT NULL,
            local_mac TEXT NOT NULL,
            subnet TEXT NOT NULL,
            scan_method TEXT NOT NULL,
            arp_discovered INTEGER NOT NULL DEFAULT 0,
            icmp_discovered INTEGER NOT NULL DEFAULT 0,
            total_hosts INTEGER NOT NULL DEFAULT 0,
            duration_ms INTEGER NOT NULL DEFAULT 0
        );

        -- Devices table: unique devices by MAC address
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT UNIQUE NOT NULL,
            first_seen TEXT NOT NULL DEFAULT (datetime('now')),
            last_seen TEXT NOT NULL DEFAULT (datetime('now')),
            last_ip TEXT,
            vendor TEXT,
            is_randomized INTEGER NOT NULL DEFAULT 0,
            risk_score INTEGER NOT NULL DEFAULT 0,
            device_type TEXT,
            hostname TEXT,
            os_guess TEXT,
            custom_name TEXT,
            notes TEXT
        );

        -- Device history: per-scan device status
        CREATE TABLE IF NOT EXISTS device_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            response_time_ms INTEGER,
            ttl INTEGER,
            risk_score INTEGER NOT NULL DEFAULT 0,
            is_randomized INTEGER NOT NULL DEFAULT 0,
            security_grade TEXT DEFAULT '',
            is_online INTEGER NOT NULL DEFAULT 1,
            discovery_method TEXT,
            open_ports TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        );

        -- Alerts table: notifications and events
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            alert_type TEXT NOT NULL,
            device_id INTEGER,
            device_mac TEXT,
            device_ip TEXT,
            dedupe_key TEXT,
            message TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            is_read INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
        );

        -- CVE Cache table: vulnerability database
        CREATE TABLE IF NOT EXISTS cve_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor TEXT NOT NULL,
            product TEXT,
            cve_id TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            cvss_score REAL,
            published_date TEXT,
            source TEXT DEFAULT 'embedded',
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(vendor, cve_id)
        );

        -- Port Warnings table: insecure port information
        CREATE TABLE IF NOT EXISTS port_warnings (
            port INTEGER PRIMARY KEY,
            service TEXT NOT NULL,
            warning TEXT NOT NULL,
            severity TEXT NOT NULL,
            recommendation TEXT
        );

        -- Indexes for performance
        CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(scan_time);
        CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
        CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
        CREATE INDEX IF NOT EXISTS idx_device_history_scan ON device_history(scan_id);
        CREATE INDEX IF NOT EXISTS idx_device_history_device ON device_history(device_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_unread ON alerts(is_read) WHERE is_read = 0;
        CREATE INDEX IF NOT EXISTS idx_cve_vendor ON cve_cache(vendor);
        CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_cache(severity);
        "#,
    )
    .context("Failed to create database tables")?;

    // Backward-compatible migration for older databases created before dedupe_key existed.
    let has_dedupe_key: bool = conn
        .prepare("PRAGMA table_info(alerts)")
        .and_then(|mut stmt| {
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let col_name: String = row.get(1)?;
                if col_name == "dedupe_key" {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .context("Failed to inspect alerts table schema")?;

    if !has_dedupe_key {
        conn.execute("ALTER TABLE alerts ADD COLUMN dedupe_key TEXT", [])
            .context("Failed to migrate alerts table with dedupe_key column")?;
    }

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_dedupe ON alerts(alert_type, device_mac, dedupe_key, created_at)",
        [],
    )
    .context("Failed to create idx_alerts_dedupe index")?;

    let has_devices_randomized: bool = conn
        .prepare("PRAGMA table_info(devices)")
        .and_then(|mut stmt| {
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let col_name: String = row.get(1)?;
                if col_name == "is_randomized" {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .context("Failed to inspect devices table schema")?;

    if !has_devices_randomized {
        conn.execute(
            "ALTER TABLE devices ADD COLUMN is_randomized INTEGER NOT NULL DEFAULT 0",
            [],
        )
        .context("Failed to migrate devices table with is_randomized column")?;
    }

    let has_devices_risk_score: bool = conn
        .prepare("PRAGMA table_info(devices)")
        .and_then(|mut stmt| {
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let col_name: String = row.get(1)?;
                if col_name == "risk_score" {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .context("Failed to inspect devices table schema for risk_score")?;

    if !has_devices_risk_score {
        conn.execute(
            "ALTER TABLE devices ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0",
            [],
        )
        .context("Failed to migrate devices table with risk_score column")?;
    }

    let has_history_randomized: bool = conn
        .prepare("PRAGMA table_info(device_history)")
        .and_then(|mut stmt| {
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let col_name: String = row.get(1)?;
                if col_name == "is_randomized" {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .context("Failed to inspect device_history table schema")?;

    if !has_history_randomized {
        conn.execute(
            "ALTER TABLE device_history ADD COLUMN is_randomized INTEGER NOT NULL DEFAULT 0",
            [],
        )
        .context("Failed to migrate device_history table with is_randomized column")?;
    }

    Ok(())
}

/// Drop all tables (for testing/reset)
#[allow(dead_code)]
pub fn drop_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        DROP TABLE IF EXISTS alerts;
        DROP TABLE IF EXISTS device_history;
        DROP TABLE IF EXISTS devices;
        DROP TABLE IF EXISTS scans;
        "#,
    )
    .context("Failed to drop tables")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_tables() {
        let conn = Connection::open_in_memory().unwrap();
        create_tables(&conn).expect("Failed to create tables");

        // Verify tables exist
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(tables.contains(&"scans".to_string()));
        assert!(tables.contains(&"devices".to_string()));
        assert!(tables.contains(&"device_history".to_string()));
        assert!(tables.contains(&"alerts".to_string()));
    }

    #[test]
    fn test_legacy_alerts_schema_migrates_dedupe_key_before_index() {
        let conn = Connection::open_in_memory().unwrap();

        // Simulate an older alerts schema without dedupe_key.
        conn.execute_batch(
            r#"
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                alert_type TEXT NOT NULL,
                device_id INTEGER,
                device_mac TEXT,
                device_ip TEXT,
                message TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'info',
                is_read INTEGER NOT NULL DEFAULT 0
            );
            "#,
        )
        .unwrap();

        create_tables(&conn).expect("Legacy schema migration should succeed");

        let has_dedupe_key: bool = conn
            .prepare("PRAGMA table_info(alerts)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .any(|name| name == "dedupe_key");

        assert!(
            has_dedupe_key,
            "alerts.dedupe_key should be added for legacy DBs"
        );

        let dedupe_index_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'idx_alerts_dedupe')",
                [],
                |row| row.get::<_, i32>(0),
            )
            .unwrap()
            == 1;

        assert!(
            dedupe_index_exists,
            "idx_alerts_dedupe should exist after migration"
        );
    }

    #[test]
    fn test_legacy_devices_schema_migrates_risk_score_column() {
        let conn = Connection::open_in_memory().unwrap();

        conn.execute_batch(
            r#"
            CREATE TABLE devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT UNIQUE NOT NULL,
                first_seen TEXT NOT NULL DEFAULT (datetime('now')),
                last_seen TEXT NOT NULL DEFAULT (datetime('now')),
                last_ip TEXT,
                vendor TEXT,
                device_type TEXT,
                hostname TEXT,
                os_guess TEXT,
                custom_name TEXT,
                notes TEXT
            );
            "#,
        )
        .unwrap();

        create_tables(&conn).expect("Legacy devices schema migration should succeed");

        let has_risk_score: bool = conn
            .prepare("PRAGMA table_info(devices)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .any(|name| name == "risk_score");

        assert!(
            has_risk_score,
            "devices.risk_score should be added for legacy DBs"
        );
    }
}
