//! Database connection and initialization
//!
//! Handles SQLite connection pooling and database setup

use anyhow::{anyhow, Context, Result};
use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::schema;

/// Database wrapper with thread-safe connection
pub struct Database {
    conn: Arc<Mutex<Connection>>,
    path: PathBuf,
}

impl Database {
    /// Creates a new database connection
    ///
    /// # Arguments
    /// * `path` - Path to the SQLite database file (created if not exists)
    pub fn new(path: PathBuf) -> Result<Self> {
        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create database directory")?;
        }

        let conn = Connection::open(&path).context("Failed to open database")?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
            path,
        };

        // Initialize schema
        db.initialize()?;

        Ok(db)
    }

    /// Creates an in-memory database (for testing)
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("Failed to open in-memory database")?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
            path: PathBuf::from(":memory:"),
        };

        db.initialize()?;

        Ok(db)
    }

    /// Initialize database schema
    fn initialize(&self) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow!("Database connection lock poisoned during initialization"))?;
        schema::create_tables(&conn)?;

        // Seed vulnerability database if empty
        let cve_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM cve_cache", [], |row| row.get(0))
            .context("Failed to query CVE cache count during database initialization")?;

        if cve_count == 0 {
            use super::seed_cves::{seed_port_warnings, seed_vulnerabilities};
            seed_vulnerabilities(&conn)?;
            seed_port_warnings(&conn)?;
        }

        Ok(())
    }

    /// Get a reference to the connection
    pub fn connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }

    /// Get database path
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Get default database path for the application
    pub fn default_path() -> PathBuf {
        // Use platform-specific app data directory
        #[cfg(target_os = "windows")]
        let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));

        #[cfg(target_os = "macos")]
        let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));

        #[cfg(target_os = "linux")]
        let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));

        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        let base = PathBuf::from(".");

        base.join("NetworkTopologyMapper").join("data.db")
    }
}

impl Clone for Database {
    fn clone(&self) -> Self {
        Self {
            conn: Arc::clone(&self.conn),
            path: self.path.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_db() {
        let db = Database::in_memory().expect("Failed to create in-memory db");
        assert_eq!(db.path().to_str(), Some(":memory:"));
    }

    #[test]
    fn test_default_path() {
        let path = Database::default_path();
        assert!(path.to_str().unwrap().contains("NetworkTopologyMapper"));
    }
}
