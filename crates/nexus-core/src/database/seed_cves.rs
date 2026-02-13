//! CVE database seeding
//!
//! Pre-loaded vulnerability database for offline operation

use anyhow::Result;
use rusqlite::{Connection, params};

/// Seed the CVE cache with curated vulnerabilities
pub fn seed_vulnerabilities(conn: &Connection) -> Result<()> {
    let cves = vec![
        // TP-Link Vulnerabilities
        (
            "TP-Link",
            "Various",
            "CVE-2023-1389",
            "Authentication bypass in HTTP server allows remote code execution",
            "CRITICAL",
            9.8,
            "2023-03-15",
        ),
        (
            "TP-Link",
            "Archer C5",
            "CVE-2022-30075",
            "Command injection vulnerability in HTTP server",
            "CRITICAL",
            9.8,
            "2022-06-01",
        ),
        (
            "TP-Link",
            "Archer AX21",
            "CVE-2023-29492",
            "Buffer overflow in web management interface",
            "HIGH",
            8.8,
            "2023-04-12",
        ),
        // MikroTik Vulnerabilities
        (
            "MikroTik",
            "RouterOS",
            "CVE-2023-30799",
            "Directory traversal vulnerability in web interface",
            "CRITICAL",
            9.1,
            "2023-05-10",
        ),
        (
            "MikroTik",
            "RouterOS",
            "CVE-2022-37057",
            "Unauthenticated arbitrary file read via WinBox protocol",
            "HIGH",
            7.5,
            "2022-08-24",
        ),
        // D-Link Vulnerabilities
        (
            "D-Link",
            "DIR-605",
            "CVE-2023-24817",
            "Remote command execution in HNAP protocol",
            "CRITICAL",
            9.8,
            "2023-02-18",
        ),
        (
            "D-Link",
            "Various",
            "CVE-2022-37056",
            "Hard-coded credentials in multiple router models",
            "HIGH",
            8.8,
            "2022-08-20",
        ),
        // Netgear Vulnerabilities
        (
            "Netgear",
            "R6700",
            "CVE-2023-27357",
            "Stack-based buffer overflow in UPnP service",
            "CRITICAL",
            9.8,
            "2023-03-22",
        ),
        (
            "Netgear",
            "Various",
            "CVE-2022-29303",
            "Pre-authentication command injection",
            "CRITICAL",
            9.8,
            "2022-05-12",
        ),
        // Generic Port-based Warnings
        (
            "*",
            "Telnet",
            "CVE-TELNET-001",
            "Unencrypted protocol transmits credentials in cleartext",
            "HIGH",
            7.5,
            "1990-01-01",
        ),
        (
            "*",
            "FTP",
            "CVE-FTP-001",
            "Unencrypted file transfer exposes data and credentials",
            "MEDIUM",
            5.9,
            "1990-01-01",
        ),
        (
            "*",
            "HTTP",
            "CVE-HTTP-001",
            "Unencrypted web traffic vulnerable to interception",
            "MEDIUM",
            5.3,
            "1990-01-01",
        ),
        (
            "*",
            "SMB",
            "CVE-2017-0144",
            "EternalBlue - Remote code execution in SMBv1 (WannaCry)",
            "CRITICAL",
            9.3,
            "2017-03-14",
        ),
        (
            "*",
            "RDP",
            "CVE-2019-0708",
            "BlueKeep - Remote desktop pre-authentication vulnerability",
            "CRITICAL",
            9.8,
            "2019-05-14",
        ),
        // Windows Common Vulnerabilities
        (
            "Microsoft",
            "Windows",
            "CVE-2023-21746",
            "Windows NTLM hash disclosure vulnerability",
            "HIGH",
            7.5,
            "2023-03-14",
        ),
        (
            "Microsoft",
            "Windows",
            "CVE-2023-23376",
            "Windows Common Log File System Driver elevation of privilege",
            "HIGH",
            7.8,
            "2023-03-14",
        ),
    ];

    for (vendor, product, cve_id, desc, severity, score, date) in cves {
        conn.execute(
            "INSERT OR IGNORE INTO cve_cache 
             (vendor, product, cve_id, description, severity, cvss_score, published_date, source) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'embedded')",
            params![vendor, product, cve_id, desc, severity, score, date],
        )?;
    }

    Ok(())
}

/// Seed port warnings database
pub fn seed_port_warnings(conn: &Connection) -> Result<()> {
    let warnings = vec![
        (
            21,
            "FTP",
            "Unencrypted file transfer protocol transmits credentials in cleartext",
            "MEDIUM",
            "Use SFTP (port 22) or FTPS (port 990) instead",
        ),
        (
            23,
            "Telnet",
            "Unencrypted remote access protocol, highly vulnerable to eavesdropping",
            "HIGH",
            "Use SSH (port 22) for secure remote access",
        ),
        (
            80,
            "HTTP",
            "Unencrypted web traffic can be intercepted",
            "LOW",
            "Use HTTPS (port 443) to encrypt web traffic",
        ),
        (
            135,
            "MS-RPC",
            "Microsoft RPC service, frequent target for attacks",
            "MEDIUM",
            "Block if not required, use firewall rules",
        ),
        (
            139,
            "NetBIOS",
            "Legacy Windows file sharing, vulnerable to various attacks",
            "MEDIUM",
            "Disable if SMB is not needed",
        ),
        (
            445,
            "SMB",
            "Server Message Block - frequent target for ransomware (e.g., WannaCry)",
            "CRITICAL",
            "Keep system patched, disable SMBv1, use firewall",
        ),
        (
            1433,
            "MS-SQL",
            "Microsoft SQL Server exposed to network",
            "HIGH",
            "Use firewall, strong authentication, and encryption",
        ),
        (
            3306,
            "MySQL",
            "MySQL database server exposed to network",
            "HIGH",
            "Bind to localhost only, use strong passwords",
        ),
        (
            3389,
            "RDP",
            "Remote Desktop Protocol - frequent brute-force target",
            "HIGH",
            "Use VPN, enable Network Level Authentication, strong passwords",
        ),
        (
            5432,
            "PostgreSQL",
            "PostgreSQL database exposed to network",
            "HIGH",
            "Restrict access, use strong authentication",
        ),
        (
            5900,
            "VNC",
            "Virtual Network Computing - often poorly secured",
            "HIGH",
            "Use SSH tunneling or VPN, enable authentication",
        ),
        (
            8080,
            "HTTP-Alt",
            "Alternative HTTP port, often used for admin panels",
            "MEDIUM",
            "Ensure proper authentication and use HTTPS",
        ),
    ];

    for (port, service, warning, severity, recommendation) in warnings {
        conn.execute(
            "INSERT OR IGNORE INTO port_warnings 
             (port, service, warning, severity, recommendation) 
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![port, service, warning, severity, recommendation],
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::schema::create_tables;

    #[test]
    fn test_seed_vulnerabilities() {
        let conn = Connection::open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        seed_vulnerabilities(&conn).unwrap();

        // Check that CVEs were inserted
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM cve_cache", [], |row| row.get(0))
            .unwrap();

        assert!(count > 0, "CVEs should be seeded");
    }

    #[test]
    fn test_seed_port_warnings() {
        let conn = Connection::open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        seed_port_warnings(&conn).unwrap();

        // Check that warnings were inserted
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM port_warnings", [], |row| row.get(0))
            .unwrap();

        assert!(count > 0, "Port warnings should be seeded");
    }
}
