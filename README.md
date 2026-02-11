# 🌐 NEXUS Core Engine

**`nexus-core` v0.5.0-dev** — Standalone Rust CLI for network discovery, security analysis, and health monitoring.

This is the **core engine** extracted from the [NEXUS Desktop App (STMAHM)](../STMAHM-main/) for independent development and upgrade work. The full Tauri + React UI lives in the original repository.

---

## ✅ Current Features

### 🔍 Scanner Module — Multi-Protocol Network Discovery

| Protocol        | Description                                                                                                                                                 |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ARP**         | Adaptive ARP scanning with early termination — dynamically adjusts timing based on network responsiveness for faster scans                                  |
| **ICMP**        | ICMP ping with configurable retries and TTL-based OS fingerprinting (Linux ~64, Windows ~128, Cisco ~255)                                                   |
| **TCP**         | TCP port probing across a fast default set of 5 common ports (SSH, HTTP, HTTPS, SMB, RDP), configurable in `config.rs`                                    |
| **SNMP**        | SNMP v2c enrichment — queries `sysName`, `sysDescr`, `sysUpTime` OIDs for device details                                                                    |
| **mDNS**        | Passive mDNS/DNS-SD listener — discovers devices via multicast service announcements (AirPlay, HomeKit, Chromecast, Printers, etc.) without sending packets |
| **Passive ARP** | Passive ARP traffic monitor — captures MAC-to-IP mappings from broadcast frames without active probing                                                      |

**5-Phase Scan Pipeline (SNMP optional):** `ARP Discovery → ICMP Ping → TCP Probe → SNMP Enrichment → DNS Lookup`

### 🧠 Network Intelligence Module

- **Device Type Inference** — Classifies devices into **15 categories** (Router, Switch, AP, PC, Mobile, IoT, Printer, Camera, NAS, Smart TV, Gaming, Server, Container Host, Hypervisor, Unknown) using multi-factor heuristics:
  - Vendor name matching (200+ OUI prefixes)
  - Hostname pattern analysis
  - Open port signatures (e.g., port 9100 → Printer, port 631 → IPP)
  - Gateway detection
- **Risk Scoring** — 0–100 risk score per device based on device type, open ports, and known vulnerabilities
- **MAC Vendor Lookup** — OUI database resolution with randomized MAC detection (checks local/multicast bit)
- **Smart Interface Selection** — Auto-detects the best network interface using scoring: physical adapters preferred, private IP ranges (192.168.x.x, 10.x.x.x, 172.16-31.x.x) prioritized
- **Concurrent DNS** — Reverse DNS lookups with parallel resolution using `tokio::spawn`
- **Subnet Management** — Centered scan windows for large subnets (>1024 hosts), special address filtering (network/broadcast)

### 🗄️ Database Module — Persistent Storage & Encryption

- **SQLite Database** — 6 tables: `scans`, `devices`, `device_history`, `alerts`, `cve_cache`, `port_warnings`
- **AES-256-GCM Encryption** — Encrypted database exports with Argon2id key derivation from machine-specific material
- **Legacy Compatibility** — SHA-256 fallback decryption for backward data migration
- **Schema Migrations** — Backward-compatible column additions (`dedupe_key`, `is_randomized`) with existence checks
- **Transactional Inserts** — Atomic scan + device data persistence prevents partial writes
- **Embedded CVE Database** — ~20 pre-seeded CVEs + port warnings for offline vulnerability assessment
- **Thread Safety** — `Arc<Mutex<Connection>>` for safe concurrent access from Tauri IPC

### 🔔 Alerts Module — Change Detection & Notifications

6 alert types with 4 severity levels:

| Alert Type       | Severity | Trigger                                            |
| ---------------- | -------- | -------------------------------------------------- |
| `NEW_DEVICE`     | Medium   | Unknown MAC address appears on network             |
| `DEVICE_OFFLINE` | Low      | Known device not found in scan                     |
| `DEVICE_ONLINE`  | Low      | Previously offline device returns                  |
| `HIGH_RISK`      | High     | Device risk score ≥ 50                             |
| `UNUSUAL_PORT`   | High     | Suspicious port open (Telnet/FTP/RDP/VNC/DB ports) |
| `IP_CHANGED`     | Low      | Known device changed IP address                    |

- Builder pattern: `Alert::new().with_device().with_severity()`
- Baseline comparison: `detect_alerts()` compares current scan vs. known device history
- First-scan support: `detect_alerts_without_baseline()` for security-only alerts

### 📡 Background Monitor Module — Real-Time Monitoring

- **Continuous Scanning** — Background ARP+TCP+DNS scan loop at configurable intervals (10–3600 seconds)
- **Live Change Detection** — Compares consecutive scans to emit real-time events:
  - `NewDeviceDiscovered`, `DeviceWentOffline`, `DeviceCameOnline`, `DeviceIpChanged`
- **Offline Device Retention** — Tracks recently-offline devices for 1 hour to detect "came back online" events
- **Progress Events** — 5 scan phases reported: INIT (5%), ARP (20%), TCP (50%), DNS (80%), COMPLETE (100%)
- **Idempotent Start** — Calling `start()` when running just updates interval without restarting
- **Graceful Shutdown** — 1-second granular stop checks prevent long waits
- **Event Callbacks** — Framework-agnostic `Fn(NetworkEvent)` for Tauri IPC integration
- **Passive Discovery Integration** — mDNS/ARP passive listeners with `DeviceSnapshot` conversion helpers

### 📊 Insights Module — AI-Powered Analytics

- **Network Health Score** — 0–100 composite score with letter grade (A–F):
  - Security component (0–40 points): based on high/medium risk device counts
  - Stability component (0–30 points): based on ICMP response rates
  - Compliance component (0–30 points): penalizes unknown types and randomized MACs
- **Security Grading** — Per-device A–F letter grade based on vulnerability severity, port warnings, risk score, and MAC randomization
- **Context-Aware CVE Filtering** — Smart vulnerability matching:
  - Windows-only CVEs (EternalBlue/BlueKeep) only applied to Windows device types
  - Universal port warnings (Telnet/FTP/HTTP) applied to all device types
  - Vendor-specific CVE lookup with wildcard exclusion
- **Security Recommendations** — Actionable advice with priority levels (Critical/High/Medium/Low/Info):
  - Telnet exposure (Critical)
  - FTP exposure (High)
  - RDP exposure (Medium)
  - Randomized MAC tracking (Low)
  - Unidentified device classification (Info)
- **Device Distribution** — Type and vendor breakdown with percentages and top-5 ranking
- **Vendor Distribution** — Manufacturer analytics with dominant vendor identification

### 📤 Exports Module — Multi-Format Reports

| Format   | Capabilities                                                                                                                                             |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CSV**  | Device inventory export (IP, MAC, hostname, vendor, type, OS, risk, ports, latency) + scan result export                                                 |
| **JSON** | Full scan result export + **Topology export** with device nodes and inferred router-to-device connections                                                |
| **PDF**  | Professional scan report (cover page, executive summary, device inventory table) + Network health report (security recommendations with priority badges) |

### 📝 Logging Module

- **Structured Logging** — Built on `tracing` crate with subscriber + appender
- **Convenience Macros** — `log_stderr!`, `log_debug!`, `log_warn!`, `log_error!` wrappers
- **Log Levels** — `DEBUG`, `INFO`, `WARN`, `ERROR` with formatted output

---

## Requirements

- **Rust** toolchain (stable `1.93+`, 2024 edition)
- **Windows**: [Npcap](https://npcap.com/) + run as Administrator
- **Linux**: `libpcap-dev`, `build-essential`
- **macOS**: `libpcap` (pre-installed or via Homebrew)
- **PDF export feature**: build with `--features pdf-export` (Krilla backend; requires system fonts)

---

## Quick Start

```bash
# Build
cargo build

# Run CLI scanner (outputs JSON to stdout)
cargo run

# Show CLI help / version
cargo run -- --help
cargo run -- --version

# List valid scan interfaces
cargo run -- interfaces

# Scan a specific interface
cargo run -- scan --interface "<INTERFACE_NAME>"

# Enable optional PDF export backend
cargo build --features pdf-export

# Run tests
cargo test --all-targets

# Run specific binary tests
cargo run --bin test_alerts
cargo run --bin test_insights

# Lint
cargo clippy --all-targets
```

## Runtime Tuning (v0.5)

Core scanner behavior can now be tuned at runtime via environment variables:

- `NEXUS_MAX_CONCURRENT_PINGS`
- `NEXUS_MAX_SCAN_HOSTS`
- `NEXUS_PING_TIMEOUT_MS`
- `NEXUS_PING_RETRIES`
- `NEXUS_ARP_MAX_WAIT_MS`
- `NEXUS_ARP_ROUNDS`
- `NEXUS_TCP_PROBE_TIMEOUT_MS`
- `NEXUS_TCP_PROBE_PORTS` (comma-separated, e.g. `22,80,443,3389`)
- `NEXUS_SNMP_ENABLED`
- `NEXUS_SNMP_COMMUNITY`
- `NEXUS_SNMP_TIMEOUT_MS`
- `NEXUS_SNMP_PORT`
- `NEXUS_DEFAULT_MONITOR_INTERVAL`
- `NEXUS_MIN_MONITOR_INTERVAL`
- `NEXUS_MAX_MONITOR_INTERVAL`

---

## Project Structure

```text
NEXUS-core/
├── Cargo.toml              # Package config (nexus-core)
├── build.rs                # Npcap SDK detection (Windows)
├── src/
│   ├── main.rs             # CLI entry point (5-phase scan pipeline)
│   ├── lib.rs              # Library exports
│   ├── models.rs           # Core data models (ScanResult, HostInfo, etc.)
│   ├── config.rs           # Configuration constants & tuning parameters
│   ├── scanner/
│   │   ├── arp.rs          # Adaptive ARP scanning with early termination
│   │   ├── icmp.rs         # ICMP ping + TTL-based OS fingerprinting
│   │   ├── tcp.rs          # TCP port probing (default 5 common ports, configurable)
│   │   ├── snmp.rs         # SNMP v2c enrichment (hostname, description, uptime)
│   │   └── passive/
│   │       ├── mdns.rs     # mDNS/DNS-SD passive discovery (9 service types)
│   │       └── arp.rs      # Passive ARP traffic monitor
│   ├── network/
│   │   ├── device.rs       # Device type inference (15 types) + risk scoring
│   │   ├── dns.rs          # Concurrent reverse DNS lookups
│   │   ├── interface.rs    # Smart interface selection with scoring
│   │   ├── subnet.rs       # Subnet calculation + centered scan windows
│   │   ├── vendor.rs       # MAC vendor OUI lookup + randomized MAC detection
│   │   └── subnet_tests.rs # Unit tests for subnet utilities
│   ├── database/
│   │   ├── connection.rs   # SQLite init + Arc<Mutex> thread safety
│   │   ├── schema.rs       # 6 tables + backward-compatible migrations
│   │   ├── queries.rs      # CRUD operations + transactional scan inserts
│   │   ├── models.rs       # DB record structs + AlertType/AlertSeverity enums
│   │   ├── encryption.rs   # AES-256-GCM + Argon2id KDF + legacy SHA-256 compat
│   │   ├── encryption_tests.rs  # Encryption key consistency tests
│   │   └── seed_cves.rs    # Embedded CVE database (~20 CVEs + port warnings)
│   ├── alerts/
│   │   ├── detector.rs     # Change detection (new/offline/risk/port/IP-change)
│   │   └── types.rs        # 6 alert types + 4 severity levels
│   ├── monitor/
│   │   ├── watcher.rs      # Background scan loop + live change detection
│   │   ├── events.rs       # 7 NetworkEvent types for frontend IPC
│   │   └── passive_integration.rs  # mDNS/ARP listener helpers
│   ├── insights/
│   │   ├── health.rs       # 3-component health score (security/stability/compliance)
│   │   ├── security.rs     # Per-device A–F security grading
│   │   ├── distribution.rs # Device type + vendor distribution stats
│   │   ├── recommendations.rs  # Actionable security advice (5 priority levels)
│   │   └── vulnerability_filter.rs  # Context-aware CVE filtering
│   ├── exports/
│   │   ├── csv.rs          # Device + scan CSV export
│   │   ├── json.rs         # Scan + topology JSON export
│   │   └── pdf.rs          # Scan report + health report PDF generation
│   ├── logging/
│   │   └── macros.rs       # Convenience logging macros (tracing wrappers)
│   └── bin/
│       ├── test_alerts.rs  # Alert detection test binary
│       └── test_insights.rs # Insights system test binary
└── .gitignore
```

---

## 🚀 Upgrade Plan (v0.4.0 → v0.5.0)

### Phase 1 — Critical Fixes (Pre-Demo) 🔴

> Must be completed before the TU Project Show demo.

- [ ] **Fix PDF multi-page reports** — Add page break logic; remove 20-device limit so all devices appear in generated PDFs
- [ ] **Persist risk scores in database** — Add `risk_score` column to `devices` table; update `DeviceRecord`, `insert_scan_with_devices()`, and CSV export to use actual scores instead of hardcoded "0"
- [ ] **Wire passive scanning into BackgroundMonitor** — Call `start_passive_listeners()` in `BackgroundMonitor::start()`; merge mDNS discoveries and ARP enrichment into the live device map
- [ ] **Error recovery for background scans** — Add connection retry logic and proper error propagation instead of silent `Utc::now()` fallbacks

### Phase 2 — Feature Completion (High Impact) 🟡

> Complete the partially-implemented features for a polished showcase.

- [ ] **Implement SNMP LLDP topology discovery** — Activate the already-defined LLDP OIDs (`lldpRemSysName`, `lldpRemPortId`, `lldpRemChassisId`); walk the LLDP remote table to build real layer-2 topology connections instead of star topology
- [ ] **Add database port security recommendations** — Flag exposed ports 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB), 1433 (MSSQL) in the recommendations engine
- [ ] **Generate DeviceCameOnline alerts** — Track last-seen timestamps to detect when previously-offline devices return; complete the alert lifecycle (discovered → offline → back online)
- [ ] **AI-powered network intelligence** — Integrate Gemini/Ollama for natural language scan summaries, anomaly detection, and predictive insights

### Phase 3 — Polish & Production Hardening 🟢

> Robustness improvements for real-world deployment.

- [ ] **Configurable SNMP community strings** — Accept via CLI argument or config file; fall back to "public" if unspecified
- [ ] **Add ICMP/SNMP to background scans** — Include ping + SNMP enrichment phases in monitor scans for richer data (with configurable toggle for speed vs. accuracy)
- [ ] **Fix MonitoringStatus total count** — Track `total_unique_devices_seen` across all scans instead of reporting `devices_total = devices_online`
- [ ] **Rogue device detection** — Trusted device whitelist with auto-alert for unknown MACs
- [ ] **Custom alert rules engine** — User-defined alert conditions (port ranges, risk thresholds, schedule)
- [ ] **Enhanced CVE database** — Auto-update from NVD/NIST feeds with local caching
- [ ] **Bandwidth monitoring** — Per-device traffic statistics using packet capture analysis
- [ ] **Predictive analytics** — Device offline prediction based on historical uptime patterns

---

## Relationship to Main Project

| Repository            | Purpose                                       |
| --------------------- | --------------------------------------------- |
| **NEXUS-core** (this) | Rust core engine — CLI development & upgrades |
| **STMAHM-main**       | Full desktop app — Tauri v2 + React 19 UI     |

After core engine upgrades are stable, changes will be integrated back into the main STMAHM project's `src/` directory and exposed via new Tauri commands.
