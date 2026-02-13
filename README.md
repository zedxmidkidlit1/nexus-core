# 🌐 NEXUS Core Engine

**Workspace (v0.1.x)** with:
- `nexus-cli` (root package) — CLI entrypoint
- `nexus-core` (`crates/nexus-engine`) — reusable engine library for CLI and upcoming Tauri UI

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

- **Continuous Scanning** — Background ARP+TCP+DNS scan loop at configurable intervals (default clamp: 10–3600 seconds; env-overridable)
- **Live Change Detection** — Compares consecutive scans to emit real-time events:
  - `NewDeviceDiscovered`, `DeviceWentOffline`, `DeviceCameOnline`, `DeviceIpChanged`
- **Offline Device Retention** — Tracks recently-offline devices for 1 hour to detect "came back online" events
- **Progress Events** — 5 scan phases reported: INIT (5%), ARP (20%), TCP (50%), DNS (80%), COMPLETE (100%)
- **Idempotent Start** — Calling `start()` when running just updates interval without restarting
- **Single-Interface Session Pinning** — Monitor can be started on a user-selected interface and remains pinned for the full session
- **Graceful Shutdown** — 1-second granular stop checks prevent long waits
- **Event Callbacks** — Framework-agnostic `Fn(NetworkEvent)` for Tauri IPC integration
- **Passive Discovery Integration** — mDNS/ARP passive listeners with `DeviceSnapshot` conversion helpers

### 📊 Insights Module — Analytics & Recommendations

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
- **Hybrid AI Overlay (Optional)** — Policy-driven LLM augmentation over rule-based output:
  - Local: Ollama (`NEXUS_AI_MODE=local`)
  - Cloud: Gemini API (`NEXUS_AI_MODE=cloud`)
  - Hybrid auto failover (`NEXUS_AI_MODE=hybrid_auto`)
  - Deterministic fallback preserved if AI is disabled/unavailable
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
# Build full workspace
cargo build --workspace

# Run CLI scanner (root package: nexus-cli, binary: nexus-core)
cargo run -p nexus-cli -- scan

# Show CLI help / version
cargo run -p nexus-cli -- --help
cargo run -p nexus-cli -- --version

# List valid scan interfaces
cargo run -p nexus-cli -- interfaces

# Scan a specific interface
cargo run -p nexus-cli -- scan --interface "<INTERFACE_NAME>"

# Run built-in load test mode (batch scan runner)
cargo run -p nexus-cli -- load-test --interface "<INTERFACE_NAME>" --iterations 10 --concurrency 2

# Validate AI provider connectivity + model availability
cargo run -p nexus-cli -- ai-check

# Generate AI insights from latest persisted scan history
cargo run -p nexus-cli -- ai-insights

# Enable optional PDF export backend (engine crate)
cargo build -p nexus-core --features pdf-export

# Run workspace tests
cargo test --workspace --all-targets

# Run engine-specific binary tests
cargo run -p nexus-core --bin test_alerts
cargo run -p nexus-core --bin test_insights

# Optional: run AI-augmented insights locally (Ollama)
$env:NEXUS_AI_ENABLED="true"; $env:NEXUS_AI_MODE="local"; $env:NEXUS_AI_MODEL="qwen3:8b"; cargo run -p nexus-core --bin test_insights

# Lint
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

When `NEXUS_AI_ENABLED=true`, `scan` JSON output includes an optional top-level `ai` block with provider/model metadata, overlay text, and fallback error details.
CLI `scan` persists results to the local SQLite database by default, so `ai-insights` can analyze the latest stored scan session.

## AI Profiles (Local/Cloud/Hybrid)

Use `.env.example` as a baseline template for runtime configuration.

```powershell
# Local only (Ollama)
pwsh ./scripts/ai-check.ps1 -Mode local -OllamaModel "qwen3:8b"

# Cloud only (Gemini)
pwsh ./scripts/ai-check.ps1 -Mode cloud -GeminiApiKey "<YOUR_API_KEY>"

# Hybrid auto fallback (local first, then cloud)
pwsh ./scripts/ai-check.ps1 -Mode hybrid_auto -GeminiApiKey "<YOUR_API_KEY>"
```

Troubleshooting:
- If `ai-check` reports `model_available=false` for Ollama, pull the model first: `ollama pull qwen3:8b`
- If cloud mode fails with configuration error, set `NEXUS_AI_GEMINI_API_KEY`
- Keep `NEXUS_AI_CLOUD_ALLOW_SENSITIVE=false` for default redaction safety

## Library Embedding (Typed API)

The core engine now exposes a reusable app layer for UI/desktop integrations:

- `execute_command_typed(...)` for strongly typed command results
- `AppContext` for runtime injection (`db_path`, `AiSettings`, output hook, event hook)
- `AppEvent` stream for progress and operational signals (`scan_phase`, `scan_persisted`, `info`, `warn`, `error`)
- cooperative cancellation via `AppContext::cancel()` / `AppContext::is_cancelled()`

```rust
use std::sync::Arc;
use nexus_core::{AppContext, AppEvent, CliCommand, execute_command_typed};

let context = AppContext::from_env()
    .with_output_hook(Arc::new(|line| println!("OUT: {}", line)))
    .with_event_hook(Arc::new(|event: &AppEvent| println!("EVENT: {:?}", event)));

let result = execute_command_typed(CliCommand::AiCheck, &context).await?;
println!("Typed result: {:?}", result);
```

For legacy CLI-compatible behavior (text/JSON lines), use `execute_command_with_context(...)` or `run_with_context(...)`.

## Release Hardening & Benchmarking (v0.1)

- `Cargo.toml` includes hardened release settings under `[profile.release]`:
  - `opt-level = 3`, `lto = "thin"`, `codegen-units = 1`
  - `strip = "symbols"`, `panic = "abort"`, `incremental = false`
- For reproducible CLI timing runs, use `scripts/benchmark.ps1`:

```powershell
# Build release + run N scan iterations
pwsh ./scripts/benchmark.ps1 -Mode scan -Iterations 5

# Build release + run load-test mode
pwsh ./scripts/benchmark.ps1 -Mode load-test -Iterations 20 -Concurrency 4
```

`load-test` output is JSON (`successful_scans`, `failed_scans`, duration and host-count aggregates), so it can be fed into CI/perf dashboards.

## Runtime Tuning (v0.1)

Core scanner behavior can now be tuned at runtime via environment variables:

- `NEXUS_MAX_CONCURRENT_PINGS`
- `NEXUS_MAX_SCAN_HOSTS`
- `NEXUS_PING_TIMEOUT_MS`
- `NEXUS_PING_RETRIES`
- `NEXUS_ARP_MAX_WAIT_MS`
- `NEXUS_ARP_CHECK_INTERVAL_MS`
- `NEXUS_ARP_IDLE_TIMEOUT_MS`
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
- `NEXUS_CAME_ONLINE_STALE_MINUTES`
- `NEXUS_AI_ENABLED` (`true|false`)
- `NEXUS_AI_MODE` (`local|cloud|hybrid_auto`)
- `NEXUS_AI_TIMEOUT_MS`
- `NEXUS_AI_ENDPOINT` (default: `http://127.0.0.1:11434`)
- `NEXUS_AI_MODEL` (default: `qwen3:8b`)
- `NEXUS_AI_GEMINI_ENDPOINT` (default: Google Generative Language API base URL)
- `NEXUS_AI_GEMINI_MODEL`
- `NEXUS_AI_GEMINI_API_KEY`
- `NEXUS_AI_CLOUD_ALLOW_SENSITIVE` (default: `false`; if `false`, cloud prompts redact host identifiers)

---

## Project Structure

```text
NEXUS-core/
├── Cargo.toml                   # Workspace root + nexus-cli package
├── build-cli.rs                 # CLI build script (root package)
├── src/
│   └── main.rs                  # CLI bootstrap (calls nexus_core::run_with_ctrl_c)
├── crates/
│   └── nexus-engine/
│       ├── Cargo.toml           # Engine crate (`nexus-core`)
│       ├── build.rs             # Npcap SDK detection (Windows engine build)
│       ├── src/                 # Full engine modules (ai, scanner, monitor, db, exports, insights)
│       ├── tests/               # Engine integration tests
│       └── examples/            # Engine examples / test binaries
├── scripts/
│   ├── ai-check.ps1        # AI provider diagnostics helper
│   └── benchmark.ps1       # Release benchmark/load-test runner
└── .gitignore
```

---

## 🚀 Roadmap Status (As of 2026-02-11)

### Completed in v0.1.0

- [x] **Release hardening profile** — Tuned `[profile.release]` (`opt-level=3`, thin LTO, single codegen unit, strip symbols, panic abort)
- [x] **Benchmark tooling + load-test mode** — Added `scripts/benchmark.ps1` and CLI `load-test` command with JSON summary
- [x] **Fix PDF multi-page reports** — Pagination and continuation headers implemented, no hard 20-device cap
- [x] **Persist risk scores in database** — `risk_score` is stored, migrated for legacy DBs, and exported in CSV/JSON/PDF flows
- [x] **Wire passive scanning into BackgroundMonitor** — Passive listeners start in monitor and merge into active scan snapshots
- [x] **Generate DeviceCameOnline alerts** — Return-to-network lifecycle is emitted for previously offline devices
- [x] **Fix MonitoringStatus total count** — `devices_total` now reflects session-wide unique devices seen
- [x] **Configurable SNMP community/timeout/port** — Runtime-configurable via environment variables
- [x] **Hybrid AI provider integration** — Added policy-driven Ollama/Gemini routing with deterministic fallback and cloud-redaction default

### Remaining backlog

- [ ] **SNMP LLDP topology discovery** — LLDP OIDs are defined, but remote-table walk + topology edge construction is still pending
- [ ] **DB-port recommendation parity in insights engine** — Port warnings exist, but recommendations do not yet elevate DB ports (3306/5432/27017/1433) as dedicated advice
- [ ] **AI deepening** — Add anomaly-specific prompts, evaluation harness, and provider quality/cost policy tuning
- [ ] **Optional ICMP/SNMP in monitor loop** — Current monitor scan path is ARP + TCP + DNS (SNMP optional in main scan path only)
- [ ] **Rogue-device trust policy** — No user-managed MAC allowlist/rules engine yet
- [ ] **Auto-refresh CVE feeds** — CVE/port warning seeds are local; no automatic NVD sync pipeline yet
- [ ] **Bandwidth and predictive uptime analytics** — Not implemented

---

## Relationship to Main Project

| Repository            | Purpose                                       |
| --------------------- | --------------------------------------------- |
| **NEXUS-core** (this) | Rust core engine — CLI development & upgrades |
| **STMAHM-main**       | Full desktop app — Tauri v2 + React 19 UI     |

After core engine upgrades are stable, engine-side changes from `crates/nexus-engine` will be integrated into the main STMAHM project and exposed via Tauri commands.
