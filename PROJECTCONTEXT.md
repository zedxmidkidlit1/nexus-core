# NEXUS Core Project Context

Last updated: 2026-02-12  
Repository: `NEXUS-core`  
Current commit snapshot: `739eb59`  
Crate: `nexus-core` `0.1.0`  
Rust: edition `2024`, `rust-version = 1.93`

## 1) What This Project Is

`nexus-core` is a Rust network intelligence engine with:
- Active network discovery (ARP + ICMP + TCP, optional SNMP enrichment)
- Passive discovery integration (mDNS and passive ARP in monitor path)
- Deterministic insights (health, security, distribution)
- Optional AI overlay (local Ollama and/or cloud Gemini)
- SQLite persistence with schema migrations and seeded vulnerability/port-warning datasets
- Export capabilities (JSON/CSV and optional PDF via feature flag)
- Reusable typed app layer for CLI and future UI entrypoints

Primary binary entrypoint is `src/main.rs`, but most operational logic is in library modules (`src/app.rs`, `src/command_handlers.rs`, `src/scan_workflow.rs`).

## 2) Current Runtime Surfaces

### CLI commands (from `src/cli.rs`)
- `nexus-core [scan] [--interface <NAME>]`
- `nexus-core load-test [--interface <NAME>] [--iterations <N>] [--concurrency <N>]`
- `nexus-core ai-check`
- `nexus-core ai-insights`
- `nexus-core interfaces`
- `nexus-core --help`
- `nexus-core --version`

Defaults:
- Default command: `scan`
- Load test defaults: `iterations=5`, `concurrency=1`

Validation:
- `--iterations` and `--concurrency` allowed only for `load-test`
- `--interface` allowed for `scan` and `load-test`

### App layer API (from `src/app.rs`)

Main public app functions:
- `run(args)`
- `run_with_context(args, &AppContext)`
- `run_with_ctrl_c(args, &AppContext)` (wires Ctrl+C cancellation)
- `execute_command(CliCommand)`
- `execute_command_with_context(CliCommand, &AppContext)`
- `execute_command_typed(CliCommand, &AppContext) -> AppCommandResult`

`AppContext` contains:
- `db_path`
- `ai_settings`
- `output_hook`
- `event_hook`
- `cancel_flag` (cooperative cancellation)

Output/result model:
- Text/JSON line output via `OutputHook`
- Strongly typed dispatch via `AppCommandResult`:
  - `HelpText`
  - `VersionText`
  - `Interfaces`
  - `AiCheck`
  - `AiInsights`
  - `Scan`
  - `LoadTest`

Event model (`AppEvent`):
- `Info`
- `Warn`
- `Error`
- `ScanPhase { phase, progress_pct }`
- `ScanPersisted { scan_id, path }`
- `Cancelled { stage }`

## 3) Cancellation Model (Current Implementation)

Cancellation is cooperative, not preemptive.

Entrypoints:
- `main` creates one `AppContext` and calls `run_with_ctrl_c(...)`
- `run_with_ctrl_c` listens for `tokio::signal::ctrl_c()` and flips `AppContext::cancel()`

Cancellation checkpoints exist in:
- command-level handlers (`scan`, `load-test`, `ai-check`, `ai-insights`)
- scan workflow stages (`scan-init`, `scan-arp`, `scan-tcp`, `scan-snmp`, `scan-dns`)
- load-test loop (`load-test-loop`)

Behavior:
- returns `Err("Operation cancelled (<stage>)")`
- emits `AppEvent::Cancelled { stage }`

Note:
- In-flight blocking work (for example a `spawn_blocking` ARP task) is not forcibly aborted mid-call; cancellation is enforced at checkpoints between phases.

## 4) Active Scan Pipeline

Core workflow is in `src/scan_workflow.rs` and `src/command_handlers.rs`.

Phases:
1. `init` (subnet/targets)
2. `arp` (active ARP discovery)
3. `tcp` (ICMP + TCP probing run in parallel)
4. `snmp` (optional, if enabled)
5. `dns` (reverse lookup)
6. complete aggregation

Important constants/behavior:
- ARP phase timeout in workflow: `15s` (`ARP_PHASE_TIMEOUT_SECS`)
- On ARP timeout, scan continues with empty ARP host set and warning event/log
- ICMP and TCP are joined concurrently after ARP
- SNMP enrichment runs only if `snmp_enabled()` returns true
- Host list sorted by IP before output
- Local host is explicitly appended with discovery method `LOCAL`
- Gateway heuristic is intentionally preserved:
  - `is_gateway = last_octet == 1 || open_ports contains 80`

Persistence behavior:
- `scan` attempts persistence via `persist_scan_result(...)`
- Persistence failure does not fail scan command; scan result still returns/prints JSON
- Successful persistence emits `AppEvent::ScanPersisted`

## 5) Load Test Behavior

`load-test`:
- Runs repeated scans in batches (`concurrency`)
- Tracks:
  - success/failure counts
  - wall time
  - min/max/avg scan duration
  - avg hosts found

Summary payload type: `LoadTestSummary` (in `src/app.rs`).

## 6) Interface Selection Rules

From `src/network/interface.rs`:
- filters loopback
- filters adapters without usable MAC
- filters link-local-only / unspecified IPv4
- filters known virtual adapter name patterns:
  - `hyper-v`, `vmware`, `virtualbox`, `docker`, `vethernet`, `wsl`
- on Windows, allows interfaces that may report `is_up=false` but have usable IPv4
- scoring priority:
  - `192.168.x.x` highest
  - `10.x.x.x` next
  - `172.16-31.x.x` lower
  - fallback for others
- explicit name selection is case-insensitive

`interfaces` command returns valid interface names in priority order.

## 7) Monitoring Subsystem (Background)

From `src/monitor/watcher.rs`:
- `BackgroundMonitor` supports:
  - `start(callback, interval)`
  - `start_with_interface(callback, interval, interface_name)`
  - `stop()`
  - `status()`
  - `selected_interface()`

Current monitor design:
- Single-interface session pinning:
  - interface resolved once at monitor start
  - cannot switch interface while running
- Event-driven callback model (`Fn(NetworkEvent)`)
- Active monitor scan path: ARP + TCP + DNS
- Passive integration path:
  - mDNS listener
  - passive ARP listener
  - enrichment/reconciliation of passive identities
- Offline retention window: `3600s`
- Background ARP phase timeout: `15s`

Network events emitted (`src/monitor/events.rs`):
- `MonitoringStarted`
- `MonitoringStopped`
- `ScanStarted`
- `ScanProgress`
- `ScanCompleted`
- `NewDeviceDiscovered`
- `DeviceWentOffline`
- `DeviceCameOnline`
- `DeviceIpChanged`
- `MonitoringError`

## 8) AI Integration (Hybrid Local/Cloud)

Module layout:
- `src/ai/config.rs`
- `src/ai/types.rs`
- `src/ai/router.rs`
- `src/ai/provider.rs`
- `src/ai/prompt.rs`
- `src/ai/redaction.rs`
- `src/ai/providers/ollama.rs`
- `src/ai/providers/gemini.rs`

Modes (`AiMode`):
- `disabled`
- `local`
- `cloud`
- `hybrid_auto`

Provider behavior:
- Local provider: Ollama (`/api/generate`, `format=json`)
- Cloud provider: Gemini (`generateContent`, JSON response MIME)
- Hybrid: tries local first, falls back to cloud

Determinism policy:
- Base rule-based insights are always computed first
- AI overlay augments result when available
- On failures, `ai_error` is populated; base insights remain valid

Data safety:
- Cloud mode supports host-identifier redaction unless `NEXUS_AI_CLOUD_ALLOW_SENSITIVE=true`

## 9) Insights + Security Logic

Insights modules:
- `health.rs`
- `security.rs`
- `distribution.rs`
- `recommendations.rs`
- `vulnerability_filter.rs`

Output types include:
- `NetworkHealth`
- `SecurityReport`
- `DeviceDistribution`
- `VendorDistribution`
- optional `AiInsightOverlay`

Recommendations currently include rules around:
- high-risk hosts
- Telnet (`23`)
- FTP (`21`)
- RDP (`3389`)
- randomized MAC presence
- unknown device types

## 10) Database, Persistence, and Encryption

DB connection:
- `src/database/connection.rs`
- Thread-safe wrapper around `rusqlite::Connection` via `Arc<Mutex<...>>`

Default DB path:
- `<platform-app-data>/NetworkTopologyMapper/data.db`

Schema (`src/database/schema.rs`):
- `scans`
- `devices`
- `device_history`
- `alerts`
- `cve_cache`
- `port_warnings`

Schema migration safeguards include adding missing legacy columns/indexes:
- `alerts.dedupe_key` + index
- `devices.is_randomized`
- `devices.risk_score`
- `device_history.is_randomized`

On DB initialization:
- seeds CVE and port-warning datasets when `cve_cache` is empty

Encryption (`src/database/encryption.rs`):
- AES-256-GCM
- Argon2id KDF for modern key derivation
- machine-bound mode and passphrase mode
- legacy SHA-256 decrypt fallback for compatibility
- env passphrase option: `NEXUS_DB_ENCRYPTION_PASSPHRASE`

## 11) Export Surfaces

JSON (`src/exports/json.rs`):
- scan export
- topology export with inferred router-to-device edges
- optional AI block embedding in scan JSON payload

CSV (`src/exports/csv.rs`):
- device inventory export
- current-host export

PDF (`src/exports/pdf.rs`):
- backend: `krilla`
- compile-time feature gated by `pdf-export`
- stubbed runtime error when feature is disabled
- relies on discovering compatible system fonts

## 12) Runtime Configuration (Environment Variables)

### AI
- `NEXUS_AI_ENABLED`
- `NEXUS_AI_MODE`
- `NEXUS_AI_TIMEOUT_MS`
- `NEXUS_AI_ENDPOINT`
- `NEXUS_AI_MODEL`
- `NEXUS_AI_GEMINI_ENDPOINT`
- `NEXUS_AI_GEMINI_MODEL`
- `NEXUS_AI_GEMINI_API_KEY`
- `NEXUS_AI_CLOUD_ALLOW_SENSITIVE`

### Scanner and monitor tuning
- `NEXUS_MAX_CONCURRENT_PINGS`
- `NEXUS_PING_TIMEOUT_MS`
- `NEXUS_PING_RETRIES`
- `NEXUS_MAX_SCAN_HOSTS`
- `NEXUS_ARP_MAX_WAIT_MS`
- `NEXUS_ARP_CHECK_INTERVAL_MS`
- `NEXUS_ARP_IDLE_TIMEOUT_MS`
- `NEXUS_ARP_ROUNDS`
- `NEXUS_TCP_PROBE_TIMEOUT_MS`
- `NEXUS_TCP_PROBE_PORTS`
- `NEXUS_SNMP_ENABLED`
- `NEXUS_SNMP_COMMUNITY`
- `NEXUS_SNMP_TIMEOUT_MS`
- `NEXUS_SNMP_PORT`
- `NEXUS_DEFAULT_MONITOR_INTERVAL`
- `NEXUS_MIN_MONITOR_INTERVAL`
- `NEXUS_MAX_MONITOR_INTERVAL`
- `NEXUS_CAME_ONLINE_STALE_MINUTES`

### DB encryption
- `NEXUS_DB_ENCRYPTION_PASSPHRASE`

Reference template exists in `.env.example`.

## 13) Build, Release, and CI

Build script:
- `build.rs` detects Npcap SDK paths on Windows for packet capture linkage

Release profile (from `Cargo.toml`):
- `opt-level = 3`
- `lto = "thin"`
- `codegen-units = 1`
- `strip = "symbols"`
- `panic = "abort"`
- `debug = false`
- `incremental = false`

CI workflow:
- `.github/workflows/ci-release-gates.yml`
- runs on `push` (main/tags) and `pull_request`
- gates:
  - `cargo fmt --all -- --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
  - benchmark smoke check via `scripts/benchmark.ps1 -Mode smoke -Iterations 1`

Benchmark script:
- `scripts/benchmark.ps1` supports:
  - `scan`
  - `load-test`
  - `smoke` (non-network sanity)

## 14) Repository Structure (Current Core Map)

Top-level:
- `Cargo.toml`
- `README.md`
- `.env.example`
- `build.rs`
- `scripts/`
- `src/`
- `tests/`

Core source folders:
- `src/app.rs` typed app orchestration
- `src/cli.rs` CLI parse contract
- `src/command_handlers.rs` command implementations
- `src/scan_workflow.rs` scan/load-test workflow
- `src/ai/` AI module and providers
- `src/network/` interface, subnet, DNS, device inference, vendor lookup
- `src/scanner/` ARP, ICMP, TCP, SNMP, passive scanners
- `src/database/` connection/schema/queries/models/encryption/seeds
- `src/alerts/` alert model + detector
- `src/monitor/` background monitor events/watcher/passive integration
- `src/exports/` CSV/JSON/PDF
- `src/insights/` health/security/distribution/recommendations/filtering
- `src/logging/` tracing setup/macros

## 15) Operational Constraints and Notes

- CLI intentionally does not include active vulnerability scanning; speed-first discovery and rule-based scoring are prioritized.
- Monitor runs on a single selected interface per active session.
- `scan` command persists to SQLite by default but is resilient if persistence fails.
- SNMP enrichment is optional and disabled by default (`NEXUS_SNMP_ENABLED=false` unless overridden).
- PDF generation is optional compile feature and depends on available system fonts.
- AI overlay is optional; base insights are always available.

## 16) Useful Commands

Core:
- `cargo run -- --help`
- `cargo run -- scan --interface "<NAME>"`
- `cargo run -- load-test --interface "<NAME>" --iterations 10 --concurrency 2`
- `cargo run -- ai-check`
- `cargo run -- ai-insights`
- `cargo run -- interfaces`

Quality:
- `cargo fmt --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-targets --all-features`

Benchmarking:
- `pwsh ./scripts/benchmark.ps1 -Mode smoke -Iterations 1`
- `pwsh ./scripts/benchmark.ps1 -Mode scan -Iterations 5`
- `pwsh ./scripts/benchmark.ps1 -Mode load-test -Iterations 20 -Concurrency 4`

---

This file is intended as the canonical high-level project memory for future work, planning, onboarding, and UI integration.
