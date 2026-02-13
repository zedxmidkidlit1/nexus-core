# NEXUS Core Project Context

Last updated: 2026-02-13  
Repository: `NEXUS-core`  
Branch: `main`

## 1) Workspace Layout (Current)

This repository is now a Cargo workspace with a split between CLI and engine:

- Root package: `nexus-cli`
  - `Cargo.toml` at repo root
  - Binary: `nexus-core` from `src/main.rs`
  - Purpose: CLI entrypoint only
- Member crate: `nexus-core`
  - Path: `crates/nexus-engine`
  - Purpose: reusable engine library for CLI and upcoming Tauri integration

Root `src/` now intentionally contains only the CLI bootstrap (`src/main.rs`).

## 2) Runtime Surfaces

CLI commands (parsed by engine crate `crates/nexus-engine/src/cli.rs`):

- `nexus-core scan [--interface <NAME>]`
- `nexus-core load-test [--interface <NAME>] [--iterations <N>] [--concurrency <N>]`
- `nexus-core ai-check`
- `nexus-core ai-insights`
- `nexus-core interfaces`
- `nexus-core --help`
- `nexus-core --version`

Current CLI UX:

- No-arg run shows help (does not auto-scan)
- Windows helper `scripts/run-nexus.cmd` pauses on no-arg launch for double-click readability

## 3) Engine API Boundary

Engine command model is decoupled from CLI parsing:

- Canonical command type: `AppCommand` (`crates/nexus-engine/src/command.rs`)
- CLI parser returns `AppCommand`
- Reusable app execution layer:
  - `execute_command(...)`
  - `execute_command_with_context(...)`
  - `execute_command_typed(...)`
  - `run(...)`, `run_with_context(...)`, `run_with_ctrl_c(...)` via `cli_adapter`

Main integration types:

- `AppContext` (db path, AI settings, output hook, event hook, cancellation flag)
- `AppEvent` (progress/info/warn/error/cancel/persisted events)
- `AppCommandResult` (typed result variants)

## 4) Core Engine Modules

Location: `crates/nexus-engine/src/`

- `scanner/` (ARP, ICMP, TCP, SNMP, passive scanners)
- `network/` (interface selection, subnet, DNS, vendor/device inference)
- `database/` (SQLite schema/queries/migrations/encryption/seeds)
- `alerts/` (detector + alert types)
- `monitor/` (background monitoring + passive integration)
- `insights/` (health/security/distribution/recommendations)
- `exports/` (JSON/CSV/PDF feature-gated)
- `ai/` (local/cloud/hybrid provider routing and overlay)
- `app.rs`, `command_handlers.rs`, `scan_workflow.rs`

## 5) Build and Release Model

Profiles:

- Release profile remains in root `Cargo.toml` (`opt-level=3`, thin LTO, codegen-units=1, strip symbols, panic abort)

Packaging scripts:

- `scripts/benchmark.ps1` now builds with `cargo build --release -p nexus-cli`
- `scripts/package.ps1` now builds with `cargo build --release -p nexus-cli`

Windows linking:

- Engine crate keeps `crates/nexus-engine/build.rs` for Npcap `Packet.lib` lookup
- CI and release workflows install Npcap SDK using `scripts/install-npcap-sdk.ps1`

## 6) CI/CD (Workspace-Aware)

`ci-release-gates.yml`:

- `push` (main) and `pull_request`, with markdown-only path filtering
- Linux quality checks run with workspace scope:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `cargo test --workspace --all-targets --all-features`
- Windows/macOS jobs use workspace-scoped check/test build commands
- Caching enabled via `actions/cache@v5`

`release.yml`:

- Trigger: `v*` tags and manual dispatch
- Cross-platform matrix (Linux, Windows, macOS Intel/ARM)
- Build command now targets CLI package explicitly:
  - `cargo build --release --locked -p nexus-cli --target <target>`
- Draft GitHub release output remains enabled

## 7) Directory Map (High-Level)

```text
NEXUS-core/
├── Cargo.toml                  # workspace root + nexus-cli package
├── build-cli.rs                # root CLI build script
├── src/
│   └── main.rs                 # CLI bootstrap
├── crates/
│   └── nexus-engine/
│       ├── Cargo.toml          # engine crate (`nexus-core`)
│       ├── build.rs            # Npcap link-path detection for engine build
│       ├── src/                # engine source modules
│       ├── tests/              # engine integration tests
│       └── examples/           # engine examples
├── scripts/
├── .github/workflows/
├── README.md
├── CHANGELOG.md
└── PROJECTCONTEXT.md
```

## 8) Operational Notes

- CLI remains intentionally present for automation, CI smoke checks, and ops workflows.
- Engine crate is now the canonical integration target for desktop GUI (Tauri) work.
- Vulnerability scanning is still not added (speed-first policy retained).
- Monitor remains single-interface per active monitoring session.

## 9) Useful Commands (Current)

- `cargo run -p nexus-cli -- --help`
- `cargo run -p nexus-cli -- scan --interface "<NAME>"`
- `cargo run -p nexus-cli -- ai-check`
- `cargo check --workspace --all-targets`
- `cargo test --workspace --all-targets --no-run`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `pwsh ./scripts/benchmark.ps1 -Mode smoke -Iterations 1`
- `pwsh ./scripts/package.ps1`
