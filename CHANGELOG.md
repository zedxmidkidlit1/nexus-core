# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- TBD

### Changed
- TBD

### Fixed
- TBD

### Removed
- TBD

### Security
- TBD

## [0.1.1] - 2026-02-12

### Added
- `NEXUS CLI` ASCII art banner in CLI help output.
- Windows runner wrapper script: `scripts/run-nexus.cmd`.

### Changed
- Running `nexus-core` with no arguments now shows help instead of starting an automatic scan.
- Help text now emphasizes explicit command usage (for example: `nexus-core scan`).
- Packaging script now includes `run-nexus.cmd` in `dist/` for double-click-friendly usage on Windows.

### Fixed
- Improved Windows UX where double-click execution closed too quickly without letting users read output.

## [0.1.0] - 2026-02-12

Initial public baseline release of `nexus-core`.

### Added
- Core CLI for network discovery and topology mapping.
- Device/network data flow with persistence and insights foundations.
- Export support for CSV reports.
- Export support for PDF reports via `krilla` (feature-gated).
- AI module foundation under `src/ai/*` for local/cloud provider integration patterns.
- Reusable app execution layer (`app.rs`) for future CLI/UI entrypoints.
- Benchmark and packaging scripts (`scripts/benchmark.ps1`, `scripts/package.ps1`).

### Changed
- Version baseline reset to `0.1.0` for release-line alignment.
- Internal refactors to reduce `main.rs` responsibility and improve maintainability.
- Release hardening updates for packaging and build/release flow.

### Fixed
- Windows CI reliability improvements around Npcap SDK handling for link-time dependency resolution.

### Security
- No specific security fix is announced in this initial baseline release.

[Unreleased]: https://github.com/zedxmidkidlit1/nexus-core/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/zedxmidkidlit1/nexus-core/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/zedxmidkidlit1/nexus-core/releases/tag/v0.1.0
