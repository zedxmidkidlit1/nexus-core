# nexus-desktop (Scaffold)

This directory is reserved for the upcoming full GUI application (Tauri + frontend).

Planned structure:

- `apps/nexus-desktop/src/` for frontend UI
- `apps/nexus-desktop/src-tauri/` for Tauri Rust backend

Integration contract:

- GUI will call `nexus-core` APIs directly (not shelling out to CLI).
- CLI (`nexus-cli`) and GUI (`nexus-desktop`) will share the same `nexus-core` engine crate.
