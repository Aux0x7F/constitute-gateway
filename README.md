# Constitute Gateway

Native gateway service for Constitute. This service is intended to run on Ubuntu Core (Raspberry Pi, VPS, or other small nodes) and provide secure relay and discovery services for browser clients.

## Status
Skeleton scaffold. Networking, relay, and auth logic are not implemented yet.

## CI/CD
GitHub Actions builds:
- Ubuntu Core snap (Linux)
- Windows ZIP artifact

Tagged releases (`v*`) publish both assets to GitHub Releases with checksums.

## Goals
- Small, secure, headless service.
- Runs on Ubuntu Core with minimal dependencies.
- Supports discovery bootstrap and relay for browser peers.

## Discovery Record
Discovery records include a `type` field to distinguish node roles:
- `relay`
- `gateway`
- `browser`
- `native`

This allows a single nostr discovery channel with filtering by role.

## Build
This repo targets Linux (Ubuntu Core). Suggested build targets:
- `x86_64-unknown-linux-gnu` for VPS or desktop Linux
- `aarch64-unknown-linux-gnu` for Raspberry Pi 4/5

### Feature flags
- `platform-linux` (default)
- `platform-windows`

Use the flags to compile platform-specific hooks:

```bash
cargo build --features platform-windows
cargo build --features platform-linux
```

### Native build on Linux
```bash
cargo build --release
```

### Cross-compile from Windows
Cross-compiling requires a Linux linker toolchain for the target. The cleanest path is WSL or a Linux container.

```bash
cargo build --release --target aarch64-unknown-linux-gnu
```

### Ubuntu Core snap build
Ubuntu Core uses snaps. This repo includes `snap/snapcraft.yaml` and a Makefile target.

```bash
make snap
```

CI runs `make snap-ci`.

On Windows, run snapcraft inside WSL2/Ubuntu or a Linux VM.

### Unified build script
For a clean, cross-platform entrypoint:

Windows (PowerShell):
```powershell
.\scripts\build.ps1 -Target auto
.\scripts\build.ps1 -Target windows
.\scripts\build.ps1 -Target snap
```

Linux (bash):
```bash
./scripts/build.sh auto
./scripts/build.sh snap
```

On Windows, `-Target snap` uses WSL to run `make snap`.

## Install (Ubuntu Core)
One-liner install from GitHub Releases:

```bash
curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/install-latest.sh | bash
```

## Windows install (one-liner)
Downloads, verifies, extracts, and installs the service:

```powershell
irm https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/install-latest.ps1 | iex
```

## Local install from clone (Windows)
Run from a local clone to install and start the service:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-service.ps1 -ServiceName ConstituteGateway -NssmPath .\nssm\nssm.exe
```

## Updates
Use GitHub Releases or CI artifacts for distribution. A helper script is included:

```powershell
.\scripts\check-update.ps1 -RepoOwner Aux0x7F -RepoName constitute-gateway
```

## Run
```bash
./target/release/constitute-gateway --config config.json
```

## Configuration
Copy `config.example.json` to `config.json` and adjust:
- `node_id`: stable identifier for this gateway
- `node_type`: `gateway` by default; other roles are `relay`, `browser`, `native`
- `bind`: host:port to listen on
- `data_dir`: data directory for local storage
- `nostr_relays`: discovery bootstrap relays
- `stun_servers`: STUN servers for NAT traversal
- `turn_servers`: TURN relays (optional)

## Logging
Default log level is `warn`. Override via `--log-level` or `RUST_LOG`.

Examples:
```bash
./constitute-gateway --log-level info
RUST_LOG=debug ./constitute-gateway
```

## Platform defaults
The gateway uses platform-specific default paths when `--config` is not provided.
- Linux (Ubuntu Core): `/var/snap/constitute-gateway/common/config.json`
- Windows: `%ProgramData%\\Constitute\\Gateway\\config.json`

Data directory defaults follow the same platform roots.

## Notes
- Ubuntu Core image packaging and hardening are tracked in the Constitute roadmap.
- The gateway will eventually provide relay, discovery, and authenticated envelopes.
- If `cargo check` fails on Windows, build inside WSL2/Ubuntu or a Linux container.
