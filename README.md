# Constitute Gateway

Native gateway service for Constitute. This repository provides the native dependency layer that browser clients and native services depend on for discovery bootstrap, relay bridging, and swarm-facing transport primitives.

## Scope
- Nostr-based discovery bootstrap and zone presence publication
- Gateway local relay surface for web clients
- Zone-scoped UDP/QUIC mesh transport and DHT-style request/response primitives
- Windows and Linux service install/update paths

Out of scope:
- OS install media/image generation
- Web UI and UX
- Service-specific application logic (for example NVR ingest/retention)

## Status
Implemented:
- Discovery and zone presence contracts
- Gateway record query and DHT put/get bridge
- UDP forwarding fanout and hop bounds
- Optional QUIC datagram transport path with local integration tests
- Release install/update scripts for Windows and Linux services

In progress:
- Transport hardening and operational tuning for difficult NAT topologies
- Web parity for full convergence on identity/device resolution behavior

## Release Install (One-Liners)
### Linux service (install/update from releases/latest)
```bash
curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/linux/install-latest.sh | bash
```

Linux installer defaults:
- Config path: `/etc/constitute-gateway/config.json`
- Data root auto-detect: `/data/constitute-gateway` when `/data` is mounted, else `/var/lib/constitute-gateway`.
- Service runtime user: `constitute-gateway` (system user).
- Update safety: updater preserves config/data and rolls back binary/config if post-update health check fails.

### Windows service (install/update from releases/latest)
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "& ([ScriptBlock]::Create((iwr https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/windows/install-latest.ps1 -UseBasicParsing).Content))"
```

Windows installer defaults:
- State root: `%ProgramData%\Constitute\Gateway`
- Config path: `%ProgramData%\Constitute\Gateway\config.json`
- Data path: `%ProgramData%\Constitute\Gateway\data`
- Bundle path: `%ProgramData%\Constitute\Gateway\bundle`
- Auto-update task: `<ServiceName>-AutoUpdate` (30 minute default interval)
- Update safety: bundle updates are non-destructive to state/config; config is backed up before reinstall.

## Development Install (One-Liner)
### Fedora Server / Linux (clone + build + install service locally)
```bash
curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/linux/install-dev-local.sh | bash
```

## Development Install (Local Clone + Local Build)
### Linux
```bash
git clone https://github.com/Aux0x7F/constitute-gateway.git
cd constitute-gateway
cargo build --release --features platform-linux
sudo ./scripts/linux/install-service.sh --binary ./target/release/constitute-gateway --config-template ./config.example.json
```

### Windows
```powershell
git clone https://github.com/Aux0x7F/constitute-gateway.git
cd constitute-gateway
cargo build --release --features platform-windows -j 1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\install-service.ps1 -ServiceName ConstituteGateway
```

## Optional Operator Utility
Release assets include:
- `constitute-operator-windows.zip`
- `constitute-operator-linux-amd64.tar.gz`

Operator scope is service install/update only (no media/image build path).

## Start Here
- Operators: [`docs/OPERATIONS.md`](docs/OPERATIONS.md)
- Contributors: [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)
- Protocol contracts: [`docs/PROTOCOL.md`](docs/PROTOCOL.md)
- Project roadmap brief: [`docs/ROADMAP.md`](docs/ROADMAP.md)
- Architecture and detailed roadmap: [`ARCHITECTURE.md`](ARCHITECTURE.md)

## Runner Entrypoints
- Linux: `./scripts/run.sh`
- Windows: `powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1`

## Security Posture
- Discovery transport is treated as observable metadata.
- Identity and application confidentiality belongs to higher crypto layers.
- Operators should apply VPN/tunnel controls based on risk profile.
- Release updates are consumed from tagged GitHub Releases by default.

## Contributing
Contribution standards and commit conventions are documented in [`CONTRIBUTING.md`](CONTRIBUTING.md).