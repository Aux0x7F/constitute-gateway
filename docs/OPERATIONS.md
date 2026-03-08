# Operations

## Runtime Targets
- Linux host (systemd)
- Windows service host

## Entry Scripts
- Linux: `./scripts/run.sh`
- Windows: `powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1`

## Install and Update

### Linux release install/update
```bash
curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/linux/install-latest.sh | bash
```

Linux defaults:
- Data root auto-detect: `/data/constitute-gateway` when `/data` is mounted, else `/var/lib/constitute-gateway`.
- Service user: `constitute-gateway` (system account).

### Linux periodic update timer (production)
```bash
curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/linux/install-latest.sh | bash -s -- --setup-timer --timer-interval 30m
```

### Linux rapid polling (development release testing)
```bash
curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/linux/install-latest.sh | bash -s -- --setup-timer --dev-poll
```

### Windows release install/update
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "& ([ScriptBlock]::Create((iwr https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/windows/install-latest.ps1 -UseBasicParsing).Content))"
```

Windows defaults:
- Bundle path: `%ProgramData%\Constitute\Gateway\bundle`
- Auto-update task: `<ServiceName>-AutoUpdate` (30 minute default interval)

## Development Install (One-Liner)
### Fedora Server / Linux (clone + build + local service install)
```bash
curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/linux/install-dev-local.sh | bash
```

## Development Install (Local Build)

### Linux local build + service install
```bash
cargo build --release --features platform-linux
sudo ./scripts/linux/install-service.sh --binary ./target/release/constitute-gateway --config-template ./config.example.json
```

### Windows local build + service install
```powershell
cargo build --release --features platform-windows -j 1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\install-service.ps1 -ServiceName ConstituteGateway
```

## Service Lifecycle
### Linux
- Status: `./scripts/run.sh service-status`
- Start: `./scripts/run.sh service-start`
- Stop: `./scripts/run.sh service-stop`
- Restart: `./scripts/run.sh service-restart`
- Uninstall registration: `./scripts/run.sh service-uninstall`

### Windows
- Status: `powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 service-status`
- Start: `powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 service-start`
- Stop: `powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 service-stop`
- Restart: `powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 service-restart`
- Uninstall registration: `powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 service-uninstall`

Uninstall removes service registration only. Binaries, config, and data are retained.

## Update Egress Profiles
Linux updater supports:
- Direct (default)
- HTTP(S) proxy: `--proxy-url <url>`
- Tor SOCKS: `--tor --tor-socks <host:port>`
- Optional Tor control: `--tor-control <host:port>`
- Disable Tor circuit rotation retry: `--no-tor-rotate`

## Host Hardening
Automation scripts:
- `scripts/linux/harden-host.sh`
- `scripts/linux/install-systemd-override.sh`

Baseline guidance:
- Expose only explicit relay and transport ports.
- Keep default logging minimal.
- Apply CPU quotas and restart policies for stability.

## Role Configuration
- `node_role` is the primary runtime role config key (default: `gateway`).
- Legacy `node_type` is accepted for backward compatibility.
- Role values are normalized to lowercase and must be ASCII `[a-z0-9_-]`.

## Mesh Transport Configuration
- UDP is always enabled via `bind` + `udp_*` settings.
- Optional QUIC mesh is enabled with:
  - `quic_enabled`
  - `quic_bind`
  - `quic_peers` (defaults to `udp_peers` when empty)
- Runtime uses dual-send fallback when QUIC is enabled (UDP + QUIC fanout).
- If QUIC startup fails, gateway continues on UDP and logs a warning.

## TURN Boundary
- Gateway does not host TURN.
- TURN remains an operator/client concern for browser-side connectivity fallback.

## Verification Checklist
- Service is installed and active (or intentionally stopped).
- Gateway self-test passes relay publication/check.
- Expected peer discovery occurs for joined zones.
- Default logs do not expose sensitive values.
- Update timer health is valid when enabled.

## Convergence Readiness Checks
Before switching primary work to web convergence:
- Gateway contract is current in [`docs/PROTOCOL.md`](PROTOCOL.md).
- Runtime behavior matches `ARCHITECTURE.md` phase status.
- CI passes on both Linux and Windows build/test lanes.
- Open gateway P0/P1 blockers are explicitly tracked.