# Operations

## Runtime Targets
- Linux host (systemd)
- Windows service host

## Install and Update
Primary install/update reference:
- [`OPERATOR.md`](OPERATOR.md)

This document focuses on runtime lifecycle, hardening, and verification.

## Entry Scripts
- Linux: `./scripts/run.sh`
- Windows: `powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1`

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

## Update Egress Profiles (Linux)
Supported by `scripts/linux/install-latest.sh`:
- Direct (default)
- HTTP(S) proxy: `--proxy-url <url>`
- Tor SOCKS: `--tor --tor-socks <host:port>`
- Optional Tor control: `--tor-control <host:port>`
- Disable Tor circuit rotation retry: `--no-tor-rotate`

## Persistence Contract
- Identity/device keys and encrypted keystore live under configured `data_dir` and are never stored in release bundle paths.
- Updaters may replace binaries/scripts only; they must not delete configured state roots.
- Relative `data_dir` values are normalized to stable platform state roots during install/update.
- Failed updates must leave service usable (rollback to previous binary/config).

## Pairing Contract (Installer)
- Pairing code input is not operator-supplied.
- Installer generates one-time pairing code only when pairing is pending and identity pairing is enabled.
- Generated code is printed to terminal and claimed from owner web UI (`Settings > Pairing > Add Device`).
- Updates should not regenerate pairing material for already-paired devices.
- On `pair_approve`, gateway persists the resolved `identity_id` in encrypted keystore state and exits once so the paired runtime reloads with the durable identity context.

## Gateway Zone Sync Contract
- Owner web clients may submit `gateway_zone_sync_request` with identity zones plus optional gateway-extra zones.
- Gateway persists synced zone scope to keystore state.
- Current runtime requires gateway service restart to apply updated transport zone listeners and filters.
- Acknowledgement arrives as `gateway_zone_sync_status` with `restartRequired=true` when persistence succeeds.

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
