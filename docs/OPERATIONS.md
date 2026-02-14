# Operations

## Runtime Targets
- Fedora CoreOS (preferred immutable baseline)
- Linux VPS or container host (systemd)
- Windows service host

## Entry Scripts
- Linux and FCOS: `./scripts/run.sh`
- Windows: `powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1`

## Install and Update
### Linux opinionated baseline deploy
```bash
curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/linux/deploy-opinionated.sh | bash
```

### Linux release install/update
```bash
curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/linux/install-latest.sh | bash
```

### Linux periodic update timer (production)
```bash
curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/linux/install-latest.sh | bash -s -- --setup-timer --timer-interval 30m
```

### Linux rapid polling (development only)
```bash
curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/linux/install-latest.sh | bash -s -- --setup-timer --dev-poll
```

### Windows release install/update
- Script path: `scripts/windows/install-latest.ps1`

Release source model:
- Hosts consume `releases/latest` assets.
- Merges to `main` do not update hosts until a tagged release is published.

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

## FCOS Operations
- Full FCOS runbook: [`docs/FCOS.md`](FCOS.md)
- Infra template reference: [`infra/fcos/README.md`](../infra/fcos/README.md)

Runner labels:
- Base image only: `fcos-download-base-image`
- Full prep: `fcos-full-prep`

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

## Verification Checklist
- Service is installed and active (or intentionally stopped).
- Gateway self-test passes relay publication/check.
- Expected peer discovery occurs for joined zones.
- Default logs do not expose sensitive values.
- Update timer health is valid when enabled.
