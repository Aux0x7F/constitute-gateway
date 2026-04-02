# Operator Guide

This document is the install and update reference for `constitute-gateway`.

## Release Artifacts
- Windows: `constitute-operator-windows.zip`
- Linux: `constitute-operator-linux-amd64.tar.gz`

## Web-Driven Install
1. In `constitute` web, open `Settings > Appliances`.
2. Click `Download Installer Utility`.
3. Run the generated command from the operator host.

The generated command passes `--pair-identity` so the installer can prepare pairing material when needed.

## CLI Quick Start (Release Utility)

### Windows
```powershell
.\constitute-operator.exe --pair-identity "<IDENTITY_LABEL>" windows-service
```

### Linux
```bash
./constitute-operator --pair-identity "<IDENTITY_LABEL>" linux-service
```

## Build From Source

### Windows
```powershell
git clone https://github.com/Aux0x7F/constitute-gateway.git
cd constitute-gateway
cargo build --release --features platform-windows --bin constitute-operator
.\target\release\constitute-operator.exe --pair-identity "<IDENTITY_LABEL>" windows-service
```

### Linux
```bash
git clone https://github.com/Aux0x7F/constitute-gateway.git
cd constitute-gateway
cargo build --release --features platform-linux --bin constitute-operator
./target/release/constitute-operator --pair-identity "<IDENTITY_LABEL>" linux-service
```

## Pairing Behavior
Pairing code generation occurs only when all conditions are true:
- `--pair-identity` is provided.
- Installer pair generation is enabled (handled by operator utility).
- Gateway is not already paired (`identity_id` is empty).
- Existing pairing material is missing or invalid for the target identity.

On generation, the installer prints the one-time code. Claim it in `Settings > Pairing > Add Device`.
After approval, the gateway persists the resolved `identity_id` into encrypted keystore state and performs one controlled restart so the paired runtime state is applied cleanly.

## Advanced CLI Options
Global options:
- `--repo-owner <owner>` (default: `Aux0x7F`)
- `--repo-name <repo>` (default: `constitute-gateway`)
- `--service-name <name>` (default: `ConstituteGateway`)
- `--update-interval-minutes <n>` (default: `30`)
- `--install-dir <path>` (Windows bundle path override)
- `--skip-update-task` (Windows only)
- `--dry-run`

Subcommands:
- `windows-service`
- `linux-service`

## Direct Script Usage
Operator utility is the primary interface. Script-level entry points are available for automation:
- Linux release installer: `scripts/linux/install-latest.sh`
- Windows release installer: `scripts/windows/install-latest.ps1`
- Linux local-dev bootstrap: `scripts/linux/install-dev-local.sh`

## Related Docs
- Runtime operations and hardening: [`OPERATIONS.md`](OPERATIONS.md)
- Development workflow: [`DEVELOPMENT.md`](DEVELOPMENT.md)
- Protocol contracts: [`PROTOCOL.md`](PROTOCOL.md)
