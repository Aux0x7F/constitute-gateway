# Operator Guide

This document is the install/update reference for `constitute-gateway`.

## Preferred Flow (Web-Driven)
1. In `constitute` web: open `Settings > Appliances`.
2. Click `Download Installer Utility`.
3. Run the generated operator command shown in the UI.

Notes:
- The command passes `--pair-identity`.
- On first install (when gateway is not already paired), installer scripts generate a one-time pairing code and print it.
- Claim that code in `Settings > Pairing > Add Device` and approve.

## Release Utility Assets
- Windows: `constitute-operator-windows.zip`
- Linux: `constitute-operator-linux-amd64.tar.gz`

## CLI Quick Start

### Windows
```powershell
.\constitute-operator.exe --pair-identity "<IDENTITY_LABEL>" windows-service
```

### Linux
```bash
./constitute-operator --pair-identity "<IDENTITY_LABEL>" linux-service
```

## Build From Source

### Windows (PowerShell)
```powershell
git clone https://github.com/Aux0x7F/constitute-gateway.git; cd constitute-gateway; cargo build --release --features platform-windows --bin constitute-operator; .\target\release\constitute-operator.exe --pair-identity "<IDENTITY_LABEL>" windows-service
```

### Linux (Bash)
```bash
git clone https://github.com/Aux0x7F/constitute-gateway.git && cd constitute-gateway && cargo build --release --features platform-linux --bin constitute-operator && ./target/release/constitute-operator --pair-identity "<IDENTITY_LABEL>" linux-service
```

## Pairing Generation Rules
Pair code generation only occurs when all of the following are true:
- `--pair-identity` is provided.
- Installer is run with pair generation enabled (operator does this automatically).
- Local gateway is not already paired (`identity_id` is empty in config).
- Existing pairing material is missing or invalid for the target identity.

Generation does not occur on normal updates for already-paired gateways.

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

## Script-Level Alternatives
You can call installer scripts directly, but operator is the canonical interface:
- Linux release script: `scripts/linux/install-latest.sh`
- Windows release script: `scripts/windows/install-latest.ps1`
- Linux local-dev bootstrap: `scripts/linux/install-dev-local.sh`

## Related Docs
- Runtime operations and hardening: [`OPERATIONS.md`](OPERATIONS.md)
- Development workflow: [`DEVELOPMENT.md`](DEVELOPMENT.md)
- Protocol contracts: [`PROTOCOL.md`](PROTOCOL.md)
