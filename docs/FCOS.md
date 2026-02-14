# FCOS Deployment

This document defines the Fedora CoreOS deployment path for `constitute-gateway`.

## Goals
- Immutable host baseline
- Network-gated first boot
- Non-interactive gateway install and update
- Operator-managed egress controls
- Reproducible provisioning artifacts

## Provisioning Pipeline
1. Render Butane config:
```bash
./scripts/fcos/render-config.sh --ssh-key-file ~/.ssh/id_ed25519.pub
```
2. Compile Ignition (automatic when `butane` is installed)
- Output: `infra/fcos/generated/config.ign`
3. Install FCOS to disk:
```bash
sudo coreos-installer install /dev/sdX --ignition-file infra/fcos/generated/config.ign
```

## Image Prep Modes
### Base image only
Downloads upstream FCOS default ISO and verifies checksum.

Linux:
```bash
./scripts/fcos/usb-prep-linux.sh
```

Windows:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\usb-prep.ps1
```

### Full prep
Embeds Ignition and optionally performs direct USB write.

Linux:
```bash
./scripts/fcos/usb-prep-linux.sh --ignition infra/fcos/generated/config.ign
./scripts/fcos/usb-prep-linux.sh --ignition infra/fcos/generated/config.ign --device /dev/sdX
```

Windows (WSL-backed full prep):
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\usb-prep.ps1 -UseWsl -IgnitionPath .\infra\fcos\generated\config.ign
powershell -ExecutionPolicy Bypass -File .\scripts\windows\usb-prep.ps1 -UseWsl -IgnitionPath .\infra\fcos\generated\config.ign -Device /dev/sdX
```

Runner labels (non-interactive):
```bash
./scripts/run.sh fcos-download-base-image
./scripts/run.sh fcos-full-prep --ignition infra/fcos/generated/config.ign
```

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 fcos-download-base-image
powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 fcos-full-prep -IgnitionPath .\infra\fcos\generated\config.ign
```

## First-Boot Behavior
`constitute-gateway-firstboot.service` runs a one-shot bootstrap flow:
1. Wait for outbound connectivity.
2. Apply optional host hardening.
3. Install or update gateway from GitHub releases.
4. Configure update timer profile (production or development).

Completion marker:
- `/var/lib/constitute-gateway/bootstrap.done`

## Egress Controls
Supported updater egress profiles:
- Direct
- HTTP(S) proxy (`--proxy-url`)
- Tor SOCKS (`--tor`, `--tor-socks`, optional `--tor-control`)

## Development Profile
Use `--dev-poll` only for rapid iteration.
Do not use development polling in production.

## Related Files
- [`infra/fcos/config.template.bu`](../infra/fcos/config.template.bu)
- [`infra/fcos/README.md`](../infra/fcos/README.md)
- [`scripts/fcos/render-config.sh`](../scripts/fcos/render-config.sh)
- [`scripts/fcos/firstboot-bootstrap.sh`](../scripts/fcos/firstboot-bootstrap.sh)
