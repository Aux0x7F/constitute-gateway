# Operations

## Runtime Targets
- Ubuntu Core (snap)
- Windows service
- Linux VPS/container host

## Security Baseline
- Treat discovery metadata as observable
- Use VPN/tunnel in high-risk environments
- Keep relay and UDP ports explicitly scoped by firewall
- Keep logs minimal and bounded

## Hardening Scripts
- `scripts/harden-host.sh`
- `scripts/install-systemd-override.sh`

## Service Controls
- Linux systemd: restart policy + CPU quota
- Windows service wrapper via NSSM

## Key Material
Sensitive data should remain in keystore-backed state, not in plaintext config.

## Verification Checklist
- Service starts and remains healthy
- Self-test passes relay publication/check
- UDP peer handshake confirms at least one peer when expected
- No sensitive material logged at default log level
