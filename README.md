# Constitute Gateway

Native gateway service for Constitute. Runs headless on Ubuntu Core, Raspberry Pi, or VPS nodes to provide discovery bootstrap and relay services for browser peers.

## Status
- Prototype: active development
- Discovery bootstrap aligned with web standard
- P0: native gateway backbone (this repo)
- P1: gateway relay + signaling
- P2: browser swarm transport

## Key Concepts
- Gateway: native node bridging discovery and transport
- Device identity: Nostr keypair used for gateway identity
- Zone: discovery scope joined by a shareable key
- Swarm discovery: signed records for identity/device resolution

## Features
- Nostr keypair generation and signed discovery events
- Zone presence broadcasts compatible with web repo
- UDP/QUIC stubs for future transport
- Windows service install + Ubuntu Core snap scaffolding

## Project Layout
- src/main.rs: config, startup, service orchestration
- src/nostr.rs: keypair + NIP-01 signing
- src/keystore.rs: encrypted key storage (keyring + fallback)
- src/discovery.rs: swarm device records + zone presence
- src/relay.rs: relay pool + websocket publishing
- src/transport.rs: UDP listener + QUIC stub
- ARCHITECTURE.md: system architecture and roadmap

## Architecture
See `ARCHITECTURE.md` for the full system overview and roadmap.

## Discovery Schema (Aligned With Web)
### Swarm Discovery Record
- `kind`: `30078`
- tags: `['t','swarm_discovery']`, `['type','device']`
- `content` (JSON): `devicePk`, `identityId`, `deviceLabel`, `updatedAt`, `expiresAt`, `role`, `relays`

### Zone Presence
- `kind`: `1`
- tags: `['t','constitute']`, `['z','<zone_key>']`
- `content.type`: `zone_presence`
- `content.devicePk`: gateway nostr pubkey

## Build
Feature flags (mutually exclusive):
- `platform-linux`
- `platform-windows`

```bash
cargo build --features platform-linux
cargo build --features platform-windows
```

### Ubuntu Core snap build
```bash
make snap
```
CI runs `make snap-ci`.

## Install (Ubuntu Core)
```bash
curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/install-latest.sh | bash
```

## Windows install (one-liner)
```powershell
irm https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/install-latest.ps1 | iex
```

## Local install from clone (Windows)
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-service.ps1 -ServiceName ConstituteGateway -NssmPath .\nssm\nssm.exe
```

## Local run (Windows)
```powershell
.\scripts\build.ps1 -Target windows
.\scripts\run.ps1 -LogLevel warn
```

## Configuration
`config.example.json` is a template. `config.json` is generated at runtime and gitignored.

Plaintext config includes only operational settings (bind, relays, logging). Sensitive fields are stored in the encrypted keystore.

Startup self-test:
- self_test (bool, default true) publishes a signed test event and waits for OK/echo
- self_test_timeout_secs (default 8) controls the per-relay wait time

## Key Storage
Keys and sensitive state are stored in an encrypted keystore under `data_dir`:
- `keystore.json`: encrypted payload
- `keystore.key`: fallback raw key (created only if no keyring/passphrase)

Sensitive fields stored in the keystore:
- `nostr_pubkey`, `nostr_sk_hex`
- `identity_id`, `device_label`
- `zones`

Key source order:
1. OS keyring (preferred)
2. Passphrase from environment: `CONSTITUTE_GATEWAY_PASSPHRASE`
3. Local key file fallback (`keystore.key`)

To disable keyring (e.g., Ubuntu Core confinement):
```
CONSTITUTE_GATEWAY_NO_KEYRING=1
```

## CI/CD
GitHub Actions builds on push and PRs:
- Windows ZIP artifact (binary + NSSM helper)
- Ubuntu Core snap

Release builds on tags (`v*`) and publish to GitHub Releases with checksums.

## Release Policy
- Use semantic version tags: `vMAJOR.MINOR.PATCH`
- Releases include:
  - `constitute-gateway-windows.zip`
  - `constitute-gateway-linux-amd64.snap`
  - `SHA256SUMS`
- Artifacts are signed only by GitHub’s release integrity (no extra signing yet).

## Security Hardening Checklist
Planned hardening (tracked in ARCHITECTURE.md):
- [ ] Encrypted key storage at rest (keyring + KDF fallback)
- [ ] Replay protection + timestamp skew checks
- [ ] Relay rate limiting
- [ ] Config integrity validation
- [ ] Service sandboxing / least-privilege defaults
- [ ] Audit logging

## Roadmap Snapshot
- P0: discovery parity with web (signed records, zone presence)
- P1: gateway relay + signaling (WebRTC offer/answer/ICE)
- P2: browser swarm transport (TURN fallback)
- P3: refactor + hardening

## TODO
- Relay signaling channels and auth envelope
- Swarm transport integration
- Hardened Ubuntu Core image + service packaging

## Security Notes
- Gateway identity is a Nostr keypair stored locally
- All discovery events are signed
- Relays are transport only (no trust assumed)

## License
TBD

