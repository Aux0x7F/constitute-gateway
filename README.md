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

Key fields:
- `nostr_relays`: discovery bootstrap relays
- `nostr_pubkey` / `nostr_sk_hex`: gateway identity (auto-generated if missing)
- `zones`: zone keys + labels (auto-generated if missing)

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
- [ ] Encrypted key storage at rest
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
