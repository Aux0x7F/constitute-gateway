# Constitute Gateway

Native gateway service for Constitute. Runs headless on Ubuntu Core, Raspberry Pi, or VPS nodes to provide discovery bootstrap and relay services for browser peers.

## Status
- Prototype: active development
- Discovery bootstrap aligned with web standard
- P0: native gateway backbone (this repo)
- P1: gateway relay + signaling (local relay in place)
- P2: browser swarm transport

## Key Concepts
- Zones: discovery scope (zone-scoped gossip)
- Communities: overlay networks that can span zones by explicit routing invites (future)
- Coalitions: groups of communities with shared interop channels (future)

- Gateway: native node bridging discovery and transport
- Device identity: Nostr keypair used for gateway identity
- Zone: discovery scope joined by a shareable key
- Swarm discovery: signed records for identity/device resolution

## Features
- Nostr keypair generation and signed discovery events
- Zone presence broadcasts compatible with web repo
- Gateway metrics (clients/cpu/mem/load) published with zone presence
- Local gateway relay (Nostr-compatible WS) with deduped rebroadcast
- Relay signature validation + replay window (created_at + payload ts/ttl)
- Swarm record store (identity/device) + **zone-scoped** UDP gossip between gateways
- UDP/QUIC stubs for future transport
- Windows service install + Ubuntu Core snap scaffolding

## Project Layout
- src/main.rs: config, startup, service orchestration
- src/nostr.rs: keypair + NIP-01 signing
- src/keystore.rs: encrypted key storage (keyring + fallback)
- src/discovery.rs: swarm device records + zone presence
- src/relay.rs: relay pool + websocket publishing
- src/local_relay.rs: local Nostr relay server (browser peers)
- src/transport.rs: UDP listener + QUIC stub
- ARCHITECTURE.md: system architecture and roadmap

## Architecture
See `ARCHITECTURE.md` for the full system overview and roadmap.

## Discovery Schema (Aligned With Web)
### Swarm Discovery Record
- `kind`: `30078`
- tags: `['t','swarm_discovery']`, `['type','device']`
- `content` (JSON): `devicePk`, `identityId`, `deviceLabel`, `updatedAt`, `expiresAt`, `role`, `relays` (gateway relay endpoints)

### Zone Presence
- `kind`: `1`
- tags: `['t','constitute']`, `['z','<zone_key>']`
- `content.type`: `zone_presence`
- `content.devicePk`: gateway nostr pubkey
- `content.metrics`: `clients`, `cpuPct`, `memPct`, `loadPct`, `memUsedMb`, `memTotalMb`, `ts`

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

## Privacy / Threat Model
We assume a high-surveillance ("big brother") environment. Transport metadata is observable on public relays, and discovery is intentionally public.

Recommendations:
- Use a VPN or tunnel when operating a gateway if your risk profile or joined zones require it.
- Prefer WSS when feasible; WS is acceptable for bootstrap but leaks more metadata.
- Treat zone membership + relay endpoints as potentially linkable metadata.
- Application-layer encryption is required for identity/communities/chat; transport is not the trust boundary.

## Host Hardening (Ubuntu Core / VPS)
Host hardening is mostly **outside** the snap. The snap runs confined; the host controls firewalling and access.

Recommended baseline:
Host hardening helper:
Additional hardening (systemd override):
- Install CPUQuota drop-in (85%): `sudo ./scripts/install-systemd-override.sh`
- Restart the service: `sudo ./scripts/install-systemd-override.sh --restart`

- Audit only: `./scripts/harden-host.sh`
- Apply UFW allow rules (if UFW active): `./scripts/harden-host.sh --apply --udp 4040 --ws 7447 --wss 7448`

- **Firewall**: allow only gateway ports (UDP swarm + WS/WSS relay) and block everything else.
- **Fail2ban / SSH hardening**: on classic Ubuntu/VPS, enable fail2ban and disable password auth.
- **Auto-updates**: Ubuntu Core snaps refresh automatically; schedule with `snap set system refresh.timer`.
- **Logs**: keep minimal logs; rotate/limit retention to avoid disk pressure.

Snap-side hardening already in place:
- `confinement: strict`
- Only `network` / `network-bind` plugs
- Systemd `daemon: simple` with restart on failure


Snap hooks:
- `snap/hooks/configure` logs bind/relay ports and warns on invalid config values.
## Configuration
`config.example.json` is a template. `config.json` is generated at runtime and gitignored.

Plaintext config includes only operational settings (bind, relays, logging). Sensitive fields are stored in the encrypted keystore.

Metrics:
- metrics_interval_secs (default 10) publishes gateway health in zone_presence

Startup self-test:
- self_test (bool, default true) publishes a signed test event and waits for OK/echo
- self_test_timeout_secs (default 8) controls the per-relay wait time

Swarm endpoint:
- swarm_endpoint: host:port advertised via zone_presence (for UDP peer discovery)
- stun_interval_secs: how often to refresh public mapping (seconds)

STUN discovery:
- The gateway probes configured STUN servers and updates swarm_endpoint when a public mapping is found.

Relay config:
- relay_bind: WS bind address for the local gateway relay (empty disables)
- relay_bind_tls: WSS bind address (optional)
- relay_tls_cert_path: TLS cert PEM for WSS (optional)
- relay_tls_key_path: TLS key PEM for WSS (optional)
- relay_rebroadcast: rebroadcast inbound app events across relays (deduped)
- relay_replay_window_secs: max age window for relay events (created_at + payload ts)
- relay_replay_skew_secs: allowed future skew for relay events
- advertise_relays: gateway relay URLs (ws:// or wss://) to advertise to peers

UDP P2P config:
- udp_peers: list of host:port peers to dial for handshake
- udp_handshake_interval_secs (default 5)
- udp_peer_timeout_secs (default 60)
- udp_max_packet_bytes (default 2048)
- udp_rate_limit_per_sec (default 60)
- udp_sync_interval_secs (default 90) periodic record sync per zone
- UDP protocol versioning: gateways reject UDP messages with unsupported version

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
- [x] Replay protection + timestamp skew checks
- [ ] Relay rate limiting
- [ ] Config integrity validation
- [ ] Service sandboxing / least-privilege defaults
- [ ] Audit logging

## Roadmap Snapshot
- P0: discovery parity with web (signed records, zone presence)
- P1: gateway relay + signaling (WebRTC offer/answer/ICE) (in progress)
- P2: browser swarm transport (TURN fallback)
- P3: refactor + hardening
- Future milestone: identity-owned gateways with web UI configuration

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





