# Constitute Gateway Architecture

This document captures the current architecture, alignment with the web repo, and the roadmap for the native gateway.

## Purpose
The gateway is a native, minimal relay node that enables browser peers to discover and bridge into the swarm. It is a dependency for the web experience, not a parallel product. All protocol decisions here must converge with the web Constitute standard.

## Alignment With Web Repo
**Authoritative reference**: `https://github.com/Aux0x7F/constitute` (web repo).

The gateway **uses the same identity model and event schemas** as the web stack:
- **Identity = Nostr device keypair** (same as `identity/sw/nostr.js`).
- **Signed NIP-01 events**.
- **Swarm discovery records** (`kind=30078`, tag `t=swarm_discovery`, tag `type=device`).
- **Zone presence** in app channel (`kind=1`, tag `t=constitute`, tag `z=<zone>`), payload type `zone_presence`.

## Core Responsibilities
1. **Discovery bootstrapping** via Nostr relays.
2. **Swarm peer presence** via zone presence events.
3. **Local gateway relay** for browser peers (Nostr-compatible; WS/WSS).
4. **Swarm record store** for identity/device records (DHT seed).
5. **UDP handshake + peer table** for native/native mesh (in progress).
5. **STUN-based external endpoint discovery** for swarm advertisement (in progress).

## Identity and Keys
- On first run, the gateway generates a **Nostr keypair** and persists it.
- The **public key is the gateway identity**.
- All discovery events are **signed**.
- The private key is stored locally and never exported by default.

## Key Storage
Keys and sensitive state are stored in an encrypted keystore under `data_dir`.

Sensitive fields stored in the keystore:
- `nostr_pubkey`, `nostr_sk_hex`
- `identity_id`, `device_label`
- `zones`

Key source order:
1. OS keyring (preferred)
2. Passphrase from env: `CONSTITUTE_GATEWAY_PASSPHRASE`
3. Local fallback key file (`keystore.key`)

To disable keyring:
```
CONSTITUTE_GATEWAY_NO_KEYRING=1
```

## Event Schemas (Current)
### Swarm Discovery Record
- `kind`: `30078`
- `tags`: `['t','swarm_discovery']`, `['type','device']`
- `content` (JSON):
  - `devicePk`
  - `identityId` (optional for now)
  - `deviceLabel` (optional)
  - `updatedAt`
  - `expiresAt`
  - `role` (gateway)
  - `relays` (gateway relay endpoints)
  - `metrics` (clients, cpuPct, memPct, loadPct, memUsedMb, memTotalMb, ts)

### Zone Presence
- `kind`: `1`
- `tags`: `['t','constitute']`, `['z','<zone_key>']`
- `content` (JSON):
  - `type: 'zone_presence'`
  - `zone`
  - `devicePk`
  - `swarm` (UDP endpoint host:port when advertised; discovered via STUN)
  - `role` (gateway)
  - `relays` (gateway relay endpoints)
  - `metrics` (clients, cpuPct, memPct, loadPct, memUsedMb, memTotalMb, ts)
  - `ts`
  - `ttl`

## Zones

## Zone-Scoped Gossip
- UDP gossip is **zone-scoped**; records include a `zone` and are ignored outside that zone.
- Gateways may join multiple zones; records are stored per-zone and never auto-bridged across zones.

## Communities and Coalitions (Future Model)
- **Communities** are overlay networks that can span zones via explicit routing invites.
- **Coalitions** group multiple communities and can define shared interop channels.
- Interop channels can be modeled as **shared rendezvous zones** with explicit membership.
- Cross-zone routing is opt-in and permissioned to avoid discovery metadata leakage.

- Zone keys are generated with the **same algorithm as web**:
  - `sha256(label|b64url(random(8)))` then `slice(0, 20)` (URL-safe base64)
- Gateway creates a default zone if none are configured and persists the generated key.
- Zone presence is broadcast periodically for each configured zone.

## Configuration
- `config.example.json` is a template.
- `config.json` is generated at runtime and **gitignored**.
- Plaintext config includes only operational settings (bind, relays).
- Sensitive config is stored in the encrypted keystore.

## Host Hardening (Ops)
- Snap confinement provides AppArmor + seccomp by default.
- Host firewalling and SSH hardening remain outside the snap.
- Recommended: lock inbound ports to the gateway relay + swarm UDP only.
- Fail2ban on classic Ubuntu/VPS; Ubuntu Core uses snap refresh for updates.

## Threat Model / Privacy Assumptions
We assume a high-surveillance ("big brother") environment. Discovery is public by design, and relay metadata can be observed or correlated.

Operational guidance:
- Community operators should use VPN/tunnels for gateways when their risk profile or zones require anonymity.
- STUN will reflect the active egress path (VPN public IP if full-tunnel; ISP IP if not).
- Prefer WSS when feasible to reduce passive metadata exposure.

## Application-Layer Security
Identity-level and above abstractions (communities, chat, app data) must be end-to-end encrypted.
Transport (relay/WS/UDP) is a delivery substrate, not a trust boundary.

## Security Posture
Current guarantees:
- Signed discovery events.
- Keys are encrypted at rest.
- Minimal data stored locally.
- Relay rebroadcast is deduped by event id.
- Relay validates NIP-01 signatures + replay window (created_at + payload ts/ttl).
- Swarm record store validates + gossips identity/device records over UDP.

Planned hardening:
- Config integrity checks.
- Optional key encryption at rest (keyring + KDF fallback).

## Roadmap
### Phase 0: Bootstrap Parity (in progress)
- [x] Nostr keypair generation and signed events
- [x] Zone presence and discovery record alignment
- [x] Local gateway relay (Nostr-compatible)
- [ ] WebRTC signaling relay (offer/answer/ICE pass-through)
- [x] Basic metrics/health reporting

### Phase 1: Swarm Transport
- [ ] Stable mesh transport (initial WebRTC + relay)
- [ ] Relay fallback strategy (nostr -> gateway -> direct)
- [ ] NAT traversal strategy, TURN/Gateway relay roles

### Phase 2: Gateway Service Hardening
- [ ] Structured logging + minimal telemetry
- [ ] Secure config management
- [ ] Service packaging (Windows service + Ubuntu Core snap)

### Phase 3: Convergence with Web Swarm
- [ ] Full compatibility with web swarm DHT resolution
- [ ] Shared identity record resolution
- [ ] Zone membership sync + presence durability

### Future Milestone: Managed Gateways
- [ ] Identity-owned gateway fleet (configuration + health via web UI)
- [ ] Client-consumable health/metrics for relay selection + balancing

## Non-Goals
- Full messaging or application data transport
- Centralized account systems
- Heavy orchestration or control panels

## Open Questions
- Long-term swarm transport layer (QUIC, RTC, or hybrid)
- Relay trust model and rate limiting
- Zone membership ACLs vs discovery openness




## Documentation Surface
- Operator and contributor entrypoint: `README.md`
- Design intent and roadmap: `ARCHITECTURE.md`
- Protocol details: `docs/PROTOCOL.md`
- Operational guidance: `docs/OPERATIONS.md`
- Development workflow: `docs/DEVELOPMENT.md`
- Generated Rust API docs: GitHub Pages via `.github/workflows/docs.yml`