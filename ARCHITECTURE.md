# Constitute Gateway Architecture

This document captures the current architecture, alignment with the web repo, and the roadmap for the native gateway.

## Purpose
The gateway is a native, minimal relay node that enables browser peers to discover and bridge into the swarm. It is a dependency for the web experience, not a parallel product. All protocol decisions here must converge with the web Constitute standard.

## Alignment With Web Repo
**Authoritative reference**: `C:\projects\Constituency\constitute` (web repo).

The gateway **uses the same identity model and event schemas** as the web stack:
- **Identity = Nostr device keypair** (same as `identity/sw/nostr.js`).
- **Signed NIP-01 events**.
- **Swarm discovery records** (`kind=30078`, tag `t=swarm_discovery`, tag `type=device`).
- **Zone presence** in app channel (`kind=1`, tag `t=constitute`, tag `z=<zone>`), payload type `zone_presence`.

## Core Responsibilities
1. **Discovery bootstrapping** via Nostr relays.
2. **Swarm peer presence** via zone presence events.
3. **WebRTC signaling relay** for browser peers (future work).
4. **Minimal local UDP/transport surfaces** for native/native mesh (future work).

## Identity and Keys
- On first run, the gateway generates a **Nostr keypair** and persists it.
- The **public key is the gateway identity**.
- All discovery events are **signed**.
- The private key is stored locally and never exported by default.

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
  - `relays` (advertised relays for discovery / bootstrap)

### Zone Presence
- `kind`: `1`
- `tags`: `['t','constitute']`, `['z', '<zone_key>']`
- `content` (JSON):
  - `type: 'zone_presence'`
  - `zone`
  - `devicePk`
  - `swarm` (placeholder; future swarm address)
  - `ts`
  - `ttl`

## Zones
- Zone keys are generated with the **same algorithm as web**:
  - `sha256(label|b64url(random(8)))` then `slice(0, 20)` (URL-safe base64)
- Gateway creates a default zone if none are configured and persists the generated key.
- Zone presence is broadcast periodically for each configured zone.

## Configuration
- `config.example.json` is a template.
- `config.json` is generated at runtime and **gitignored**.
- Minimal required fields:
  - `nostr_relays`
  - `nostr_sk_hex` (auto-generated if missing)
  - `zones` (auto-generated if missing)

## Security Posture
Current guarantees:
- Signed discovery events.
- Minimal data stored locally.

Planned hardening:
- Replay protection + timestamp skew checks (match web).
- Config integrity checks.
- Optional key encryption at rest.

## Roadmap
### Phase 0: Bootstrap Parity (in progress)
- [x] Nostr keypair generation and signed events
- [x] Zone presence and discovery record alignment
- [ ] WebRTC signaling relay (offer/answer/ICE pass-through)
- [ ] Basic metrics/health reporting

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

## Non-Goals (for now)
- Full messaging or application data transport
- Centralized account systems
- Heavy orchestration or control panels

## Open Questions
- Long-term swarm transport layer (QUIC, RTC, or hybrid)
- Relay trust model and rate limiting
- Zone membership ACLs vs discovery openness

