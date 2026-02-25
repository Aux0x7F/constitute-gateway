# Constitute Gateway Architecture

This document captures the gateway architecture, convergence requirements with the web repo, and the current roadmap.

Roadmap brief companion: [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Purpose
The gateway is a native dependency that enables browser clients to bootstrap discovery, bridge into swarm transport, and consume DHT-backed primitives. It is not a parallel product surface.

## Alignment With Web Repo
Authoritative reference: `https://github.com/Aux0x7F/constitute`.

Required convergence points:
- Identity model: Nostr device keypair
- Signed NIP-01 events
- Discovery record schema (`kind=30078`, `t=swarm_discovery`, `type=device`)
- Zone presence envelope (`kind=1`, `t=constitute`, `z=<zone>`, `type=zone_presence`)
- Shared role vocabulary (`relay|gateway|browser|native`)

## Core Responsibilities
1. Discovery bootstrap via Nostr relays
2. Zone-scoped presence and peer discovery
3. Local gateway relay for browser peers (WS/WSS)
4. Swarm record storage for identity/device/DHT records
5. UDP + QUIC handshake and request forwarding across native peers
6. External endpoint publication for swarm advertisement

## Identity and Key Management
- On first run, gateway generates a Nostr keypair and persists it.
- Public key is gateway identity (`devicePk`).
- Discovery and signaling events are signed.
- Private key remains local by default.

Key storage:
- Sensitive values are stored in encrypted keystore state under `data_dir`.
- Source order:
  1. OS keyring
  2. `CONSTITUTE_GATEWAY_PASSPHRASE`
  3. Local fallback key file (`keystore.key`)

## Discovery and Presence Contracts
### Swarm Discovery Record
- `kind`: `30078`
- Tags: `['t','swarm_discovery']`, `['type','device']`, `['role','<role>']`
- Content fields include:
  - `devicePk`, optional `identityId`, optional `deviceLabel`
  - `updatedAt`, `expiresAt`
  - `role` (`relay|gateway|browser|native`; runtime defaults to `gateway` but is configurable)
  - `relays`
  - `serviceVersion`

### Zone Presence
- `kind`: `1`
- Tags: `['t','constitute']`, `['z','<zone_key>']`
- Content fields include:
  - `type: zone_presence`
  - `zone`, `devicePk`
  - `swarm` endpoint
  - `role`, `relays`, `serviceVersion`, `metrics`
  - `ts`, `ttl`

## Zone and Overlay Direction
- UDP gossip is zone-scoped.
- Gateways may join multiple zones.
- Records are stored per-zone and not auto-bridged across zones.

Future overlay model:
- Communities can span zones via explicit routing/invites.
- Coalitions group communities and can define shared interop channels.
- Cross-zone routing remains opt-in to reduce metadata leakage.

## Update Distribution Direction
Current model:
- Gateways poll GitHub tagged releases (`releases/latest`).
- Poll interval is operator-configured (`--timer-interval`) with development override (`--dev-poll`).
- Egress policy is operator-managed (direct/proxy/tunnel).

Planned model:
- Optional proxy/Tor egress helper flows.
- Signed `update_available` announcements from web devices.
- Optional no-clearnet mode where release payloads arrive via trusted network peers.

## Host Baseline and Hardening
Preferred host baseline:
- Fedora CoreOS with first-boot provisioning (Ignition/Butane)

Operational hardening:
- Bounded firewall rules for explicit ports only
- Systemd service limits and restart policy
- Non-root runtime where feasible
- Minimal logging by default

## Threat Model
Assume high-surveillance environments:
- Discovery metadata is observable.
- Transport endpoints are correlatable without operator OPSEC.

Operational guidance:
- Use VPN/tunnel controls based on risk profile.
- Treat transport as delivery substrate, not confidentiality boundary.
- Enforce encryption at identity/application layers.

## Security Posture
Current guarantees:
- Signed discovery events
- Encrypted key material at rest
- Replay mitigation in relay paths
- DHT/record validation before acceptance

Planned hardening:
- Config integrity validation and migration guards
- Signed release metadata verification
- Stronger host config update verification path

## Roadmap
Execution order:
1. Finish gateway contract freeze and parity gaps in this repository.
2. Converge web implementation against frozen contracts.
3. Build service-layer repos (starting with `constitute-nvr`) on top of the converged base.

### Phase 0: Bootstrap Parity
- [x] Nostr keypair generation and signed events
- [x] Zone presence and discovery schema alignment
- [x] Local gateway relay
- [x] DHT put/get bridge for app-channel + UDP lookup
- [x] Basic metrics publication

### Phase 1: Swarm Transport
- [~] Stable mesh transport baseline (`udp + optional quic`)
- [~] Relay fallback strategy (`udp <-> quic` dual-send + graceful degrade)
- [~] TURN/gateway role boundaries documented (browser TURN remains client-side fallback)

### Phase 2: Host and Service Hardening
- [x] FCOS first-boot bootstrap scaffold
- [x] Operator-managed update timer path
- [ ] Signature-verified release payload enforcement
- [ ] Non-root runtime hardening profile completion

### Phase 3: Web Convergence
- [~] DHT contract convergence (gateway side implemented, web side pending)
- [ ] Shared identity/device resolution behavior parity
- [ ] Zone membership durability and sync behavior parity

### Future Milestone: Managed Gateways
- [ ] Identity-owned gateway fleet management in web surface
- [ ] Signed update broadcasts from web devices
- [ ] Optional no-clearnet gateway update mode

## Documentation Surface
- `README.md`
- `docs/PROTOCOL.md`
- `docs/ROADMAP.md`
- `docs/OPERATIONS.md`
- `docs/DEVELOPMENT.md`
- `docs/FCOS.md`
- `infra/fcos/README.md`
