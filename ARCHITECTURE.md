# Constitute Gateway Architecture

This document captures the gateway architecture, convergence requirements with the browser shell, and the active roadmap direction.

Roadmap brief companion: [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Purpose
The gateway is the canonical browser control-plane boundary for managed Constitution services.
It is not the permanent UI container for first-party apps, and it is not a parallel product surface.

## Alignment With Other Repos
The active contract slice aligns with:
- `constitute` for management shell and launch
- `constitute-nvr` for hosted service inventory and live preview signaling
- `constitute-nvr-ui` for managed app surface bootstrap

Required convergence points:
- service-backed device publication
- hosted service inventory and freshness
- launch authorization for managed app surfaces
- gateway-mediated WebRTC signaling
- zone and identity durability semantics

## Core Responsibilities
1. Discovery bootstrap via Nostr relays
2. Zone-scoped presence and peer discovery
3. Browser relay/app-channel surface
4. Swarm record storage for identity/device/DHT records
5. UDP + QUIC handshake and request forwarding across native peers
6. Hosted-service inventory publication
7. Managed launch authorization and signaling brokerage

## Identity and Key Management
- On first run, gateway generates a Nostr keypair and persists it.
- Public key is the gateway device identity (`devicePk`).
- Gateway is a service-backed device with `deviceKind = service`.
- Discovery, status, and signaling events are signed.
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
  - `devicePk`
  - optional `identityId`, `deviceLabel`
  - `updatedAt`, `expiresAt`
  - `role`
  - `deviceKind` (`user|service`, gateway publishes `service`)
  - optional `service`
  - optional `hostGatewayPk` for hosted service-backed devices
  - `relays`
  - `hostPlatform`
  - `serviceVersion`
  - optional hosted-service inventory and freshness fields

### Zone Presence
- `kind`: `1`
- Tags: `['t','constitute']`, `['z','<zone_key>']`
- Content fields include:
  - `type: zone_presence`
  - `zone`, `devicePk`
  - `swarm` endpoint
  - `role`, `relays`, `hostPlatform`, `serviceVersion`
  - `metrics`
  - `ts`, `ttl`

## Hosted Service Model
Gateway may host multiple service-backed devices on the same machine.

For each hosted service the gateway should be able to publish:
- service slug (`nvr`)
- hosted service device key
- `hostGatewayPk`
- version
- freshness / last-seen
- launch availability / managed status

Gateway owns:
- install/update/control requests
- launch authorization
- signaling brokerage
- service inventory

Gateway does not need to be the long-term UI container for those services.

## Managed Launch Model
Canonical flow:
1. browser shell selects an owned gateway
2. browser shell requests managed launch for a hosted service
3. gateway validates identity membership, device authorization, and capability
4. gateway issues short-lived launch authorization
5. browser app surface uses gateway-mediated signaling to establish WebRTC with the hosted service
6. hosted service validates the gateway-issued authorization before admitting the session

## WebRTC Direction
Gateway is the signaling/control boundary for browser-safe direct paths:
- same-LAN clients should win via ICE host candidates
- NAT-friendly remote clients may win via server reflexive candidates
- hard-NAT fallback via TURN remains a later slice unless operator TURN is already available

Gateway should not force all media through itself if a direct authorized browser-to-service session is available.

## Zone and Overlay Direction
- UDP gossip remains zone-scoped.
- Gateways may join multiple zones.
- Effective gateway zone scope is `identity zones + gateway extra zones`.
- Records remain stored per-zone and are not auto-bridged across zones.

## Update Distribution Direction
Current model:
- gateways poll GitHub tagged releases
- poll interval is operator-configured
- egress policy is operator-managed

Planned extensions:
- signed update metadata verification
- signed `update_available` announcements
- optional proxy/Tor and no-clearnet flows

## Security Posture
Current guarantees:
- signed discovery/status events
- encrypted key material at rest
- replay mitigation in relay paths
- record validation before acceptance

Active sprint direction:
- short-lived launch authorization
- capability-enforced managed service launch
- gateway-mediated signaling without leaking long-lived browser secrets to app surfaces

## Documentation Surface
- `README.md`
- `docs/PROTOCOL.md`
- `docs/ROADMAP.md`
- `docs/OPERATIONS.md`
- `docs/DEVELOPMENT.md`
