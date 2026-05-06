# Constitute Gateway Architecture

This document captures the gateway architecture, convergence requirements with the browser shell, and the active roadmap direction.

Roadmap brief companion: [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Purpose
The gateway is the canonical browser control-plane boundary for managed Constitution services.
It is not the permanent UI container for first-party apps, and it is not a parallel product surface.

## Alignment With Other Repos
The active contract slice aligns with:
- `constitute-account` for browser identity/session/grant authority and shared runtime
- `constitute-gateway-ui` for gateway-specific management UX
- `constitute-storage` for encrypted object/index substrate health and proof-record storage
- `constitute-logging` for blind structured event observation, safe-fact indexing, service-owned projection exchange, and service-side query/watch
- `constitute-nvr` for hosted service inventory and live preview signaling
- `constitute-nvr-ui` for managed app surface bootstrap

Required convergence points:
- service-backed device publication
- hosted service inventory and freshness
- service access authorization for managed app surfaces
- gateway-mediated WebRTC signaling
- zone and identity durability semantics

## Core Responsibilities
1. Discovery bootstrap via Nostr relays
2. Zone-scoped presence and peer discovery
3. Browser relay/app-channel surface
4. Swarm record storage for identity/device/DHT records
5. UDP + QUIC handshake and request forwarding across native peers
6. Hosted-service inventory publication
7. Service access authorization and signaling brokerage

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
Gateway may host multiple service-backed devices and host-local capability services on the same machine.
The gateway-hosted service inventory is an installed-service health/configuration projection, not a launcher list.
Some installed services expose an app action, such as NVR opening Security Cameras; others, such as storage, primarily expose health, configuration, and capability state.

For each hosted service the gateway should be able to publish:
- service slug (`nvr`, `storage`, `logging`)
- hosted service device key when the service has one, or a stable host-local service identifier for local capability services
- `hostGatewayPk`
- version
- freshness / last-seen
- service access availability / managed status
- safe service health/configuration summary

Gateway owns:
- install/update/control requests
- service access authorization
- signaling brokerage
- service inventory
- server-side hydration of browser-consumable projections for hosted capability services

Gateway does not need to be the long-term UI container for those services.
Gateway also does not treat every service inventory item as launchable; launch is an optional action owned by app-backed services.

## Service Access Model
Canonical flow:
1. browser shell selects an owned gateway
2. browser shell requests service access for a hosted service
3. gateway validates identity membership, device authorization, and capability
4. gateway issues short-lived service access authorization
5. browser app surface uses gateway-mediated signaling to establish WebRTC with the hosted service
6. hosted service validates the gateway-issued authorization before admitting the session

Direct app entry is primary. The gateway may participate after the app has attached to account/runtime authority; the user should not need to visit account manually before using a first-party app.

Current service access authorization uses `constitute-protocol` CAAC envelopes for gateway-issued service capabilities. Browser-to-gateway service access and service signal requests are sealed to the gateway. Gateway-to-browser service access status, service signal status, and service signal payloads are sealed back to the requesting device. The capability is bound to identity, device, gateway, service, scope, expiry, and nonce/replay protection. Sensitive capability claims are encrypted to the gateway and target service; browser surfaces carry the capability opaquely.

## Service Control And Observe Routing

Gateway routes and attests service-owned CAAC exchange frames for browser/runtime clients. It is not the service data-plane adapter and does not own service-specific projection semantics.

Current projection rules:
- browser apps do not call hosted service HTTP or WebSocket APIs directly
- account/runtime observes retained projections and requests service projection sync through generic service exchange
- gateway routes exchange frames to hosted services by descriptor and service identity
- target services own describe, projection, control, invoke, watch, close, and diagnostics semantics
- projection results include channel, policy/scope, cursor/freshness, coverage, and payload metadata
- logging projections return generic log event envelopes, dashboard reductions, health, safe facts, typed refs, tags, encrypted detail refs, and freshness only
- gateway must not expose raw hosted logging API URLs as browser access instructions

## WebRTC Direction
Gateway is the signaling/control boundary for browser-safe direct paths:
- same-LAN clients should win via ICE host candidates
- NAT-friendly remote clients may win via server reflexive candidates
- hard-NAT fallback via TURN remains a later slice unless operator TURN is already available

Gateway should not force all media through itself if a direct authorized browser-to-service session is available.
Gateway should also not become the routine media projection or transcoding data path. NVR/media services own media projection; gateway owns admission, signaling, and orchestration.

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
- CAAC-backed short-lived service access authorization
- capability-enforced managed service access
- gateway-mediated signaling without leaking long-lived browser secrets to app surfaces
- explicit signed-versus-encrypted audit for service access, signaling, and session metadata
- installed-service projection for `constitute-storage` in the hosted-service inventory, with health/config facts and no launcher implication
- cursor-based logging surface for `constitute-logging`, replacing direct storage proof as the durable observability path
- installed-service projection for `constitute-logging` in the hosted-service inventory, with health/config facts and optional app action
- gateway-routed service-owned projection exchange for `constitute-logging-ui`, replacing direct browser access to logging HTTP/watch APIs and Gateway-owned Logging query adapters

## Host-Capability Direction

Storage foundation is the current durable substrate. Logging is now the active observability slice; the other host capabilities below remain planned.

- gateway should converge toward orchestrating and projecting host capabilities rather than directly embodying every host concern
- planned host-local capability services include:
  - `constitute-logging`
  - `constitute-service-manager`
  - `constitute-cybersec`
  - `constitute-storage`
- planned product/app surfaces that may consume gateway-projected capability state include:
  - `constitute-physec`
- gateway should:
  - authorize and coordinate capability use
  - surface status and notifications
  - project policy/result state upward to browser surfaces
- gateway should not become the permanent implementation home for:
  - host service-manager/deployment engines
  - firewall/security engines
  - object-storage engines
  - every host-level daemon concern

### Current Browser UI Split
- gateway-specific browser management lives in `constitute-gateway-ui`
- gateway UI focuses on:
  - host/service inventory
  - network posture
  - cybersecurity posture
  - deploy/update/runtime state
  - hosted-service control

### Planned Capability Leases
- future workloads should consume explicit host-capability leases instead of embedding those systems directly
- expected early lease targets:
  - structured event truth from `constitute-logging`
  - host/service lifecycle and configuration execution from `constitute-service-manager`
  - hostile camera-network policy from `constitute-cybersec`
  - durable encrypted object/archive allocation from `constitute-storage`

### Logging Surface
Gateway exposes a durable cursor-based logging surface for `constitute-logging`.
Current producer-owned event streams cover service access, service signaling, hosted service health, storage/logging availability, account bridge failures, and control-plane errors.

Gateway formulates safe facts from its own plaintext context and encrypts sensitive detail before exposing the log record.
The logging surface intentionally excludes identities, device public keys, service capabilities, CAAC plaintext, raw payloads, decrypted request bodies, credential-bearing URLs, and raw secret material from safe facts.

Direct storage proof hooks are retired as the primary observability path. Storage remains the durable archive substrate behind `constitute-logging`.

### Service Projection Routing
Gateway routes service-owned CAAC exchange frames to hosted services by descriptor and service identity.
Gateway does not own Logging projection semantics, query Logging event APIs, or reshape `logging.events` / `logging.health` payloads.
The browser receives retained runtime projections, not a raw service API base URL.

### Service Manager And Cybersecurity Boundary
`constitute-service-manager` is the planned privileged host/service lifecycle and configuration capability. It should own install/update/restart/start/stop, systemd integration, service env/args, package/runtime checks, host log adapters, and authorized remediation execution.

`constitute-cybersec` is the planned cyber/network/service security capability. Host-security inputs such as fail2ban, AppArmor/SELinux, auth/sudo/audit, firewall posture, exposed ports, service hardening drift, and suspicious service behavior belong under `cybersec.host` for now. Cybersecurity interprets security meaning and requests remediation through service-manager; gateway routes and projects safe summaries.

Gateway may attest reachability, grants, route selection, metering, and delivery status. Service-specific projection, control, invoke, and watch semantics belong to the target service.

## Documentation Surface
- `README.md`
- `docs/PROTOCOL.md`
- `docs/ROADMAP.md`
- `docs/OPERATIONS.md`
- `docs/DEVELOPMENT.md`
