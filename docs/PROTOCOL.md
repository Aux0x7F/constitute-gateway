# Gateway Protocol Contract

This document defines the protocol contract for `constitute-gateway` and the expected convergence surface with the first-party browser repos.

## Contract Status
- Status: `active`
- Scope: gateway runtime, browser<->gateway app channel, managed service launch/signaling, gateway<->gateway transport
- Browser-facing repos currently include `constitute-account`, `constitute-gateway-ui`, and `constitute-nvr-ui`.
- Change rule: this pre-prod contract may break only when the active project contract moves all affected repos together.

## Canonical Terms
- `devicePk`: Nostr public key that identifies a runtime node
- `identityId`: logical identity identifier
- `zone`: discovery/replication partition key
- `record`: signed Nostr event carrying `identity`, `device`, or `dht` payload
- `deviceKind`: `user` or `service`
- `service`: service slug for service-backed devices
- `hostGatewayPk`: gateway device public key that hosts a service-backed device
- `launchToken`: short-lived gateway-issued authorization for managed app launch/session setup
- `serviceCapability`: planned explicit cryptographic service-access capability that may supersede launch-token-only admission semantics

## Node Roles
The role vocabulary is shared across discovery and presence payloads:
- `relay`
- `gateway`
- `browser`
- `native`

Current runtime behavior:
- Gateway defaults to `role = gateway` and may publish another configured role.
- Consumers must treat unknown role values as non-fatal.

## Discovery Plane

### 1) Swarm Discovery Record
Signed Nostr event:
- `kind = 30078`
- Required tags:
  - `['t', 'swarm_discovery']`
  - `['type', 'device']`
  - `['role', '<role>']`

Content fields:
- `devicePk` (required)
- `identityId` (optional)
- `deviceLabel` (optional)
- `updatedAt` (required, ms)
- `expiresAt` (required, ms)
- `role` (required)
- `deviceKind` (optional; defaults to `user`)
- `service` (optional)
- `hostGatewayPk` (optional)
- `relays` (array, optional)
- `hostPlatform` (optional; `linux`, `windows`, or `unknown`)
- `serviceVersion` (required)
- `releaseChannel` (optional; `release` or `dev`)
- `releaseTrack` (optional; `latest` or custom track)
- `releaseBranch` (optional; branch name for local/dev installs)
- `hostedServices` (optional array, gateway only)
- `freshnessMs` (optional)

### 2) Zone Presence
Signed Nostr event:
- `kind = 1`
- Required tags:
  - `['t', 'constitute']`
  - `['z', '<zone_key>']`

Content fields:
- `type = zone_presence`
- `zone` (required)
- `devicePk` (required)
- `swarm` (required; may be empty until endpoint resolves)
- `role` (required)
- `relays` (array, optional)
- `hostPlatform` (optional; `linux`, `windows`, or `unknown`)
- `serviceVersion` (required)
- `releaseChannel` (optional; `release` or `dev`)
- `releaseTrack` (optional; `latest` or custom track)
- `releaseBranch` (optional; branch name for local/dev installs)
- `metrics` (optional)
- `ts` (required, ms)
- `ttl` (required, seconds)

### Metrics Payload (when present)
- `clients`
- `cpuPct`
- `memPct`
- `memUsedMb`
- `memTotalMb`
- `loadPct`
- `ts`

## Web <-> Gateway App Channel
App-channel events are Nostr events tagged with `['t', 'constitute']`.

### Request: Record Lookup
Incoming types accepted by gateway:
- `swarm_record_request`

Fields:
- `requestId` (optional)
- `timeoutMs` (optional)
- `zone` (optional)
- `identityId` (optional)
- `devicePk` (optional)
- `want` (optional array: `identity`, `device`, `dht`)

Gateway responses:
- `swarm_identity_record`
- `swarm_device_record`
- `swarm_dht_record`
- `swarm_record_response` (`pending`, `complete`, `timeout`)

### Request: DHT Read
Incoming type:
- `swarm_dht_get`

Fields:
- Required: `scope` or `dhtScope`, `key` or `dhtKey`
- Optional: `zone`, `requestId`, `timeoutMs`

### Request: DHT Write
Incoming type:
- `swarm_dht_put`

Fields:
- Required: `scope` or `dhtScope`, `key` or `dhtKey`, `value`
- Optional: `zone`, `updatedAt`, `expiresAt`, `requestId`

### Request: Gateway Service Install
Incoming type:
- `gateway_service_install_request`

Current supported operation:
- `service = nvr`
- `action = install`

Required fields:
- `requestId`
- `toDevicePk` (must match gateway `devicePk`)
- `identityId` (must match gateway runtime `identity_id`)
- `pairIdentity`
- `pairCode`
- `pairCodeHash`

Optional fields:
- `zone` / `zoneKeys`
- `authorizedDevicePks`
- `swarmPeers`
- `publicWsUrl`
- `allowUnsignedDebugHello`
- `reolink*` provisioning hints
- `storageRoot`
- `timeoutSecs`

Gateway status events:
- `gateway_service_install_status`
- status lifecycle: `accepted` -> `started` -> (`complete` | `failed` | `rejected`)
- includes `requestId`, `gatewayPk`, `toDevicePk`, `identityId`, `service`, `action`, optional `reason`/`detail`

### Request: Managed Service Launch
Incoming type:
- `gateway_managed_launch_request`

Required fields:
- `requestId`
- `toDevicePk` (must match gateway `devicePk`)
- `identityId`
- `devicePk` (requesting paired browser device)
- `servicePk` (target hosted service-backed device)
- `service`
- `capability` (for example `nvr.view` or `nvr.manage`)
- `launchNonce`

Optional fields:
- `zone`
- `appRepo`
- `display`

Gateway responses:
- `gateway_managed_launch_status`
- lifecycle: `accepted` -> (`complete` | `failed` | `rejected`)
- `complete` includes:
  - `gatewayPk`
  - `servicePk`
  - `service`
  - `launchToken`
  - `expiresAt`
  - optional `display`

Validation rules:
- requesting device must belong to the same identity as the gateway runtime
- target service must be owned/hosted by the gateway
- requesting device must hold the requested capability
- launch token must be short-lived and service-scoped

Planned convergence direction:
- the launch token is a transitional short-lived bearer-style capability
- future service access should be represented as an explicit cryptographic capability bound to identity, requesting device, gateway, service, scope, expiry, and nonce/replay protection
- sensitive session material must be encrypted to intended principals/devices, not merely signed
- direct first-party app entry should be able to resolve valid retained account/runtime capability state without requiring a manual account-app visit first

### Request: Managed Service Signaling
Incoming type:
- `gateway_signal_request`

Required fields:
- `requestId`
- `toDevicePk` (must match gateway `devicePk`)
- `identityId`
- `devicePk` (requesting browser device)
- `servicePk`
- `service`
- `signalType`
- `payload`
- `launchToken`

Current `signalType` values:
- `offer`
- `answer`
- `ice_candidate`
- `ice_complete`
- `session_close`

Gateway responses:
- `gateway_signal_status`
- lifecycle: `accepted` -> (`complete` | `failed` | `rejected`)

Gateway forwarding events:
- `gateway_signal`
- delivered to the target hosted service or requesting browser path with:
  - `gatewayPk`
  - `servicePk`
  - `service`
  - `signalType`
  - `payload`

Validation rules:
- launch token must still be valid
- token must bind the requesting device, target gateway, and target service
- gateway may reject signaling that is not associated with an active launch/session

### Request: Gateway Zone Sync
Incoming type:
- `gateway_zone_sync_request`

Required fields:
- `requestId`
- `toDevicePk` (must match gateway `devicePk`)
- `identityId` (must match gateway runtime `identity_id`)
- `zoneKeys` (identity zone keys)

Optional fields:
- `zone`
- `extraZoneKeys` (gateway-local additional zones)

Gateway status events:
- `gateway_zone_sync_status`
- status lifecycle: `complete` | `failed` | `rejected`
- includes `requestId`, `gatewayPk`, `toDevicePk`, `identityId`, `zoneKeys`, `extraZoneKeys`, `restartRequired`, optional `reason`/`detail`
- current runtime behavior persists zone scope immediately and requires service restart to apply transport listeners/filters

## Gateway <-> Gateway Mesh Transport

### Transport Modes
- UDP mesh (default)
- QUIC datagram mesh (optional, enabled with `quic_enabled`)

Runtime behavior:
- Gateway always runs UDP transport.
- When QUIC is enabled, gateway runs QUIC in parallel and uses dual-send fanout for record propagation and lookups.
- Failures on one transport do not block the other transport path.

### Message Envelope
- Shared envelope across UDP and QUIC datagrams
- Version field: `v`
- Current version: `1`
- Unknown versions: drop silently

### Message Kinds
- `hello`
- `ack`
- `record`
- `recordrequest`

### Zone-Scoped Rules
- Gossip and record propagation are zone-scoped.
- Requests may be targeted by:
  - `identityId`
  - `devicePk`
  - `dhtScope` + `dhtKey`
- Forwarding bounds:
  - max peers per request: `udp_request_fanout`
  - max forwarding depth: `udp_request_max_hops`

### TURN / Gateway Boundary
- Gateway does not terminate TURN sessions.
- TURN remains a browser/client fallback path when direct browser connectivity is required.
- Gateway mesh transport (UDP/QUIC) is the native backbone plane.

## Managed Service Media Direction
- Gateway is the control/signaling boundary for browser-managed service access.
- Browser media path for managed live view is WebRTC.
- Preview codec direction is H.264.
- Same-LAN host ICE candidates are preferred.
- NAT-friendly server reflexive candidates are allowed.
- Hard-NAT guaranteed fallback via TURN is not required for this iteration unless operator TURN is present.
- WebRTC media is encrypted in transit through DTLS-SRTP.
- Gateway should not become the routine media data path when direct authorized browser-to-service media can be established.
- Media projection, transcoding, and recording remain workload concerns, not gateway protocol responsibilities.
- Signed discovery, launch, or signaling records are not confidential unless their sensitive fields are encrypted.

## Validation and Security Invariants

### Relay Ingest (WS/WSS)
- Reject non-JSON or non-Nostr envelopes.
- Verify NIP-01 signature before fanout.
- Enforce created-at replay window and skew bounds.
- If payload has `ts`, enforce timestamp window.
- If payload has `ts` + `ttl`, enforce expiration.
- Deduplicate by event id before broadcast.
- Enforce per-client frame size and rate limit.

### Store Validation
Record acceptance requires:
- valid signature
- valid tag contract (`kind=30078`, `t=swarm_discovery`, `type=<record>`)
- non-expired `expiresAt` when provided
- record-specific checks:
  - `identity`: `identityId` present and publisher included in `devicePks`
  - `device`: `devicePk` present and equals event `pubkey`
  - `dht`: `scope`, `key`, and `value` present; optional `authorPk` must match event `pubkey`

### Replay/Loop Boundaries
- Event-id replay cache is enforced for inbound processing.
- Mesh transport drops invalid-signature `record` envelopes before they enter request/store flows.
- Rebroadcast excludes events authored by self.
- Allowed relay fanout classes are constrained to `t=constitute` or `t=swarm_discovery`.

### Managed Launch Security
- launch tokens must expire quickly
- launch tokens must bind gateway, service, identity, and requesting device
- services must reject invalid, expired, unsigned, or wrong-target launch tokens
- browser launch/bootstrap must not rely on long-lived secrets in URL parameters

## Convergence Targets (Gateway -> Web)
The following are executed during convergence:
- service-backed device record parity
- managed launch authorization parity
- managed signaling envelope parity
- identity/device resolution behavior and fallback order
- zone membership durability and sync semantics
- shared test vectors for accepted/rejected envelopes

## Versioning Policy
- This pre-prod contract may break when the active project contract changes.
- Do not keep stale aliases once all in-repo callers have moved.
- Add explicit version markers when the protocol graduates beyond pre-prod convergence.
