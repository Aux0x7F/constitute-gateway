# Gateway Protocol Contract

This document defines the protocol contract for `constitute-gateway` and the expected convergence surface with the web repository.

## Contract Status
- Status: `active`
- Scope: gateway runtime, web<->gateway app channel, gateway<->gateway transport
- Compatibility rule: additive changes only unless a version gate is introduced and implemented on both gateway and web

## Canonical Terms
- `devicePk`: Nostr public key that identifies a runtime node
- `identityId`: logical identity identifier
- `zone`: discovery/replication partition key
- `record`: signed Nostr event carrying `identity`, `device`, or `dht` payload

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
- `relays` (array, optional)
- `serviceVersion` (required)

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
- `serviceVersion` (required)
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
- `swarm_discovery_request` (compat alias)

Fields:
- `requestId` (optional)
- `timeoutMs` (optional)
- `zone` (optional)
- `identityId` (optional)
- `devicePk` (optional)
- `want` (optional array: `identity`, `device`, `dht`; defaults depend on request type)

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

## Convergence Targets (Gateway -> Web)
The following are executed during web convergence to validate parity; gateway-side transport/fallback/auth baselines are complete for iteration-1:
- exact signaling envelope parity for swarm signaling messages
- parity for identity/device resolution behavior and fallback order
- parity for zone membership durability and sync semantics
- shared test vectors for accepted/rejected envelopes

## Versioning Policy
- Keep this contract backward-compatible whenever possible.
- For breaking changes, add an explicit version marker and dual-accept period.
- Remove legacy aliases only after web and gateway both pass compatibility tests.
