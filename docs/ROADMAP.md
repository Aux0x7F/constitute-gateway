# Project Roadmap Brief

This brief captures execution order across `constitute-gateway`, `constitute-account`, `constitute-gateway-ui`, `constitute-nvr`, and `constitute-nvr-ui`.

## Delivery Strategy
1. Freeze cross-repo contracts for service-backed devices and managed app surfaces.
2. Implement gateway-managed launch/signaling.
3. Implement NVR live preview over managed WebRTC.
4. Converge shell and app surfaces against the managed-service contract.

Rationale:
- Gateway is the browser control dependency for managed services.
- Contract stability reduces cross-repo thrash.
- App surfaces should consume stable launch/signaling primitives, not redefine auth or transport.

## Current Snapshot
- Gateway: discovery, app-channel bridge, zone-scoped UDP/DHT path, optional QUIC mesh path, and gateway zone-sync/install contracts implemented.
- Managed-service launch/signaling: active implementation slice.
- NVR: service install path exists; live preview and managed launch parity remain active work.
- Browser/runtime split and direct app entry are current convergence work across `constitute-account`, `constitute-ui`, `constitute-gateway-ui`, and app surfaces.

## Phase Plan

### Phase A: Contract Freeze
Objectives:
- finalize protocol contracts in `docs/PROTOCOL.md`
- align repo-local docs with the project-level service-backed device and app-surface model
- keep security invariants explicit before code churn

Exit criteria:
- contract docs reviewed and stable across repos
- default behavior documented without stale aliases
- no unresolved schema ambiguity for launch/signaling records

### Phase B: Gateway Managed Launch and Signaling
Objectives:
- publish service-backed device metadata and hosted-service inventory
- issue short-lived managed launch authorization
- broker browser <-> service signaling for WebRTC
- expose gateway/service freshness and status cleanly

Exit criteria:
- launch authorization tests pass
- signaling contract tests pass
- hosted-service inventory publishes deterministically
- same-LAN and NAT-friendly paths have a consistent gateway signaling story

### Phase C: NVR Managed Live View
Objectives:
- publish NVR as a service-backed device hosted by a gateway
- implement gateway-authorized WebRTC H.264 live preview
- preserve encrypted recording and segment retrieval
- keep direct/manual debug mode available but non-canonical

Exit criteria:
- at least one live preview tile renders through managed launch
- multiple preview tiles can coexist using substreams where available
- archived segment retrieval still works

### Phase D: Shell and App Surface Convergence
Objectives:
- retire launcher-first shell framing in favor of direct app entry plus `constitute-account`
- make `constitute-nvr-ui` a clean Pages-hosted app surface
- remove long-lived secret expectations from managed app launch
- ensure direct app entry does not require a manual account visit before app use

Exit criteria:
- first-party app launch opens separate app surface cleanly
- account and gateway surfaces keep service-backed devices distinct from user devices
- launch context/bootstrap works without query-string secrets

## Known Risks and Controls
- Risk: contract drift during active iteration.
  - Control: protocol-first changes and cross-repo test vectors.
- Risk: WebRTC complexity slows delivery.
  - Control: keep gateway as signaling boundary and preserve recorded-media fallback.
- Risk: shell/app bootstrap leaks secrets.
  - Control: short-lived launch tokens and non-secret launch ids only.

## Near-Term Priority Order
1. freeze service-backed device and managed-launch docs
2. land gateway launch/signaling implementation
3. land NVR live preview path
4. converge shell and NVR UI

## Install/Deploy Model (Current)
- No repository-managed OS image/media generation path.
- Dev: clone repository, build locally, install service locally.
- Release: install/update service from tagged release artifacts.

## Current / Planned Later Phases

The product-surface split is current local convergence work. Host-capability services are planned later.

### Phase E: Product-Surface Split
Objectives:
- keep `constitute-account` as the browser identity/session/grant authority
- make direct app entry canonical instead of shell-launcher-first
- keep gateway-specific management in `constitute-gateway-ui`

Exit criteria:
- account/profile/device/grant management has a clear primary app boundary
- gateway-specific host/service management has a separate UI home
- launcher behavior is convenience/navigation rather than the required primary flow

### Phase F: Host-Capability Services
Objectives:
- introduce cryptographic media projection and warm NVR stream planning before burying stream lifecycle in gateway or recording
- introduce `constitute-logging` as the structured event truth capability feeding operators, development diagnostics, Cybersecurity, and Physical Security incident timelines
- introduce `constitute-cybersec` as a cyber/network/service security capability surfaced in UI as `Cybersecurity`
- introduce `constitute-storage` as a host-local capability service for encrypted content-addressed object/archive semantics
- keep `constitute-physec` as a future Physical Security app surfaced in UI as `Security`, consuming NVR, Zigbee, and future sensor projections rather than absorbing gateway capability internals
- keep gateway as orchestrator/projector of those capabilities rather than making it their permanent implementation home

Exit criteria:
- gateway remains admission/signaling/orchestration boundary rather than routine media data path
- workloads can request capability leases instead of embedding logging/cybersecurity/storage logic directly
- hostile camera-network posture and higher-level anomaly reporting have an explicit home
- durable object/blob/archive semantics have an explicit shared home without forcing all service config/runtime state into storage
