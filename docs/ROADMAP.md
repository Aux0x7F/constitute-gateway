# Project Roadmap Brief

This brief captures execution order across `constitute-gateway`, `constitute`, `constitute-nvr`, and `constitute-nvr-ui`.

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

## Phase Plan

### Phase A: Contract Freeze
Objectives:
- finalize protocol contracts in `docs/PROTOCOL.md`
- align repo-local docs with the project-level service-backed device and app-surface model
- keep security invariants explicit before code churn

Exit criteria:
- contract docs reviewed and stable across repos
- compatibility defaults documented
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
- make `constitute` a clean management shell plus launcher
- make `constitute-nvr-ui` a clean Pages-hosted app surface
- remove long-lived secret expectations from managed app launch

Exit criteria:
- first-party app launch opens separate app surface cleanly
- shell surfaces service-backed devices distinctly from user devices
- launch context/bootstrap works without query-string secrets

## Known Risks and Controls
- Risk: contract drift during active iteration.
  - Control: protocol-first changes and compatibility test vectors.
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
