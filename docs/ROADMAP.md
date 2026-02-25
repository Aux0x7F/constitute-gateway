# Project Roadmap Brief

This brief captures execution order across `constitute-gateway`, `constitute` (web), and `constitute-nvr`.

## Delivery Strategy
1. Stabilize and freeze gateway contracts.
2. Converge web implementation against those contracts.
3. Add higher-level services (starting with `constitute-nvr`) on top of the converged base.

Rationale:
- Gateway is the transport/control dependency for web and native service clients.
- Contract stability reduces thrash during web convergence.
- Service-layer work (NVR and similar) should consume stable primitives, not redefine them.

## Current Snapshot
- Gateway: core discovery, app-channel bridge, zone-scoped UDP/DHT path, and optional QUIC mesh path implemented.
- Web convergence: partial; parity work remains.
- NVR: not started in this repository (future sibling service repository).

## Phase Plan

### Phase A: Gateway Contract Freeze
Objectives:
- finalize protocol contracts in `docs/PROTOCOL.md`
- close remaining transport/runtime gaps needed for parity
- keep security invariants test-backed

Exit criteria:
- contract doc reviewed and stable
- gateway tests green in CI for Linux and Windows
- no unresolved P0 parity blockers in gateway architecture roadmap

### Phase B: Web Convergence
Objectives:
- align `constitute` web event envelopes and request/response flows
- match identity/device lookup behavior with gateway
- validate zone durability and sync behavior end-to-end

Exit criteria:
- cross-repo compatibility test plan passes
- no schema drift between web and gateway contracts
- web fallback path validated: relay <-> gateway path behaves deterministically

### Phase C: Service Layer (NVR First)
Objectives:
- implement `constitute-nvr` as a separate native service/client
- publish service capability and endpoint metadata via contract-compliant records
- keep gateway focused on transport/control plane, not NVR app internals

Exit criteria:
- NVR service advertises and resolves over converged gateway/web contracts
- NVR ingestion/retention/auth flows are isolated to service layer
- operational runbook includes co-hosted and split-host deployment models

## Known Risks and Controls
- Risk: gateway/web contract drift during active iteration.
  - Control: protocol-first changes and compatibility test vectors.
- Risk: transport changes break app-channel assumptions.
  - Control: end-to-end contract tests before web merge.
- Risk: service scope bleeding into gateway core.
  - Control: strict boundary; services consume gateway APIs/events.

## Near-Term Priority Order
1. finish gateway parity gaps called out in `ARCHITECTURE.md`
2. execute web convergence pass
3. start `constitute-nvr` scaffolding and capability advertisements

## Iteration-1 Handoff Status
Gateway iteration-1 is considered handoff-ready for web catch-up when the following are true:
- contract docs are frozen for current behavior (`docs/PROTOCOL.md`)
- CI is green on Linux and Windows build/test lanes
- gateway app-channel flows are verified by tests (`swarm_record_request`, `swarm_dht_put/get`)
- role publication model is extensible and backward compatible

Current disposition:
- Not yet handoff-ready for web catch-up; transport/fallback and auth-boundary closure remains active under gateway blocker issue #1.
- Longer-running operator host validation (real deployment environment soak checks) remains tracked as follow-up issue #7.

## Estimation Guidance
To account for offline human intervals and review latency:
- apply a 1.5x to 2.0x calendar buffer to implementation estimates
- split work into issue-sized slices that each close within 1-3 focused sessions
- prefer milestone-level target dates over single-day deadlines for integration-heavy phases

