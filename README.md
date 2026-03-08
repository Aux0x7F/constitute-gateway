# Constitute Gateway

Native gateway service for Constitute. This repository provides the native dependency layer that browser clients and native services depend on for discovery bootstrap, relay bridging, and swarm-facing transport primitives.

## Scope
- Nostr-based discovery bootstrap and zone presence publication
- Gateway local relay surface for web clients
- Zone-scoped UDP/QUIC mesh transport and DHT-style request/response primitives
- Windows and Linux service install/update paths

Out of scope:
- OS install media/image generation
- Web UI and UX
- Service-specific application logic (for example NVR ingest/retention)

## Status
Implemented:
- Discovery and zone presence contracts
- Gateway record query and DHT put/get bridge
- UDP forwarding fanout and hop bounds
- Optional QUIC datagram transport path with local integration tests
- Release install/update scripts for Windows and Linux services

In progress:
- Transport hardening and operational tuning for difficult NAT topologies
- Web parity for full convergence on identity/device resolution behavior

## Install Paths
Recommended (owner workflow):
- In `constitute` web, open `Settings > Appliances`
- Use `Download Installer Utility`
- Run the generated operator command shown in UI

CLI and source-build install flows:
- README intentionally keeps install snippets minimal; complete CLI/source/advanced flows live in `docs/OPERATOR.md`.
- See [`docs/OPERATOR.md`](docs/OPERATOR.md)

Operations and lifecycle (status/start/stop/hardening):
- See [`docs/OPERATIONS.md`](docs/OPERATIONS.md)

## Operator Artifacts
Release assets include:
- `constitute-operator-windows.zip`
- `constitute-operator-linux-amd64.tar.gz`

Operator scope is service install/update only (no media/image build path).

## Start Here
- Operator install and CLI reference: [`docs/OPERATOR.md`](docs/OPERATOR.md)
- Runtime operations: [`docs/OPERATIONS.md`](docs/OPERATIONS.md)
- Contributors: [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)
- Protocol contracts: [`docs/PROTOCOL.md`](docs/PROTOCOL.md)
- Project roadmap brief: [`docs/ROADMAP.md`](docs/ROADMAP.md)
- Architecture and detailed roadmap: [`ARCHITECTURE.md`](ARCHITECTURE.md)

## Runner Entrypoints
- Linux: `./scripts/run.sh`
- Windows: `powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1`

## Security Posture
- Discovery transport is treated as observable metadata.
- Identity and application confidentiality belongs to higher crypto layers.
- Operators should apply VPN/tunnel controls based on risk profile.
- Release updates are consumed from tagged GitHub Releases by default.

## Contributing
Contribution standards and commit conventions are documented in [`CONTRIBUTING.md`](CONTRIBUTING.md).
