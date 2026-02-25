# Constitute Gateway

Native gateway service for Constitute. This repository provides the native dependency layer that browser clients and native services depend on for discovery bootstrap, relay bridging, and swarm-facing transport primitives.

## Scope
- Nostr-based discovery bootstrap and zone presence publication
- Gateway local relay surface for web clients
- Zone-scoped UDP/QUIC mesh transport and DHT-style request/response primitives
- Host bootstrap automation for Linux, Windows, and FCOS paths

Out of scope:
- Web UI and UX
- Community policy UX
- Service-specific application logic (for example NVR ingest/retention)

## Status
Implemented:
- Discovery and zone presence contracts
- Gateway record query and DHT put/get bridge
- UDP forwarding fanout and hop bounds
- Optional QUIC datagram transport path with local integration tests
- FCOS provisioning scaffolding

In progress:
- Transport hardening and operational tuning for difficult NAT topologies
- Web parity for full convergence on identity/device resolution behavior

## Opinionated Release Deploy (One-Liners)
### Linux (install/update, production update timer, baseline host hardening)
```bash
curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/linux/deploy-opinionated.sh | bash
```

### Windows (install/update latest release as service)
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/windows/install-latest.ps1 -UseBasicParsing | iex"
```

## Start Here
- Operators: [`docs/OPERATIONS.md`](docs/OPERATIONS.md)
- FCOS operators: [`docs/FCOS.md`](docs/FCOS.md)
- Contributors: [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)
- Protocol contracts: [`docs/PROTOCOL.md`](docs/PROTOCOL.md)
- Project roadmap brief: [`docs/ROADMAP.md`](docs/ROADMAP.md)
- Architecture and detailed roadmap: [`ARCHITECTURE.md`](ARCHITECTURE.md)

## Runner Entrypoints
- Linux/FCOS: `./scripts/run.sh`
- Windows: `powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1`

## Security Posture
- Discovery transport is treated as observable metadata.
- Identity and application confidentiality belongs to higher crypto layers.
- Operators should apply VPN/tunnel controls based on risk profile.
- Release updates are consumed from tagged GitHub Releases.

## Contributing
Contribution standards and commit conventions are documented in [`CONTRIBUTING.md`](CONTRIBUTING.md).
