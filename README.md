# Constitute Gateway

Native gateway service for Constitute. This repository provides the native layer that browser clients depend on for discovery bootstrap, relay bridging, and swarm-facing transport primitives.

## Scope
- Nostr-based discovery bootstrap and zone presence publication
- Gateway local relay surface for web clients
- Zone-scoped UDP transport and DHT-style request/response primitives
- Host bootstrap automation for Linux, Windows, and FCOS paths

Out of scope:
- Web UI and UX
- Community policy UX
- Higher-layer application crypto semantics

## Status
- Discovery and zone presence contracts: implemented
- Gateway record query and DHT put/get bridge: implemented
- UDP forwarding fanout and hop bounds: implemented
- FCOS provisioning scaffolding: implemented

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
- Architecture and roadmap: [`ARCHITECTURE.md`](ARCHITECTURE.md)

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

