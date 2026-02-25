# Documentation Index

This folder is the primary documentation surface for `constitute-gateway`.

## Start Here
- Operators: [`docs/OPERATIONS.md`](OPERATIONS.md)
- FCOS operators: [`docs/FCOS.md`](FCOS.md)
- Contributors: [`docs/DEVELOPMENT.md`](DEVELOPMENT.md)
- Protocol implementers: [`docs/PROTOCOL.md`](PROTOCOL.md)
- Program roadmap brief: [`docs/ROADMAP.md`](ROADMAP.md)
- Architecture and long-form roadmap: [`ARCHITECTURE.md`](../ARCHITECTURE.md)

## Document Roles
- [`docs/PROTOCOL.md`](PROTOCOL.md)
  - Wire contracts, validation rules, app-channel and UDP message semantics.
- [`docs/ROADMAP.md`](ROADMAP.md)
  - Project-wide sequencing: gateway -> web convergence -> service layer (`constitute-nvr`).
- [`docs/OPERATIONS.md`](OPERATIONS.md)
  - Runtime operations, install/update flows, hardening, and verification checks.
- [`docs/FCOS.md`](FCOS.md)
  - FCOS image prep, Ignition rendering, install path, and first-boot behavior.
- [`docs/DEVELOPMENT.md`](DEVELOPMENT.md)
  - Build/test workflow, CI parity checks, and contribution quality gates.

## Infrastructure References
- FCOS templates and generated placeholders: [`infra/fcos/`](../infra/fcos/)
- FCOS infra notes: [`infra/fcos/README.md`](../infra/fcos/README.md)

## Publishing
- Markdown docs render natively on GitHub.
- Generated Rust API docs can be published with [`.github/workflows/docs.yml`](../.github/workflows/docs.yml).
