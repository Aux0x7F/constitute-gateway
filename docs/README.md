# Documentation Index

This folder is the primary documentation surface for `constitute-gateway`.

## Start Here
- Operator install and CLI: [`docs/OPERATOR.md`](OPERATOR.md)
- Runtime operations: [`docs/OPERATIONS.md`](OPERATIONS.md)
- Contributors: [`docs/DEVELOPMENT.md`](DEVELOPMENT.md)
- Protocol implementers: [`docs/PROTOCOL.md`](PROTOCOL.md)
- Program roadmap brief: [`docs/ROADMAP.md`](ROADMAP.md)
- Architecture and long-form roadmap: [`ARCHITECTURE.md`](../ARCHITECTURE.md)

## Document Roles
- [`docs/OPERATOR.md`](OPERATOR.md)
  - Installer utility usage, CLI quick start, source-build one-liners, and pairing behavior.
- [`docs/OPERATIONS.md`](OPERATIONS.md)
  - Runtime operations, service lifecycle, hardening, and verification checks.
- [`docs/PROTOCOL.md`](PROTOCOL.md)
  - Wire contracts, validation rules, app-channel and UDP message semantics.
- [`docs/ROADMAP.md`](ROADMAP.md)
  - Project-wide sequencing: gateway -> web convergence -> service layer (`constitute-nvr`).
- [`docs/DEVELOPMENT.md`](DEVELOPMENT.md)
  - Build/test workflow, CI parity checks, and contribution quality gates.

## Publishing
- Markdown docs render natively on GitHub.
- Generated Rust API docs can be published with [`.github/workflows/docs.yml`](../.github/workflows/docs.yml).
