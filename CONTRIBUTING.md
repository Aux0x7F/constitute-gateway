# Contributing

## Objectives
This repo is the native gateway dependency for Constitute web clients. Contributions should optimize for:
- Protocol correctness
- Security invariants
- Cross-repo convergence with web standards
- Operational legibility

## Ground Rules
- Keep protocol behavior aligned with `constitute` web repo semantics
- Prefer explicit, testable behavior over convenience abstractions
- Avoid hidden side effects in transport and relay paths
- Preserve backward compatibility unless a migration path is defined

## Branching and PR Workflow
1. Keep changes scoped to one behavior theme per PR
2. Add or update tests for behavior changes
3. Update docs when protocol/config behavior changes

Recommended branch names:
- `feat/<topic>`
- `fix/<topic>`
- `chore/<topic>`

## Commit Style
Use multi-line commits with Conventional Commit subject line:
- `feat:` behavior additions
- `fix:` bug/security corrections
- `refactor:` structure changes without behavior change
- `docs:` documentation-only changes
- `test:` test-only changes
- `chore:` repo/process updates

## Coding Conventions
- Rust edition: 2021
- Keep code ASCII unless the file already requires otherwise
- Favor clear names over abbreviated names
- Add comments only where logic is non-obvious
- Do not add broad `allow` attributes unless tightly scoped and justified

## Testing Requirements
Before opening a PR, run at least:
```bash
cargo test --features platform-windows -j 1
```
If editing platform-agnostic logic, also run:
```bash
cargo test --features platform-linux -j 1
```

When changing transport/relay protocol behavior:
- Add a smoke/integration-style test in `tests/smoke.rs`
- Add unit tests for parser/validation edge cases where practical

## Documentation Requirements
Update docs for any of the following:
- New config keys
- Protocol envelope/tag changes
- Security behavior changes
- Service/runtime workflow changes

Primary docs:
- `README.md` for operator/developer quickstart
- `ARCHITECTURE.md` for design and roadmap
- `docs/` for protocol/operations/development references
- Rust module docs (`//!`) for code-level navigation

## Security Reporting
Do not open a public issue for active exploit details.
Use a private channel first for high-severity vulnerabilities, then publish a patched advisory.

## Quality Bar Checklist
Before merge:
- [ ] Tests pass
- [ ] Behavior documented
- [ ] No accidental debug artifacts
- [ ] No secrets or environment-specific values committed
- [ ] Cross-repo behavior impact noted (if any)
