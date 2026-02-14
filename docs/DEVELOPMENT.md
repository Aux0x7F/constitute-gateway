# Development Workflow

## Local Commands
Build:
```bash
cargo build --features platform-windows
cargo build --features platform-linux
```

Test:
```bash
cargo test --features platform-windows -j 1
cargo test --features platform-linux -j 1
```

Format:
```bash
cargo fmt
```

## Change Expectations
- Add tests for behavior changes
- Update docs for schema/config/runtime changes
- Keep protocol naming aligned with web repo

## Commit Style
Use Conventional Commit subject prefixes:
- `feat:`
- `fix:`
- `refactor:`
- `docs:`
- `test:`
- `chore:`

## Review Readiness
Before opening PR:
- Tests pass locally
- No debug artifacts left in committed files
- Docs updated for user-facing behavior changes
