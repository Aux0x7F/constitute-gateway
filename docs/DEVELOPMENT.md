# Development Workflow

## Toolchain
- Rust 2021 edition
- `cargo` for build and test
- PowerShell and Bash scripts under `scripts/`

## Local Build
### Direct cargo
```bash
cargo build --features platform-windows
cargo build --features platform-linux
```

### Via runners
- Windows: `powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1`
- Linux: `./scripts/run.sh`

Build actions are grouped under the `Build` menu in both runners.

## Local Test
```bash
cargo test --features platform-windows -j 1
cargo test --features platform-linux -j 1
```

## Formatting
```bash
cargo fmt
```

## Script Layout
- `scripts/run.sh`: Linux and FCOS command router
- `scripts/run.ps1`: Windows command router
- `scripts/linux/*`: Linux build, install, update, hardening
- `scripts/windows/*`: Windows build, service, update, image prep helpers
- `scripts/fcos/*`: FCOS provisioning and image prep

## FCOS Provisioning (Dev)
Render Butane and Ignition:
```bash
./scripts/fcos/render-config.sh --ssh-key-file ~/.ssh/id_ed25519.pub
```

Render Butane only:
```bash
./scripts/fcos/render-config.sh --ssh-key-file ~/.ssh/id_ed25519.pub --skip-ignition
```

## CI Parity Checks
Before opening a PR:
```bash
cargo test --features platform-windows -j 1
cargo test --features platform-linux -j 1
bash -n scripts/run.sh scripts/linux/*.sh scripts/fcos/*.sh
```

Optional PowerShell parser check:
```powershell
[void][System.Management.Automation.Language.Parser]::ParseFile('.\scripts\run.ps1',[ref]$null,[ref]$null)
```

## Change Expectations
- Add or update tests when behavior changes.
- Keep protocol naming convergent with the web repo.
- Update docs when protocol, config, or runtime behavior changes.
- Keep FCOS templates aligned with bootstrap scripts.

## Done Criteria
- Tests pass.
- Docs reflect behavior.
- No debug artifacts are committed.
- No environment-specific secrets are committed.
