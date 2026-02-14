# FCOS Provisioning (Infra)

This directory contains FCOS provisioning templates and generated placeholders used by gateway bootstrap workflows.

## Files
- `infra/fcos/config.template.bu`
  - Butane template for first-boot bootstrap unit wiring.
- `infra/fcos/generated/.gitkeep`
  - Placeholder directory for locally generated artifacts.
- `scripts/fcos/render-config.sh`
  - Renders Butane template and compiles Ignition.

## Typical Usage
Render config:
```bash
./scripts/fcos/render-config.sh --ssh-key-file ~/.ssh/id_ed25519.pub
```

Install FCOS:
```bash
sudo coreos-installer install /dev/sdX --ignition-file infra/fcos/generated/config.ign
```

For full operator and bootstrap behavior details, use `docs/FCOS.md`.
