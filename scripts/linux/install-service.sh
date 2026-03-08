#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-constitute-gateway}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/constitute-gateway}"
DATA_DIR="${DATA_DIR:-}"
SERVICE_USER="${SERVICE_USER:-constitute-gateway}"
BINARY_PATH=""
CONFIG_TEMPLATE=""
NO_START=0
PAIR_IDENTITY=""
PAIR_GENERATE=0
GENERATED_PAIR_CODE=""

usage() {
  cat <<'EOF'
Usage: install-service-linux.sh --binary <path> [options]

Install/update constitute-gateway Linux binary and systemd service.

Options:
  --binary <path>             Path to constitute-gateway binary (required)
  --config-template <path>    Optional config example to seed config.json
  --service-name <name>       Systemd service name (default: constitute-gateway)
  --install-dir <path>        Binary install dir (default: /usr/local/bin)
  --config-dir <path>         Config dir (default: /etc/constitute-gateway)
  --data-dir <path>           Data dir (default: auto: /data/constitute-gateway if mounted, else /var/lib/constitute-gateway)
  --pair-identity <label>     Identity label for pairing enrollment
  --pair-generate             Generate one-time pairing code when pairing is needed
  --no-start                  Do not restart/start service after install
  -h, --help                  Show this help
EOF
}

run_sudo() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

detect_data_dir() {
  if [[ -d "/data" ]]; then
    if command -v findmnt >/dev/null 2>&1; then
      if findmnt -rn -T /data >/dev/null 2>&1; then
        echo "/data/constitute-gateway"
        return
      fi
    else
      echo "/data/constitute-gateway"
      return
    fi
  fi
  echo "/var/lib/constitute-gateway"
}

ensure_service_user() {
  if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    return
  fi
  if ! command -v useradd >/dev/null 2>&1; then
    echo "useradd not found; cannot create service user ${SERVICE_USER}" >&2
    exit 1
  fi
  run_sudo useradd --system --no-create-home --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      BINARY_PATH="${2:?missing value for --binary}"
      shift 2
      ;;
    --config-template)
      CONFIG_TEMPLATE="${2:?missing value for --config-template}"
      shift 2
      ;;
    --service-name)
      SERVICE_NAME="${2:?missing value for --service-name}"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="${2:?missing value for --install-dir}"
      shift 2
      ;;
    --config-dir)
      CONFIG_DIR="${2:?missing value for --config-dir}"
      shift 2
      ;;
    --data-dir)
      DATA_DIR="${2:?missing value for --data-dir}"
      shift 2
      ;;
    --no-start)
      NO_START=1
      shift
      ;;
    --pair-identity)
      PAIR_IDENTITY="${2:?missing value for --pair-identity}"
      shift 2
      ;;
    --pair-generate)
      PAIR_GENERATE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$BINARY_PATH" ]]; then
  echo "--binary is required" >&2
  usage
  exit 1
fi

if [[ ! -f "$BINARY_PATH" ]]; then
  echo "Binary not found: $BINARY_PATH" >&2
  exit 1
fi

if [[ -z "$DATA_DIR" ]]; then
  DATA_DIR="$(detect_data_dir)"
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl not found; Linux service install requires systemd" >&2
  exit 1
fi

run_sudo mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" "$DATA_DIR/data"
ensure_service_user
run_sudo chown -R "${SERVICE_USER}:${SERVICE_USER}" "$DATA_DIR"
installed_bin="$INSTALL_DIR/constitute-gateway"
source_real="$(readlink -f "$BINARY_PATH" 2>/dev/null || echo "$BINARY_PATH")"
target_real="$(readlink -f "$installed_bin" 2>/dev/null || true)"
if [[ -n "$target_real" && "$source_real" == "$target_real" ]]; then
  run_sudo chmod 0755 "$installed_bin"
else
  run_sudo install -m 0755 "$BINARY_PATH" "$installed_bin"
fi
if [[ -n "$CONFIG_TEMPLATE" && -f "$CONFIG_TEMPLATE" && ! -f "$CONFIG_DIR/config.json" ]]; then
  run_sudo install -m 0644 "$CONFIG_TEMPLATE" "$CONFIG_DIR/config.json"
fi

if [[ -f "$CONFIG_DIR/config.json" ]]; then
  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to normalize config data_dir" >&2
    exit 1
  fi
  run_sudo python3 - "$CONFIG_DIR/config.json" "$DATA_DIR" <<'PY'
import json
import sys
from pathlib import Path

cfg_path = Path(sys.argv[1])
state_root = sys.argv[2].rstrip("/") or "/var/lib/constitute-gateway"
with cfg_path.open("r", encoding="utf-8") as f:
    cfg = json.load(f)

raw = str(cfg.get("data_dir", "")).strip()
normalized = raw.replace("\\", "/") if raw else ""

if not normalized:
    cfg["data_dir"] = f"{state_root}/data"
elif normalized in {"./data", "data"}:
    cfg["data_dir"] = f"{state_root}/data"
elif normalized.startswith("/"):
    cfg["data_dir"] = normalized
else:
    cfg["data_dir"] = f"{state_root}/{normalized.lstrip('./')}"

with cfg_path.open("w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PY
fi

if [[ -n "$PAIR_IDENTITY" || "$PAIR_GENERATE" -eq 1 ]]; then
  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required for pairing config injection" >&2
    exit 1
  fi

  GENERATED_PAIR_CODE="$(run_sudo python3 - "$CONFIG_DIR/config.json" "$PAIR_IDENTITY" "$PAIR_GENERATE" <<'PY'
import base64
import hashlib
import json
import secrets
import sys

path, pair_identity, pair_generate = sys.argv[1:4]
pair_generate = str(pair_generate).strip() == '1'

with open(path, 'r', encoding='utf-8') as f:
    cfg = json.load(f)

previous_identity = str(cfg.get('pair_identity_label', '')).strip()
if pair_identity:
    cfg['pair_identity_label'] = pair_identity

identity = str(cfg.get('pair_identity_label', '')).strip()
existing_identity = previous_identity
existing_code = str(cfg.get('pair_code', '')).strip()
existing_hash = str(cfg.get('pair_code_hash', '')).strip()
identity_id = str(cfg.get('identity_id', '')).strip()

generated = ''
if pair_generate and identity and not identity_id:
    need_new = (not existing_code) or (not existing_hash) or (existing_identity != identity)
    if need_new:
        code = f"{secrets.randbelow(900000) + 100000:06d}"
        digest = hashlib.sha256(f"{identity}|{code}".encode('utf-8')).digest()
        cfg['pair_code'] = code
        cfg['pair_code_hash'] = base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
        generated = code

cfg.setdefault('pair_request_interval_secs', 15)
cfg.setdefault('pair_request_attempts', 24)

with open(path, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")

if generated:
    print(generated)
PY
)"
fi

service_unit="/etc/systemd/system/${SERVICE_NAME}.service"
run_sudo tee "$service_unit" >/dev/null <<EOF
[Unit]
Description=Constitute Gateway
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${DATA_DIR}
ExecStart=${INSTALL_DIR}/constitute-gateway --config ${CONFIG_DIR}/config.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
SystemCallArchitectures=native
ReadWritePaths=${CONFIG_DIR} ${DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF

run_sudo systemctl daemon-reload
run_sudo systemctl enable "${SERVICE_NAME}.service"

if [[ "$NO_START" -eq 0 ]]; then
  if run_sudo systemctl is-active --quiet "${SERVICE_NAME}.service"; then
    run_sudo systemctl restart "${SERVICE_NAME}.service"
  else
    run_sudo systemctl start "${SERVICE_NAME}.service"
  fi
fi

echo "Linux service installed: ${SERVICE_NAME}.service"
if [[ -n "$GENERATED_PAIR_CODE" ]]; then
  echo "Pairing code (claim in Settings > Pairing > Add Device): ${GENERATED_PAIR_CODE}"
fi
