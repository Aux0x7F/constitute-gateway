#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-constitute-gateway}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/constitute-gateway}"
DATA_DIR="${DATA_DIR:-/var/lib/constitute-gateway}"
BINARY_PATH=""
CONFIG_TEMPLATE=""
NO_START=0

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
  --data-dir <path>           Data dir (default: /var/lib/constitute-gateway)
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

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl not found; Linux service install requires systemd" >&2
  exit 1
fi

run_sudo mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR"
run_sudo install -m 0755 "$BINARY_PATH" "$INSTALL_DIR/constitute-gateway"

if [[ -n "$CONFIG_TEMPLATE" && -f "$CONFIG_TEMPLATE" && ! -f "$CONFIG_DIR/config.json" ]]; then
  run_sudo install -m 0644 "$CONFIG_TEMPLATE" "$CONFIG_DIR/config.json"
fi

service_unit="/etc/systemd/system/${SERVICE_NAME}.service"
run_sudo tee "$service_unit" >/dev/null <<EOF
[Unit]
Description=Constitute Gateway
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
DynamicUser=yes
StateDirectory=constitute-gateway
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
