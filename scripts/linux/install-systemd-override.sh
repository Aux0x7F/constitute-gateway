#!/usr/bin/env bash
set -euo pipefail

SERVICE="${SERVICE:-constitute-gateway.service}"
CPU_QUOTA="85%"
RESTART=0

usage() {
  cat <<'EOF'
Usage: install-systemd-override.sh [--service <unit>] [--restart]

Installs a systemd drop-in with conservative limits.
- CPUQuota=85%

Requires root. Works on Linux hosts with systemd.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service)
      SERVICE="${2:?missing value for --service}"
      shift 2
      ;;
    --restart)
      RESTART=1
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

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[override] must be run as root" >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "[override] systemctl not found" >&2
  exit 1
fi

mkdir -p "/etc/systemd/system/${SERVICE}.d"
cat > "/etc/systemd/system/${SERVICE}.d/override.conf" <<EOF
[Service]
CPUQuota=${CPU_QUOTA}
EOF

systemctl daemon-reload

if [[ "$RESTART" -eq 1 ]]; then
  systemctl restart "$SERVICE"
fi

echo "[override] installed for ${SERVICE} (CPUQuota=${CPU_QUOTA})"
