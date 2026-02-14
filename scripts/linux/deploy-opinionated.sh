#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="${REPO_OWNER:-Aux0x7F}"
REPO_NAME="${REPO_NAME:-constitute-gateway}"
TIMER_INTERVAL="${TIMER_INTERVAL:-30m}"
UDP_PORT="${UDP_PORT:-4040}"
WS_PORT="${WS_PORT:-7447}"
WSS_PORT="${WSS_PORT:-}"
PROXY_URL="${PROXY_URL:-}"
USE_TOR="${USE_TOR:-0}"
TOR_SOCKS="${TOR_SOCKS:-127.0.0.1:9050}"
TOR_CONTROL="${TOR_CONTROL:-127.0.0.1:9051}"
TOR_NO_ROTATE="${TOR_NO_ROTATE:-0}"

usage() {
  cat <<'EOF'
Usage: deploy-opinionated.sh [options]

Opinionated Linux release deploy:
1) install/update from latest GitHub release
2) configure production update timer
3) apply baseline host hardening rules
4) install systemd CPU override and restart service

Options:
  --repo-owner <owner>       GitHub owner (default: Aux0x7F)
  --repo-name <name>         GitHub repo (default: constitute-gateway)
  --timer-interval <value>   Update timer interval (default: 30m)
  --udp-port <port>          UDP swarm port for firewall allow (default: 4040)
  --ws-port <port>           WS relay port for firewall allow (default: 7447)
  --wss-port <port>          Optional WSS relay port for firewall allow
  --proxy-url <url>          Optional HTTP(S) proxy for release fetches
  --tor                      Use Tor SOCKS egress for release fetches
  --tor-socks <host:port>    Tor SOCKS endpoint (default: 127.0.0.1:9050)
  --tor-control <host:port>  Tor control endpoint (default: 127.0.0.1:9051)
  --no-tor-rotate            Disable NEWNYM retry rotation
  -h, --help                 Show help
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
    --repo-owner)
      REPO_OWNER="${2:?missing value for --repo-owner}"
      shift 2
      ;;
    --repo-name)
      REPO_NAME="${2:?missing value for --repo-name}"
      shift 2
      ;;
    --timer-interval)
      TIMER_INTERVAL="${2:?missing value for --timer-interval}"
      shift 2
      ;;
    --udp-port)
      UDP_PORT="${2:?missing value for --udp-port}"
      shift 2
      ;;
    --ws-port)
      WS_PORT="${2:?missing value for --ws-port}"
      shift 2
      ;;
    --wss-port)
      WSS_PORT="${2:?missing value for --wss-port}"
      shift 2
      ;;
    --proxy-url)
      PROXY_URL="${2:?missing value for --proxy-url}"
      shift 2
      ;;
    --tor)
      USE_TOR=1
      shift
      ;;
    --tor-socks)
      USE_TOR=1
      TOR_SOCKS="${2:?missing value for --tor-socks}"
      shift 2
      ;;
    --tor-control)
      TOR_CONTROL="${2:?missing value for --tor-control}"
      shift 2
      ;;
    --no-tor-rotate)
      TOR_NO_ROTATE=1
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

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/main"

install_args=(
  --repo-owner "$REPO_OWNER"
  --repo-name "$REPO_NAME"
  --setup-timer
  --timer-interval "$TIMER_INTERVAL"
)

if [[ -n "$PROXY_URL" ]]; then
  install_args+=(--proxy-url "$PROXY_URL")
fi
if [[ "$USE_TOR" -eq 1 ]]; then
  install_args+=(--tor --tor-socks "$TOR_SOCKS" --tor-control "$TOR_CONTROL")
fi
if [[ "$TOR_NO_ROTATE" -eq 1 ]]; then
  install_args+=(--no-tor-rotate)
fi

echo "[deploy] install/update from release + timer (${TIMER_INTERVAL})"
curl -fsSL "${RAW_BASE}/scripts/linux/install-latest.sh" | bash -s -- "${install_args[@]}"

harden_args=(--apply --udp "$UDP_PORT" --ws "$WS_PORT")
if [[ -n "$WSS_PORT" ]]; then
  harden_args+=(--wss "$WSS_PORT")
fi

echo "[deploy] apply host hardening"
curl -fsSL "${RAW_BASE}/scripts/linux/harden-host.sh" | run_sudo bash -s -- "${harden_args[@]}"

echo "[deploy] install systemd override and restart"
curl -fsSL "${RAW_BASE}/scripts/linux/install-systemd-override.sh" | run_sudo bash -s -- --restart

echo "[deploy] complete"
