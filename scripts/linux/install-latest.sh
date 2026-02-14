#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="${REPO_OWNER:-Aux0x7F}"
REPO_NAME="${REPO_NAME:-constitute-gateway}"
SETUP_TIMER=0
# Production-safe default. Keep this moderate to avoid noisy release polling.
TIMER_INTERVAL="${TIMER_INTERVAL:-30m}"
# Development profile: intentionally short poll interval for rapid release iteration.
DEV_TIMER_INTERVAL="${DEV_TIMER_INTERVAL:-2m}"
DEV_POLL=0
INSTALL_DIR="/usr/local/lib/constitute-gateway"
UPDATER_SCRIPT="${INSTALL_DIR}/update-from-github.sh"
TIMER_UNIT="constitute-gateway-update.timer"
SERVICE_UNIT="constitute-gateway-update.service"
CURL_PROXY_URL="${CURL_PROXY_URL:-}"
USE_TOR=0
TOR_SOCKS_ADDR="${TOR_SOCKS_ADDR:-127.0.0.1:9050}"
TOR_CONTROL_ADDR="${TOR_CONTROL_ADDR:-127.0.0.1:9051}"
TOR_ROTATE_ON_RETRY=1

usage() {
  cat <<'EOF'
Usage: install-latest.sh [options]

Install or update constitute-gateway Linux artifact from GitHub Releases.

Options:
  --repo-owner <owner>       GitHub owner (default: Aux0x7F)
  --repo-name <name>         GitHub repo (default: constitute-gateway)
  --setup-timer              Install and enable systemd timer for periodic updates
  --timer-interval <value>   systemd OnUnitActiveSec value (default: 30m)
  --dev-poll                 Use fast dev polling interval (default: 2m)
  --proxy-url <url>          Use HTTP(S) proxy for release fetches
  --tor                      Use Tor SOCKS egress for release fetches
  --tor-socks <host:port>    Tor SOCKS endpoint (default: 127.0.0.1:9050)
  --tor-control <host:port>  Tor control endpoint for optional NEWNYM (default: 127.0.0.1:9051)
  --no-tor-rotate            Disable NEWNYM attempt on retry
  -h, --help                 Show this help

Examples:
  ./scripts/linux/install-latest.sh
  ./scripts/linux/install-latest.sh --setup-timer --timer-interval 1h
  ./scripts/linux/install-latest.sh --setup-timer --dev-poll
  ./scripts/linux/install-latest.sh --setup-timer --tor --tor-socks 127.0.0.1:9050
EOF
}

run_sudo() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
}

build_curl_args() {
  CURL_ARGS=(-fsSL)
  if [[ -n "$CURL_PROXY_URL" ]]; then
    CURL_ARGS+=(--proxy "$CURL_PROXY_URL")
  fi
  if [[ "$USE_TOR" -eq 1 ]]; then
    CURL_ARGS+=(--proxy "socks5h://${TOR_SOCKS_ADDR}")
  fi
}

rotate_tor_exit() {
  [[ "$USE_TOR" -eq 1 ]] || return 0
  [[ "$TOR_ROTATE_ON_RETRY" -eq 1 ]] || return 0
  command -v nc >/dev/null 2>&1 || return 0

  local host="${TOR_CONTROL_ADDR%:*}"
  local port="${TOR_CONTROL_ADDR##*:}"
  [[ -n "$host" && -n "$port" && "$host" != "$port" ]] || return 0

  {
    printf 'AUTHENTICATE\r\n'
    printf 'SIGNAL NEWNYM\r\n'
    printf 'QUIT\r\n'
  } | nc -w 2 "$host" "$port" >/dev/null 2>&1 || true
}

verify_tor_proxy() {
  [[ "$USE_TOR" -eq 1 ]] || return 0
  if ! curl "${CURL_ARGS[@]}" --max-time 12 -I https://github.com >/dev/null 2>&1; then
    echo "Tor proxy check failed at socks5h://${TOR_SOCKS_ADDR}" >&2
    exit 1
  fi
}

download_with_retry() {
  local url="$1"
  local out="$2"
  local attempt
  for attempt in 1 2 3; do
    if curl "${CURL_ARGS[@]}" "$url" -o "$out"; then
      return 0
    fi
    rotate_tor_exit
    sleep "$attempt"
  done
  return 1
}

setup_update_timer() {
  local persisted_args=(--repo-owner "$REPO_OWNER" --repo-name "$REPO_NAME")
  local persisted_args_str=""

  if [[ "$DEV_POLL" -eq 1 ]]; then
    persisted_args+=(--dev-poll)
  else
    persisted_args+=(--timer-interval "$TIMER_INTERVAL")
  fi
  if [[ -n "$CURL_PROXY_URL" ]]; then
    persisted_args+=(--proxy-url "$CURL_PROXY_URL")
  fi
  if [[ "$USE_TOR" -eq 1 ]]; then
    persisted_args+=(--tor --tor-socks "$TOR_SOCKS_ADDR" --tor-control "$TOR_CONTROL_ADDR")
  fi
  if [[ "$TOR_ROTATE_ON_RETRY" -eq 0 ]]; then
    persisted_args+=(--no-tor-rotate)
  fi

  printf -v persisted_args_str ' %q' "${persisted_args[@]}"

  run_sudo mkdir -p "$INSTALL_DIR"

  run_sudo tee "$UPDATER_SCRIPT" >/dev/null <<EOF
#!/usr/bin/env bash
set -euo pipefail
curl -fsSL "https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/main/scripts/linux/install-latest.sh" | bash -s --${persisted_args_str}
EOF
  run_sudo chmod 0755 "$UPDATER_SCRIPT"

  run_sudo tee "/etc/systemd/system/${SERVICE_UNIT}" >/dev/null <<EOF
[Unit]
Description=Constitute Gateway update from GitHub Releases
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=${UPDATER_SCRIPT}
EOF

  run_sudo tee "/etc/systemd/system/${TIMER_UNIT}" >/dev/null <<EOF
[Unit]
Description=Periodic Constitute Gateway update check

[Timer]
OnBootSec=10m
OnUnitActiveSec=${TIMER_INTERVAL}
RandomizedDelaySec=2m
Persistent=true

[Install]
WantedBy=timers.target
EOF

  run_sudo systemctl daemon-reload
  run_sudo systemctl enable --now "$TIMER_UNIT"
  run_sudo systemctl status "$TIMER_UNIT" --no-pager || true
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
    --setup-timer)
      SETUP_TIMER=1
      shift
      ;;
    --timer-interval)
      TIMER_INTERVAL="${2:?missing value for --timer-interval}"
      DEV_POLL=0
      shift 2
      ;;
    --dev-poll)
      DEV_POLL=1
      # Development convenience only: fast polling to shorten release feedback loops.
      # For production operators, prefer --timer-interval 30m (or higher).
      TIMER_INTERVAL="$DEV_TIMER_INTERVAL"
      shift
      ;;
    --proxy-url)
      CURL_PROXY_URL="${2:?missing value for --proxy-url}"
      shift 2
      ;;
    --tor)
      USE_TOR=1
      shift
      ;;
    --tor-socks)
      USE_TOR=1
      TOR_SOCKS_ADDR="${2:?missing value for --tor-socks}"
      shift 2
      ;;
    --tor-control)
      TOR_CONTROL_ADDR="${2:?missing value for --tor-control}"
      shift 2
      ;;
    --no-tor-rotate)
      TOR_ROTATE_ON_RETRY=0
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

require_cmd curl
require_cmd grep
require_cmd sha256sum
require_cmd tar
require_cmd bash
build_curl_args
verify_tor_proxy

BASE="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest/download"
LINUX_ASSET="constitute-gateway-linux-amd64.tar.gz"
SUMS_NAME="SHA256SUMS"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

if ! download_with_retry "${BASE}/${LINUX_ASSET}" "${tmpdir}/${LINUX_ASSET}"; then
  echo "Failed to download ${LINUX_ASSET}" >&2
  exit 1
fi

if ! download_with_retry "${BASE}/${SUMS_NAME}" "${tmpdir}/${SUMS_NAME}"; then
  echo "Failed to download ${SUMS_NAME}" >&2
  exit 1
fi

if ! grep " ${LINUX_ASSET}$" "${tmpdir}/${SUMS_NAME}" | (cd "$tmpdir" && sha256sum -c -); then
  echo "Checksum verification failed for ${LINUX_ASSET}" >&2
  exit 1
fi

mkdir -p "$tmpdir/extract"
tar -C "$tmpdir/extract" -xzf "${tmpdir}/${LINUX_ASSET}"

installer=""
if [[ -f "$tmpdir/extract/scripts/linux/install-service.sh" ]]; then
  installer="$tmpdir/extract/scripts/linux/install-service.sh"
fi

if [[ ! -f "$tmpdir/extract/constitute-gateway" ]]; then
  echo "Release artifact missing constitute-gateway binary" >&2
  exit 1
fi
if [[ -z "$installer" ]]; then
  echo "Release artifact missing Linux installer script" >&2
  exit 1
fi

bash "$installer" \
  --binary "$tmpdir/extract/constitute-gateway" \
  --config-template "$tmpdir/extract/config.example.json"

echo "Install/update complete: constitute-gateway"

if [[ "$SETUP_TIMER" -eq 1 ]]; then
  require_cmd systemctl
  setup_update_timer
  echo "Auto-update timer configured: ${TIMER_UNIT} (interval: ${TIMER_INTERVAL})"
fi


