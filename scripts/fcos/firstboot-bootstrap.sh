#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="${REPO_OWNER:-Aux0x7F}"
REPO_NAME="${REPO_NAME:-constitute-gateway}"
NETWORK_CHECK_URL="${NETWORK_CHECK_URL:-https://github.com}"
NETWORK_TIMEOUT_SECS="${NETWORK_TIMEOUT_SECS:-300}"
TIMER_INTERVAL="${TIMER_INTERVAL:-30m}"
DEV_POLL=0
SETUP_TIMER=1
SKIP_HARDENING=0
UDP_PORT="${UDP_PORT:-}"
WS_PORT="${WS_PORT:-}"
WSS_PORT="${WSS_PORT:-}"
CURL_PROXY_URL="${CURL_PROXY_URL:-}"
USE_TOR=0
TOR_SOCKS_ADDR="${TOR_SOCKS_ADDR:-127.0.0.1:9050}"
TOR_CONTROL_ADDR="${TOR_CONTROL_ADDR:-127.0.0.1:9051}"
TOR_ROTATE_ON_RETRY=1

usage() {
  cat <<'EOF'
Usage: fcos-firstboot-bootstrap.sh [options]

Network-gated first-boot bootstrap for FCOS hosts.

Options:
  --repo-owner <owner>            GitHub owner (default: Aux0x7F)
  --repo-name <name>              GitHub repo (default: constitute-gateway)
  --network-check-url <url>       URL used to verify outbound network (default: https://github.com)
  --network-timeout-secs <secs>   Max wait for network before failing (default: 300)
  --timer-interval <value>        Auto-update timer interval (default: 30m)
  --dev-poll                      Development polling profile (2m)
  --no-timer                      Skip timer setup
  --skip-hardening                Skip hardening script execution
  --udp-port <port>               UDP port to allow when hardening
  --ws-port <port>                WS TCP port to allow when hardening
  --wss-port <port>               WSS TCP port to allow when hardening
  --proxy-url <url>               Use HTTP(S) proxy for remote fetches
  --tor                           Use Tor SOCKS egress for remote fetches
  --tor-socks <host:port>         Tor SOCKS endpoint (default: 127.0.0.1:9050)
  --tor-control <host:port>       Tor control endpoint for optional NEWNYM (default: 127.0.0.1:9051)
  --no-tor-rotate                 Disable NEWNYM attempt on retry
  -h, --help                      Show this help

Example:
  curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/fcos/firstboot-bootstrap.sh | sudo bash -s -- --dev-poll
EOF
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
}

build_curl_args() {
  CURL_ARGS=(-fsSL --retry 3 --retry-delay 1)
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

wait_for_network() {
  local started now elapsed
  started="$(date +%s)"

  while true; do
    if curl "${CURL_ARGS[@]}" --max-time 8 -I "$NETWORK_CHECK_URL" >/dev/null 2>&1; then
      echo "[bootstrap] network reachable: $NETWORK_CHECK_URL"
      return 0
    fi

    now="$(date +%s)"
    elapsed="$((now - started))"
    if (( elapsed >= NETWORK_TIMEOUT_SECS )); then
      echo "[bootstrap] network not reachable within ${NETWORK_TIMEOUT_SECS}s" >&2
      return 1
    fi

    sleep 5
  done
}

run_remote_script() {
  local script_path="$1"
  shift
  local url="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/main/${script_path}"
  local tmp
  tmp="$(mktemp)"
  if ! download_with_retry "$url" "$tmp"; then
    rm -f "$tmp"
    echo "[bootstrap] failed to fetch script: $script_path" >&2
    return 1
  fi
  chmod 0755 "$tmp"
  bash "$tmp" "$@"
  rm -f "$tmp"
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
    --network-check-url)
      NETWORK_CHECK_URL="${2:?missing value for --network-check-url}"
      shift 2
      ;;
    --network-timeout-secs)
      NETWORK_TIMEOUT_SECS="${2:?missing value for --network-timeout-secs}"
      shift 2
      ;;
    --timer-interval)
      TIMER_INTERVAL="${2:?missing value for --timer-interval}"
      shift 2
      ;;
    --dev-poll)
      DEV_POLL=1
      shift
      ;;
    --no-timer)
      SETUP_TIMER=0
      shift
      ;;
    --skip-hardening)
      SKIP_HARDENING=1
      shift
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

require_cmd bash
require_cmd curl
build_curl_args
wait_for_network

if [[ "$SKIP_HARDENING" -eq 0 ]]; then
  harden_args=(--apply)
  if [[ -n "$UDP_PORT" ]]; then harden_args+=(--udp "$UDP_PORT"); fi
  if [[ -n "$WS_PORT" ]]; then harden_args+=(--ws "$WS_PORT"); fi
  if [[ -n "$WSS_PORT" ]]; then harden_args+=(--wss "$WSS_PORT"); fi

  echo "[bootstrap] applying host hardening"
  run_remote_script "scripts/linux/harden-host.sh" "${harden_args[@]}"
fi

install_args=(--repo-owner "$REPO_OWNER" --repo-name "$REPO_NAME")
if [[ "$SETUP_TIMER" -eq 1 ]]; then
  install_args+=(--setup-timer)
fi
if [[ "$DEV_POLL" -eq 1 ]]; then
  install_args+=(--dev-poll)
else
  install_args+=(--timer-interval "$TIMER_INTERVAL")
fi
if [[ -n "$CURL_PROXY_URL" ]]; then
  install_args+=(--proxy-url "$CURL_PROXY_URL")
fi
if [[ "$USE_TOR" -eq 1 ]]; then
  install_args+=(--tor --tor-socks "$TOR_SOCKS_ADDR" --tor-control "$TOR_CONTROL_ADDR")
fi
if [[ "$TOR_ROTATE_ON_RETRY" -eq 0 ]]; then
  install_args+=(--no-tor-rotate)
fi

echo "[bootstrap] installing/updating constitute-gateway"
run_remote_script "scripts/linux/install-latest.sh" "${install_args[@]}"

echo "[bootstrap] complete"

