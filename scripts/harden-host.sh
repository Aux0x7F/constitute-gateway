#!/usr/bin/env bash
set -euo pipefail

APPLY=0
UDP_PORT=""
WS_PORT=""
WSS_PORT=""

usage() {
  cat <<'EOF'
Usage: harden-host.sh [--apply] [--udp PORT] [--ws PORT] [--wss PORT]

Audit host hardening posture and optionally apply minimal, safe changes.

Defaults:
  - Audit-only (no changes) unless --apply is set.
  - Only adjusts UFW rules if UFW is already active.
  - Does not enable/disable services or overwrite existing configs.

Examples:
  ./scripts/harden-host.sh
  ./scripts/harden-host.sh --apply --udp 4040 --ws 7447 --wss 7448
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=1; shift ;;
    --udp) UDP_PORT="${2:-}"; shift 2 ;;
    --ws) WS_PORT="${2:-}"; shift 2 ;;
    --wss) WSS_PORT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1"; usage; exit 1 ;;
  esac
done

log() { echo "[harden] $*"; }

ufw_exists=0
if command -v ufw >/dev/null 2>&1; then
  ufw_exists=1
else
  log "ufw not installed"
fi

if [[ "$ufw_exists" -eq 1 ]]; then
  ufw_status="$(ufw status 2>/dev/null | head -n 1 || true)"
  log "ufw status: ${ufw_status:-unknown}"
  if [[ "$ufw_status" =~ active ]]; then
    log "ufw is active"
    if [[ "$APPLY" -eq 1 ]]; then
      if [[ -n "$UDP_PORT" ]]; then
        if ! ufw status | grep -q "${UDP_PORT}/udp"; then
          log "allowing UDP ${UDP_PORT} (swarm)"
          ufw allow "${UDP_PORT}/udp" comment "constitute-gateway swarm" >/dev/null
        else
          log "udp ${UDP_PORT} already allowed"
        fi
      fi
      if [[ -n "$WS_PORT" ]]; then
        if ! ufw status | grep -q "${WS_PORT}/tcp"; then
          log "allowing TCP ${WS_PORT} (relay ws)"
          ufw allow "${WS_PORT}/tcp" comment "constitute-gateway relay ws" >/dev/null
        else
          log "tcp ${WS_PORT} already allowed"
        fi
      fi
      if [[ -n "$WSS_PORT" ]]; then
        if ! ufw status | grep -q "${WSS_PORT}/tcp"; then
          log "allowing TCP ${WSS_PORT} (relay wss)"
          ufw allow "${WSS_PORT}/tcp" comment "constitute-gateway relay wss" >/dev/null
        else
          log "tcp ${WSS_PORT} already allowed"
        fi
      fi
    else
      log "ufw active; run with --apply to add allow rules for gateway ports"
    fi
  else
    log "ufw installed but inactive (no changes). Consider enabling ufw and allowing gateway ports."
  fi
fi

if command -v fail2ban-client >/dev/null 2>&1; then
  if systemctl is-active --quiet fail2ban; then
    log "fail2ban is active"
    if fail2ban-client status sshd >/dev/null 2>&1; then
      log "fail2ban sshd jail enabled"
    else
      log "fail2ban sshd jail not detected"
    fi
  else
    log "fail2ban installed but inactive (no changes)"
  fi
else
  log "fail2ban not installed"
fi

log "done"
