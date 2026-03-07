#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="${SERVICE_NAME:-constitute-gateway}"
SERVICE_UNIT="${SERVICE_NAME}.service"

run_sudo() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

has_systemd() {
  command -v systemctl >/dev/null 2>&1
}

service_exists() {
  has_systemd || return 1
  systemctl list-unit-files "$SERVICE_UNIT" --no-legend 2>/dev/null | awk '{print $1}' | grep -Fxq "$SERVICE_UNIT"
}

service_status_text() {
  if ! has_systemd; then
    echo "NoSystemd"
    return
  fi
  if ! service_exists; then
    echo "NotInstalled"
    return
  fi
  if systemctl is-active --quiet "$SERVICE_UNIT"; then
    echo "Running"
  else
    echo "Stopped"
  fi
}

service_action() {
  local action="$1"
  if ! has_systemd; then
    echo "systemctl not available on this host" >&2
    return 1
  fi
  if ! service_exists; then
    echo "Service not installed: $SERVICE_UNIT" >&2
    return 1
  fi
  case "$action" in
    status)
      systemctl status "$SERVICE_UNIT" --no-pager || true
      ;;
    start)
      run_sudo systemctl start "$SERVICE_UNIT"
      ;;
    stop)
      run_sudo systemctl stop "$SERVICE_UNIT"
      ;;
    restart)
      run_sudo systemctl restart "$SERVICE_UNIT"
      ;;
    uninstall)
      run_sudo systemctl disable --now "$SERVICE_UNIT" || true
      run_sudo rm -f "/etc/systemd/system/$SERVICE_UNIT"
      run_sudo systemctl daemon-reload
      echo "Service removed from systemd: $SERVICE_UNIT"
      echo "Binary/config/data were not deleted."
      ;;
    *)
      echo "Unknown service action: $action" >&2
      return 1
      ;;
  esac
}

run_cmd() {
  local cmd="$1"
  shift
  case "$cmd" in
    build-linux) "$SCRIPT_DIR/linux/build.sh" linux "$@" ;;
    install-linux) "$SCRIPT_DIR/linux/install-latest.sh" "$@" ;;
    install-linux-fast-poll) "$SCRIPT_DIR/linux/install-latest.sh" --setup-timer --dev-poll "$@" ;;
    deploy-linux-opinionated) "$SCRIPT_DIR/linux/deploy-opinionated.sh" "$@" ;;
    harden-audit) "$SCRIPT_DIR/linux/harden-host.sh" "$@" ;;
    harden-apply) "$SCRIPT_DIR/linux/harden-host.sh" --apply "$@" ;;
    systemd-override) "$SCRIPT_DIR/linux/install-systemd-override.sh" "$@" ;;
    service-status) service_action status ;;
    service-start) service_action start ;;
    service-stop) service_action stop ;;
    service-restart) service_action restart ;;
    service-uninstall) service_action uninstall ;;
    help)
      cat <<'EOF'
Usage: scripts/run.sh [command] [args]

Commands:
  build-linux
  install-linux
  install-linux-fast-poll
  deploy-linux-opinionated
  harden-audit
  harden-apply
  systemd-override
  service-status
  service-start
  service-stop
  service-restart
  service-uninstall
EOF
      ;;
    *)
      echo "Unknown command: $cmd" >&2
      exit 1
      ;;
  esac
}

show_build_menu() {
  while true; do
    echo ""
    echo "Build Menu"
    echo "1) Build Linux package"
    echo "0) Back"
    read -r -p "Select build option: " bopt
    case "$bopt" in
      1) run_cmd build-linux; return ;;
      0) return ;;
      *) echo "Invalid option" ;;
    esac
  done
}

if [[ $# -gt 0 ]]; then
  run_cmd "$@"
  exit 0
fi

svc_state="$(service_status_text)"

echo "Constitute Gateway Script Runner (Linux)"
echo "Service '$SERVICE_UNIT': $svc_state"
echo "1) Build"
echo "2) Install/update from latest release"
echo "3) Install/update + fast dev poll timer"
echo "4) Host hardening audit"
echo "5) Host hardening apply"
echo "6) Install systemd CPU override"
if [[ "$svc_state" != "NoSystemd" ]]; then
  if [[ "$svc_state" == "NotInstalled" ]]; then
    echo "7) Service install/update (latest release)"
  else
    echo "7) Service status"
    echo "8) Service start"
    echo "9) Service stop"
    echo "10) Service restart"
    echo "11) Service uninstall"
  fi
fi
echo "0) Exit"
read -r -p "Select option: " opt

case "$opt" in
  1) show_build_menu ;;
  2) run_cmd install-linux ;;
  3) run_cmd install-linux-fast-poll ;;
  4) run_cmd harden-audit ;;
  5)
    read -r -p "UDP port (blank skip): " udp
    read -r -p "WS port (blank skip): " ws
    read -r -p "WSS port (blank skip): " wss
    args=()
    [[ -n "$udp" ]] && args+=(--udp "$udp")
    [[ -n "$ws" ]] && args+=(--ws "$ws")
    [[ -n "$wss" ]] && args+=(--wss "$wss")
    run_cmd harden-apply "${args[@]}"
    ;;
  6) run_cmd systemd-override --restart ;;
  7)
    if [[ "$svc_state" == "NotInstalled" ]]; then
      run_cmd install-linux
    elif [[ "$svc_state" != "NoSystemd" ]]; then
      run_cmd service-status
    else
      echo "Invalid option"
      exit 1
    fi
    ;;
  8)
    if [[ "$svc_state" != "NotInstalled" && "$svc_state" != "NoSystemd" ]]; then
      run_cmd service-start
    else
      echo "Invalid option"
      exit 1
    fi
    ;;
  9)
    if [[ "$svc_state" != "NotInstalled" && "$svc_state" != "NoSystemd" ]]; then
      run_cmd service-stop
    else
      echo "Invalid option"
      exit 1
    fi
    ;;
  10)
    if [[ "$svc_state" != "NotInstalled" && "$svc_state" != "NoSystemd" ]]; then
      run_cmd service-restart
    else
      echo "Invalid option"
      exit 1
    fi
    ;;
  11)
    if [[ "$svc_state" != "NotInstalled" && "$svc_state" != "NoSystemd" ]]; then
      read -r -p "Type YES to uninstall $SERVICE_UNIT: " confirm
      if [[ "$confirm" == "YES" ]]; then
        run_cmd service-uninstall
      else
        echo "Uninstall aborted."
      fi
    else
      echo "Invalid option"
      exit 1
    fi
    ;;
  0) exit 0 ;;
  *) echo "Invalid option"; exit 1 ;;
esac