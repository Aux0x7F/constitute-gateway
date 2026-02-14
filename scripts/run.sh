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
    deploy-linux-opinionated) "$SCRIPT_DIR/linux/deploy-opinionated.sh" "$@" ;;
    install-linux-dev) "$SCRIPT_DIR/linux/install-latest.sh" --setup-timer --dev-poll "$@" ;;
    render-fcos) "$SCRIPT_DIR/fcos/render-config.sh" "$@" ;;
    bootstrap-fcos) "$SCRIPT_DIR/fcos/firstboot-bootstrap.sh" "$@" ;;
    harden-audit) "$SCRIPT_DIR/linux/harden-host.sh" "$@" ;;
    harden-apply) "$SCRIPT_DIR/linux/harden-host.sh" --apply "$@" ;;
    systemd-override) "$SCRIPT_DIR/linux/install-systemd-override.sh" "$@" ;;
    fcos-download-base-image) "$SCRIPT_DIR/fcos/usb-prep-linux.sh" "$@" ;;
    fcos-full-prep)
      local default_ign="$SCRIPT_DIR/../infra/fcos/generated/config.ign"
      if [[ " $* " != *" --ignition "* && -f "$default_ign" ]]; then
        "$SCRIPT_DIR/fcos/usb-prep-linux.sh" --ignition "$default_ign" "$@"
      else
        "$SCRIPT_DIR/fcos/usb-prep-linux.sh" "$@"
      fi
      ;;
    service-status) service_action status ;;
    service-start) service_action start ;;
    service-stop) service_action stop ;;
    service-restart) service_action restart ;;
    service-uninstall) service_action uninstall ;;
    # Compatibility aliases (kept for existing automation).
    fcos-image-only) "$SCRIPT_DIR/fcos/usb-prep-linux.sh" "$@" ;;
    image-prep) "$SCRIPT_DIR/fcos/usb-prep-linux.sh" "$@" ;;
    help)
      cat <<'EOF'
Usage: scripts/run.sh [command] [args]

Commands:
  build-linux
  install-linux
  deploy-linux-opinionated
  install-linux-dev
  render-fcos
  bootstrap-fcos
  harden-audit
  harden-apply
  systemd-override
  fcos-download-base-image
  fcos-full-prep
  service-status
  service-start
  service-stop
  service-restart
  service-uninstall

Compatibility aliases:
  fcos-image-only
  image-prep
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

echo "Constitute Gateway Script Runner (Linux/FCOS)"
echo "Service '$SERVICE_UNIT': $svc_state"
echo "1) Build"
if [[ "$svc_state" == "NotInstalled" || "$svc_state" == "NoSystemd" ]]; then
  echo "2) Install gateway (latest release)"
else
  echo "2) Update gateway (latest release)"
fi
echo "3) Install/update gateway (dev poll)"
echo "4) Render FCOS config"
echo "5) Run FCOS firstboot bootstrap on this host"
echo "6) Host hardening audit"
echo "7) Host hardening apply"
echo "8) Install systemd CPU override"
if [[ "$svc_state" != "NoSystemd" ]]; then
  if [[ "$svc_state" == "NotInstalled" ]]; then
    echo "9) Service install/update (latest release)"
  else
    echo "9) Service status"
    echo "10) Service start"
    echo "11) Service stop"
    echo "12) Service restart"
    echo "13) Service uninstall"
  fi
fi
echo "14) Download upstream FCOS base ISO only (no Ignition, no write)"
echo "15) FCOS full prep (default Ignition if present; optional direct write)"
echo "0) Exit"
read -r -p "Select option: " opt

case "$opt" in
  1) show_build_menu ;;
  2) run_cmd install-linux ;;
  3) run_cmd install-linux-dev ;;
  4) run_cmd render-fcos ;;
  5) run_cmd bootstrap-fcos ;;
  6) run_cmd harden-audit ;;
  7)
    read -r -p "UDP port (blank skip): " udp
    read -r -p "WS port (blank skip): " ws
    read -r -p "WSS port (blank skip): " wss
    args=()
    [[ -n "$udp" ]] && args+=(--udp "$udp")
    [[ -n "$ws" ]] && args+=(--ws "$ws")
    [[ -n "$wss" ]] && args+=(--wss "$wss")
    run_cmd harden-apply "${args[@]}"
    ;;
  8) run_cmd systemd-override --restart ;;
  9)
    if [[ "$svc_state" == "NotInstalled" ]]; then
      run_cmd install-linux
    elif [[ "$svc_state" != "NoSystemd" ]]; then
      run_cmd service-status
    else
      echo "Invalid option"
      exit 1
    fi
    ;;
  10)
    if [[ "$svc_state" != "NotInstalled" && "$svc_state" != "NoSystemd" ]]; then
      run_cmd service-start
    else
      echo "Invalid option"
      exit 1
    fi
    ;;
  11)
    if [[ "$svc_state" != "NotInstalled" && "$svc_state" != "NoSystemd" ]]; then
      run_cmd service-stop
    else
      echo "Invalid option"
      exit 1
    fi
    ;;
  12)
    if [[ "$svc_state" != "NotInstalled" && "$svc_state" != "NoSystemd" ]]; then
      run_cmd service-restart
    else
      echo "Invalid option"
      exit 1
    fi
    ;;
  13)
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
  14) run_cmd fcos-download-base-image ;;
  15)
    read -r -p "Ignition path override (blank = default if present): " ign
    read -r -p "Write directly to USB device? (blank for image-only): " dev
    args=()
    [[ -n "$ign" ]] && args+=(--ignition "$ign")
    [[ -n "$dev" ]] && args+=(--device "$dev")
    run_cmd fcos-full-prep "${args[@]}"
    ;;
  0) exit 0 ;;
  *) echo "Invalid option"; exit 1 ;;
esac
