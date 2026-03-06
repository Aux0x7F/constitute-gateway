#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="${REPO_OWNER:-Aux0x7F}"
REPO_NAME="${REPO_NAME:-constitute-gateway}"
STREAM="${STREAM:-stable}"
ARCH="${ARCH:-x86_64}"
TIMER_INTERVAL="${TIMER_INTERVAL:-30m}"
DEV_POLL=0
DEV_SOURCE=0
DEV_SOURCE_BRANCH="main"
DEV_SOURCE_DIR=""
PAIR_IDENTITY=""
PAIR_CODE=""
PAIR_CODE_HASH=""
DOWNLOAD_DIR="${DOWNLOAD_DIR:-$PWD/constitute-gateway-fcos}"
SSH_KEY_FILE=""
DEVICE=""

usage() {
  cat <<'EOF'
Usage: prepare-auto-update-image.sh [options]

Prepare a Fedora CoreOS install image with embedded Ignition that bootstraps
constitute-gateway and enables release auto-update timer on first boot.

Options:
  --repo-owner <owner>            GitHub owner (default: Aux0x7F)
  --repo-name <name>              GitHub repo (default: constitute-gateway)
  --stream <stable|testing|next>  FCOS stream (default: stable)
  --arch <x86_64|aarch64>         FCOS architecture (default: x86_64)
  --download-dir <path>           Output directory for ISO/artifacts
  --ssh-key-file <path>           SSH public key for FCOS core user
  --timer-interval <value>        Gateway update timer interval (default: 30m)
  --dev-poll                      Development polling profile (2m)
  --dev-source                    Build gateway from source branch on host
  --dev-branch <name>             Branch for --dev-source (default: main)
  --dev-source-dir <path>         Source checkout path on host (optional)
  --pair-identity <label>         Pairing identity label for first boot enrollment
  --pair-code <code>              Pairing code for first boot enrollment
  --pair-code-hash <hash>         Pairing code hash override
  --device <path>                 Optional direct write target (destructive)
  -h, --help                      Show help

Examples:
  curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/fcos/prepare-auto-update-image.sh | bash
  curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/fcos/prepare-auto-update-image.sh | bash -s -- --download-dir "$HOME/Downloads/fcos"
EOF
}

run_sudo() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

ensure_cmd() {
  local cmd="$1"
  local pkg="$2"
  if command -v "$cmd" >/dev/null 2>&1; then
    return 0
  fi

  echo "[prep] installing missing dependency: $cmd"
  if command -v apt-get >/dev/null 2>&1; then
    run_sudo apt-get update
    run_sudo apt-get install -y "$pkg"
  elif command -v dnf >/dev/null 2>&1; then
    run_sudo dnf install -y "$pkg"
  elif command -v yum >/dev/null 2>&1; then
    run_sudo yum install -y "$pkg"
  elif command -v pacman >/dev/null 2>&1; then
    run_sudo pacman -Sy --noconfirm "$pkg"
  elif command -v zypper >/dev/null 2>&1; then
    run_sudo zypper --non-interactive install "$pkg"
  elif command -v brew >/dev/null 2>&1; then
    brew install "$pkg"
  else
    echo "[prep] no supported package manager found to install $cmd" >&2
    return 1
  fi

  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[prep] failed to install dependency: $cmd" >&2
    return 1
  fi
}

resolve_ssh_key() {
  if [[ -n "$SSH_KEY_FILE" ]]; then
    if [[ ! -f "$SSH_KEY_FILE" ]]; then
      echo "[prep] ssh key file not found: $SSH_KEY_FILE" >&2
      return 1
    fi
    echo "$SSH_KEY_FILE"
    return 0
  fi

  for candidate in "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_rsa.pub"; do
    if [[ -f "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done

  local key_base="$HOME/.ssh/constitute_gateway_bootstrap_ed25519"
  mkdir -p "$HOME/.ssh"
  if [[ ! -f "${key_base}.pub" ]]; then
    echo "[prep] no SSH pubkey found; generating ${key_base}.pub"
    ssh-keygen -t ed25519 -f "$key_base" -N "" -C "constitute-gateway-bootstrap" >/dev/null
  fi
  echo "${key_base}.pub"
}

download_raw() {
  local rel="$1"
  local out="$2"
  local url="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/main/${rel}"
  curl -fsSL "$url" -o "$out"
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
    --stream)
      STREAM="${2:?missing value for --stream}"
      shift 2
      ;;
    --arch)
      ARCH="${2:?missing value for --arch}"
      shift 2
      ;;
    --download-dir)
      DOWNLOAD_DIR="${2:?missing value for --download-dir}"
      shift 2
      ;;
    --ssh-key-file)
      SSH_KEY_FILE="${2:?missing value for --ssh-key-file}"
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
    --dev-source)
      DEV_SOURCE=1
      shift
      ;;
    --dev-branch)
      DEV_SOURCE=1
      DEV_SOURCE_BRANCH="${2:?missing value for --dev-branch}"
      shift 2
      ;;
    --dev-source-dir)
      DEV_SOURCE=1
      DEV_SOURCE_DIR="${2:?missing value for --dev-source-dir}"
      shift 2
      ;;
    --pair-identity)
      PAIR_IDENTITY="${2:?missing value for --pair-identity}"
      shift 2
      ;;
    --pair-code)
      PAIR_CODE="${2:?missing value for --pair-code}"
      shift 2
      ;;
    --pair-code-hash)
      PAIR_CODE_HASH="${2:?missing value for --pair-code-hash}"
      shift 2
      ;;
    --device)
      DEVICE="${2:?missing value for --device}"
      shift 2
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

ensure_cmd curl curl
ensure_cmd ssh-keygen openssh-client
ensure_cmd butane butane
ensure_cmd coreos-installer coreos-installer

SSH_KEY_FILE="$(resolve_ssh_key)"
mkdir -p "$DOWNLOAD_DIR"
DOWNLOAD_DIR="$(cd "$DOWNLOAD_DIR" && pwd)"

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT

mkdir -p "$TMP_ROOT/scripts/fcos" "$TMP_ROOT/infra/fcos/generated"

download_raw "scripts/fcos/render-config.sh" "$TMP_ROOT/scripts/fcos/render-config.sh"
download_raw "scripts/fcos/usb-prep-linux.sh" "$TMP_ROOT/scripts/fcos/usb-prep-linux.sh"
download_raw "infra/fcos/config.template.bu" "$TMP_ROOT/infra/fcos/config.template.bu"

chmod +x "$TMP_ROOT/scripts/fcos/render-config.sh" "$TMP_ROOT/scripts/fcos/usb-prep-linux.sh"

render_args=(
  --ssh-key-file "$SSH_KEY_FILE"
  --repo-owner "$REPO_OWNER"
  --repo-name "$REPO_NAME"
  --output-bu "$TMP_ROOT/infra/fcos/generated/config.bu"
  --output-ign "$TMP_ROOT/infra/fcos/generated/config.ign"
)

if [[ "$DEV_POLL" -eq 1 ]]; then
  render_args+=(--dev-poll)
else
  render_args+=(--timer-interval "$TIMER_INTERVAL")
fi
if [[ "$DEV_SOURCE" -eq 1 ]]; then
  render_args+=(--dev-source --dev-branch "$DEV_SOURCE_BRANCH")
  if [[ -n "$DEV_SOURCE_DIR" ]]; then
    render_args+=(--dev-source-dir "$DEV_SOURCE_DIR")
  fi
fi
if [[ -n "$PAIR_IDENTITY" ]]; then
  render_args+=(--pair-identity "$PAIR_IDENTITY")
fi
if [[ -n "$PAIR_CODE" ]]; then
  render_args+=(--pair-code "$PAIR_CODE")
fi
if [[ -n "$PAIR_CODE_HASH" ]]; then
  render_args+=(--pair-code-hash "$PAIR_CODE_HASH")
fi

echo "[prep] rendering ignition config"
bash "$TMP_ROOT/scripts/fcos/render-config.sh" "${render_args[@]}"

echo "[prep] preparing FCOS image with embedded ignition"
prep_args=(
  --stream "$STREAM"
  --arch "$ARCH"
  --download-dir "$DOWNLOAD_DIR"
  --ignition "$TMP_ROOT/infra/fcos/generated/config.ign"
)
if [[ -n "$DEVICE" ]]; then
  prep_args+=(--device "$DEVICE")
fi
bash "$TMP_ROOT/scripts/fcos/usb-prep-linux.sh" "${prep_args[@]}"

cp "$TMP_ROOT/infra/fcos/generated/config.bu" "$DOWNLOAD_DIR/constitute-gateway-config.bu"
cp "$TMP_ROOT/infra/fcos/generated/config.ign" "$DOWNLOAD_DIR/constitute-gateway-config.ign"

echo "[prep] complete"
echo "[prep] artifacts:"
echo "  - $DOWNLOAD_DIR/constitute-gateway-config.bu"
echo "  - $DOWNLOAD_DIR/constitute-gateway-config.ign"
