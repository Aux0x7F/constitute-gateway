#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="${REPO_OWNER:-Aux0x7F}"
REPO_NAME="${REPO_NAME:-constitute-gateway}"
BRANCH="${BRANCH:-main}"
REPO_DIR="${REPO_DIR:-$HOME/constitute-gateway}"
SKIP_PULL=0
SKIP_PREREQS=0
NO_START=0
PAIR_IDENTITY=""
PAIR_GENERATE=0

usage() {
  cat <<'EOF'
Usage: install-dev-local.sh [options]

Clone/update source, build gateway locally, then install/update Linux service.

Options:
  --repo-owner <owner>       GitHub owner (default: Aux0x7F)
  --repo-name <name>         GitHub repo (default: constitute-gateway)
  --branch <name>            Branch to build (default: main)
  --repo-dir <path>          Local checkout path (default: $HOME/constitute-gateway)
  --skip-pull                Do not fetch/reset branch before build
  --skip-prereqs             Do not auto-install prerequisites
  --pair-identity <label>    Identity label for pairing bootstrap
  --pair-generate            Generate one-time pairing code when pairing is needed
  --no-start                 Install service but do not start/restart it
  -h, --help                 Show help

Example:
  curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-gateway/main/scripts/linux/install-dev-local.sh | bash
EOF
}

run_sudo() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

detect_pkg_manager() {
  if command -v dnf >/dev/null 2>&1; then
    echo dnf
  elif command -v apt-get >/dev/null 2>&1; then
    echo apt
  else
    echo none
  fi
}

install_prereqs() {
  local pm
  pm="$(detect_pkg_manager)"
  case "$pm" in
    dnf)
      run_sudo dnf -y install git curl gcc make pkg-config python3
      ;;
    apt)
      run_sudo apt-get update
      run_sudo apt-get install -y git curl build-essential pkg-config python3
      ;;
    none)
      echo "No supported package manager found for prerequisite install." >&2
      echo "Install manually: git curl gcc make pkg-config python3" >&2
      ;;
  esac
}

ensure_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
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
    --branch)
      BRANCH="${2:?missing value for --branch}"
      shift 2
      ;;
    --repo-dir)
      REPO_DIR="${2:?missing value for --repo-dir}"
      shift 2
      ;;
    --skip-pull)
      SKIP_PULL=1
      shift
      ;;
    --skip-prereqs)
      SKIP_PREREQS=1
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

if [[ "$SKIP_PREREQS" -eq 0 ]]; then
  install_prereqs
fi

ensure_cmd git
ensure_cmd curl
ensure_cmd python3

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found; installing rustup toolchain..."
  curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal
fi

if [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi

ensure_cmd cargo

mkdir -p "$(dirname "$REPO_DIR")"
if [[ ! -d "$REPO_DIR/.git" ]]; then
  git clone "https://github.com/${REPO_OWNER}/${REPO_NAME}.git" "$REPO_DIR"
fi

cd "$REPO_DIR"

if [[ "$SKIP_PULL" -eq 0 ]]; then
  git fetch --prune origin
  git checkout "$BRANCH"
  git reset --hard "origin/$BRANCH"
fi

cargo build --release --locked --features platform-linux

install_args=(
  --binary "$REPO_DIR/target/release/constitute-gateway"
  --config-template "$REPO_DIR/config.example.json"
)

if [[ -n "$PAIR_IDENTITY" ]]; then
  install_args+=(--pair-identity "$PAIR_IDENTITY")
fi
if [[ "$PAIR_GENERATE" -eq 1 ]]; then
  install_args+=(--pair-generate)
fi
if [[ "$NO_START" -eq 1 ]]; then
  install_args+=(--no-start)
fi

bash "$REPO_DIR/scripts/linux/install-service.sh" "${install_args[@]}"

run_sudo env CFG_PATH="/etc/constitute-gateway/config.json" CFG_CHANNEL="dev" CFG_TRACK="local" CFG_BRANCH="$BRANCH" python3 - <<'PY'
import json
import os
from pathlib import Path

path = Path(os.environ.get('CFG_PATH', '/etc/constitute-gateway/config.json'))
if not path.exists():
    raise SystemExit(0)

cfg = json.loads(path.read_text(encoding='utf-8'))
cfg['release_channel'] = os.environ.get('CFG_CHANNEL', 'dev').strip() or 'dev'
cfg['release_track'] = os.environ.get('CFG_TRACK', 'local').strip() or 'local'
cfg['release_branch'] = os.environ.get('CFG_BRANCH', '').strip()
path.write_text(json.dumps(cfg, indent=2) + '\n', encoding='utf-8')
PY

echo "Dev install complete: $REPO_DIR (branch: $BRANCH)"