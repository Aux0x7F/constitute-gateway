#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TARGET="${1:-auto}"

case "$TARGET" in
  auto)
    if [[ "$(uname -s)" == "Linux" ]]; then
      echo "Detected Linux. Building Linux release package."
      (cd "$REPO_ROOT" && cargo build --release --features platform-linux)
      "$SCRIPT_DIR/package.sh"
    else
      echo "Unsupported OS for auto on this script."
      exit 1
    fi
    ;;
  linux)
    (cd "$REPO_ROOT" && cargo build --release --features platform-linux)
    "$SCRIPT_DIR/package.sh"
    ;;
  windows)
    echo "windows target is only supported on Windows hosts."
    exit 1
    ;;
  *)
    echo "Usage: ./scripts/linux/build.sh [auto|linux]"
    exit 1
    ;;
esac
