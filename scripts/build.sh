#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-auto}"

case "$TARGET" in
  auto)
    if [[ "$(uname -s)" == "Linux" ]]; then
      echo "Detected Linux. Building snap."
      make snap
    else
      echo "Unsupported OS for auto on this script."
      exit 1
    fi
    ;;
  snap)
    make snap
    ;;
  windows)
    echo "windows target is only supported on Windows hosts."
    exit 1
    ;;
  *)
    echo "Usage: ./scripts/build.sh [auto|snap]"
    exit 1
    ;;
esac
