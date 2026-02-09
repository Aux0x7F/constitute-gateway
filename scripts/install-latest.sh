#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="${REPO_OWNER:-Aux0x7F}"
REPO_NAME="${REPO_NAME:-constitute-gateway}"
BASE="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest/download"
SNAP_NAME="constitute-gateway-linux-amd64.snap"
SUMS_NAME="SHA256SUMS"

curl -L -o "$SNAP_NAME" "${BASE}/${SNAP_NAME}"
curl -L -o "$SUMS_NAME" "${BASE}/${SUMS_NAME}"

grep "${SNAP_NAME}" "$SUMS_NAME" | sha256sum -c -

sudo snap install --dangerous "./${SNAP_NAME}"
