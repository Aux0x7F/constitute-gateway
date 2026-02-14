#!/usr/bin/env bash
set -euo pipefail

STREAM="${STREAM:-stable}"
ARCH="${ARCH:-x86_64}"
DEVICE=""
ISO_PATH=""
DOWNLOAD_DIR="${DOWNLOAD_DIR:-infra/fcos/generated}"
IGNITION_PATH=""

usage() {
  cat <<'EOF'
Usage: usb-prep-linux.sh [options]

Fetch and verify a Fedora CoreOS installer image (Ventoy-friendly by default).
Optionally write the image directly to a USB device.

Options:
  --device <path>                 Optional block device to write (destructive)
  --iso <path>                    Existing FCOS ISO path (skip download)
  --stream <stable|testing|next>  FCOS stream for download (default: stable)
  --arch <x86_64|aarch64>         FCOS architecture (default: x86_64)
  --download-dir <path>           Download/output dir (default: infra/fcos/generated)
  --ignition <path>               Optional ignition file to embed into the ISO
  -h, --help                      Show help

Notes:
  - Without --device, this script only downloads/verifies and outputs the ISO path.
  - With --device, this script requires root and writes the ISO to that device.
  - Ventoy users should run without --device and copy the ISO to Ventoy storage.
EOF
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --device)
      DEVICE="${2:?missing value for --device}"
      shift 2
      ;;
    --iso)
      ISO_PATH="${2:?missing value for --iso}"
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
    --ignition)
      IGNITION_PATH="${2:?missing value for --ignition}"
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

mkdir -p "$DOWNLOAD_DIR"

if [[ -z "$ISO_PATH" ]]; then
  require_cmd coreos-installer
  echo "Downloading FCOS ISO (stream=$STREAM arch=$ARCH)..."
  coreos-installer download \
    --stream "$STREAM" \
    --architecture "$ARCH" \
    --platform metal \
    --format iso \
    --directory "$DOWNLOAD_DIR"
  ISO_PATH="$(ls -1 "$DOWNLOAD_DIR"/*-live-iso*.iso 2>/dev/null | sort | tail -n 1)"
  if [[ -z "$ISO_PATH" ]]; then
    echo "Unable to locate downloaded FCOS ISO in $DOWNLOAD_DIR" >&2
    exit 1
  fi
fi

if [[ ! -f "$ISO_PATH" ]]; then
  echo "ISO not found: $ISO_PATH" >&2
  exit 1
fi

WORK_ISO="$ISO_PATH"
if [[ -n "$IGNITION_PATH" ]]; then
  require_cmd coreos-installer
  if [[ ! -f "$IGNITION_PATH" ]]; then
    echo "Ignition file not found: $IGNITION_PATH" >&2
    exit 1
  fi
  WORK_ISO="${DOWNLOAD_DIR}/$(basename "$ISO_PATH" .iso)-with-ignition.iso"
  cp "$ISO_PATH" "$WORK_ISO"
  coreos-installer iso ignition embed -i "$IGNITION_PATH" "$WORK_ISO"
fi

sha="$(sha256sum "$WORK_ISO" | awk '{print $1}')"
echo "Image ready: $WORK_ISO"
echo "SHA256: $sha"

if [[ -z "$DEVICE" ]]; then
  echo "No --device provided; skipping raw USB write."
  echo "Use this image with Ventoy or pass --device /dev/sdX for direct write."
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root (or with sudo) to write USB media." >&2
  exit 1
fi

echo "About to overwrite $DEVICE with $(basename "$WORK_ISO")"
read -r -p "Type YES to continue: " confirm
if [[ "$confirm" != "YES" ]]; then
  echo "Aborted."
  exit 1
fi

dd if="$WORK_ISO" of="$DEVICE" bs=4M conv=fsync status=progress
sync
echo "USB ready: $DEVICE"
