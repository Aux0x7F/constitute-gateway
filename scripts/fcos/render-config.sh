#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

REPO_OWNER="${REPO_OWNER:-Aux0x7F}"
REPO_NAME="${REPO_NAME:-constitute-gateway}"
TIMER_INTERVAL="${TIMER_INTERVAL:-30m}"
DEV_POLL=0
TEMPLATE="${REPO_ROOT}/infra/fcos/config.template.bu"
OUTPUT_BU="${REPO_ROOT}/infra/fcos/generated/config.bu"
OUTPUT_IGN="${REPO_ROOT}/infra/fcos/generated/config.ign"
SSH_KEY_FILE=""
SKIP_IGNITION=0

usage() {
  cat <<'EOF'
Usage: render-config.sh --ssh-key-file <path> [options]

Render FCOS Butane config from template and optionally compile to Ignition JSON.

Options:
  --ssh-key-file <path>    Required public SSH key file for the core user
  --repo-owner <owner>     GitHub owner (default: Aux0x7F)
  --repo-name <name>       GitHub repo (default: constitute-gateway)
  --timer-interval <value> Gateway update timer interval (default: 30m)
  --dev-poll               Use development polling profile in bootstrap command
  --output-bu <path>       Rendered Butane output path
  --output-ign <path>      Ignition output path
  --skip-ignition          Render Butane only
  -h, --help               Show this help
EOF
}

escape_sed() {
  printf '%s' "$1" | sed -e 's/[\\&/]/\\&/g'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-key-file)
      SSH_KEY_FILE="${2:?missing value for --ssh-key-file}"
      shift 2
      ;;
    --repo-owner)
      REPO_OWNER="${2:?missing value for --repo-owner}"
      shift 2
      ;;
    --repo-name)
      REPO_NAME="${2:?missing value for --repo-name}"
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
    --output-bu)
      OUTPUT_BU="${2:?missing value for --output-bu}"
      shift 2
      ;;
    --output-ign)
      OUTPUT_IGN="${2:?missing value for --output-ign}"
      shift 2
      ;;
    --skip-ignition)
      SKIP_IGNITION=1
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

if [[ -z "$SSH_KEY_FILE" ]]; then
  echo "--ssh-key-file is required" >&2
  usage
  exit 1
fi

if [[ ! -f "$TEMPLATE" ]]; then
  echo "Template not found: $TEMPLATE" >&2
  exit 1
fi

if [[ ! -f "$SSH_KEY_FILE" ]]; then
  echo "SSH key file not found: $SSH_KEY_FILE" >&2
  exit 1
fi

ssh_key="$(tr -d '\r\n' < "$SSH_KEY_FILE")"
if [[ -z "$ssh_key" ]]; then
  echo "SSH key file is empty: $SSH_KEY_FILE" >&2
  exit 1
fi

bootstrap_flags=(--repo-owner "$REPO_OWNER" --repo-name "$REPO_NAME")
if [[ "$DEV_POLL" -eq 1 ]]; then
  bootstrap_flags+=(--dev-poll)
else
  bootstrap_flags+=(--timer-interval "$TIMER_INTERVAL")
fi

printf -v bootstrap_flags_str '%q ' "${bootstrap_flags[@]}"
bootstrap_flags_str="${bootstrap_flags_str% }"

mkdir -p "$(dirname "$OUTPUT_BU")"

sed \
  -e "s/__SSH_PUBLIC_KEY__/$(escape_sed "$ssh_key")/g" \
  -e "s/__REPO_OWNER__/$(escape_sed "$REPO_OWNER")/g" \
  -e "s/__REPO_NAME__/$(escape_sed "$REPO_NAME")/g" \
  -e "s/__BOOTSTRAP_FLAGS__/$(escape_sed "$bootstrap_flags_str")/g" \
  "$TEMPLATE" > "$OUTPUT_BU"

echo "Rendered: $OUTPUT_BU"

if [[ "$SKIP_IGNITION" -eq 1 ]]; then
  exit 0
fi

if ! command -v butane >/dev/null 2>&1; then
  echo "butane not found; skipping ignition render" >&2
  echo "Install Butane or rerun with --skip-ignition" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT_IGN")"
butane --strict --pretty < "$OUTPUT_BU" > "$OUTPUT_IGN"
echo "Rendered: $OUTPUT_IGN"
