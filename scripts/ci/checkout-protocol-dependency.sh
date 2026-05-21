#!/usr/bin/env bash
set -euo pipefail

repo_url="${CONSTITUTE_PROTOCOL_REPO:-https://github.com/Aux0x7F/constitute-protocol.git}"
target="${CONSTITUTE_PROTOCOL_PATH:-../constitute-protocol}"
ref="${CONSTITUTE_PROTOCOL_REF:-${GITHUB_HEAD_REF:-${GITHUB_REF_NAME:-main}}}"
fallback_ref="${CONSTITUTE_PROTOCOL_FALLBACK_REF:-main}"

if [ -d "$target/.git" ] && [ "${GITHUB_ACTIONS:-}" != "true" ] && [ "${CONSTITUTE_PROTOCOL_ALLOW_REPLACE:-}" != "1" ]; then
  echo "Refusing to replace existing git checkout at '$target' outside GitHub Actions." >&2
  echo "Set CONSTITUTE_PROTOCOL_PATH to an ignored temp path or CONSTITUTE_PROTOCOL_ALLOW_REPLACE=1." >&2
  exit 2
fi

rm -rf "$target"

if git ls-remote --exit-code --heads "$repo_url" "$ref" >/dev/null 2>&1; then
  git clone --depth 1 --branch "$ref" "$repo_url" "$target"
elif [ "$ref" != "$fallback_ref" ] && git ls-remote --exit-code --heads "$repo_url" "$fallback_ref" >/dev/null 2>&1; then
  git clone --depth 1 --branch "$fallback_ref" "$repo_url" "$target"
else
  echo "No constitute-protocol branch found for '$ref' or fallback '$fallback_ref'." >&2
  exit 1
fi
