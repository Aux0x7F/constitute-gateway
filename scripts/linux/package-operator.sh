#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

BIN_PATH="${BIN_PATH:-$REPO_ROOT/target/release/constitute-operator}"
ARTIFACT_NAME="${ARTIFACT_NAME:-constitute-operator-linux-amd64.tar.gz}"
STAGE_DIR="${STAGE_DIR:-$REPO_ROOT/dist/operator-linux}"

artifact_path="$ARTIFACT_NAME"
if [[ "$artifact_path" != /* ]]; then
  artifact_path="$REPO_ROOT/$artifact_path"
fi

if [[ ! -f "$BIN_PATH" ]]; then
  echo "Binary not found: $BIN_PATH" >&2
  echo "Build first: cargo build --release --bin constitute-operator --features platform-linux" >&2
  exit 1
fi

rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

install -m 0755 "$BIN_PATH" "$STAGE_DIR/constitute-operator"
cp -R "$REPO_ROOT/scripts" "$STAGE_DIR/scripts"
find "$STAGE_DIR/scripts" -type f -name "*.sh" -exec chmod 0755 {} \;

cat > "$STAGE_DIR/README-operator.txt" <<'EOF'
Constitute Operator Utility

Linux usage:
  ./constitute-operator linux-service

Windows usage (from Windows package):
  constitute-operator.exe windows-service

Default mode uses releases/latest.
EOF

rm -f "$artifact_path"
tar -C "$STAGE_DIR" -czf "$artifact_path" .

echo "Packaged: $artifact_path"