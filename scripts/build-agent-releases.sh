#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT_DIR="$ROOT_DIR/agent"
RELEASE_ROOT="${RELEASE_ROOT:-$ROOT_DIR/releases}"
OUT_DIR="${OUT_DIR:-$RELEASE_ROOT/agent}"

version_from_source() {
  local src="$AGENT_DIR/internal/app.go"
  if [[ -f "$src" ]]; then
    awk -F'"' '/^[[:space:]]*version[[:space:]]*=/{print $2; exit}' "$src" || true
  fi
}

VERSION="${VERSION:-$(version_from_source)}"
VERSION="${VERSION:-dev}"

COMMON_FLAGS=(-trimpath -buildvcs=false -ldflags "-s -w")

WINDOWS_DIR="$OUT_DIR/windows_amd64"
CENTOS_DIR="$OUT_DIR/centos7.9_amd64"

mkdir -p "$WINDOWS_DIR" "$CENTOS_DIR" "$RELEASE_ROOT"

echo "[build] windows amd64 (portable, CGO_ENABLED=0)"
(cd "$AGENT_DIR" && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build "${COMMON_FLAGS[@]}" -o "$WINDOWS_DIR/d-eyes.exe" ./cmd/agent)

echo "[build] centos 7.9 amd64 (portable, CGO_ENABLED=0)"
(cd "$AGENT_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build "${COMMON_FLAGS[@]}" -o "$CENTOS_DIR/d-eyes" ./cmd/agent)
chmod +x "$CENTOS_DIR/d-eyes" || true

WIN_ZIP="$RELEASE_ROOT/d-eyes-agent_${VERSION}_windows_amd64.zip"
LINUX_TGZ="$RELEASE_ROOT/d-eyes-agent_${VERSION}_centos7.9_amd64.tar.gz"

echo "[pack] $WIN_ZIP"
rm -f "$WIN_ZIP"
(cd "$WINDOWS_DIR" && zip -9 -X "$WIN_ZIP" "d-eyes.exe" >/dev/null)

echo "[pack] $LINUX_TGZ"
rm -f "$LINUX_TGZ"
(cd "$CENTOS_DIR" && tar -czf "$LINUX_TGZ" "d-eyes")

echo "[hash] $RELEASE_ROOT/SHA256SUMS"
(cd "$RELEASE_ROOT" && sha256sum "$(basename "$WIN_ZIP")" "$(basename "$LINUX_TGZ")" > SHA256SUMS)

echo
echo "Artifacts:"
echo "  - $WIN_ZIP"
echo "  - $LINUX_TGZ"
echo "  - $RELEASE_ROOT/SHA256SUMS"
