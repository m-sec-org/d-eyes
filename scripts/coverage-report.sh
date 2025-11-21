#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )/.." && pwd)"
cd "$ROOT_DIR"

COVER_THRESHOLD_AGENT=${COVER_THRESHOLD_AGENT:-100}
COVER_THRESHOLD_SERVER=${COVER_THRESHOLD_SERVER:-0}

mkdir -p coverage

run_cover() {
  local dir="$1"
  local name="$2"
  local threshold="$3"
  local cover_file="$ROOT_DIR/coverage/${name}.out"
  echo "[coverage] ${name}"
  (cd "$dir" && go test -coverpkg=./... -covermode=count -coverprofile="$cover_file" ./...)
  (cd "$dir" && go tool cover -func "$cover_file" | tail -n 1)
  local total
  total=$(cd "$dir" && go tool cover -func "$cover_file" | tail -n 1 | awk '{print substr($3, 1, length($3)-1)}')
  if [[ -n "$threshold" && "$threshold" != "0" ]]; then
    awk -v val="$total" -v thr="$threshold" 'BEGIN { if (val+0 < thr+0) exit 1 }' || {
      echo "coverage for ${name} ${total}% is below threshold ${threshold}%" >&2
      exit 1
    }
  fi
}

run_cover agent "agent" "$COVER_THRESHOLD_AGENT"
run_cover server "server" "$COVER_THRESHOLD_SERVER"

echo "[coverage] reports stored in coverage/"
