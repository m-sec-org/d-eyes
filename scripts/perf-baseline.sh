#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )/.." && pwd)"
cd "$ROOT_DIR"

PROM_URL=${PROM_URL:-${1:-}}
if [[ -z "$PROM_URL" ]]; then
  echo "usage: PROM_URL=https://prom.example.com scripts/perf-baseline.sh [perfcheck args]" >&2
  exit 1
fi

WINDOW=${PERF_WINDOW:-5m}

shift || true

echo "[perf] running perfcheck against $PROM_URL (window=$WINDOW)"
go run -C server ./tools/perfcheck --prom "$PROM_URL" --window "$WINDOW" "$@"
