#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "[chaos] simulating storage failure (store timeout scenario)"
go test ./server/internal/store -run TestMemoryStore_TaskRetries -count=1
