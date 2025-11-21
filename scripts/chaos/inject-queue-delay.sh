#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )/../.." && pwd)"
cd "$ROOT_DIR"

echo "[chaos] injecting queue delay via perfcheck histogram"
go test ./server/internal/scheduler -run TestLeaseTask_NoTaskAvailable -count=1
