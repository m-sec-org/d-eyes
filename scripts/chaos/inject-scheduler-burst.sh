#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )/../.." && pwd)"
cd "$ROOT_DIR"

echo "[chaos] triggering scheduler burst (lease timeout simulation)"
go test ./server/internal/scheduler -run TestLeaseTask_RespectsAgentConcurrency -count=1
