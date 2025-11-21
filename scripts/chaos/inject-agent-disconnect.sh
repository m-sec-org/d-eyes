#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )/../.." && pwd)"
cd "$ROOT_DIR"

echo "[chaos] simulating agent disconnect (grpc heartbeat test)"
go test ./server/internal/grpcsvc -run TestService_Heartbeat -count=1
