#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )/.." && pwd)"
cd "$ROOT_DIR"

echo "[plugin] go test ./agent/internal/plugin/..."
(cd agent && go test ./internal/plugin/...)

echo "[plugin] building sample plugins"
samples=(respond_example detect_example bas_example)
for sample in "${samples[@]}"; do
  echo "  -> $sample"
  (cd agent && CGO_ENABLED=1 go build -buildmode=plugin -o "../tmp/${sample}.so" "./internal/plugin/examples/${sample}")
done

echo "[plugin] compatibility checks completed"
