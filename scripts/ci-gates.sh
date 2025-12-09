#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )/.." && pwd)"
cd "$ROOT_DIR"

log() {
  printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$1"
}

log "测试矩阵"
scripts/test-matrix.sh

log "覆盖率报告"
scripts/coverage-report.sh

log "插件兼容性"
scripts/plugin-compat.sh

log "eBPF 构建校验"
scripts/verify-ebpf-build.sh

if [[ -n "${PROM_URL:-}" ]]; then
  log "性能基线"
  scripts/perf-baseline.sh "$PROM_URL"
else
  log "PROM_URL 未设置，跳过性能基线"
fi

log "发布说明校验"
scripts/check-release-notes.sh

log "CI 门禁全部通过"
