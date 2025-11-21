#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

log() {
  printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$1"
}

run_go_tests() {
  local path="$1"
  shift
  log "go test $path $*"
  (cd "$path" && go test "$@" ./...)
}

log "Agent 单元测试"
(cd agent && go test ./...)

log "Server 单元测试"
(cd server && go test ./...)

log "Server BAS/Scheduler/Postgres 关键路径 (no cache)"
(cd server && go test -run BAS -count=1 ./internal/scheduler ./internal/basscenarios ./internal/store/postgres)

log "Server API 审批 / 插件 / 证书错误流"
(cd server && go test -run '(BAS|Playbook|Plugin|Cert)' -count=1 ./internal/api/v1)

if command -v pnpm >/dev/null 2>&1; then
  log "前端回归 (pnpm vitest run subset)"
  FRONTEND_SPECS=(
    src/components/ui/__tests__/Button.test.tsx
    src/components/ui/__tests__/FormField.test.tsx
    tests/perf/taskLiveMonitor.baseline.test.tsx
    src/features/settings/__tests__/SystemConfigCenter.test.tsx
  )
  (cd frontend && pnpm vitest run "${FRONTEND_SPECS[@]}" --passWithNoTests)
else
  log "pnpm 未安装，跳过前端测试"
fi

log "Docs lint"
scripts/docs-lint.sh >/dev/null
log "测试矩阵执行完成"
