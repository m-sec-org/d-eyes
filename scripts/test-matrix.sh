#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

GOOS="$(go env GOOS 2>/dev/null || echo unknown)"
GO_TEST_TIMEOUT="${GO_TEST_TIMEOUT:-}"
if [[ "$GOOS" == "windows" && -z "$GO_TEST_TIMEOUT" ]]; then
  GO_TEST_TIMEOUT="15m"
fi

GO_TEST_ARGS=()
if [[ -n "$GO_TEST_TIMEOUT" ]]; then
  GO_TEST_ARGS+=("-timeout=$GO_TEST_TIMEOUT")
fi

log() {
  printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$1"
}

has_native_yara() {
  if ! command -v pkg-config >/dev/null 2>&1; then
    return 1
  fi
  if ! pkg-config --exists yara >/dev/null 2>&1; then
    return 1
  fi
  if command -v gcc >/dev/null 2>&1; then
    return 0
  fi
  if command -v cc >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

log "Agent 单元测试"
(cd agent && CGO_ENABLED=0 go test "${GO_TEST_ARGS[@]}" ./...)

if has_native_yara; then
  log "Agent 单元测试 (yara_native tag)"
  (cd agent && CGO_ENABLED=1 go test "${GO_TEST_ARGS[@]}" -tags yara_native ./...)
else
  log "Agent native YARA 不可用，跳过 yara_native 测试（需要 libyara + pkg-config + C 编译器）"
fi

if [[ "$GOOS" == "windows" ]]; then
  log "Agent Windows memscan e2e (pid/all) (no cache, bounded timeout)"
  (cd agent && go test -count=1 -timeout=5m -run '^(TestDetectMemscanWindowsE2E|TestDetectMemscanWindowsAllE2E)$' ./internal/detect)

  log "Agent Windows detect export e2e (no cache, bounded timeout)"
  (cd agent && go test -count=1 -timeout=2m -run '^TestDetectExportWindowsE2E$' ./internal/detect)
fi

log "Server 单元测试"
(cd server && go test "${GO_TEST_ARGS[@]}" ./...)

log "Server BAS/Scheduler/Postgres 关键路径 (no cache)"
(cd server && go test "${GO_TEST_ARGS[@]}" -run BAS -count=1 ./internal/scheduler ./internal/basscenarios ./internal/store/postgres)

log "Server API 审批 / 插件 / 证书错误流"
(cd server && go test "${GO_TEST_ARGS[@]}" -run '(BAS|Playbook|Plugin|Cert)' -count=1 ./internal/api/v1)

if command -v pnpm >/dev/null 2>&1; then
  if (cd frontend && pnpm exec vitest --version >/dev/null 2>&1); then
    log "前端回归 (vitest run subset)"
    FRONTEND_SPECS=(
      src/components/ui/__tests__/Button.test.tsx
      src/components/ui/__tests__/FormField.test.tsx
      tests/perf/taskLiveMonitor.baseline.test.tsx
      src/features/settings/__tests__/SystemConfigCenter.test.tsx
    )
    (cd frontend && pnpm exec vitest run "${FRONTEND_SPECS[@]}" --passWithNoTests)
  else
    if [[ "${CI:-}" == "true" || "${CI:-}" == "1" ]]; then
      log "前端依赖未安装或 vitest 不可用（CI 环境应先执行 pnpm install），终止"
      exit 1
    fi
    log "前端依赖未安装或 vitest 不可用，跳过前端测试（可先在 frontend 执行 pnpm install）"
  fi
else
  log "pnpm 未安装，跳过前端测试"
fi

log "Docs lint"
scripts/docs-lint.sh >/dev/null
log "测试矩阵执行完成"
