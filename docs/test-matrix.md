# 统一测试矩阵（Server / Agent / BAS / 前端）

Stage4 要求在发布或 PR 合入前执行完整的测试矩阵。可以直接运行 `scripts/test-matrix.sh`，或根据下表分别执行。

| 维度 | 目的 | 命令 |
|------|------|------|
| Agent-Portable | 覆盖所有 Runner/CLI/远程守护逻辑（pure Go 保底路径） | `cd agent && CGO_ENABLED=0 go test ./...` |
| Agent-Native (可选) | 覆盖 `yara_native`（CGO + libyara）路径，用于验证 native backend 与 match 映射 | `cd agent && CGO_ENABLED=1 go test -tags yara_native ./...` |
| Server-Core | 覆盖 API、Scheduler、Store 等核心模块 | `cd server && go test ./...` |
| Server-BAS/Scheduler | 针对 BAS 审批、调度限流与 Postgres JSON 序列化的关键路径，强制 `-count=1` 规避缓存 | `cd server && go test -run BAS -count=1 ./internal/scheduler ./internal/basscenarios ./internal/store/postgres` |
| Server-API (BAS/Playbook/Plugin/Cert) | 覆盖 BAS 场景、审批、插件安装与证书轮换的 RBAC/错误分支 | `cd server && go test -run '(BAS\|Playbook\|Plugin\|Cert)' -count=1 ./internal/api/v1` |
| 前端 | Ops Console 关键视图（默认使用 pnpm） | `cd frontend && pnpm exec vitest run --passWithNoTests` |
| 前端-Workspace Vitest | 验证 PluginMarketplace SSE/回滚、AuditLogView 过滤/导出等关键交互 | `cd frontend && pnpm exec vitest run --pool=vmThreads src/features/plugins/__tests__/PluginMarketplace.test.tsx src/features/audit/__tests__/AuditLogView.test.tsx` |
| 前端-Playwright | 回归工具工作台（Report/Config/Compliance）端到端流程 | `cd frontend && pnpm test:e2e` |
| Docs | 确保发布文档、SDK 指南、发布说明有效 | `scripts/docs-lint.sh` |

## 脚本执行

```bash
scripts/test-matrix.sh
```

脚本会顺序执行表格中的命令，并在缺少 `pnpm` 时自动跳过前端回归。

## Native YARA 运行条件

`Agent-Native` 仅在环境满足以下条件时执行：

- `pkg-config --exists yara` 可用（能找到 libyara）
- 存在可用的 C 编译器（`gcc` 或 `cc`）

CI 中建议将 `Agent-Native` 独立为可选 Job（或在具备依赖的 runner 上启用）。

## Windows 专项（memscan e2e）

Windows Job/开发机上建议额外确认 `detect memscan --all` 端到端链路稳定且不会 hang（禁用缓存，并设置 `go test` 超时上限）：

```bash
cd agent && go test -count=1 -timeout=5m -run '^TestDetectMemscanWindows' ./internal/detect
```

同时，`scripts/test-matrix.sh` 在 Windows 上默认会为所有 `go test` 增加全局 `-timeout=15m`（可通过 `GO_TEST_TIMEOUT` 覆盖）。

### 常见问题

- **pnpm 未安装**：在本地或 CI 中安装 `pnpm`（`npm install -g pnpm`）后重新运行脚本，或对前端部分单独执行 `npm test`。
- **BAS 相关测试超时**：确保 PostgreSQL/mock store 可用；如仅需内存数据库，可保持默认配置。
- **Docs lint 失败**：根据 `scripts/docs-lint.sh` 输出修复缺失标题或断链。

### 前端专项验证清单

| 场景 | 涉及视图 | 预期 |
|------|---------|------|
| PluginMarketplace SSE | 插件安装/回滚、SSE 断线、错误告警 | EventSource 断线后关闭流、重试刷新，AntD Alert 提示 API/SSE 错误 |
| AuditLogView 过滤/导出 | 审计日志、操作时间线 | Inline Form 触发 SWR 请求，分页保持排序，导出 JSON 触发 `message.success` |
| Compliance/BAS 固定高度 | 合规框架差距、BAS Modal | Timeline Affix 不随表单滚动，Modal `destroyOnHidden` 重置状态 |
| 行为异常图谱 | Anomaly Center | Split Pane 保持拖拽宽度，Graph 与列表联动 |
