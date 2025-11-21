# 统一测试矩阵（Server / Agent / BAS / 前端）

Stage4 要求在发布或 PR 合入前执行完整的测试矩阵。可以直接运行 `scripts/test-matrix.sh`，或根据下表分别执行。

| 维度 | 目的 | 命令 |
|------|------|------|
| Agent | 覆盖所有 Runner/CLI/远程守护逻辑 | `cd agent && go test ./...` |
| Server-Core | 覆盖 API、Scheduler、Store 等核心模块 | `cd server && go test ./...` |
| Server-BAS/Scheduler | 针对 BAS 审批、调度限流与 Postgres JSON 序列化的关键路径，强制 `-count=1` 规避缓存 | `cd server && go test -run BAS -count=1 ./internal/scheduler ./internal/basscenarios ./internal/store/postgres` |
| Server-API (BAS/Playbook/Plugin/Cert) | 覆盖 BAS 场景、审批、插件安装与证书轮换的 RBAC/错误分支 | `cd server && go test -run '(BAS\|Playbook\|Plugin\|Cert)' -count=1 ./internal/api/v1` |
| 前端 | Ops Console 关键视图（默认使用 pnpm） | `cd frontend && pnpm test --runInBand --passWithNoTests` |
| Docs | 确保发布文档、SDK 指南、发布说明有效 | `scripts/docs-lint.sh` |

## 脚本执行

```bash
scripts/test-matrix.sh
```

脚本会顺序执行表格中的命令，并在缺少 `pnpm` 时自动跳过前端回归。

### 常见问题

- **pnpm 未安装**：在本地或 CI 中安装 `pnpm`（`npm install -g pnpm`）后重新运行脚本，或对前端部分单独执行 `npm test`。
- **BAS 相关测试超时**：确保 PostgreSQL/mock store 可用；如仅需内存数据库，可保持默认配置。
- **Docs lint 失败**：根据 `scripts/docs-lint.sh` 输出修复缺失标题或断链。
