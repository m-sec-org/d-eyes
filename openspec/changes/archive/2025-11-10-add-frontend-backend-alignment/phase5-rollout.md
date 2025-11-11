# Phase 5 – Validation & Rollout

## 集成测试覆盖
| 场景 | 覆盖方式 | 说明 |
| --- | --- | --- |
| 任务创建→调度→执行→结果查询 | `server/internal/api/v1/tasks_test.go::TestTaskLifecycle`、`scheduler` 单元测试 | 覆盖 REST 创建、队列入列、Lease→Complete、结果查询；需在 PR 中继续维护数据契约校验。 |
| 任务→实时流→前端监控 | 手动：`pnpm dev` + `useTaskStream`，结合新增 `manual_action` 事件；计划在 e2e 套件中加入 Playwright 脚本，通过 Mock Agent 推送 SSE 事件验证 `TaskLiveMonitor` 显示。 |
| 报告模板生成 | `server/internal/api/v1/reports.go` 新增的模板 CRUD + `generateReport` API；下一步在 Vitest 中通过 `msw` Mock `/reports/templates` 补充前端接入测试。 |
| RBAC + 审计链路 | `server/internal/app` 集成测试确保 Router 注入 RBAC/Audit；SecOps 演练时需通过 `X-User-Role` Header 覆盖 operator/admin 等角色，验证审计条目写入 `auditlog.Manager`. |

## Feature Flag / 灰度策略
| 模块 | Feature Flag | 默认状态 | 灰度策略 | 回滚 |
| --- | --- | --- | --- | --- |
| 实时监控指挥面板 | `ff_task_live_monitor`（frontend env + server SSE payload） | Off（仅自测环境开启） | 按环境变量启用，配合 SSE Hub 监控延迟 <2s 后再向生产开放。 | 关闭 flag，同时 server 端 `PublishExternalEvent` 保留兼容行为。 |
| BAS 场景编排 | `ff_bas_console`, `ff_bas_scenario_api` | On (staging)，Off (prod) | 先在专用 tenant 启用 BAS API + UI；审批链路通过 mock 审批人演练后放量。 | 关闭 flag 恢复旧版 CLI-only BAS；场景数据保留。 |
| 报告模板服务 | `ff_report_templates` | On | 与 RBAC 联动，仅 `admin` 角色可见；若导出链路异常，可关 Flag 并退回旧的 `/reports/export`。 |

Feature Flag 建议统一放置在 `frontend/src/config/featureFlags.ts`（待补文件）与 server 端 `config.yaml`，在部署流水线中通过 Helm/环境变量注入。

## SecOps / CS 验收要点
1. **BAS 场景**：由 SecOps 在 staging 环境导入 2 个场景，校验审批→启用→执行全链路；确认 audit log 记录 `bas.scenario.*` 事件。
2. **实时监控 & 干预**：CS 团队演练 respond 任务，使用 `TaskLiveMonitor` 触发暂停/恢复；对照 server 日志确认 `manual_action` 事件写入。
3. **权限矩阵**：对 operator/auditor/admin 三角色执行 smoke 测试，验证 `/rbac/policies`、Audit 查询以及 UI 入口可见性；输出角色矩阵文档给支持团队。
4. **回滚预案**：若出现 SSE 延迟或 RBAC 误判，可通过 Feature Flag 关闭对应模块并回到 Phase 3 状态。灰度窗口建议 2 天，期间持续观察 Grafana 中 task/stream 错误指标。

## 测试执行记录
- `cd server && go test ./...`
- `cd agent && go test ./...`
- `pnpm vitest run`

如需端到端验证，可使用 `./scripts/dev/seed_tasks.sh` 生成任务数据，结合 `mock-agent` 推送心跳，确保 Dashboard 体验稳定。
