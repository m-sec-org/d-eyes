## Why
Frontend 控制台与 Server REST/gRPC 接口目前存在明显错位：
- 任务指挥中心（`TaskOverview`）请求 `/api/v1/tasks` 并期望 `{data: Task[]}` 包装、跨状态筛选与全文搜索，但 server `TaskHandler.listTasks` 仅返回裸数组、限制 20 条且不支持多状态/模糊查询，导致前端需要本地过滤与分页占位。
- 队列监控、命令队列视图完全依赖本地 `MOCK_QUEUE`，因为调度器没有公开队列/租约可观测性 API 或 SSE 渠道，无法显示真实 priority、agent、阻塞原因。
- 威胁情报工作台已实现事件流与样本审计 UI，但 server 只暴露 indicator/sample API，缺少 `/threat-intel/jobs` 与 `artifact_ids`/`source` 结构化字段，难以把 SSE 事件映射到 UI 卡片。
要让控台成为可信的运营界面，必须同时调整 server API 返回值、增加缺失的端点，并更新 Ops Console 规范描述。

## What Changes
- 定义并实现任务查询/筛选契约：`GET /api/v1/tasks` 需支持多状态、关键字搜索、limit/cursor，并统一返回 `{data: Task[], next_cursor}`，同时暴露 `/api/v1/task-views` 允许前端保存/复用视图。
- 新增队列观测接口：调度器暴露 `/api/v1/queues/summary`、`/api/v1/queues/events`（SSE）返回每个任务类型、优先级、阻塞原因与 agent 占用，用于 QueueMonitor & TaskLiveMonitor。
- 扩充 Threat Intel API：`/api/v1/threat-intel/jobs` 与 `/samples/{id}` 要返回 job 列表、artifact_ids、source/status 字段，并确保 SSE 流与 REST 一致；Ops Console 规范需描述工作台如何消费这些字段。

## Impact
- Specs 受影响：`align-ops-console`（描述任务指挥中心、队列监控、威胁情报 UI 合同）与 `server-core`（新增/调整 REST API & SSE 要求）。
- 代码影响：`server/internal/api/v1/tasks.go`, `scheduler` 观测 API, Threat Intel handler, 以及前端 `services/api/*`, `features/tasks/*`, `features/queues`, `features/threatintel`。
- 测试：需要针对新的 API shape、SSE 事件与存储视图添加单元、集成及契约测试。
