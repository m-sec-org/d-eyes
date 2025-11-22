## ADDED Requirements
### Requirement: Task Command Center UX Contracts
Ops Console MUST 在任务指挥中心提供基于 Server API 的统一数据视图，支持多状态筛选、关键字搜索、分页以及跨终端同步的“保存视图”。

#### Scenario: Operator filters, paginates, and saves a view
- **GIVEN** 用户在 `TaskOverview` 中设置 `status=running,failed`、搜索关键字并选择 page size
- **WHEN** 前端调用 `GET /api/v1/tasks?status=running,failed&search=acme&page_size=50&cursor=...`
- **THEN** API 返回 `{data: Task[], page_size, next_cursor, applied_filters}`，`Task` 项包含 `metadata.targets/scenario_*`、`last_run.summary/metadata`，供 `TaskList/TaskDetailDrawer` 展示
- **AND** 当用户点击“保存视图”时，前端调用 `POST /api/v1/task-views` 按用户 ID 存储筛选条件，并在刷新页面后通过 `GET /api/v1/task-views` 还原视图列表

### Requirement: Queue Monitor & Live Dispatch Surface
Ops Console MUST 展示真实的调度队列与租约事件，而不是本地 mock 数据，支持实时刷新、SSE 状态提示与诊断入口。

#### Scenario: Queue monitor consumes summary + SSE
- **GIVEN** 用户打开 QueueMonitor
- **WHEN** 前端调用 `GET /api/v1/queues/summary` 并连接 `/api/v1/queues/stream`
- **THEN** summary 响应包含每个任务类型的 `pending/running/blocked` 数量、优先级分布与最近阻塞原因；SSE 事件推送 `task_id`, `task_type`, `status`, `priority`, `agent`, `timestamp`
- **AND** UI 根据事件更新时间线与卡片，必要时提示“连接中/已断线”，并提供跳转到排障文档的操作

### Requirement: Threat Intel Workspace Data Alignment
威胁情报工作台 MUST 依赖统一的 REST+SSE 契约展示 indicator、样本、job、artifact 以及审计线索。

#### Scenario: Analyst pivots from indicator → sample → job artifacts
- **GIVEN** 分析员通过 `lookupIndicator` 触发扫描
- **WHEN** 客户端刷新 `/api/v1/threat-intel/iocs/{indicator}`、`/samples/{id}`、`/jobs?sample_id=...` 并订阅 `/threat-intel/stream`
- **THEN** indicator 响应包含 `verdicts[source,classification,confidence,metadata]`; sample 明细提供 `artifact_ids`, `job_statuses`, `metadata.hash/source`; job 列表提供 `source`, `status`, `attempt`, `artifact_ids`
- **AND** SSE 事件字段与 REST 一致（`sample_id`, `job_id`, `source`, `status`, `classification`），供 UI 聚合出“最近样本卡片”与“审计事件”，同时暴露错误信息和“重新拉取”操作
