## 1. Contract & data audit
- [x] 1.1 盘点 frontend `services/api`、SWR hook 与 server handler，列出每个视图需要的字段/筛选器/分页形式。（见 `notes/contract-data-audit.md`）
- [x] 1.2 设计统一任务列表响应（包含 `data`, `page_size`, `next_cursor`, `filters` 回显）及保存视图 API，并与前端过滤器/本地存储方案对齐。（见 `notes/contract-data-audit.md` 中“Task 1.2”章节）
- [x] 1.3 梳理 Threat Intel 工作台的 SSE / REST 映射（indicator → sample → jobs → artifacts），补齐缺失字段与错误码定义。（见 `notes/contract-data-audit.md` 中“Task 1.3”章节）

## 2. Server API & stream implementation
- [x] 2.1 扩展 `server/internal/api/v1/tasks.go`、`store.ListTasks` 支持多状态、搜索、limit/cursor，并返回新的响应 envelope。
- [x] 2.2 实现 `/api/v1/task-views` CRUD（按用户存储筛选器）以及 `/api/v1/queues/summary` + `/api/v1/queues/stream`，使用 scheduler 指标和队列快照。
- [x] 2.3 丰富 Threat Intel handler 与 orchestrator 数据：`/threat-intel/jobs`、`/samples/:id`、SSE 事件需包含 `artifact_ids`, `source`, `status`, `classification`，并增加 store 查询与单测。

## 3. Frontend & UX alignment
- [x] 3.1 更新 `useTasksData`、`TaskFilters`、`CreateTaskDrawer` 等逻辑，调用新的任务 API / 视图存储，并展示分页、保存视图与批量操作。
- [x] 3.2 替换 QueueMonitor、TaskLiveMonitor 的 mock 数据，接入新的 queue summary + SSE，新增故障/阻塞提示。
- [x] 3.3 调整 ThreatIntelWorkspace 以 job/samples API 为真源，显示 artifact/engine 进度，并对 SSE 状态断线/重连做提示。

## 4. Validation
- [x] 4.1 编写契约/集成测试覆盖任务 API、queue API、Threat Intel API，确保与前端类型定义一致；更新 README/控制台文档描述新的交互流。
