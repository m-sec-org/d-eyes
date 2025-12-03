## ADDED Requirements
### Requirement: Task Query & Saved View APIs
Server MUST 提供支持多状态、关键字搜索、分页与用户视图存储的任务查询接口，确保前端与 CLI 均可消费一致的数据结构。

#### Scenario: Filtered task list with cursor + saved views
- **GIVEN** 客户端调用 `GET /api/v1/tasks?status=running,failed&search=acme&limit=50&cursor=eyJ0YXNrX2lkIjoiLi4uIn0=`
- **WHEN** Handler 查询 store（按多状态、关键字匹配 `id/type/profile/metadata.targets/scenario_*`），并封装 `[]taskResponse`
- **THEN** 响应为 `{data:[...], page_size:50, next_cursor:"...", applied_filters:{status:["running","failed"], search:"acme"}}`，`taskResponse` 保留 `last_run.summary`（JSON）、`metadata`、`scenario_*` 字段
- **AND** `POST /api/v1/task-views` / `GET /api/v1/task-views` 以用户维度读写 saved views（名称、filters、默认排序），用于恢复控制台视图

### Requirement: Scheduler Queue Inspection & Stream
Server MUST 暴露调度队列/租约观察接口，为 Ops Console 与运维工具提供实时可视化数据。

#### Scenario: Queue summary + SSE for live monitor
- **GIVEN** Scheduler 维护优先级队列与租约
- **WHEN** 客户端调用 `GET /api/v1/queues/summary`
- **THEN** 响应包含每个 `task_type` 的 `pending`, `leased/running`, `blocked`, `oldest_pending_age`, `top_agents`, `blocked_reason`
- **AND** `/api/v1/queues/stream`（SSE）推送 `event`, `task_id`, `task_type`, `priority`, `agent`, `status`, `timestamp`，并在断开时返回 5xx 以便前端提示；接口必须复用 scheduler 指标并附带权限校验（`tasks.read`）

### Requirement: Threat Intel Job Directory API
Server MUST 提供 job 级 REST API 以支撑威胁情报工作台的列表、样本详情与 artifact 追踪。

#### Scenario: Job list + sample detail expose artifact metadata
- **GIVEN** Orchestrator 持久化 `threat_intel_jobs` 与 `threat_intel_samples`
- **WHEN** 客户端调用 `GET /api/v1/threat-intel/jobs?sample_id=<uuid>&limit=100` 或 `?indicator=sha256`
- **THEN** 响应 `[{id,sample_id,indicator,kind,source,status,attempt,error,next_run_at,artifact_ids,metadata,created_at,updated_at}]`
- **AND** `/api/v1/threat-intel/samples/{id}` 返回 `artifact_ids`, `job_statuses`, `metadata.hash/source`, `task_run_id`, `agent_id`; SSE `/threat-intel/stream` 必须对齐上述字段并包含 `classification/confidence`，确保 UI 可同步状态
