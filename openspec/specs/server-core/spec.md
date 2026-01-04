# server-core Specification

## Purpose
TBD - created by archiving change add-server-core-modules. Update Purpose after archive.
## Requirements
### Requirement: Agent Registration & Heartbeat Service
Server MUST 提供安全的 gRPC 服务供 Agent 注册与心跳同步，校验 token/TLS、幂等更新 Agent 元数据，并把心跳遥测写入行为/指标服务，确保 Agent 状态实时可见且可下发 shutdown 信号。

#### Scenario: Token Authenticated Registration
- **GIVEN** 预配置的合法 token 与 TLS 证书，Agent 在 `RegisterRequest` 中附带 `metadata{name,platform,version,capabilities,labels}`
- **WHEN** Server 验证 token，通过名称查找或创建 Agent，更新平台/版本/能力/标签并置状态为 online、心跳时间戳为当前时间
- **THEN** 服务器在 3 秒内返回唯一 `agent_id` 与 `heartbeat_interval_seconds = scheduler.HeartbeatTimeout/2`，用于指导 Agent 心跳频率；若心跳在 15 秒内缺失或 TLS 校验失败，则 Server 将 Agent 标记为 offline 并记录事件

#### Scenario: Heartbeat telemetry recorded
- **GIVEN** Agent 的 gRPC 心跳流包含 `HeartbeatTelemetry{latency_ms,cpu_percent,memory_percent,io_util_percent,blocked_actions}`、`load` 与 `running_tasks`
- **WHEN** Server 接收到 `HeartbeatRequest` 时
- **THEN** `store.UpdateAgentStatus` 会立即刷新负载与运行中的任务 ID，`behavior.Recorder`、`Analyzer`、`GraphService` 复用 telemetry/metadata 更新行为指标，Prometheus 指标 `AgentCPUPercent/AgentIOUtilPercent` 也会观测同样数值，Server 再通过 `HeartbeatResponse.should_shutdown` 控制远程 Agent 生命周期

### Requirement: Task Dispatch & Lease Management
Server MUST 支持通过优先级队列向 Agent 分配任务，使用租约机制保证幂等与超时重试，并在租约中携带 profile/payload/metadata 供 Agent 执行。

#### Scenario: Lease Renewal Failure
- **GIVEN** REST API 创建了 `respond` 类型任务，优先级为高
- **WHEN** Scheduler 将任务分配给满足能力的 Agent 并设置 120 秒租约，同时调用 `store.UpdateTaskRunStatusByLease` 记为 running
- **AND** Agent 未在租约期内报告结果
- **THEN** Server 自动回收租约并将任务状态恢复为 `pending`，`retry_count` 增加 1，若超过 `cfg.MaxRetries` 则标记失败并写入 `streams.TaskEvent`

#### Scenario: Metadata-preserving lease creation
- **GIVEN** 任务实体包含 JSON payload、profile、metadata 与期望的 capability 标签
- **WHEN** `PullTasks` 命中 Scheduler 的待执行任务
- **THEN** Server 复制任务 metadata、payload（保持 flags 与保留字段）、profile、租约超时时间 (`cfg.Scheduler.LeaseTTL`) 填入 `TaskLease` 并在 `sched.MarkRunStarted` 之后返回；若 Agent 负载或能力不足，Scheduler 会返回 `ErrAgentAtCapacity` 并保持任务在队列中

### Requirement: Result Persistence & Query
Server MUST 持久化任务执行结果、metadata、artifact 并通过 REST API 提供查询能力，同时把 telemetry metadata 推送给行为/监控系统。

#### Scenario: Fetch Task Summary
- **GIVEN** Agent 通过 `ReportResult` 成功上传任务结果（含 `summary_json`、`metadata`、`artifacts`、`exit_code`、`error_code`）
- **WHEN** Scheduler 调用 `CompleteTask`，把 summary/metadata 写入 `task_runs`、`task_results`，并通过 `behavior.RecordTaskTelemetry` 解析 `telemetry.process_tree`、`telemetry.task_resources`、`telemetry.bas_steps` 等键
- **THEN** 客户端调用 `GET /api/v1/tasks/{id}` 可获得 `status=succeeded`、summary 摘要、telemetry 字段（供 UI 渲染行为/沙箱/资源图表）与 artifact 引用；后端同时确保 artifacts 落地在 store 并遵守 `ResultRetention` 的过期策略

### Requirement: Threat Intelligence Orchestrator
Server MUST provide a central service that ingests agent-submitted artifacts（gRPC `artifacts` 或 `threatintel.artifact_tokens`）、执行 OpenTIP/MetaDefender 扫描、缓存 verdict，并通过 REST/SSE 暴露样本进度，支撑后续 Playbook。

#### Scenario: File escalated to dual engines
- **GIVEN** an Agent uploads an encrypted artifact referencing hash `abc123`
- **WHEN** the `/api/v1/threat-intel/jobs` worker dequeues it
- **THEN** the Server first queries MetaDefender (`POST /v4/file` → `GET /v4/file/{data_id}`) and OpenTIP (`POST /api/v1/scan/file?filename=abc123`), stores both verdicts with TTL, and pushes a `verdict_ready` event to `/api/v1/threat-intel/stream` so the originating task and operators can view the combined result

#### Scenario: Artifact token ingestion pipeline
- **GIVEN** `ReportResult` metadata 携带 `threatintel.artifact_tokens`（JSON UUID 列表）或额外的 gRPC `artifacts`
- **WHEN** gRPC 服务解析 metadata 时
- **THEN** `artifact.Manager.Consume` 会读取 token 对应的上传文件、生成 `model.Artifact` 与 `threatintel.SampleSubmission{artifact_ids,hash,size,metadata}`，并与内联 artifacts 一同入库/排队；Orchestrator 记录审计事件并把样本 ID 与原始 `task_run_id`/`agent_id` 关联，供 `/api/v1/threat-intel/jobs` 与 SSE 流显示处理进度

### Requirement: Behavior Graph & Anomaly Detection
Server MUST ingest telemetry from tasks/heartbeats, build a correlation graph, and surface anomaly events with contextual entities via API/SSE.

#### Scenario: Correlated anomaly query
- **GIVEN** Agent heartbeats and Respond outputs stream into the behavior service
- **WHEN** a rule detects “same agent connected to three blacklisted IPs within 5 minutes”
- **THEN** the service emits an anomaly event linking the agent, IPs, threat intel verdicts, and related tasks; `GET /api/v1/anomalies/{id}` returns nodes/edges so the frontend can render the attack path.

### Requirement: Playbook Automation & Approval
Server MUST host a Playbook engine that listens to threat/anomaly/Task events, enforces multi-stage approvals, and dispatches actions/child tasks with full auditability.

#### Scenario: Auto-response with approval gate
- **GIVEN** a Playbook is configured to quarantine hosts when MetaDefender verdict = `malware`
- **WHEN** an event arrives but the Playbook requires `security.lead` approval
- **THEN** the Engine pauses execution, records an audit entry, and only after `POST /api/v1/playbooks/runs/{id}/approve` succeeds will it dispatch the isolate action to the relevant Agent and log the action output.

### Requirement: Compliance Mapping & Reporting
Server MUST maintain multi-framework control mappings, reconcile task evidence, and generate gap/rectification data plus downloadable reports.

#### Scenario: CIS gap export
- **GIVEN** Respond/Baseline tasks upload control evidence referencing CIS v8 controls
- **WHEN** a user calls `GET /api/v1/compliance/frameworks/cis-v8/gaps?status=open`
- **THEN** the API returns each failing control with linked assets, recommended remediation, and associated tasks; `POST /api/v1/reports` with the CIS template produces a signed PDF ready for download.

### Requirement: BAS Scenario Orchestration
Server MUST own BAS scenario lifecycle (versioning, approval, scheduling) and stream per-step updates received from Agents to watchers and audit logs.

#### Scenario: Multi-agent BAS run coordination
- **GIVEN** a BAS scenario requires two agent groups (`edge`, `db`)
- **WHEN** an operator executes the scenario via `POST /api/v1/tasks` (`type=bas.advanced`)
- **THEN** the Scheduler assigns steps to matching Agents, enforces sandbox/resource limits, records each step update from Agents, and exposes `/api/v1/bas-runs/{run_id}/stream` so the frontend can mirror progress and highlight failures.

### Requirement: Artifact Presign & Upload Service
Server MUST 暴露 `/api/v1/artifacts/presign` 与 `/api/v1/artifacts/upload/:id` REST 接口，提供受限的分块上传渠道（自定义 TTL/大小/类型校验）以便 Agent 托管无法通过 gRPC 直接传输的大型样本。

#### Scenario: Agent uploads encrypted sample via presigned endpoint
- **GIVEN** Agent 需要上送 40 MB 样本且配置了 `artifact.storage_dir`, `max_size_bytes`, `upload_ttl`
- **WHEN** Agent 调用 `POST /api/v1/artifacts/presign`，携带 `filename/content_type/hash/size/encryption`，Server 会验证参数、写入内存 token 并返回 `upload_id`、`upload_url` 与过期时间；Agent 随后在 `upload_ttl` 内向 `PUT /api/v1/artifacts/upload/{id}` 上传内容
- **THEN** Artifact Manager 将流式写入临时文件、校验大小限制并标记 token 为 completed，之后 gRPC `ReportResult` 通过 `threatintel.artifact_tokens` 引用该 ID，Server 可在消费后立即把文件从上传目录移动到永久存储并附带 metadata（hash/encryption/type），确保威胁情报与审计链路能够访问加密样本

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

### Requirement: System event ingestion service
Server MUST 暴露 `/api/v1/events/ingest`（或等价 gRPC）以接收 Agent `SystemEvent` 流，并提供可持久化的队列/存储、速率限制与监控指标，确保事件在 <100 ms 内进入后端处理管道。

#### Scenario: Successful ingestion
- **GIVEN** Agent 以流式方式推送 `SystemEvent`（含 collector metadata、payload）
- **WHEN** Server 接收到事件
- **THEN** 需验证签名、写入事件队列/存储，并更新指标（吞吐、延迟、丢弃数），供后续阶段（高级监测/异常检测）消费

#### Scenario: Backpressure & durability
- **WHEN** 队列达到高水位或后端不可用
- **THEN** Server MUST 返回明确的 429/503，携带推荐重试退避；还应通过观察指标与告警提示运维，避免 silent drop

#### Scenario: Event schema validation
- **WHEN** 收到缺失字段或超出配额的事件
- **THEN** Server MUST 返回 400/413，并记录拒绝原因供审计，确保下游数据质量

### Requirement: Collector control plane
Server MUST 维护 Collector 配置版本与状态，能够向 Agent 下发启停/过滤/采样率，并聚合每台 Agent 的 Collector 遥测（资源占用、丢包率、缓冲水位）。

#### Scenario: Configuration delivery
- **GIVEN** 运维在控制台更新“启用 eBPF syscall 监控 + 5% 采样率”
- **WHEN** Server 生成新的配置版本
- **THEN** 需通过 REST/SSE/gRPC 在 30 秒内推送到目标 Agent，并追踪应用结果（成功/失败/超时）

#### Scenario: State aggregation
- **WHEN** Agent 在心跳中附带 Collector 状态
- **THEN** Server MUST 存档最近一次状态、暴露查询 API/仪表盘（包含运行 Collector、采样率、事件速率、异常原因），并在状态异常（degraded/offline）时触发告警

#### Scenario: Audit & RBAC
- **WHEN** 控制面配置被修改或下发
- **THEN** Server MUST 记录操作人、变更内容、目标 Agent，并依据 RBAC 限制仅授权角色可执行该操作，满足安全与合规要求

### Requirement: Seeded Task Catalog For Core Tasks
Server MUST ship with a built-in task catalog seed (task types + profiles) that covers the Agent core task surface (`respond/audit/inventory/supplychain/baseline/bas/action`) so operators can create profile-based tasks without out-of-band catalog bootstrapping.

#### Scenario: Seed imported on first start
- **GIVEN** the Server starts with an empty task catalog and no persisted catalog state is available
- **WHEN** the Server initialises the task catalog manager
- **THEN** it MUST import the built-in seed definitions for the core task surface
- **AND** `GET /api/v1/task-types` MUST include the seeded task types
- **AND** `GET /api/v1/task-profiles` MUST include at least one profile per seeded task type

#### Scenario: Seed persisted when configured
- **GIVEN** the Server is configured with `task_catalog.persist_path`
- **AND** the Server starts with an empty task catalog (no existing persisted state)
- **WHEN** the Server imports the built-in seed definitions
- **THEN** it MUST persist the resulting catalog state such that a subsequent restart loads the same task types/profiles without additional operator actions

#### Scenario: Existing catalog is preserved
- **GIVEN** the task catalog contains at least one existing task type or task profile (via persisted state or prior API writes)
- **WHEN** the Server starts
- **THEN** it MUST NOT overwrite or delete existing catalog entries
- **AND** it MUST NOT import the built-in seed in a way that mutates user-defined catalog data

### Requirement: Core Task Report Surface Covers Audit And Detect
Server MUST provide a stable report/read surface for all core Agent task types, including `audit` and remotely-dispatchable detect tasks (`detect.diag`, `detect.memscan`), such that remotely executed tasks can be consumed consistently via REST APIs with consistent authorization and auditing.

#### Scenario: Audit task report can be retrieved
- **GIVEN** an Agent completed an `audit` task and reported an execution result via `ReportResult`
- **WHEN** an operator fetches the task report via `GET /api/v1/tasks/{id}/audit/report`
- **THEN** the response MUST include the stored `ExecutionResult` (summary + metadata) and task identifiers
- **AND** the endpoint MUST require the same permission gate as other task report endpoints (e.g. `reports.view`)
- **AND** the Server MUST record an audit log entry for the report read action

#### Scenario: Detect task report can be retrieved
- **GIVEN** an Agent completed a `detect.diag` or `detect.memscan` task and reported an execution result via `ReportResult`
- **WHEN** an operator fetches the task report via `GET /api/v1/tasks/{id}/detect/report`
- **THEN** the response MUST include the stored `ExecutionResult` (summary + metadata) and task identifiers
- **AND** the endpoint MUST require the same permission gate as other task report endpoints (e.g. `reports.view`)
- **AND** the Server MUST record an audit log entry for the report read action

#### Scenario: Report aggregation endpoints enforce the same permission gate
- **GIVEN** a principal without `reports.view`
- **WHEN** the principal calls `GET /api/v1/reports/summary`, `GET /api/v1/reports/export`, or `POST /api/v1/reports/generate`
- **THEN** the Server MUST reject the request with `403`

### Requirement: Seeded Task Catalog For Detect Tasks
Server MUST ship with a built-in task catalog seed (task types + profiles + profile schemas) for remotely-dispatchable detect tasks (`detect.diag`, `detect.memscan`) so operators can create validated detect tasks via REST with predictable payload semantics.

#### Scenario: Detect task types and profiles are available after seeding
- **GIVEN** the Server starts with an empty task catalog and no persisted catalog state is available
- **WHEN** the Server initialises the task catalog manager
- **THEN** it MUST import the built-in seed definitions for `detect.diag` and `detect.memscan`
- **AND** `GET /api/v1/task-types` MUST include `detect.diag` and `detect.memscan`
- **AND** `GET /api/v1/task-profiles?task_type=detect.diag` MUST include at least one seeded profile
- **AND** `GET /api/v1/task-profiles?task_type=detect.memscan` MUST include at least one seeded profile

#### Scenario: Detect diag profile schema validates payload
- **GIVEN** an operator creates a `detect.diag` task using a seeded profile
- **WHEN** the payload provides `backend` outside the allowed set (`auto`, `native`, `portable`)
- **THEN** `POST /api/v1/tasks` MUST reject the request with `400`
- **AND** the seeded `detect.diag` profile schema MUST define `backend` as an enum with default `auto`
- **AND** the seeded `detect.diag` profile schema MUST define `rule` as an optional string (empty means using the built-in rule set)

#### Scenario: Detect memscan profile schema validates payload and expresses target selection constraints
- **GIVEN** an operator creates a `detect.memscan` task using a seeded profile
- **WHEN** the payload violates the profile schema (e.g. `pid <= 0`, `max_bytes <= 0`, or non-boolean `evidence/minidump`)
- **THEN** `POST /api/v1/tasks` MUST reject the request with `400`
- **AND** the seeded `detect.memscan` profile schema MUST define `pid` as an optional number (>0)
- **AND** the seeded `detect.memscan` profile schema MUST define `all` as an optional boolean
- **AND** the seeded `detect.memscan` profile schema MUST define `backend` as an enum with default `auto`
- **AND** the seeded `detect.memscan` profile schema MUST define `rule` as an optional string (empty means using the built-in rule set)
- **AND** the seeded `detect.memscan` profile schema MUST define guardrails with safe defaults: `rwx_only=true`, `max_bytes=33554432`, `max_regions=128`
- **AND** the seeded `detect.memscan` profile schema MUST define evidence toggles defaulting to disabled: `evidence=false`, `minidump=false`
- **AND** the seeded `detect.memscan` profile schema MUST include a constraint expressing that exactly one of `pid` or `all` MUST be provided

### Requirement: Detect Report Responses Follow The Standard Report Envelope
Server MUST return detect task reports using the same response envelope fields as existing report endpoints (e.g. `respond`/`baseline`) to keep client-side consumption consistent across task types.

#### Scenario: Detect report response envelope is stable
- **GIVEN** an Agent completed a `detect.diag` or `detect.memscan` task and reported an execution result via `ReportResult`
- **WHEN** an operator fetches the task report via `GET /api/v1/tasks/{id}/detect/report`
- **THEN** the response MUST include `task_id`, `task_type`, `profile`, `run_id`, `agent_id`, `task_status`, and `result`
- **AND** the response MUST include `run_metadata`, `exit_code`, `error_code`, `completed_at`, and `expires_at` when available

### Requirement: Default required_capabilities From Task Catalog
Server MUST ensure scheduler capability filtering can be applied consistently by defaulting `metadata.required_capabilities` during task creation when the client does not provide it (the key is absent), using the task type definition from the task catalog.

#### Scenario: Server injects default required_capabilities for catalog-known task types
- **GIVEN** a client calls `POST /api/v1/tasks` with `type` set and without `metadata.required_capabilities`
- **AND** the Server task catalog contains the task type and defines a non-empty `capabilities[]` list for that task type
- **WHEN** the Server accepts the create request
- **THEN** the persisted task metadata MUST include `required_capabilities` populated from the catalog task type `capabilities[]` (comma-separated, in catalog order)
- **AND** subsequent scheduling MUST only lease the task to Agents whose advertised capabilities satisfy `required_capabilities`

#### Scenario: Explicit required_capabilities is preserved
- **GIVEN** a client provides `metadata.required_capabilities` explicitly in `POST /api/v1/tasks`
- **WHEN** the Server stores the task
- **THEN** the Server MUST NOT overwrite the provided value (even if it is empty)

#### Scenario: Unknown task type does not force a default
- **GIVEN** a client creates a task with a task type that is not present in the task catalog
- **WHEN** the Server stores the task
- **THEN** the Server MUST NOT inject `required_capabilities` automatically

#### Scenario: Catalog-known task type without capabilities does not force a default
- **GIVEN** a client creates a task with a task type present in the task catalog
- **AND** the catalog task type defines an empty `capabilities[]` list
- **WHEN** the Server stores the task without `metadata.required_capabilities`
- **THEN** the Server MUST NOT inject `required_capabilities` automatically

