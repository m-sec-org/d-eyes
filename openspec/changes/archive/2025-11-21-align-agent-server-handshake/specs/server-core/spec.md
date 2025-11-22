## MODIFIED Requirements
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

## ADDED Requirements
### Requirement: Artifact Presign & Upload Service
Server MUST 暴露 `/api/v1/artifacts/presign` 与 `/api/v1/artifacts/upload/:id` REST 接口，提供受限的分块上传渠道（自定义 TTL/大小/类型校验）以便 Agent 托管无法通过 gRPC 直接传输的大型样本。

#### Scenario: Agent uploads encrypted sample via presigned endpoint
- **GIVEN** Agent 需要上送 40 MB 样本且配置了 `artifact.storage_dir`, `max_size_bytes`, `upload_ttl`
- **WHEN** Agent 调用 `POST /api/v1/artifacts/presign`，携带 `filename/content_type/hash/size/encryption`，Server 会验证参数、写入内存 token 并返回 `upload_id`、`upload_url` 与过期时间；Agent 随后在 `upload_ttl` 内向 `PUT /api/v1/artifacts/upload/{id}` 上传内容
- **THEN** Artifact Manager 将流式写入临时文件、校验大小限制并标记 token 为 completed，之后 gRPC `ReportResult` 通过 `threatintel.artifact_tokens` 引用该 ID，Server 可在消费后立即把文件从上传目录移动到永久存储并附带 metadata（hash/encryption/type），确保威胁情报与审计链路能够访问加密样本
