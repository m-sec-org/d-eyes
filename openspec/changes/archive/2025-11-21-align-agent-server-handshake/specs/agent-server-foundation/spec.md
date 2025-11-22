## MODIFIED Requirements
### Requirement: Agent Registration and Heartbeat
Server MUST expose a secure gRPC 接口供 Agent 注册并维持带遥测与 metadata 的心跳，写入 `store.UpdateAgentStatus`、行为分析与指标模块，同时在 15 秒无心跳时判定离线。

#### Scenario: TLS Enrolled Agent
- **GIVEN** Agent 将 `RemoteConfig` 中的 token、TLS 证书以及 `Metadata{Name,Platform,Version,Capabilities,Labels}` 注入 `RegisterRequest`（默认标签含 `mode=remote`，缺失名称时退回 hostname），并在 `agent/internal/agent/daemon.go` 里缓存 Server 颁发的 `agent_id`
- **WHEN** gRPC `AgentService.Register` 收到请求且 `cfg.Security.AgentToken` 校验通过
- **THEN** Server 以 `metadata.name` 去幂等 upsert Agent，回写最新平台/版本/能力与标签，标记在线并在 3 秒内返回 `RegisterResponse{agent_id, heartbeat_interval_seconds = scheduler.HeartbeatTimeout/2}`
- **AND** Agent 复用返回的 `agent_id` 进行后续心跳、任务拉取与结果上报

#### Scenario: Heartbeat telemetry fan-out
- **GIVEN** 远程循环在每次任务轮询前调用 `enqueueHeartbeatPayload`，填充 `load`（当前运行任务数）、`running_tasks`（租约 ID 列表）以及从 `telemetry.Latest*` 与 `cache.*` 统计生成的 metadata（含 `telemetry.cpu_percent/memory_percent/io_util_percent`、`telemetry.blocked_actions`、最近一次结果里携带的 `cache.<namespace>` 指标）
- **WHEN** `remote.Client.StartHeartbeat` 以 `cfg.HeartbeatInterval` 频率发送 `HeartbeatRequest{agent_id, timestamp, load, running_tasks, telemetry, metadata}` 并等待 `HeartbeatResponse`
- **THEN** Server 立即调用 `store.UpdateAgentStatus` 与 `behavior.RecordHeartbeat`/`Analyzer.ProcessHeartbeat`/`Graph.HandleHeartbeat`，把 `telemetry.*` 指标写入 Metrics，若 15 秒未收到消息则按 `scheduler.HeartbeatTimeout` 标记 offline，并可通过 `HeartbeatResponse.should_shutdown` 通知 Agent 退出

### Requirement: Remote Task Execution Loop
Agent MUST 按租约机制循环调用 `PullTasks`、执行 `TaskRunner` 并通过 `ReportResult` 回传 `model.ExecutionResult` JSON、metadata、artifact/token，Server 则追踪租约与任务生命周期。

#### Scenario: Respond Task Roundtrip
- **GIVEN** REST `/api/v1/tasks` 创建 respond 任务携带 JSON payload（含 `flags`、profile、timeout、自定义 metadata）并至少有一台在线 Agent
- **WHEN** Agent 通过 `PullTasks(agent_id, max_tasks)` 获得 `TaskLease{task_id, lease_id, task_type, payload, metadata, profile, lease_timeout_seconds}`，查找对应 `tasks.TaskRunner` 并执行 `tasks.ExecuteWithResult`
- **THEN** Agent 将 `model.ExecutionResult` 编码进 `ReportResultRequest.summary_json`，把 runner metadata 与 `telemetry.AppendTaskResourceMetadata`/`telemetry.CollectExecutionMetadata` 采集的 `telemetry.task.*`、`telemetry.process_tree`、`telemetry.net_connections` 等键合并为 `metadata`，同时写入 `status`、`exit_code`、`error_code` 并缓存到本地 `remote.FileStore` 方便断线重放
- **AND** Server 在收到 `ReportResult` 后调用 `scheduler.CompleteTask` 按租约入库，REST `GET /api/v1/tasks/{id}` 可以读取最新状态、summary 摘要与 metadata

#### Scenario: Lease payload & sandbox merging
- **GIVEN** `TaskLease.payload` 内包含 `flags`（CLI 参数）与保留字段（profile/name/timeout/json/quiet/ti_mode 等），`TaskLease.metadata` 则带着 dispatcher 写入的附加键
- **WHEN** Agent 在 `processLease` 中调用 `applyRemotePayload` 与 `req.ApplyDefaults`，会把 payload flags 解包进 `TaskRequest.Flags`，用 `profile/name/timeout/json/quiet` 覆盖 CLI 默认，并通过 `threatintel.ParseMode`/`mergeSandboxConfig` 合并 `ti-mode` 与 `Sandbox` 配置，强制开启 `req.Quiet=true` 与 `req.Config.Tasks.BAS.SandboxEnabled=true` 以匹配 Server 约束
- **THEN** 构造完成的 `TaskRequest` 必须通过 `tasks.ValidateRequest`，Runner 才能执行；若任务类型不存在或验证失败，Agent 会立刻走 `reportFailure`，Server 依据 `error_code=agent.remote_execution_failed` 对租约重试

## ADDED Requirements
### Requirement: Result Metadata & Artifact Escrow
Agent MUST 在每次 `ReportResult` 中提供结构化 metadata、telemetry 与大文件托管 token，使 Server 能把任务遥测写入行为/指标，并把高危样本升阶到 Threat Intel Orchestrator。

#### Scenario: Telemetry bundle mirrored to Server
- **GIVEN** 任务运行期间生成 process tree、网络连接、资源占用、BAS 步骤或沙箱统计，Agent 通过 `telemetry.EncodeBASteps`、`EncodeSandboxStats`、`AppendTaskResourceMetadata` 把 payload gzip+base64 编码并写入 `metadata[telemetry.process_tree|telemetry.net_connections|telemetry.bas_steps|telemetry.sandbox_stats|telemetry.task_resources]`
- **WHEN** `remoteRunner` 上报 `ReportResultRequest` 时附带上述 metadata，Server 的 gRPC 服务在 `extractTelemetryMetadata` 里筛选出这些键并交给 `behavior.RecordTaskTelemetry`、`Analyzer.ProcessTaskTelemetry` 与 `Graph.HandleTaskTelemetry`
- **THEN** 行为图、BAS 审计与 `GET /api/v1/tasks/{id}` 的摘要必须能够复用这些 telemetry 字段，确保 UI/告警管线可重放完整执行上下文

#### Scenario: Threat intel artifacts via presign
- **GIVEN** Respond/Baseline/BAS 检测到无法线下判定的 40 MB 样本，Agent 在 `ti-mode=server` 时调用 `/api/v1/artifacts/presign` 获取上传 token，PUT `/api/v1/artifacts/upload/{id}` 完成加密分块上传，并将 token 列表 JSON 写入 `metadata[threatintel.artifact_tokens]`
- **WHEN** 样本较小（例如 <5 MB）且策略允许，Agent 也可直接把内容作为 `ReportResultRequest.artifacts{name,content_type,data}` 发送，metadata 中补充 `threatintel.hash`、`threatintel.source` 等键
- **THEN** Server `ReportResult` 读取 `threatintel.artifact_tokens`，通过 `artifact.Manager.Consume` 生成 `model.Artifact`，并把 gRPC 附带的 artifacts 一并保存，再将 `threatintel.SampleSubmission`（含 artifact_ids、hash、size、metadata）推入 Orchestrator，使 `/api/v1/threat-intel/jobs`、SSE 事件与后续 Playbook 可以关联样本与原始任务
