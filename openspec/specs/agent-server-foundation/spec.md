# agent-server-foundation Specification

## Purpose
TBD - created by archiving change plan-agent-server-foundation. Update Purpose after archive.
## Requirements
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

### Requirement: Resilient Result Delivery
Agent MUST 在网络中断时缓存未上报结果并在连接恢复后重放，以保证任务结果最终一致。

#### Scenario: Retry After Network Loss
- **GIVEN** Agent 执行任务后与 Server 的 gRPC 连接中断
- **WHEN** Agent 在 60 秒内恢复连接
- **THEN** Agent 会自动重放缓存的结果，Server 将去重并持久化，不得产生重复任务记录

### Requirement: Embedded Threat Intelligence Connectors
Agent MUST embed dual-source threat intelligence clients (OpenTIP & MetaDefender) that can run locally with caching/quotas and fall back to server-orchestrated scans.

#### Scenario: Local OpenTIP lookup with caching
- **GIVEN** `ti-mode=local` and the operator provides a valid OpenTIP `x-api-key`
- **WHEN** the Respond task hashes a suspicious file and invokes `GET https://opentip.kaspersky.com/api/v1/search/hash?request=<sha256>`
- **THEN** the Agent caches the verdict (type, classification, TTL) locally for 24h and annotates the task summary with the threat score before returning to the Server.

#### Scenario: MetaDefender fallback when quota exceeded
- **GIVEN** `ti-mode=hybrid` and the MetaDefender `X-RateLimit-Remaining` header reports <5 calls left
- **WHEN** the Agent needs to rescan a 15 MB sample during a BAS task
- **THEN** it records the hash + metadata, tags the artifact as `needs_server_scan`, and skips the direct upload so the Server orchestrator can continue without hitting the quota.

### Requirement: Suspicious Artifact Escalation
Agent MUST be able to escrow suspicious files (encrypted & chunked) to the Server so that central services can run external scans and share artifacts with other consumers.

#### Scenario: Chunked upload with server escrow
- **GIVEN** a respond task detects a 40 MB executable without a local verdict
- **WHEN** `ti-mode=server` is active
- **THEN** the Agent requests a pre-signed upload URL from the Server, streams the encrypted archive in chunks (with sha256 metadata), and includes the artifact reference inside `ReportResult`, enabling the Server to queue the sample for OpenTIP/MetaDefender scanning.

### Requirement: BAS Step Telemetry & Sandbox Stats
Agent MUST emit per-step BAS telemetry (status, stdout/stderr, sandbox usage, fallback) in near real time so Server-side scenario management and UIs can reflect execution progress.

#### Scenario: Step lifecycle streaming
- **GIVEN** a BAS scenario with five steps, three of which request sandbox execution
- **WHEN** each step starts and completes
- **THEN** the Agent sends a step update (`run_id`, `step_id`, `status`, `sandboxed`, `started_at`, `ended_at`) to the Server within 2 seconds, and any sandbox fallback is explicitly flagged for downstream correlation.

### Requirement: Automation Action Executor
Agent MUST expose a secure action channel so approved Playbooks can trigger low-level responses (process isolation, firewall block, YARA scan) with idempotency and audit trails.

#### Scenario: Server-triggered isolation command
- **GIVEN** a Playbook instructs an Agent to isolate a PID as part of an automatic response
- **WHEN** the Agent receives an `ExecuteAction` gRPC call containing `action_id=auto-isolate-123`, command `isolate_process`, and parameters
- **THEN** it validates permissions, executes the action once, returns structured output (success/exit code/log excerpt), and records the action + correlation ID in its local audit log so the Server and UI can confirm execution.

### Requirement: Remote Agent Reliability Test Coverage
Agent remote control logic MUST ship deterministic automated tests that simulate the full server contract so regressions in registration, execution, or replay are caught before release. Statement coverage for `agent/internal/agent` and `agent/internal/agent/remote` MUST remain at 100% via the documented `go test` command.

#### Scenario: Remote loop simulated end-to-end
- **GIVEN** a fake gRPC server that exercises Register → Heartbeat → PullTasks → ReportResult, and stubbed task runners registered through the new test hook
- **WHEN** the remote runner executes with injected clients/stores
- **THEN** metadata defaults (agent name fallback, capability list, telemetry sampler) match the contract in `agent/internal/agent/daemon.go`
- **AND** task execution results are cached, retried, and acknowledged exactly once even when transient errors are injected.

#### Scenario: Result replay after network loss
- **GIVEN** the FileStore contains cached `ReportResultRequest` objects and the fake server intentionally drops the first delivery
- **WHEN** connectivity resumes
- **THEN** `flushPending` resubmits every cached artifact in order and prunes the on-disk state, proving the resiliency guarantee described in `Resilient Result Delivery`.

#### Scenario: Payload parity and sandbox enforcement
- **GIVEN** payloads that include flags, reserved keys, sandbox overrides, and multiple encodings (string/bool/duration)
- **WHEN** `applyRemotePayload` and `mergeSandboxConfig` run inside the remote runner
- **THEN** the resulting `tasks.TaskRequest` mirrors the CLI defaults, enforces quiet/JSON output, and merges sandbox allow/deny lists exactly as documented, with 100% helper coverage preventing regressions.

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

### Requirement: Cross-platform System Event Collectors
Agent MUST 实现统一的 `EventCollector` 接口，以 Windows ETW 与 Linux eBPF 为底座采集核心系统事件（进程、文件、注册表、系统调用），并将事件格式化为 `SystemEvent{timestamp,event_type,source,payload,metadata}` 输送到现有 telemetry 通道。

#### Scenario: CLI capture session
- **WHEN** 操作者在受管节点运行 `deyes collect --backend=etw --providers=Kernel,Security --duration=300s --output=events.json`
- **THEN** Agent 启动短时 ETW 会话，按配置 Provider/过滤条件写入 JSONL/STDOUT，结束后清理会话与缓冲，并在失败时输出明确诊断

#### Scenario: Probe streaming session
- **GIVEN** Agent 以常驻模式运行在 Linux 节点并接收启用 eBPF 的配置（采样率、探针列表）
- **WHEN** `collector.Manager` 装配 `ebpfCollector`、加载 CO-RE 程序并把 ringbuffer 中的事件转换成 `SystemEvent`
- **THEN** 事件将通过 Agent telemetry/gRPC 通道实时上传，遇到 backpressure 时需启用本地缓存/丢弃策略并上报状态

#### Scenario: Performance guardrails
- **WHEN** 任一 Collector 处于运行状态
- **THEN** Agent 需持续采样 CPU、内存、丢包率，确保采集开销维持在 CPU<5%、内存<100 MB、事件延迟<100 ms，并在超过阈值时降低采样率或暂停会话并记录告警

### Requirement: Collector configuration and telemetry
Agent MUST 支持 CLI 与 Probe 双模式下的统一配置 schema（Provider/Probe、过滤、采样率、输出），能够动态应用 Server 下发的启停/过滤变更，并回传 Collector 状态与诊断日志。

#### Scenario: CLI configuration schema
- **WHEN** CLI 使用 `--config=collector.yaml` 指定 Provider/Probe、过滤字段、输出目标
- **THEN** Agent 解析并验证 schema（含权限检测、平台兼容性），在运行期间提供 `Ctrl+C` 安全退出与进度统计

#### Scenario: Probe dynamic reconfiguration
- **GIVEN** Server 通过配置通道下发“启用 Windows Sysmon Provider + 过滤 PID=1234”
- **WHEN** Agent 收到指令
- **THEN** 需在 60 秒内应用变更（必要时重建 Session/Probe）、保留队列中的在途事件，并把状态（启用的 Provider、采样率、缓冲水位）写入心跳/遥测

#### Scenario: Failure reporting
- **WHEN** Collector 因权限不足、内核不兼容或缓冲溢出而退出
- **THEN** Agent MUST 记录可诊断日志、在心跳中报告 `collector_status=degraded` 与错误详情，并提供 CLI/Probe 级别的退出码或告警，避免 silent failure

### Requirement: Agent CLI Debug Mode Telemetry
Agent CLI commands (respond, audit, inventory, supplychain, baseline, bas, collect) MUST expose a debug mode toggle that streams timestamped lifecycle logs plus a dynamic progress percentage to STDOUT while persisting the same events into task metadata for remote troubleshooting.

#### Scenario: Debug flag streams lifecycle logs
- **GIVEN** an operator runs `d-eyes respond --targets agent-1 --debug`
- **WHEN** runner phases occur (config load, profile selection, IP enumeration, sandbox warm-up, artifact upload, result synthesis)
- **THEN** the CLI prints timestamped structured lines (module, phase, message) in real time, and the collected events are serialized into `ExecutionResult.metadata["debug.logs"]` so remote / Ops Console views can replay the timeline.

#### Scenario: Progress percentage stays in sync with runner milestones
- **GIVEN** a BAS task with five steps and a sample upload executes with debug mode enabled
- **WHEN** each step starts/completes or artifact upload chunks finish
- **THEN** the CLI refreshes a progress indicator (e.g., `Progress 60% · 3/5 steps · uploading sample.zip`) at least every 2 seconds using the runner milestone counts, and the same samples are appended to `ExecutionResult.metadata["debug.progress"]` for remote inspection.

#### Scenario: Inventory sweep outputs IP diagnostics
- **GIVEN** an operator runs `d-eyes inventory --config assets.yaml --debug` to enumerate a subnet
- **WHEN** the runner iterates through each IP/asset and records reachability or fingerprint results
- **THEN** the CLI emits debug lines like `10.1.0.25 reachable via ssh, missing patches=3` and updates the progress indicator based on IP count (e.g., `Progress 40% · 12/30 IPs scanned`), and the same per-IP samples are captured within `ExecutionResult.metadata["debug.logs"]`/`["debug.progress"]` for remote consumers.

#### Scenario: Collector mode streams ETW/eBPF events
- **GIVEN** an operator runs `d-eyes collect --backend=etw --providers=Kernel,Security --debug`
- **WHEN** the collector ingests ETW/eBPF events and batches them for upload
- **THEN** the CLI prints debug entries for each provider/event sample (timestamp, provider, summary payload) and refreshes a progress indicator tied to event batches/duration (e.g., `Progress 25% · 5k events captured · backend=etw`), while persisting the emitted entries under `ExecutionResult.metadata["debug.logs"]` and `["debug.progress"]` so remote diagnostics can replay the capture session.

### Requirement: Shell-free Windows Privilege & Interface Inspection
Agent MUST avoid invoking OS shell commands to determine Windows privilege state or to collect interface metadata in its default execution paths, and MUST instead rely on native APIs or library calls while producing equivalent diagnostic output.

#### Scenario: Windows privilege detection without shell execution
- **GIVEN** the Agent runs on Windows
- **WHEN** inventory/port scanning needs to decide whether privileged probes (raw sockets/SYN/UDP) are allowed
- **THEN** it uses Windows token membership / privilege APIs (not `net session`), and toggles the privileged scan paths accurately.

#### Scenario: Host summary collects interface info without ipconfig
- **GIVEN** an operator runs `d-eyes detect export` on Windows
- **WHEN** interface details are collected for the report
- **THEN** the Agent uses native/library interfaces to fetch adapter/address data and writes them into the summary report without invoking `ipconfig`.

### Requirement: Threat Intel Hybrid Degrades Gracefully
Agent MUST ensure `ti-mode=hybrid` still produces local heuristic findings when remote API keys are missing or when remote sources are temporarily unavailable, while clearly labeling sources and degradation reasons in outputs and metadata.

#### Scenario: Hybrid mode without API keys returns local findings
- **GIVEN** `ti-mode=hybrid` and no remote API keys are configured
- **WHEN** respond modules extract indicators (IPs, hashes, domains) for threat intel enrichment
- **THEN** the Agent records local heuristic findings, labels the source as local-only, and emits a notice explaining remote connectors are inactive.

#### Scenario: Hybrid mode handles quota exhaustion
- **GIVEN** `ti-mode=hybrid` and a remote source responds with quota exhaustion / rate limit
- **WHEN** the Agent attempts to enrich an indicator during `respond` or `bas`
- **THEN** it skips further remote lookups for that source, records the fallback reason, and continues to return local heuristic findings without failing the task.

