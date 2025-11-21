# agent-server-foundation Specification

## Purpose
TBD - created by archiving change plan-agent-server-foundation. Update Purpose after archive.
## Requirements
### Requirement: Agent Registration and Heartbeat
Server MUST expose a secure gRPC 接口以注册 Agent 并维持心跳，确保实时感知在线状态。

#### Scenario: TLS Enrolled Agent
- **GIVEN** Agent 配置了有效的 token 与 TLS 证书
- **WHEN** Agent 向 `/grpc.AgentService/Register` 提交注册请求并建立心跳流
- **THEN** Server 持久化 Agent 元数据并在 3 秒内返回成功响应
- **AND** 后续心跳周期内若 15 秒未收到数据，Server 将 Agent 标记为 offline

### Requirement: Remote Task Execution Loop
Agent MUST 能够领取 Server 下发的 respond/baseline 任务，执行后上报结果，Server 应追踪状态并保存摘要。

#### Scenario: Respond Task Roundtrip
- **GIVEN** REST API `/api/v1/tasks` 创建了 respond 任务且至少有一台在线 Agent
- **WHEN** Agent 通过 `PullTask` 获取任务并调用共享执行器运行 respond 模块
- **THEN** Agent 在任务完成 2 秒内通过 `ReportResult` 回传执行结果
- **AND** Server 将任务状态更新为 `succeeded` 并可通过 REST 查询到输出摘要

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

