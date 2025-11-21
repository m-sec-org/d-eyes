# server-core Specification

## Purpose
TBD - created by archiving change add-server-core-modules. Update Purpose after archive.
## Requirements
### Requirement: Agent Registration & Heartbeat Service
Server MUST 提供安全的 gRPC 服务供 Agent 注册与心跳同步，确保 Agent 状态实时可见。

#### Scenario: Token Authenticated Registration
- **GIVEN** 预配置的合法 token 与 TLS 证书
- **WHEN** Agent 调用 `AgentService.Register` 并建立心跳流
- **THEN** Server 在 3 秒内持久化 Agent 元数据并返回唯一 `agent_id`
- **AND** 若心跳在 15 秒内缺失，Server 将 Agent 标记为 offline 并记录事件

### Requirement: Task Dispatch & Lease Management
Server MUST 支持通过优先级队列向 Agent 分配任务，使用租约机制保证幂等与超时重试。

#### Scenario: Lease Renewal Failure
- **GIVEN** REST API 创建了 `respond` 类型任务，优先级为高
- **WHEN** Scheduler 将任务分配给满足能力的 Agent 并设置 120 秒租约
- **AND** Agent 未在租约期内报告结果
- **THEN** Server 自动回收租约并将任务状态恢复为 `pending`，同时 `retry_count` 增加 1

### Requirement: Result Persistence & Query
Server MUST 持久化任务执行结果与摘要，并通过 REST API 提供查询能力。

#### Scenario: Fetch Task Summary
- **GIVEN** Agent 通过 `ReportResult` 成功上传任务结果
- **WHEN** 客户端调用 `GET /api/v1/tasks/{id}`
- **THEN** Server 返回 `status=succeeded` 与结果摘要（风险计数、产出 artifact 列表）
- **AND** 结果应包含任务创建时的 metadata 与执行耗时

### Requirement: Threat Intelligence Orchestrator
Server MUST provide a central service that ingests agent-submitted artifacts, executes OpenTIP/MetaDefender scans with quota management, caches verdicts, and exposes REST/SSE interfaces.

#### Scenario: File escalated to dual engines
- **GIVEN** an Agent uploads an encrypted artifact referencing hash `abc123`
- **WHEN** the `/api/v1/threat-intel/jobs` worker dequeues it
- **THEN** the Server first queries MetaDefender (`POST /v4/file` → `GET /v4/file/{data_id}`) and OpenTIP (`POST /api/v1/scan/file?filename=abc123`), stores both verdicts with TTL, and pushes a `verdict_ready` event to `/api/v1/threat-intel/stream` so the originating task and operators can view the combined result.

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

