# align-ops-console Specification

## Purpose
TBD - created by archiving change add-frontend-backend-alignment. Update Purpose after archive.
## Requirements
### Requirement: Task-Type Specific Configuration Contracts
Server MUST 提供统一的任务类型与 profile API，使前端能够针对 respond、audit、inventory、supplychain 等任务渲染专用表单并校验参数。

#### Scenario: Inventory Task Port Range Enforcement
- **GIVEN** 前端调用 `POST /api/v1/task-types/inventory/tasks` 并在 payload 中设置 `port_range: "1-1024"`
- **WHEN** Server 校验 profile schema 中的 `port_range` 与 `service_checks`
- **THEN** 若范围与受支持协议匹配，任务被创建并返回 profile 快照
- **AND** 若字段缺失或超出允许范围，Server 返回 422 并包含 schema 提示，前端得以提示用户

### Requirement: Rich Result Visualization Payloads
Server MUST 为每种任务类型返回结构化可视化数据，包括网络连通图、文件扫描风险分布及主机摘要，以驱动前端组件。

#### Scenario: Network Connectivity Graph Output
- **GIVEN** respond 任务完成且 Agent 报告 `connections` 数组与 `risk_scores`
- **WHEN** 客户端调用 `GET /api/v1/tasks/{id}/visuals?type=network`
- **THEN** Server 返回包含 `nodes`, `edges`, `severity_buckets` 的 JSON
- **AND** 结果中附带时间戳及 Agent 列表，供前端绘制拓扑与风险热力图

### Requirement: BAS Scenario Lifecycle Management
Server MUST 提供 BAS 场景创建、编排、审批及安全边界配置接口，支持按步骤顺序执行并进行权限控制。

#### Scenario: Scenario Approval Gate
- **GIVEN** 用户通过 `POST /api/v1/bas-scenarios` 创建包含多个 action 的场景
- **WHEN** 安全审核者调用 `POST /api/v1/bas-scenarios/{id}/approve`
- **THEN** Server 在记录审批轨迹后才允许调度执行，并确保 `resource_limits`、`network_boundaries` 已配置，否则拒绝执行

### Requirement: Agent Asset Management & Monitoring
Server MUST 暴露 Agent 列表、详情、心跳与能力指标，并支持标签/分组管理，以便前端监控和筛选。

#### Scenario: Agent Heartbeat Health View
- **GIVEN** Agent 通过 gRPC 心跳上报 `capabilities`, `latency_ms`, `packet_loss`
- **WHEN** 前端调用 `GET /api/v1/agents?group=production`
- **THEN** 响应包含每个 Agent 的在线状态、最近心跳时间、指标及标签
- **AND** 若心跳超时，Server 提供 `status: offline` 与原因，供前端高亮告警

### Requirement: Report Template & Multi-Format Export
Server MUST 支持报告模板管理、任务结果与模板合成，以及 PDF/HTML/JSON 多格式导出，支持受控分享。

#### Scenario: Template-Based Export
- **GIVEN** 管理员上传 `respond-risk` 模板并标记为最新版
- **WHEN** 用户调用 `POST /api/v1/reports` 指定 `template_id` 与 `task_id`
- **THEN** Server 生成报告 artifact，支持 `format=pdf|html|json`
- **AND** 返回下载链接与可选分享 token，供前端触发分享流程

### Requirement: Real-Time Monitoring & Intervention Stream
Server MUST 推送任务执行进度、关键操作、异常与人工干预事件，并允许前端通过安全通道触发暂停/重试等指令。

#### Scenario: Interactive Respond Task Control
- **GIVEN** 前端订阅 `wss://.../task-stream?task_id=123`
- **WHEN** 后端发送 `progress` 与 `alert` 事件，并收到用户 `POST /api/v1/tasks/123/actions` 请求 `pause`
- **THEN** Server 广播最新状态给所有订阅者，并在 2 秒内暂停任务且记录谁触发了干预

### Requirement: Fine-Grained RBAC & Audit Trails
Server MUST 实现资源级别 RBAC、敏感操作审批与可检索审计日志，以满足合规要求。

#### Scenario: Sensitive Action Approval & Audit
- **GIVEN** 用户尝试触发 BAS 场景执行，操作被标记为 `sensitive`
- **WHEN** RBAC 引擎发现用户缺少 `bas.execute` 权限并要求审批
- **THEN** Server 记录一条审计日志，通知审批人完成授权
- **AND** 审批通过后，日志应捕捉审批链与最终执行结果，可通过 `/api/v1/audit-logs` 查询和过滤

### Requirement: Unified Theme Tokens & Control Variants
Ops Console MUST expose a shared theme token system that drives buttons, inputs, selectors, radios, checkboxes and upload控件的主次状态、禁用/错误反馈与暗色模式基线，确保不同页面的视觉与交互一致。

#### Scenario: Primary Actions Use Shared Tokens
- **GIVEN** 主题层定义 `action.primary`, `action.secondary`, `danger` 等 Token，并指定 hover/focus/disabled 状态
- **WHEN** 任务创建页或 BAS 场景审批页渲染 “创建/执行/审批” 等主操作按钮
- **THEN** 这些按钮均使用相同的 Token、字号与圆角，hover/focus 状态保持一致
- **AND** 当按钮被禁用或呈现危险操作时，颜色/描边/提示与 Token 规范一致，提供 aria-label 说明

#### Scenario: Form Controls Share Validation Feedback
- **GIVEN** 输入框、Textarea、Select、Radio、Checkbox 与 Upload 控件引用统一的 `field.*` Token（边框、背景、辅助文本）
- **WHEN** 用户触发 focus、填写错误或查看禁用字段
- **THEN** 所有控件显示统一的高亮边框、错误提示颜色及帮助文本排版
- **AND** 无论位于任务、Agent 还是审计模块，控件高度、内边距与标签位置保持一致，便于无障碍与键盘操作

### Requirement: Threat Intelligence Workspace
Ops Console MUST expose a dedicated UI for IOC/file lookups, meta-data timelines, and artifact triage leveraging the Server’s threat intelligence APIs and streams.

#### Scenario: Dual-source verdict display
- **GIVEN** a user pastes a SHA256 into the IOC search bar
- **WHEN** the console calls `GET /api/v1/threat-intel/iocs/{sha}`
- **THEN** it renders OpenTIP & MetaDefender verdicts, enrichment attributes, related tasks/agents, and live status badges that update via `/api/v1/threat-intel/stream` when the backend finishes scanning the associated artifact.

### Requirement: Anomaly Graph & Timeline
Ops Console MUST visualise anomaly events with graphs/timelines, allow pivoting across entities, and offer evidence export.

#### Scenario: Attack path drill-down
- **GIVEN** `/api/v1/anomalies/stream` emits a new anomaly
- **WHEN** the analyst opens it
- **THEN** the UI shows a node-link graph (agents, IPs, IOC, tasks) plus a chronological table; clicking an entity filters related anomalies and allows exporting the evidence bundle as JSON/PDF.

### Requirement: Playbook Builder & Approval UX
Ops Console MUST provide low-code Playbook authoring, simulation, approval, execution monitoring, and manual trigger controls with RBAC enforcement.

#### Scenario: Draft → approve → monitor
- **GIVEN** an admin drafts a Playbook via the visual builder
- **WHEN** they submit it for review
- **THEN** reviewers receive an in-app approval request; upon approval the Playbook can be enabled, and live runs show per-action status, logs, and rollback controls without refreshing the page.

### Requirement: Compliance Workspace
Ops Console MUST expose dashboards for multi-framework scores, gap matrices, remediation tracking, and on-demand report export.

#### Scenario: Gap matrix + report download
- **GIVEN** the CIS v8 dashboard shows 80% compliance
- **WHEN** a user filters by “High severity gaps” and clicks “Export”
- **THEN** the matrix highlights affected assets/tasks, shows remediation progress bars, and the user receives a signed PDF/JSON generated via the Server report endpoint.

### Requirement: BAS Workbench & Attack Chain Visuals
Ops Console MUST include a BAS scenario editor, execution monitor, and attack-chain visualisation aligned with Server-side orchestration.

#### Scenario: Scenario edit and live run
- **GIVEN** an engineer edits a BAS scenario in the graphical builder (dragging steps, defining variables)
- **WHEN** they launch the run
- **THEN** the workbench streams per-step updates, flagging sandbox fallback and failed actions, while the attack-chain diagram updates in real time and links to threat intel/anomaly findings for the same run.

### Requirement: Advanced Reporting Hub
Ops Console MUST provide a centralized hub where operators can browse generated reports (threat intel, anomaly, compliance, BAS), schedule exports, and share signed links.

#### Scenario: Scheduled report delivery
- **GIVEN** a user schedules a weekly “Threat Intel + Compliance” pack
- **WHEN** the schedule triggers
- **THEN** the hub shows the run status, provides download links (PDF/HTML/JSON), and allows copying a time-bound sharing URL with revocation controls.

### Requirement: BAS Sandbox Injection
BAS runner MUST expose injectable `ScenarioLoader`, `SandboxExecutor`, and `TelemetryEncoder` interfaces so tests and alternative engines can reuse the BAS workflow without invoking real sandboxes.

#### Scenario: Custom scenario loader
- **WHEN** a test injects a fake scenario loader
- **THEN** BAS runner processes the provided scenarios without reading filesystem, ensuring deterministic tests.

#### Scenario: Sandbox executor abstraction
- **WHEN** a custom sandbox executor is injected (e.g., for testing or alternative backends)
- **THEN** BAS runner uses it to run steps and encode telemetry while preserving default behavior when no override is provided.

### Requirement: Core Service Injection
Agent MUST expose injectable core-service interfaces (`ThreatIntelProvider`, `SandboxController`, `RuleEngineFactory`) so task runners and tests can operate without tightly coupling to concrete implementations.

#### Scenario: Custom ThreatIntel provider
- **WHEN** a test or plugin injects a fake ThreatIntel provider
- **THEN** TaskRequest initialization uses it instead of creating the default manager, enabling deterministic tests.

#### Scenario: Sandbox/YARA factories
- **WHEN** alternate sandbox controllers or rule engine factories are provided
- **THEN** runners reuse the injected implementations while CLI/remote defaults remain unchanged.

### Requirement: Agent Runner Injection Layer
Task runners (respond, inventory, supplychain, baseline, BAS) MUST expose injectable executor interfaces so that the CLI, remote agent, and unit tests can share the same code paths while swapping heavy dependencies (filesystem, sandbox, YARA) when needed.

#### Scenario: Respond runner with pluggable modules
- **GIVEN** an alternate `RespondExecutor` is supplied (e.g., test double)
- **WHEN** the respond runner executes via CLI or remote mode
- **THEN** it uses the injected executor, enabling deterministic tests without affecting production behavior.

#### Scenario: ThreatIntel and sandbox providers
- **GIVEN** `ThreatIntelProvider` and `SandboxController` implementations
- **WHEN** TaskRequest initializes in CLI or remote contexts
- **THEN** the provider interfaces abstract cache/network/sandbox operations, keeping D-Eyes flexible as a standalone tool or server-managed agent.

### Requirement: Task & Detection Coverage Enforcement
Agent task runners, ThreatIntel SDK, sandbox orchestration, and Go-based detection backend MUST ship automated tests achieving 100% statement coverage so regressions in business logic are caught without relying on CLI stubs.

#### Scenario: Task runner and sandbox tests
- **GIVEN** the test suite executing respond/inventory/supplychain/baseline/bas runners with fake managers
- **WHEN** profile selection, validation, risk aggregation, and sandbox approval code paths are exercised
- **THEN** coverage reports show 100% statements for `agent/internal/tasks/*` and sandbox helpers, preventing unnoticed behavioral drift.

#### Scenario: ThreatIntel & detection engine tests
- **GIVEN** unit tests for `pkg/threatintel` and `internal/detect/*` construct synthetic indicators and YARA rules (success/error cases)
- **WHEN** `go test -coverpkg` runs across these packages
- **THEN** coverage stays at 100%, ensuring classification heuristics and rule parsing logic remain stable.

### Requirement: CLI Regression Coverage
Agent CLI commands MUST ship automated integration tests that exercise every public command (respond, audit, inventory, supplychain, baseline, bas, remote) to guarantee flag/config parity and 100% statement coverage for the CLI entry layer.

#### Scenario: Config fallback verified via CLI tests
- **GIVEN** the CLI regression suite is executed
- **WHEN** commands run without explicit `--targets`/`--profile`
- **THEN** the tests assert config fallbacks and notices behave exactly as documented, preventing future regressions.

#### Scenario: Remote CLI parity ensured
- **GIVEN** the CLI regression suite stubs `RunRemote`
- **WHEN** `d-eyes remote` is invoked in tests
- **THEN** the stub receives the expected config payload, ensuring remote CLI wiring stays in sync with the automation loop.

### Requirement: Testing & Coverage Governance
Ops Console program MUST ensure the Agent codebase maintains 100% statement coverage across CLI, remote daemon, tasks, detect pipeline, sandbox, SBOM, and supporting packages.

#### Scenario: Coverage Gate in CI
- **GIVEN** contributors push to any branch
- **WHEN** CI runs `go test -coverpkg` over all Agent packages
- **THEN** the pipeline fails unless total coverage equals 100% with artifacts published for review.

#### Scenario: Documented Coverage Command
- **GIVEN** developers read the Agent README / contributing guide
- **WHEN** they follow the documented coverage command
- **THEN** running it locally reproduces the CI checks, ensuring regressions are caught before PR submission.

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

### Requirement: Detect Remote Dispatch UX Contract
Ops Console MUST provide an operator workflow that can create and observe remotely-dispatched detect tasks (`detect.diag`, `detect.memscan`) using the Server task catalog (type/profile/schema) and the stable detect report/read surface.

#### Scenario: Create detect.diag task with capability filtering
- **GIVEN** the operator opens the task creation drawer in Ops Console
- **WHEN** they choose task type `detect.diag` and a seeded profile (e.g. `profile="detect.diag"`) and submit the form
- **THEN** Ops Console MUST call `POST /api/v1/tasks` with `type="detect.diag"` and `profile="detect.diag"`
- **AND** it MUST include `metadata.required_capabilities="detect.diag"` to enable scheduler capability filtering
- **AND** it MUST include `payload.backend` and `payload.rule` fields following the task catalog schema (e.g. `backend="auto"`, `rule=""`)

#### Scenario: Create detect.memscan task with guardrails and approvals
- **GIVEN** the operator chooses task type `detect.memscan` (Windows-only) in Ops Console
- **WHEN** they prepare a memscan task payload
- **THEN** Ops Console MUST enforce client-side guardrails that exactly one of `payload.pid` or `payload.all` is provided
- **AND** it MUST include `metadata.required_capabilities="detect.memscan"` so only Agents advertising `detect.memscan` can lease the task
- **AND** it MUST explain that memscan requires a Windows Agent with explicit opt-in (for example: `allow_memscan="true"` sourced from Agent configuration/registration)
- **AND** it MUST require explicit approval metadata before submission: `memscan_approval_required="true"` and `memscan_approved="true"`
- **AND** **WHEN** `payload.evidence=true` or `payload.minidump=true` is requested
- **THEN** Ops Console MUST additionally require `memscan_evidence_approved="true"` and explain the additional risk to the operator

#### Scenario: View detect report and surface error_code guidance
- **GIVEN** a `detect.diag`/`detect.memscan` task has a completed run
- **WHEN** the operator opens the task details or report view
- **THEN** Ops Console MUST retrieve and display the report using `GET /api/v1/tasks/{id}/detect/report`
- **AND** it MUST surface `exit_code` and `error_code` with recommended actions
- **AND** **WHEN** `error_code` equals `detect.memscan.approval_required` or `detect.memscan.evidence_approval_required`
- **THEN** the UI MUST explain that the Agent rejected execution due to missing approval metadata and guide the operator to resubmit with the required fields (or disable evidence/minidump)

#### Scenario: Detect report RBAC denied (403)
- **GIVEN** the operator does not have the `reports.view` permission
- **WHEN** Ops Console calls `GET /api/v1/tasks/{id}/detect/report`
- **THEN** the Server responds with HTTP 403
- **AND** Ops Console MUST surface a “permission denied” message and suggest requesting access (instead of rendering an empty/incorrect report)

#### Scenario: Detect report not available yet (404)
- **GIVEN** a `detect.diag`/`detect.memscan` task exists but does not yet have an available detect report (for example: no task run, or the latest run has no summary)
- **WHEN** Ops Console calls `GET /api/v1/tasks/{id}/detect/report`
- **THEN** the Server responds with HTTP 404
- **AND** Ops Console MUST surface a “report not available yet” message and allow the operator to retry later (or fall back to task-level details)

### Requirement: Agent Labels UI Clarifies Source Of Truth
Ops Console MUST clearly communicate that Agent labels used for capabilities/behavior are sourced from Agent Register metadata, and that Server-side label edits are non-authoritative and may be overwritten on the next Agent re-registration.

#### Scenario: Editing reserved labels shows overwrite warning
- **GIVEN** the operator opens the Agent label editor in Ops Console
- **WHEN** they view or attempt to edit reserved keys such as `allow_memscan`, `build.commit`, `build.tags`, or `mode`
- **THEN** Ops Console MUST display a warning that Server-side edits will be overwritten by the Agent’s next Register payload
- **AND** it MUST recommend changing the Agent local configuration as the source of truth (for example: `remote.labels.allow_memscan="true"` for memscan opt-in)

### Requirement: Audit Report Viewing UX Contract
Ops Console MUST provide a stable, actionable audit report viewing experience using the Server `audit/report` endpoint, including deterministic handling for RBAC denials and “report not available yet” states.

#### Scenario: View audit report successfully
- **GIVEN** an `audit` task has a completed run
- **WHEN** the operator opens the task details or report view
- **THEN** Ops Console MUST retrieve the report using `GET /api/v1/tasks/{id}/audit/report`
- **AND** it MUST display a stable subset of fields including `task_id`, `task_type`, `profile`, `run_id`, `agent_id`, `task_status`, and `completed_at`
- **AND** it MUST display `exit_code` and `error_code` with actionable guidance when present

#### Scenario: Audit report RBAC denied (403)
- **GIVEN** the operator does not have the `reports.view` permission
- **WHEN** Ops Console calls `GET /api/v1/tasks/{id}/audit/report`
- **THEN** the Server responds with HTTP 403
- **AND** Ops Console MUST surface a “permission denied” message and suggest requesting access (instead of rendering an empty/incorrect report)

#### Scenario: Audit report not available yet (404)
- **GIVEN** an `audit` task exists but does not yet have an available audit report (for example: no task run, or the latest run has no summary)
- **WHEN** Ops Console calls `GET /api/v1/tasks/{id}/audit/report`
- **THEN** the Server responds with HTTP 404
- **AND** Ops Console MUST surface a “report not available yet” message and allow the operator to retry later (or fall back to task-level details)

