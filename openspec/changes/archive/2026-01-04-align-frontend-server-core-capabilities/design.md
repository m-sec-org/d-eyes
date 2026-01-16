# Server ↔ Frontend Core Capabilities 对齐设计（草案）

## Context

在 `align-server-agent-core-capabilities` 归档后，Server 已提供：

- task catalog（`/api/v1/task-types`、`/api/v1/task-profiles`）作为 profile/schema 驱动表单与 payload 校验的基线
- audit/detect 的 report/read 稳定读取面（`/api/v1/tasks/{id}/audit/report`、`/api/v1/tasks/{id}/detect/report`）
- detect 远程调度语义：`detect.diag` / `detect.memscan`（Windows-only + `allow_memscan="true"` opt-in + 审批 metadata + error_code）

但控制台端尚未把这些合同“产品化”（创建→调度→查看→排障闭环）。

## Goals / Non-Goals

Goals：
- 任务创建默认带 `required_capabilities`，减少误调度与失败噪声。
- 控制台端补齐 detect.diag/memscan 的创建 UX（含 memscan 审批与 guardrails）。
- 控制台端补齐 audit/detect 报告查看与 error_code 提示。
- 在 Agent 标签页合同化 “labels 权威来源” 与保留键提示，避免误用 labels 控制 Agent 能力。

Non-Goals：
- 不在本变更内实现 outputs/artifacts 的集中下载/回收能力。
- 不在本变更内强制落地 memscan 的 Server 端 RBAC/审批流程（仅提供建议与 UI 引导）。

## Decisions

### 0) 鉴权/身份 Headers 注入（生产联调前置条件）

- 生产形态由 **网关/反向代理** 统一注入 `X-API-Key` 与 `X-User`/`X-User-Role`（敏感接口再叠加 `X-MFA-Code`）。
- 浏览器侧不直接持有/发送 API Key；`Authorization: Bearer` 仅用于网关侧登录态/SSO（Server 本身不解析）。
- 本地联调可通过 dev-proxy 注入上述 headers（或临时关闭 `security.api_keys`）。

### 1) `required_capabilities` 默认策略

- `required_capabilities` 存放在 `metadata.required_capabilities`（字符串，逗号分隔）。
- Frontend：创建任务时默认注入 `metadata.required_capabilities`：
  - **优先**使用 task catalog 的 `task_type.capabilities[]`（逗号拼接，按原顺序输出）。
  - **兜底**：若 catalog 未返回 capabilities，则使用 `<task.type>`。
- Server：当请求未提供 `metadata.required_capabilities` 且 task type 在 task catalog 中存在且定义了 `capabilities[]` 时，自动补齐默认值；显式传入时不覆写；未知 task type 不强制。

理由：同时兼容 UI/脚本调用，减少“lease 给不支持的 Agent”导致的失败与重试噪声。

### 2) detect.memscan 的 UI guardrails 与审批字段

- guardrails（提交前校验）：
  - `payload.pid` 与 `payload.all` 必须二选一（满足 profile constraint：`xor(pid, all)`）。
  - 若提供 `pid`，必须为 `>= 1` 的整数；选择 `all=true` 时应清空/省略 `pid`。
- 审批字段（均写入 task **metadata**，值为字符串，推荐输出小写 `true`）：
  - 必需：`memscan_approval_required="true"`、`memscan_approved="true"`（缺失会被 Agent 以 exit_code=65 拒绝）。
  - **WHEN** `payload.evidence=true` 或 `payload.minidump=true`  
    **THEN** 额外必需：`memscan_evidence_approved="true"`（同样以 exit_code=65 拒绝）。
- gating 文案：UI 需提示 `detect.memscan` 为 Windows-only，且需要 Agent 侧显式 opt-in（`allow_memscan="true"`）。
- 错误展示：若 `error_code=detect.memscan.approval_required` / `detect.memscan.evidence_approval_required`，UI 显示推荐动作（补齐审批字段/关闭 evidence/minidump）。

### 3) audit/detect report/read 的展示字段与错误提示口径

- 对 audit/detect：UI 以 `GET /api/v1/tasks/{id}/audit/report`、`GET /api/v1/tasks/{id}/detect/report` 作为稳定读取面。
- 展示字段（最小稳定子集）：
  - 任务元信息：`task_id`、`task_type`、`profile`、`run_id`、`agent_id`、`task_status`、`completed_at`
  - 执行摘要：`result.summary.command`、`result.summary.status`、`result.summary.duration_seconds`、`result.summary.risks`、`result.summary.notes`
  - 产物列表：`result.summary.outputs[]`、`result.artifacts[]`（当前多为 Agent 本地路径；UI 仅提供复制路径/说明，不提供“下载”）
  - 错误与排障：`exit_code`、`error_code`、`result.error`（按 error_code 显示可操作指引）
- 关键错误提示：
  - `error_code=detect.memscan.approval_required`：提示补齐 `memscan_approval_required/memscan_approved`
  - `error_code=detect.memscan.evidence_approval_required`：提示补齐 `memscan_evidence_approved` 或关闭 evidence/minidump
  - HTTP 403：提示无 `reports.view` 权限
  - HTTP 404（summary 不可用）：提示任务尚未产出报告（可提示稍后重试/查看 last_run）
- 调试区（可选但推荐）：UI 可提供默认折叠的可展开面板，展示 `result.metadata`、`run_metadata`，并可选展示 `result` / `result.summary` 全量 JSON，用于快速排障与复现（例如查看 `failed_steps`、telemetry、Runner 注入的诊断键）。

### 4) labels 权威与保留键提示

- UI 侧将 `allow_memscan`、`mode`、`build.*` 等保留键标记为 “Agent-managed understanding”，并明确提示 Server 侧编辑会被 Agent 下次 Register 覆盖。

### 5) 表单可访问性约定（`FormField`）

- 错误/提示信息应通过 `aria-describedby` 与具体控件关联，避免把错误文本拼入 `<label>` 的可访问名称（否则会污染 `getByRole(..., { name })` 与读屏体验）。
- **多控件字段（范围/区间输入等）**：`FormField` 的 `label` 仅作为组标题（`role="group"`），因此**每个子控件必须提供明确的可访问名称**（例如 `aria-label`/`aria-labelledby`，或提供对应的可见/隐藏 `<label>`）。
- 对新增的多控件字段，应在同一 PR 中补充回归用例：至少覆盖“每个子控件可被按 name 查询”与“错误/提示可被读屏关联”的断言，防止后续重构回退 a11y 语义。

## Risks / Trade-offs

- Server 默认补齐 required_capabilities 后，某些“依赖 base runner 解析 dot task type”但未宣称 capability 的旧用法可能被能力过滤挡住；因此仅在 catalog 可解析到 capabilities 的 task type 上执行默认补齐，避免影响未知/实验 task type。
- UI 默认注入 required_capabilities 后，若当前无满足 capability 的在线 Agent，任务可能长期处于 pending；需要在 UI 上给出“无匹配 Agent/能力不满足”的解释（而不是让用户误判为系统故障）。

## Open Questions

- 是否需要为 memscan 在 Server 侧引入专用 RBAC 权限与审批 API（例如 `detect.memscan.execute`）以避免 UI 仅靠提示与 metadata 约定？
- outputs 为 Agent 本地路径时，控制台的“下载”按钮应如何呈现（隐藏/复制路径/提示需要走 artifacts 上传下载能力）？
