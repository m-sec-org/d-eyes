## Why

`align-server-agent-core-capabilities` 已完成 Server↔Agent 的核心任务面对齐，并补齐了一批 **对前端可见/可消费的后端合同**，包括：

- Task Catalog：`GET /api/v1/task-types`、`GET /api/v1/task-profiles`（含 detect profiles/schema）
- Core task report/read：`GET /api/v1/tasks/{id}/audit/report`、`GET /api/v1/tasks/{id}/detect/report`
- detect 远程调度语义：`detect.diag`、`detect.memscan`（Windows-only + `allow_memscan="true"` opt-in + memscan 审批 metadata + `error_code` 口径）

但当前 Frontend（Ops Console）仍存在典型“后端能力已齐、前端消费仍按旧口径/缺少 UX”的断层：

- **任务创建未对齐调度合同**：前端创建任务时未默认注入 `metadata.required_capabilities`，可能导致任务被 lease 给不支持该 task type 的 Agent，最终以“unsupported task type / remote_execution_failed”失败，用户体验差且浪费重试预算。
- **detect.memscan 缺少可落地的创建/审批 UX**：memscan 需要 Windows-only + opt-in + 审批字段；若前端未提供 guardrail 与审批输入，用户创建后必然被 Agent 拒绝（exit_code=65 + `error_code=detect.memscan.*`），难以闭环。
- **报告读取面未被 UI 消费**：后端已提供 `/audit/report`、`/detect/report` 的稳定 envelope，但前端详情页目前仅展示 `last_run.summary` 的粗粒度字段，缺少 task-type report 的稳定展示与错误码提示。
- **Agent labels 的“来源权威”未在 UI 合同化**：Server 侧的 label 编辑会被 Agent 下次 Register 覆盖（现状/合同已固化），但前端仍提供编辑入口，容易误导运维用“改 label 控制 Agent 能力”（例如误以为改 `allow_memscan` 可启用 memscan）。

因此需要一个 follow-up 变更：把 **Server 端接口/输入输出合同** 与 **Frontend 页面展示与交互** 对齐，确保 detect 与 core report/read 能在控制台端“可创建、可调度、可查看、可排障”。

## What Changes

- **对齐任务创建请求合同（Server + Frontend）**
  - Frontend 创建任务时默认注入 `metadata.required_capabilities`（推荐：等于 task type / 或由 catalog capabilities 推导）。
  - Server 在缺省 `required_capabilities` 时提供安全默认（从 task catalog task type 的 `capabilities[]` 推导；若未知 task type 则不强制）。
- **补齐 detect 远程调度的前端 UX**
  - 在任务创建表单中支持 `detect.diag` 与 `detect.memscan` 的 profile/schema 驱动表单，并对 memscan 施加 UI guardrails（pid/all 二选一）。
  - 为 memscan 提供显式审批输入/确认流程（`memscan_approval_required/memscan_approved/memscan_evidence_approved`），并展示 Windows-only + `allow_memscan="true"` gating 的解释与风险提示。
- **补齐 audit/detect 报告展示**
  - 前端增加报告查看入口，消费 `GET /api/v1/tasks/{id}/audit/report` 与 `GET /api/v1/tasks/{id}/detect/report`，并对 `exit_code`/`error_code` 给出可操作的排障提示。
- **澄清 Agent labels 的权威来源与保留键**
  - 前端在 Agent 标签编辑页面显式提示“Server 侧编辑会在 Agent 下次 Register 被覆盖”，并对保留键（如 `allow_memscan`、`build.*`、`mode`）做高亮/限制或提示。

## Impact

- Affected specs:
  - `server-core`（任务创建默认 required_capabilities 的合同化）
  - `align-ops-console`（detect 调度/报告展示/labels 权威提示的 UX 合同化）
- Affected code (expected):
  - Server：`server/internal/api/v1/tasks.go`（createTask metadata 默认值）
  - Frontend：`frontend/src/services/api/*`、`frontend/src/features/tasks/*`、`frontend/src/features/agents/*`
- Testing:
  - Server 单测覆盖默认值行为与回归
  - Frontend（vitest）覆盖 schema 解析、CreateTask payload 生成与 memscan guardrails

## Non-Goals（本变更不做）

- 不引入通用 “outputs/artifacts 下载” 能力（目前 detect 报告文件路径为 Agent 本地路径；集中回收需单独规划 artifacts 上传/下载与配额策略）。
- 不在本变更内强制落地 `detect.memscan.execute/detect.memscan.evidence` 的 Server 端 RBAC 鉴权（可作为后续安全加固变更）。

