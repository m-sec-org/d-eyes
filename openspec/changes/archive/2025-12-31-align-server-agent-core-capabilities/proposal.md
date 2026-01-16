## Why

`add-agent-stage-one-core-capabilities` 已补齐 Agent 的阶段一核心能力（例如：detect 引擎增强、Windows memscan、ThreatIntel 联动等），但当前 **Server 与 Agent 的“可调度任务面”和“元数据口径”仍存在不一致**，会直接影响联动体验与运维可观测性：

- **任务面不对齐**：Agent 内置任务包含 `respond/audit/inventory/supplychain/baseline/bas/action`，Server 侧目前仅对部分任务提供了报告/可视化聚合接口（如 respond/baseline/inventory/supplychain/bas），`audit` 等任务缺少对齐的 report 读取路径，导致远程执行虽可回传结果但难以在 Server 侧稳定消费。
- **detect 能力未纳入远程调度面**：阶段一已实现 `detect diag/memscan` 等核心诊断/对抗能力，但目前它们主要停留在本地 CLI 子命令层面，无法通过 Server 统一下发与回收结果，导致“能力已具备但无法平台化编排”的断层。
- **Task Catalog 为空导致 profile 体系无法落地**：Server 默认启用 task catalog 的 payload 校验，但 catalog 初始为空时，带 profile 的任务创建/校验链路缺乏“内置基线”，难以与 Agent 的 `--profile` 与 `config.tasks.*` 默认值形成闭环。
- **Agent 注册版本口径不一致**：Remote 注册上报的 `metadata.version` 若与 CLI `d-eyes version`/发布版本不一致，会导致 Server 侧 Agent 清单无法准确呈现版本、排查升级与兼容性问题。

本变更目标是把 **“阶段一 Agent 能力”落到可被 Server 调度、校验、展示、排障的一致合同**，形成可持续的对齐机制，避免靠源码对照与人工约定。

## What Changes

- **定义并固化 Server ↔ Agent 的“可远程调度任务/能力合同”**：明确 task types、capability 命名、`required_capabilities` 语义、以及 profile 与 payload 的边界（flags/保留字段）。
- **把 detect 系列纳入远程调度面**：将 `detect diag` 与 `detect memscan` 纳入可远程调度的 task types（建议命名：`detect.diag`、`detect.memscan`），并定义：
  - Server 侧 Task Catalog seed（profiles/schema）与创建校验；
  - Agent 侧 capability 广告与执行语义（`memscan` Windows-only，不应在非 Windows 上宣称可执行）；
  - Server 侧 report/read API 的稳定读取面，保证结果可消费。
- **为 Server 提供可落地的默认 Task Catalog 种子（seed）**：内置 core task types + profiles（与 Agent 默认配置保持一致），Server 首次启动时在 catalog 为空且未配置持久化数据时自动导入；若用户已有 catalog 则不覆盖。
- **补齐 Server 对齐的 report 读取面**：为 `audit`/`detect` 等 core task 提供与现有 report API 一致的 JSON 读取/聚合入口（或提供通用 report endpoint 作为兜底），保证远程任务结果在 Server 侧可稳定消费。
- **统一 Agent 注册版本口径**：Remote 注册时上报的版本字段与 `d-eyes version` 输出一致，并支持附带构建信息（commit/build tags）供 Server 展示与排障。

## Impact

- Affected specs:
  - `server-core`（task catalog seed、core task report surface、capability/metadata contract）
  - `agent-server-foundation`（注册 metadata.version 口径、capabilities 合同、detect 远程调度语义）
- Affected code (expected):
  - `server/internal/taskcatalog`、`server/internal/app`、`server/internal/api/v1`
  - `agent/internal/agent`、`agent/internal`、`agent/internal/detect`

## Resolved (0.4)

- `detect memscan` 作为高风险能力：按 `detect.memscan` task type/capability 管控，Windows-only 宣称，且默认要求 Agent 端显式 opt-in（建议 `remote.labels.allow_memscan=true`）；Server 侧建议增加专用 RBAC 权限（如 `detect.memscan.execute`）并要求显式 `memscan_approved=true` 后才允许运行（详见 `openspec/changes/align-server-agent-core-capabilities/design.md` 的 0.4）。
- 证据保全（evidence/minidump）：默认禁用；仅在“权限允许 + 审批字段通过”时开启（建议 `detect.memscan.evidence` + `memscan_evidence_approved=true`）。考虑到当前 Server 缺少通用 artifacts 回收面，默认仅在 Agent 本地落盘，通过 outputs 暴露路径；后续如需集中回收，再规划通用上传/下载与配额策略（详见 `openspec/changes/align-server-agent-core-capabilities/design.md` 的 0.4）。

## Frontend Alignment（Out of Scope / Follow-up）

本变更聚焦 **Server ↔ Agent 合同与后端落地**（task catalog seed、report/read API、capabilities/version 口径与 contract 测试），**未把前端（ops console / governance console）的页面与交互改造纳入本次 tasks**。

为避免“后端能力已齐但前端仍按旧口径消费”，建议单独规划一个 follow-up change，将前端对齐明确化（并对齐对应 UI specs），最小范围建议包含：

- Task Catalog：消费 `GET /api/v1/task-types` / `GET /api/v1/task-profiles`，用于前端“任务创建/编辑”时的 task type/profile 选择与 schema 驱动表单。
- Report/Read：为 `audit` 与 `detect.*` 增加统一的报告查看入口，消费 `GET /api/v1/tasks/{id}/audit/report` 与 `GET /api/v1/tasks/{id}/detect/report`（本变更已保证 envelope 字段稳定）。
- Capability/RBAC 提示：在 UI 上显式提示 `required_capabilities`、`detect.memscan` 的 Windows-only + `allow_memscan=true` gating，以及 RBAC 拒绝/审批缺失时的错误码（例如 `detect.memscan.approval_required`）与推荐处理动作。
