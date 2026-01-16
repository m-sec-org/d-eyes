## 0. Research & Alignment
- [x] 0.1 盘点前端（tasks/create、task detail、agents/labels、reports）现状与 Server API 映射，形成对齐矩阵（Frontend/Server/Specs）。
- [x] 0.2 明确对齐口径：`required_capabilities` 默认策略、memscan 审批字段与 UI guardrails、report/read 展示字段与错误提示。

## 1. Specs（对齐合同）
- [x] 1.1 在 `align-ops-console` spec delta 中新增 “Detect Remote Dispatch UX Contract” 要求与场景（创建/审批/查看报告/错误码提示/labels 权威提示）。
- [x] 1.2 在 `server-core` spec delta 中新增 “Default required_capabilities from task catalog” 要求与场景。

## 2. Server Implementation
- [x] 2.1 在 `POST /api/v1/tasks` 创建时：当 `metadata.required_capabilities` 缺省且 task type 可在 catalog 中解析到 `capabilities[]` 时，自动写入默认值（不影响显式传入者）。
- [x] 2.2 增加回归测试覆盖：默认注入行为、未知 task type 不强制、显式传入（含空值）不覆写、catalog capabilities 为空不注入。

## 3. Frontend Implementation
- [x] 3.1 增加 audit/detect report API client + Zod schema：`GET /api/v1/tasks/{id}/audit/report`、`GET /api/v1/tasks/{id}/detect/report`。
- [x] 3.2 更新任务创建：默认注入 `metadata.required_capabilities`；detect.memscan 增加 pid/all 互斥校验与审批输入（evidence/minidump 触发额外审批字段）。
- [x] 3.2.1 `FormField`：错误/提示通过 `aria-describedby` 关联，避免污染输入框可访问名称。
- [x] 3.2.2 `FormField`：多子控件场景也自动注入 `aria-describedby`（含嵌套控件）。
- [x] 3.2.3 排查实际页面的 `FormField` 用法：当前均为单控件包装；补充回归用例防止后续引入多控件/复杂控件场景时破坏 a11y 语义。
- [x] 3.2.4 多控件字段（范围/区间输入）约定：每个子控件必须具备明确可访问名称（如 `aria-label`），并在 PR 中补对应回归用例。
- [x] 3.3 更新任务详情/报告展示：展示 audit/detect report 的结构化结果、`exit_code`/`error_code` 与建议动作（特别是 memscan 审批缺失）。
- [x] 3.3.1 Task 详情：基于 `/audit/report`、`/detect/report` 拉取报告并展示稳定字段（task meta + summary + outputs/artifacts）。
- [x] 3.3.2 排障提示：对 `detect.memscan.approval_required` / `detect.memscan.evidence_approval_required` 显示可操作建议动作；对 403/404 做友好提示。
- [x] 3.3.3 单测覆盖：增加 TaskDetailDrawer 报告/错误码展示回归用例。
- [x] 3.3.4 继续完善：补充 `agent.remote_execution_failed` 等 error_code 建议动作映射，并增强 risks/notes 的展示。
- [x] 3.3.5 继续完善：增加可展开的调试区展示 `result.metadata`/`run_metadata`（用于排障与复现），并补充回归用例。
- [x] 3.3.6 继续完善：调试区可选展示 `result` / `result.summary` 全量 JSON（默认折叠）。
- [x] 3.4 更新 Agent 标签页：提示 “Server-side label edits are non-authoritative（会被 Agent 下次 Register 覆盖）”，并对保留键（`allow_memscan`、`build.*`、`mode`）做高亮/限制。

## 4. Tests
- [x] 4.1 Frontend：增加单测覆盖 detect/audit report schema 解析与 CreateTask payload 注入逻辑（含 memscan guardrails）。
- [x] 4.2 Server：增加/更新契约测试确保 task catalog + report/read + required_capabilities 默认行为稳定。

## 5. Docs
- [x] 5.1 更新前端使用/发布文档：detect 远程调度入口、memscan gating（Windows-only + allow_memscan）、审批字段与 error_code 口径说明。
