# Playbook 审批与链路指南（Stage 4）

Stage 4 对 Playbook 引擎引入了多级审批、MFA 与审计闭环。本指南面向运维与应急编排同学，说明如何配置审批策略、调用 API 以及在 Ops Console 中体验新版流程。

## 1. 审批模型

- `approval_policy`：定义顺序执行的角色集合（如 `secops` → `dept.owner` → `ciso`），支持 `timeout_seconds` 超时控制。
- `approval_states`：Server 按角色生成的审批记录，包含 `status`（pending/approved/rejected）、`actor`、`notes`、`updated_at`。
- `status` 轨迹：
  1. `draft` → `pending`（提交审核）。
  2. 审批通过后进入 `approved`，方可 `activate`。
  3. 任意节点 `reject` 会回到 `pending` 并重置后续审批。
- 审批行为会同步写入审计日志，字段包括 `playbook_id`、`role`、`actor`、`sandbox_policy_id` 等，满足合规要求。

## 2. API 调用流程

1. **提交审批**

   ```bash
   curl -X POST https://d-eyes/api/v1/playbooks/{id}/publish \
     -H "X-API-Key: <key>" \
     -d '{"updated_by":"secops.lead"}'
   ```

2. **查看审批策略 / 记录**

   ```bash
   curl -X GET https://d-eyes/api/v1/playbooks/{id}/approvals \
     -H "X-API-Key: <key>"
   # 返回 approval_policy + approval_states
   ```

3. **审批 / 驳回**

   ```bash
   curl -X POST https://d-eyes/api/v1/playbooks/{id}/approvals \
     -H "X-API-Key: <key>" \
     -H "X-MFA-Code: 123456" \
     -H "X-User-Role: secops" \
     -d '{"role":"secops","action":"approve","actor":"secops.lead","notes":"Ready for SOC"}'
   ```

4. **激活**

   ```bash
   curl -X POST https://d-eyes/api/v1/playbooks/{id}/activate \
     -H "X-API-Key: <key>"
   ```

> 若结合 Stage 4 RBAC / MFA，可在敏感接口上强制 `X-User`、`X-User-Role`、`X-MFA-Code`，否则请求会被拒绝。

## 3. Ops Console 体验

- 新增「审批记录」面板，实时展示每个角色的状态、执行人和备注。
- 审批按钮会根据当前用户角色与 `approval_policy` 自动启用/禁用，确保顺序执行。
- 激活前会校验 Playbook 是否已通过全部审批；失败原因会直接贴在 UI 上（例如“等待 CISO 审批”）。

## 4. 审计与告警

- Server 会把所有审批事件写入 `audit.log_path`，字段包含 `playbook_id/name`、`role`、`actor`、`result`。
- 可配置 `alerts.notify_playbook_failure`（参见 `docs/operations-guide.md`）以便在审批被拒绝、超时或执行失败时触发通知。
- 与 BAS/Sandbox 一样，审计事件可被转发到 SIEM，形成统一的 Stage 4 安全证据链。

## 5. 常见问题

| 问题 | 排查建议 |
| --- | --- |
| `403 insufficient permissions` | 确认用户是否具备 `playbook.approve` / `playbook.manage` 权限，并且通过了 MFA 校验。 |
| 审批卡在 pending | 检查 `approval_states` 中的 `status` 与 `timeout_seconds`；必要时使用 `POST /playbooks/:id/approvals` 重新提交。 |
| Ops Console 无法激活 | 多数情况是审批未完成或 Playbook 仍为 `draft`，可在列表中查看状态或查询 `/playbooks/:id`. |

---

更多细节可参考 `server/internal/api/v1/playbooks.go` 与 `frontend/src/features/playbooks/*` 的实现，或直接运行 `scripts/docs-lint.sh` 确定文档与 API 接口一致。
