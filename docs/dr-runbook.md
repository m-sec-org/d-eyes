# D-Eyes Geo 灾备演练手册

该手册面向 Ops/平台 SRE，帮助在多地域部署中完成故障演练、自愈验证与切换流程。

## 1. 演练目标

1. 验证 Agent 心跳/任务在主 Region 异常时，能被自愈逻辑自动恢复。
2. 演练 Server 级别故障时的备库/备节点切换步骤。
3. 确认运维可通过 `/api/v1/ops/self-heal`、`/api/v1/security/mfa` 等接口驱动手动救援。

## 2. 前置条件

- 至少部署两个 Region（primary / secondary），共享 PostgreSQL/Redis 或通过 CDC 同步。
- `scheduler.self_heal_interval` 保持默认 1m（或更短），确保自动检测离线 Agent 并重排任务。
- Ops Console/CLI 已配置 API Key + MFA（`security.mfa.*`）。

## 3. 心跳中断自愈流程

1. 人为断开某 Region 内 Agent 网络（或关闭 Agent 进程）。
2. 观察 Server `monitor` 组件将 Agent 状态标记为 `offline`，并在日志中记录 `self-heal recovered tasks`。
3. 若需立即手动触发，可执行：
   ```bash
   curl -X POST https://server/api/v1/ops/self-heal \
     -H "X-API-Key: <ops-key>" \
     -H "X-User: dr-operator" -H "X-User-Role: admin" \
     -H "X-MFA-Code: <code>" \
     -d '{"agent_id":"<offline-agent-uuid>"}'
   ```
   响应会返回各 Agent 重新排队的任务数量。
4. 验证 `scheduler` 队列/任务状态恢复为 `pending` 并重新分配给健康 Agent。

## 4. Region 故障切换手册

1. **检测**：Prometheus/Alertmanager 触发 Region 不可用告警（HTTP、gRPC、数据库连接）。
2. **冻结写入**：停止 Primary Region 的调度进程（`make dev-down` 或 systemd stop），确保不再产生新任务。
3. **数据确认**：检查 PostgreSQL/Redis 复制延迟，确认 Secondary 已 Catch-up。
4. **切换**：
   - 在 Secondary Region 启动 Server（指向只读/备库的 DSN，或 Promote 到新的 Primary）。
   - 更新负载均衡/全局 DNS 指向 Secondary。
   - 通知 Agent（或通过配置管理）将 `server_grpc_addr` 指向新的 Region。
5. **恢复自愈**：确保 Secondary 的 `scheduler.StartSelfHeal` 运行，继续监视离线 Agent。
6. **归档**：记录演练时间、任务 ID、手动操作步骤，纳入审计。

## 5. 回切流程

1. Primary 修复后，重新加入复制，并等待数据同步完成。
2. 通知 Agent 按计划切回 Primary。
3. 将流量从 Secondary 迁回 Primary，生成演练报告，确认没有丢单/重复调度。

## 6. 常用 API & 命令

| 功能 | 说明 |
| ---- | ---- |
| `POST /api/v1/ops/self-heal` | 立即对离线 Agent 执行任务回收，可带 `agent_id` 或留空批量处理。 |
| `GET /api/v1/security/mfa` | 查看当前 MFA 配置、Header 名称和缓存的秘钥。 |
| `POST /api/v1/security/mfa/secrets` | 从 Vault/Secrets Manager 拉取或直接提交 JSON，实时更新验证码。 |
| `POST /api/v1/playbooks/:id/approvals` | 在灾备演练中走完审批链确保自动化脚本受控。 |

## 7. 复盘 checklist

- [ ] 心跳超时后自动触发自愈，任务无长时间卡死。
- [ ] 手动 `/ops/self-heal` 能命中目标 Agent 并返回统计。
- [ ] DNS/LB 切换记录及通知审计妥善留存。
- [ ] 演练结果更新到 Ops Console/Runbook，确保下次可复用。

通过上述演练，可确保 D-Eyes 在跨地域部署下具备自愈能力，并在严重故障时具备明确可执行的 DR 手册。
