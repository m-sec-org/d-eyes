# D-Eyes 运维与扩容指南

本文面向运维/安全平台同学，总结 Server-Agent 架构的部署要点、可观测性、告警与回滚策略，帮助在生产环境稳定运行 D-Eyes。

## 1. 部署规划

### 1.1 运行角色

- **Server**：集中调度、模板管理、报告中心和 SSE 推送；建议部署在具备持久化存储的节点。
- **Agent**：执行扫描/模拟任务，可按业务域分组部署。

### 1.2 系统需求

| 角色 | CPU | 内存 | 磁盘 | 备注 |
|------|-----|------|------|------|
| Server | 2C+ | 4GB+ | 20GB | 需要 PostgreSQL/Redis 时按需扩容 |
| Agent | 1C+ | 2GB+ | 10GB | BAS 沙箱需额外空间（`sandbox.temp_dir`） |

### 1.3 配置关键项

`server/config/server.yaml` 示例：

```yaml
server:
  http_addr: ":8080"
  grpc_addr: ":9090"
security:
  agent_token: "changeme"
  api_keys: ["changeme"]
database:
  dsn: "postgres://user:pass@db/d_eyes?sslmode=disable"
  in_memory: false
redis:
  enabled: true
  addr: "redis:6379"
scheduler:
  lease_ttl: 120s
  max_retries: 3
metrics:
  enabled: true
  path: /metrics
audit:
  enabled: true
  log_path: /var/log/d-eyes/bas-audit.log
alerts:
  enabled: true
  channel: log
  notify_bas_failure: true
  notify_sandbox_fallback: true
templates:
  persist_path: /var/lib/d-eyes/templates.json
```

Agent 需配置 `remote.server_grpc_addr`、`sandbox` 等信息，可参考 `docs/bas-sandbox-guide.md`。

### 1.4 RBAC/MFA & Playbook 审批

- **细粒度权限**：`security.rbac.policies` 支持 `tasks.read/tasks.create/tasks.cancel/tasks.retry/tasks.actions`、`reports.view`、`playbook.execute/playbook.approve`、`bas.view/bas.manage` 等粒度，默认 `operator` 具备日常操作权限，`admin` 仍然是 ALL (`"*"`）。调整策略后无需重启即可生效。
- **多因子认证**：启用 `security.mfa.enabled=true` 后，Server 会对 `security.mfa.required_roles`（默认 `admin`）强制校验 `security.mfa.header`（默认 `X-MFA-Code`）中的验证码。  
  - 可在 `security.mfa.secrets` 中配置 `user:code` 或 `role:admin:code`/`default:code`，也可通过环境变量 `D_EYES_MFA_SECRETS="alice:123456,role:admin:999000"` 注入。  
  - 运维可调用 `GET /api/v1/security/mfa` 查看当前启用状态，并通过 `POST /api/v1/security/mfa/secrets` 动态下发（或指定 `remote_url`，让 Server 从 Vault/Secrets Manager 拉取 JSON `{"user":"code"}`），避免重启。  
  - 请求需携带 `X-User`/`X-User-Role` + `X-MFA-Code` 才能访问敏感接口（例如证书轮换、Playbook 审批）。
- **Playbook 审批链**：每个 Playbook 的 `approvals` 字段定义顺序审批角色，新增的 `approval_states` 会在 `/api/v1/playbooks/:id/approvals` 返回；`POST /api/v1/playbooks/:id/approvals` 可执行 `approve`/`reject`。全部审批通过后 `status=approved`，才能通过 `/playbooks/:id/activate` 激活并运行。
- **自愈与 DR**：调度器内置 `self_heal_interval` 定期回收离线 Agent 的任务，也可通过 `POST /api/v1/ops/self-heal` 手动触发；跨地域步骤详见 `docs/dr-runbook.md`。

### 1.5 BAS 场景审批与安全策略

- **审批 API**：`POST /api/v1/bas-scenarios/:id/publish` 将草稿推进到待审批状态，审批者可调用 `GET /bas-scenarios/:id/approvals` 查看策略与历史，再通过 `POST /bas-scenarios/:id/approvals`（或 `POST /bas-scenarios/:id/approve`）逐条完成 `approve/reject`。审批记录会写入 `approval_records` 列，并同步到 Ops Console 卡片。
- **Playbook 审批**：同样适用于 `Playbook` 审批链路，详见 `docs/playbook-approvals.md`。
- **网络边界**：BAS 场景的 `network_boundaries` 必须填写（例如 `dmz,prod`），调度器仅会把任务派发给 `remote.labels.network_boundary` 与之匹配的 Agent。未配置或不匹配会导致 `ErrNoTaskAvailable`，并保持队列安全。
- **资源阈值**：`resource_limits`（目标数量、并发、最长执行、CPU 上限）在审批前应对齐并写入场景，Server 会在任务创建及审计中同步这些信息，便于复核 `perfcheck` 告警。
- **标签约束**：`scenario_required_labels` 支持 `key=value` 或 `key` 形式，调度器会比对 Agent 在 `remote.labels` 中的声明（`tenant=blue`、`zone=dmz` 等）。所有条件满足后才允许执行，避免误入高权限节点。
- **审计字段**：每次 BAS 运行都会在 `audit.log_path` 记录 `sandbox_approval_required`、`sandbox_approved`、`sandbox_fallback`、`scenario_id/name` 等字段，审计平台可根据 `ApprovalGranted=false`、`SandboxFallback=true` 触发告警。
- **配置指引**：参见 `docs/bas-sandbox-guide.md` 中的示例配置与 `remote.labels` 说明，确保 Agent 在接入 Server 前就声明所属网络边界与租户标签，Ops Console 卡片也会同步展示差异以便排查。
- **辅助资料**：可在 `docs/observability-api.md` 获取观测 API 清单，在 `docs/ops-scripts.md` 复用部署/回滚脚本模板。
- **仪表板与告警**：`monitoring/grafana/stage4-dashboard.json` 与 `monitoring/alerts/stage4-alerts.yaml` 的使用方法见 `docs/monitoring-guide.md`。
- **日志与 Trace**：集中化方案、任务调度追踪脚本参考 `docs/logging-trace-guide.md`。
- **性能基线**：发布前执行 `scripts/perf-baseline.sh`（详见 `docs/perf-baseline.md`）校验调度、TI、BAS、Ops Console 指标。

### 1.6 Agent-Server 握手自检

- **契约测试**：Server 与 Agent 的 Register/Heartbeat/PullTasks/ReportResult 流程已经通过 `server/internal/grpcsvc/contract_test.go` 覆盖。运维在升级配置或改动调度策略后，可执行 `cd server && go test ./internal/grpcsvc -run AgentLifecycleContract`，自动模拟 gRPC 握手并通过 HTTP `/api/v1/tasks/{id}` 校验结果是否可查询。
- **指标对齐**：测试会验证 `telemetry.*`/`cache.*` metadata 是否写入 `store.UpdateAgentStatus`，可配合 Prometheus `agent_cpu_percent`、`agent_heartbeats_total` 以及 SSE `/api/v1/tasks/stream` 监控现场表现。
- **生产回归**：若升级链路涉及 Agent 运行时，请在 staging 环境跑完上述契约测试，再使用真实 Agent 验证：观察 Register 日志、15 秒心跳采样、`PullTasks` 返回的 profile/metadata，以及 `GET /api/v1/tasks/<taskId>` 中的 summary/metadata/artifact ID，确认威胁情报与行为图能够消费这些字段。

## 2. 可观测性

### 2.1 健康检查

- `GET /healthz`：Server 存活检测，可用于负载均衡探针。
- `GET /metrics`：Prometheus 指标，含任务队列、BAS 任务次数、沙箱回退等。

### 2.2 实时执行监控

- `GET /api/v1/tasks/stream`：SSE 通道，推送事件：
  - `leased`、`running`、`completed`、`timeout_*` 等事件；
  - `stats` 事件内含 `in_flight`、`bas_in_flight`、`queue_depth`。
- 建议前端或运维面板订阅 SSE，及时获知执行进度。

### 2.3 审计日志

- X 包含沙箱审批、回退信息，输出到 `audit.log_path`；
- 可接入 SIEM 或集中日志平台，追踪 BAS 执行链路。

## 3. 告警与通知

当前内置 `alerts.channel = log`，可通过日志采集对以下事件触发告警：

| 事件 | 日志字段 | 建议告警级别 |
|------|----------|--------------|
| BAS 场景失败 | `msg="BAS 场景失败"` | 高 |
| 沙箱回退宿主执行 | `msg="BAS 沙箱回退为宿主执行"` | 中 |

如需对接短信/邮件，可在 `alerts` 包外围实现自定义 Notifier 或二次开发。

## 4. 模板与调度

- `/api/v1/task-templates` 管理任务模板（F1），`templates.persist_path` 持久化模板列表；
- `/api/v1/task-templates/{id}/deploy` 支持一键下发；
- 启用 `schedule.interval_minutes` 后，调度器会自动投递任务并通过 SSE 报告状态。

## 5. 报告中心

- `/api/v1/reports/summary` 汇总最近任务的结果与风险统计；
- `/api/v1/reports/export?format=html` 导出可打印报告（详见 `docs/report-center.md`）；
- 建议定期归档导出文件，并结合模板与 SSE 构建完整的可视化报表。

## 6. 扩容与容灾

- **多实例 Server**：通过负载均衡 (例如 Nginx) + 共享数据库/Redis，实现水平扩展；Agent 使用同一 `agent_token`。
- **灾备**：定期备份 PostgreSQL、`templates.persist_path`、`audit.log_path`；故障时可在备份节点复原并更新 Agent 指向新的 Server 地址。
- **回滚**：保持上一版本二进制与配置；如需回滚，可停止新版本、恢复旧二进制并重放备份配置，Agent 重连后即恢复任务调度。

## 7. 常见问题

| 问题 | 处理建议 |
|------|----------|
| SSE 订阅断开 | 检查反向代理是否支持长连接（需关闭超时和缓冲） |
| 队列积压 | 观察 `/metrics` 中 `task_queue_depth`，必要时增加 Agent 节点或调高并发配置 |
| BAS 沙箱频繁回退 | 确认 gVisor 运行时是否部署，检查 `sandbox.fallback_to_host` 配置 |
| 模板未按期执行 | 检查模板 schedule、Server 日志；必要时查询 `templates.persist_path` 内容或调用 `/reports/summary` 验证任务历史 |

通过以上部署与运维实践，可确保 D-Eyes Server 在生产环境稳定运行、快速扩容并具备完善的监控与回滚能力。***
