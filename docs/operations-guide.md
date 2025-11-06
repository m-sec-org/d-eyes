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
