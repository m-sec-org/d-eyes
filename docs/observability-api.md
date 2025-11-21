# 观测 API 与指标集成指南

Stage4 引入统一的观测接口，方便运维脚本、Grafana/Prometheus 以及自动化验收流程复用相同的数据面。本文总结可直接调用的 API、指标字段与典型查询。

## 1. Prometheus `/metrics`

- 路径：`GET http(s)://<server-host>:8080/metrics`（可在 `server/config/server.yaml` 中调整）。
- 命名空间：`d_eyes_server_*`。
- 授权：默认开放在内网，可配合 Ingress/OAuth2 Proxy 进行访问控制。

常用指标（更多详见 `server/docs/OBSERVABILITY.md`）：

| 指标 | 说明 | 示例告警 |
|------|------|----------|
| `d_eyes_server_agent_cpu_percent_bucket` | Agent 心跳上报 CPU 使用率（Histogram） | `histogram_quantile(0.95, rate(...[5m])) > 80` |
| `d_eyes_server_agent_memory_percent_bucket` | Agent 心跳上报内存占用 | `histogram_quantile(0.95, rate(...[5m])) > 85` |
| `d_eyes_server_tasks_completed_total{status}` | Scheduler 完成任务次数 | `failed / total > 0.01` |
| `d_eyes_server_task_time_to_lease_seconds_bucket` | 任务排队耗时 | `histogram_quantile(0.95, rate(...[5m])) > 5` |
| `d_eyes_bas_scenarios_total{scenario_id,status}` | BAS 场景执行次数 | 监控 `status="failed"` 激增 |

示例 PromQL：

```promql
// BAS 任务失败率
sum(rate(d_eyes_server_tasks_completed_total{status="failed"}[5m])) 
/ sum(rate(d_eyes_server_tasks_completed_total[5m]))

// Agent CPU P95
histogram_quantile(0.95, rate(d_eyes_server_agent_cpu_percent_bucket[5m]))
```

## 2. 任务流 SSE `/api/v1/tasks/stream`

- 请求：`GET /api/v1/tasks/stream?type=bas&status=running`
- 认证：与 REST API 相同（`X-API-Key` / Token / RBAC）。
- 事件：`leased`、`running`、`completed`、`stats`。可用于实时看板和自动化干预。

客户端示例：

```bash
curl -N -H "Accept: text/event-stream" \
     -H "X-API-Key: <key>" \
     "https://d-eyes/api/v1/tasks/stream?type=bas" | jq .
```

## 3. 观测摘要 API

| API | 说明 |
|-----|------|
| `GET /api/v1/reports/summary` | 任务历史与聚合结果（见 `docs/report-center.md`） |
| `GET /api/v1/reports/export?format=html` | 导出 HTML/JSON 报告，适配发布验收 |
| `GET /api/v1/bas-scenarios/:id/approvals` | BAS 审批链路与审批人列表 |
| `GET /api/v1/playbooks/:id/approvals` | Playbook 审批链路（参见 `docs/playbook-approvals.md`） |

### Prometheus Pull + API Push 混合模式

> **用途**：CI/发布前的 `perfcheck`、`scripts/docs-release.sh` 等流程需要即刻获取观测数据。

流程建议：

1. 通过 `/metrics` 拉取指标，并使用 `server/tools/perfcheck`（见 `server/docs/LOADTEST.md`）校验 P95 CPU/内存/IO 与失败率。
2. 若需要历史上下文，可调用 `/api/v1/reports/summary` 获取最近 N 次运行的趋势。
3. 将检查结果附加到 `docs/operations-guide.md` 所述的运维手册或自动化脚本（见 `docs/ops-scripts.md`）。

## 4. Grafana/Prometheus 集成模板

**Prometheus `scrape_config` 示例：**

```yaml
scrape_configs:
  - job_name: d-eyes-server
    static_configs:
      - targets: ['server:8080']
    scheme: https
    tls_config:
      insecure_skip_verify: true
    authorization:
      credentials: ${D_EYES_METRICS_TOKEN}
```

**Grafana 面板建议：**

1. Agent 健康（在线数量、`agent_cpu_percent` P95、`agent_memory_percent` P95）。
2. 调度吞吐（`tasks_leased_total`、`tasks_completed_total`）。
3. BAS 任务详情（`bas_scenarios_total` 分布、`sandbox_fallback` 计数）。
4. 队列洞察（`task_queue_depth`、`task_time_to_lease`）。

## 5. API 与 Observability 自动化脚本

结合 `docs/ops-scripts.md` 的模板，可在 CI 或运维平台中执行以下动作：

- `perfcheck`：在部署后调用 Prometheus + `/api/v1/reports/summary` 验证 P95、失败率与审批状态。
- `bas self-heal`: 使用 `/api/v1/ops/self-heal`（如已启用）触发调度自愈，同时监控 `tasks_completed_total` 与 `bas_sandbox_fallback`。
- `docs-release`: 生成文档快照后上传 `docs/releases/<version>.zip`，并记录观测结果作为发布附件。

通过上述 API，Stage4 的观测数据可在 Prometheus/Grafana、CI、运维脚本之间共享，实现告警、可视化与流程自动化的统一。
