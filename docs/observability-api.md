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
| `d_eyes_events_ingested_by_tier_total{priority,tier}` | 分层统计事件写入量（观察高/低优先级与冷热层命中） | `rate(d_eyes_events_ingested_by_tier_total{priority="high",tier="hot"}[5m])` 异常飙升时触发告警 |
| `d_eyes_events_parsers_configured{parser}` | 当前已启用的 parser/plugin（Gauge=1 表示注册成功） | `absent(d_eyes_events_parsers_configured{parser="process-schema"}) or d_eyes_events_parsers_configured{parser="process-schema"} < 1` |
| `d_eyes_events_parser_failures_total{parser,reason}` | Parser 校验失败次数，`reason` 标明缺失字段/标签/JSON 错误等 | `rate(d_eyes_events_parser_failures_total[5m]) > 0` 并结合 `rate(d_eyes_events_dropped_total[5m])` 触发“事件校验失败”告警 |
| `d_eyes_bas_scenarios_total{scenario_id,status}` | BAS 场景执行次数 | 监控 `status="failed"` 激增 |
| `d_eyes_collector_rollout_targets{rollout,state}` | Collector 配置下发的目标数，按 rollout ID 与状态（pending/acked/failed）分组 | `d_eyes_collector_rollout_targets{state="pending"} > 0` 同时 `time() - rolled_back_at > grace` → rollout 卡住 |
| `d_eyes_collector_rollout_actions_total{action,result}` | Rollout 操作（push/rollback）的成功/失败次数 | `rate(d_eyes_collector_rollout_actions_total{result="failed"}[5m]) > 0` 提醒人工介入 |

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

- `GET /api/v1/detections/stream`：推送检测告警事件（`event="detection.triggered"`），包含 `detection_id/rule/severity/respond_task_id` 等字段，可直接驱动 Events Workspace 或告警面板。

## 3. 观测摘要 API

| API | 说明 |
|-----|------|
| `GET /api/v1/reports/summary` | 任务历史与聚合结果（见 `docs/report-center.md`） |
| `GET /api/v1/reports/export?format=html` | 导出 HTML/JSON 报告，适配发布验收 |
| `GET /api/v1/events` | 查询已入库的系统事件，支持 `priority`、`storage_tier`、`collector_kind` 等过滤，适合作为前端 Events Workspace 数据源 |
| `GET /api/v1/events/stats` | 对 `events` 查询结果做快速聚合，返回 `total/by_event_type/by_source` 方便热图/看板复用 |
| `GET /api/v1/events/detections` | 仅返回 `event_type=detection.alert` 的告警事件，等价于 `/events?event_type=detection.alert`，便于前端/脚本快速查询最新检测结果 |
| `GET /api/v1/collector/configs/rollouts` | 列出 Server 最近的 Collector rollout（含 `target_count/ack_count/failed_count/status`）|
| `GET /api/v1/collector/configs/rollouts/:id` | 返回指定 rollout 的完整详情与目标列表，方便 UI 呈现实时状态 |
| `POST /api/v1/collector/configs/rollouts` | 创建新的 Collector rollout，可按标签筛选 Agent 并自动 auditing/metrics |
| `POST /api/v1/collector/configs/rollouts/:id/rollback` | 快速回滚 rollout，按需指定单个或全部 Agent，接口会同步写审计日志与 metrics |
| `GET /api/v1/bas-scenarios/:id/approvals` | BAS 审批链路与审批人列表 |
| `GET /api/v1/playbooks/:id/approvals` | Playbook 审批链路（参见 `docs/playbook-approvals.md`） |

`/api/v1/events` 支持 `limit`（≤1000）、`sort=asc|desc` 以及 `cursor_time/cursor_id` 游标分页，响应会附带 `next_cursor`，便于长时间窗口滚动查询；调用 `/api/v1/events/stats` 时可沿用同样的过滤参数，Server 会返回对应过滤范围内的总数与 event_type/source 维度统计，前端无需二次聚合即可绘制热图或表格。

### Prometheus Pull + API Push 混合模式

> **用途**：CI/发布前的 `perfcheck`、`scripts/docs-release.sh` 等流程需要即刻获取观测数据。

流程建议：

1. 通过 `/metrics` 拉取指标，并使用 `server/tools/perfcheck`（见 `server/docs/LOADTEST.md`）校验 P95 CPU/内存/IO 与失败率。
2. 若需要历史上下文，可调用 `/api/v1/reports/summary` 获取最近 N 次运行的趋势。
3. 将检查结果附加到 `docs/operations-guide.md` 所述的运维手册或自动化脚本（见 `docs/ops-scripts.md`）。Parser 校验失败会同时增加 `d_eyes_events_parser_failures_total` 与 `d_eyes_events_dropped_total`，便于 CI/监控快速判定拒收原因。

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
