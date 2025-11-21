# Prometheus / Grafana 监控与告警指南

本指南提供 Stage4 所需的仪表板、Alerting 模板以及部署步骤，覆盖任务调度、Agent、Threat Intel、BAS 四个维度。

## 1. 仪表板

- 位置：`monitoring/grafana/stage4-dashboard.json`
- 导入 Grafana：选择 **Dashboards → Import**，将 JSON 粘贴或指向该文件；使用已有 Prometheus 数据源。
- 包含的核心图表：
  1. Agent CPU/Memory P95（指标：`d_eyes_server_agent_cpu_percent_bucket`, `...memory_percent_bucket`）。
  2. Scheduler Queue Depth (`d_eyes_server_task_queue_depth`).
  3. Task Failure Rate（`tasks_completed_total`）。
  4. Threat Intel TPS (`d_eyes_server_ti_requests_total`).
  5. BAS Scenario Failures (`d_eyes_bas_scenarios_total`).
- 可根据需要追加前端 `tests/perf` 输出的 SSE 性能数据，或者在 dashboard 中嵌入日志链接。

## 2. Alertmanager 模板

- 文件：`monitoring/alerts/stage4-alerts.yaml`
- 包含 Agent CPU/Memory 阈值、任务失败率、队列堆积、Threat Intel 失败、BAS 失败等规则。
- 部署：
  ```bash
  kubectl create configmap d-eyes-alerts --from-file=monitoring/alerts/stage4-alerts.yaml -n monitoring
  kubectl patch alertmanager main -n monitoring --type merge -p '{"spec":{"config":{"route":{"receiver":"pager"},"receivers":[{"name":"pager","slack_configs":[{"channel":"#sec-ops","send_resolved":true}]}]}}}'
  ```

## 3. 指标速查

| 维度 | PromQL | 阈值 |
|------|--------|------|
| Agent CPU P95 | `histogram_quantile(0.95, rate(d_eyes_server_agent_cpu_percent_bucket[5m]))` | <80% |
| Agent 内存 P95 | 同上 | <85% |
| 队列深度 | `d_eyes_server_task_queue_depth` | <200 |
| 任务失败率 | `sum(rate(d_eyes_server_tasks_completed_total{status="failed"}[5m])) / sum(rate(d_eyes_server_tasks_completed_total[5m]))` | <1% |
| TI 请求失败 | `rate(d_eyes_server_ti_requests_failed_total[5m])` | 0 |
| BAS 失败 | `increase(d_eyes_bas_scenarios_total{status="failed"}[30m])` | 0 |

更多指标可参考 `docs/observability-api.md`、`server/docs/OBSERVABILITY.md`。

## 4. 集成到运维流程

1. 参考 `docs/operations-guide.md` 配置 Prometheus + Alerting。
2. 使用 `scripts/perf-baseline.sh` 结合 Prometheus 校验指标。
3. 将仪表板链接与 Alertmanager 配置记录在 `docs/release-notes/<version>.md`，确保可追溯。
