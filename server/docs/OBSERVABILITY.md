# D-Eyes Server 观测指标草案

## 1. 指标暴露

- 访问 `http://<server-host>:8080/metrics`（可通过 `config.server.metrics` 调整路径）。
- Prometheus 命名空间：`d_eyes_server_*`。
- 所有指标默认以 Counter/Gauge/Histogram 暴露，可直接接入 Prometheus + Grafana。

## 2. 指标列表

| 指标 | 类型 | 含义 | 建议关注点 |
| ---- | ---- | ---- | ---- |
| `d_eyes_server_agent_heartbeats_total` | Counter | 收到的 Agent 心跳次数 | 心跳速率突降代表 Agent 离线或网络中断 |
| `d_eyes_server_tasks_leased_total` | Counter | Scheduler 成功租约的任务数 | 均匀增长表示 Agent 正常领取任务 |
| `d_eyes_server_tasks_completed_total{status}` | Counter | 任务按照状态完成的次数 | `status=failed` 持续上升需排查执行失败率 |
| `d_eyes_server_task_queue_depth` | Gauge | 当前调度队列中的等待任务数量 | 持续高位提示调度/Agent 供给不足 |
| `d_eyes_server_task_time_to_lease_seconds` | Histogram | 任务从创建到租约的排队耗时 | P95 > 5s 说明调度或 Agent 承载不足 |
| `d_eyes_server_task_run_duration_seconds` | Histogram | Agent 报告的任务执行耗时 | 与任务 SLA 对齐，可结合失败率观察 |

## 3. 告警/阈值草案

- **心跳缺失**：`increase(d_eyes_server_agent_heartbeats_total[5m]) == 0` 触发，提示 Agent 全部离线。
- **失败率**：`rate(d_eyes_server_tasks_completed_total{status="failed"}[5m])` 超过总完成量的 5% 需要排查。
- **排队时间**：`histogram_quantile(0.95, rate(d_eyes_server_task_time_to_lease_seconds_bucket[5m])) > 5` 秒，提示扩容或调度异常。
- **执行耗时**：针对关键任务计算 P95/P99，超过业务 SLA 时预警。

## 4. 仪表盘建议

1. **Agent 健康**：在线数量、心跳速率、失败 Agent 列表。
2. **任务流量**：提交速率、租约速率、完成/失败率、平均排队时间。
3. **执行耗时**：Histogram/P95 曲线，按任务类型维度拆分。
4. **队列深度**：`task_queue_depth` 折线，结合任务吞吐判断扩缩容。

## 5. 下一步

- 结合业务自定义指标（例如任务类型维度的计数）。
- 将指标对接 Alertmanager，输出告警模板。
- 后续扩展 Trace（OpenTelemetry）用于长链路分析。
