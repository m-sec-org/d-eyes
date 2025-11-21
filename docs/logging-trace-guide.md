# 日志集中化、Trace 关联与调度追踪

本指南提供 Stage4 的日志/Trace 解决方案，包括集中化推送、任务调度追踪与 Trace 关联流程。

## 1. 日志集中化

- 建议使用 Loki/Promtail 或 ELK。示例 Loki 流程：
  1. 在 Server 所在节点部署 Promtail。
  2. 采集 `server/logs/server.log`、`/var/log/d-eyes/audit.log` 等文件，附带 label `env`, `component`。
  3. 推送到 Loki 后可在 Grafana 中关联 Dashboard。
- 快速脚本：`scripts/logging/ship-audit-to-loki.sh`
  ```bash
  LOG_FILE=/var/log/d-eyes/audit.log \
  LOKI_ENDPOINT=https://loki.example.com/loki/api/v1/push \
  LOKI_LABELS='{job="d_eyes_audit",env="staging"}' \
  scripts/logging/ship-audit-to-loki.sh
  ```

## 2. Trace 关联

- 调度器、审计与 API 响应中均带有 `task_id` / `run_id` / `scenario_id`。在日志集中后可通过这些字段 join。
- 推荐在日志采集器中添加 pipeline：
  ```yaml
  pipeline_stages:
    - json:
        expressions:
          task_id: task_id
          run_id: run_id
          scenario_id: scenario_id
    - labels:
        task: task_id
        run: run_id
        scenario: scenario_id
  ```
- 若使用 OpenTelemetry，可在 Server 侧添加 `OTEL_EXPORTER_OTLP_ENDPOINT` 并启用 `otel` provider（未来扩展）。

## 3. 调度 / 任务追踪

- 使用 SSE `tasks/stream` 实时追踪任务状态：
  ```bash
  API_BASE=https://d-eyes.example.com/api/v1 \
  API_KEY=xxxxx \
  TASK_ID=12345678-90ab-cdef-1234-567890abcdef \
  scripts/logging/task-trace.sh
  ```
  该脚本会持续读取 SSE，筛选 `task_id` 匹配的事件，并输出调度、运行、完成等日志，便于匹配集中式日志。

## 4. 运维流程建议

1. 发布前运行 `scripts/logging/ship-audit-to-loki.sh` 将关键日志推送到统一平台。
2. 使用 `docs/monitoring-guide.md` 中的 Dashboard + Alert 观察 Agent/Scheduler 指标。
3. 遇到异常时，用 `scripts/logging/task-trace.sh` 和 Loki 查询 `task_id`、`run_id`，实现日志与调度的 Trace 关联。

通过以上流程，可在 Stage4 环境中实现日志集中管理、Trace 追踪与调度排查的闭环。
