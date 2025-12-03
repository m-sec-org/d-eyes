# Collector 控制面可观测性

本篇用于指导如何在 Grafana/Prometheus 中监控 `/api/v1/collector/*` 控制面。

## Prometheus 指标

| 指标 | 维度 | 说明 |
| ---- | ---- | ---- |
| `d_eyes_collector_config_updates_total` | 无 | 配置下发成功次数 |
| `d_eyes_collector_status_alerts_total{tenant,level}` | `tenant`、`level`(`normal`/`warning`/`critical`) | Agent 状态上报触发的告警计数 |
| `d_eyes_events_ingest_latency_seconds` | 无 | 事件摄取时延（可用于和状态流对比） |

### 推荐 Grafana 面板

1. **配置发布速率**：`increase(d_eyes_collector_config_updates_total[5m])`
2. **按租户的 Collector 告警堆叠图**：`sum by (tenant,level)(increase(d_eyes_collector_status_alerts_total[5m]))`
3. **系统事件摄取延迟**：`histogram_quantile(0.9, rate(d_eyes_events_ingest_latency_seconds_bucket[5m]))`

## SSE / 审计流

* `/api/v1/collector/status/stream?tenant=xxx` 可用于实时显示告警（推荐启用浏览器 EventSource 或 grafana-json-datasource）。
* `/api/v1/audit/events?action=collector.config.update` 可追踪配置变更操作人，结合 Grafana 的 table 面板可形成“配置发布历史”。

## RBAC 建议

默认 `sre` 角色具备所有 collector 管控权限，`operator`/`auditor` 仅可读取状态。多租户隔离场景可追加角色：

```yaml
rbac:
  policies:
    - role: acme-ops
      permissions:
        - collector.config.read
        - collector.status.read

## Collector 输出配置示例

CLI/Probe 可通过 `collectors[].output` 字段把事件写入本地文件或 HTTP 流。示例：

```yaml
collectors:
  - name: diag-ebpf
    kind: ebpf
    output:
      mode: stream
      stream:
        url: https://ops.example.com/api/v1/events/ingest
        api_key: ${OPS_STREAM_KEY}
        agent_id: diag-edge-01      # 可选；默认读取 D_EYES_AGENT_ID
        agent_name: prod-node-01    # 可选；默认使用主机名
        max_batch: 25
        flush_interval: 2s
```

若仅需本地落盘，可将 `mode` 设置为 `file` 并指定 `output.path`。CLI `deyes collect` 始终保留控制台输出以便故障排查，但 Collector 会同时写入所配置的输出管道并保证事件也进入 Remote 模式的遥测通道。
```
