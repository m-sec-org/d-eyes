# Collector 诊断与验收指南

本指南结合 CLI/Probe 与 Server 控制面，给出 Collector 的日志、健康检查与性能验收步骤，可直接用于阶段验收或问题排查。

## 1. 诊断日志

| 场景 | 操作 | 输出位置 |
| --- | --- | --- |
| CLI/Probe 本地调试 | 在 `config.yaml` 中设置 `logging.verbose=true` 或以 `--verbose` 运行 `d-eyes collect` | 终端 + `~/.d-eyes/logs/collector.log`（若配置 `logging.log_path`） |
| Remote Agent | 在 `config.logging` 中启用 `debug`，并通过 `journalctl -u d-eyes-agent` / `systemctl status` 查看 | systemd journal / `/var/log/d-eyes/agent.log` |
| Server 控制面 | `server/internal/api/v1/collector` 相关日志包含请求体、RBAC、Hub 推送等信息 | `server/logs/server.log` 或 stdout |

诊断重点：

- eBPF：`clang not found`、`asm/types.h`、`operation not permitted (MEMLOCK)` 均会在 CLI/Agent 日志与 `/api/v1/collector/status` 的 `last_error` 中显示。
- ETW：`enable provider ... access denied`、`StartTrace failed` 会附带 Session 名称，可快速定位权限或冲突。
- 遥测：`event_uploader` 失败会记录 HTTP 状态码与响应体，便于对照 Server `/api/v1/events/ingest` 日志。

## 2. 健康检查

### 2.1 Agent 自检

```bash
# Linux eBPF
sudo d-eyes collect --backend=ebpf --duration=60s \
  --output-mode=stdout \
  --probes=sys_enter_execve \
  --stream-url=https://server/api/v1/events/ingest \
  --stream-api-key=$TOKEN

# Windows ETW（管理员 PowerShell）
.\d-eyes.exe collect --backend=etw --collector diag-etw --duration=60
```

检查要点：

1. CLI 输出“采集器已启动”，`运行中的采集器` 应为 `running`。
2. `collector.status` 上报（Remote Agent 自动执行）：
   ```bash
   curl -H "X-API-Key: $KEY" \
     "https://server/api/v1/collector/status?tenant=default&state=running"
   ```
   返回结果中 `stats.events_emitted`、`drop_rate` 等需持续更新。
3. SSE 订阅：
   ```bash
   curl -N -H "Accept: text/event-stream" -H "X-API-Key: $KEY" \
     "https://server/api/v1/collector/status/stream?tenant=default"
   ```
   出现 `event: status` 流并展示 `last_error=""` 视为正常。

### 2.2 资源/权限探测脚本

为方便批量运维，可在节点上运行以下脚本：

```bash
scripts/perf/ebpf-load-test.sh   # Linux：检测 clang、BTF、CAP_BPF、memlock 等依赖
scripts/perf/etw-load-test.ps1   # Windows：检测 ETW Provider、Session 权限与丢包
```

脚本会在缺失依赖时打印 `[WARN]` / `[ERROR]` 并退出非零状态，可用于 CI 或验收前检查。

## 3. 性能与验收报告

Collector 验收建议覆盖以下步骤：

| 指标 | 验收方法 | 目标 |
| --- | --- | --- |
| 事件吞吐 | 运行 `scripts/perf/ebpf-load-test.sh`（或自定义流量脚本）并查询 Prometheus `rate(d_eyes_events_ingest_total[1m])` | > 5k events/s（测试环境可按需调整） |
| 延迟 | Prometheus `histogram_quantile(0.95, rate(d_eyes_events_ingest_latency_seconds_bucket[5m]))` | < 200 ms |
| 丢包率 | `collector.status.stats.drop_rate` / `perf_queue_dropped` | < 5% |
| 资源占用 | Agent `telemetry.system.*` 指标（CPU、mem）、Node Exporter | CPU < 5%，内存 < 100 MB |

最终报告建议包含：

- 各平台（Windows/Linux）运行截图或 `collector.status` JSON。
- Prometheus/Grafana 截图，证明吞吐/延迟/丢包指标满足阈值。
- CLI/Probe 日志中的关键事件（启动/停止/错误恢复）及处理结果。

## 4. 问题排查决策树

1. **Collector 启动失败**
   - 查看 CLI/Agent 日志 → 若提示权限/依赖缺失，参考《Collector 安装与权限指南》补齐。
   - 若 `collector.status` 长时间 `stopped`，检查 Server 日志与 `collectorctrl.Hub` SSE 是否推送。
2. **事件迟迟未到达 Server**
   - 查询 `eventstream` 缓存目录是否堆积（`/tmp/d-eyes/remote-cache/events`），若有则检查网络/Agent Token。
   - 查看 `/api/v1/events/ingest` 429/5xx 日志，必要时调大队列或限流阈值。
3. **性能不达标**
   - 运行性能脚本收集 `perf_events_*` 指标，确认是否为 Probe 端 CPU/内存不足。
   - 检查 Prometheus 指标 `d_eyes_collector_status_alerts_total` 是否触发告警，必要时调整采样率或过滤条件。

遵循以上流程即可形成 Collector 的诊断记录、健康检查表和性能验收报告，并纳入阶段结项材料。
