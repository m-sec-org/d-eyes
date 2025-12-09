# Feature Flags & Runtime Controls

本文总结 D-Eyes 中可动态启用/禁用或按租户隔离的 Feature Flag、配置探针、回滚开关，帮助运维在阶段交付或灰度过程中控制风险。

## 1. 配置入口

| 范围 | 入口 | 说明 |
| --- | --- | --- |
| Server 全局 | `config/server.yaml` 或 `SERVER_CONFIG_PATH` | 支持热加载的模块：Events、Detection、Collectors、Scheduler、Alerts。 |
| Collector | `collector/config.yaml` 或 Remote Control Plane (`/api/v1/collector/configs`) | eBPF/ETW 的探针、采样率、过滤器等均可通过控制面热推送。 |
| 前端 | `.env` (`VITE_USE_MSW`、`VITE_DETECTION_STREAM_URL` 等) | 开发/演示环境用于切换 Mock、SSE 终端。 |

## 2. Events & Detection

```yaml
events:
  enabled: true
  parsers:
    - name: default-parser
      enabled: true
  detection:
    enabled: true
    max_workers: 4
    queue_size: 2048
    stream_events: true
    auto_respond:
      enabled: true
      default_profile: respond_profile_v1
      default_priority: 1
```

- `events.enabled`：关闭后 `/api/v1/events/ingest` 将直接返回 503，适合紧急故障时阻断入口。
- `events.parsers[].enabled`：可针对特定 collector/event_type 切换 parser；关闭意味着事件以原始形式入库。
- `events.detection.enabled`：控制 DetectionEngine 是否消费系统事件；关闭后 SSE `/api/v1/detections/stream` 仍可访问，但不会有新事件。
- `events.detection.auto_respond.enabled`：可在规则命中仍生成 `detection.alert` 的情况下，暂时停用自动下发 Respond 任务。

> **Rolling Upgrade 建议**：先以 `auto_respond.enabled=false`、`stream_events=false` 启动新的 DetectionEngine，确认 Metrics/SSE 正常后再开启自动 Respond。

## 3. Collector Rollout & Feature Flag

Collector 支持以下热切换特性：

| Flag | 描述 |
| --- | --- |
| `collectors.heartbeat_lag_threshold` | 定义心跳延迟上限，超出将标记 `lagging` 并触发告警。 |
| `/api/v1/collector/configs/rollouts` | 使用 `enabled` 字段临时关闭指定 Collector（无需卸载 Agent）。 |
| `sampling_rate` | 0~1 浮点值，可在 UI 表单或 API 中随时调整，常用于告警期降低负载。 |

结合 `docs/collector-diagnostics.md` 的脚本可在 rollout 前后自动执行 eBPF/ETW 健康检查，避免配置漂移。

## 4. Scheduler & Task 路径

- `scheduler.max_agent_concurrency` / `global_max_concurrency`：可在高峰期临时下调以保护核心服务。
- `scheduler.self_heal_interval`：设置为 0 可关闭自动自愈（需配合 `/api/v1/ops/self-heal` 手动触发）。
- `alerts.channel`：默认为 `log`，可切换为 `webhook`、`email`（需在 `alerts.*` 中额外配置）。

## 5. 前端 / Mock

- `VITE_USE_MSW=false`：关闭 Mock，前端直连真实 API；反之则使用 `src/mocks` 中的数据与 SSE 模拟器。
- `VITE_DETECTION_STREAM_URL`、`VITE_WS_BASE_URL`：可为 E2E/Playwright 环境指定独立的流终端，避免与生产共用。

## 6. 灰度策略

1. **分批 Collector**：利用 `collector.tags`（如 `tenant=blue`、`region=hk`）为不同批次分配 rollout/回滚。
2. **Detection Rules**：`events.detection.rules[].enabled=false` 时，系统保留规则配置但不执行，适合灰度阶段按需放量。
3. **Respond 模板**：通过 `tasks` 模块的 `profiles` 控制 Respond 行为，可在灰度中指向空模板以避免实际执行。

## 7. 回滚路径

- 关闭 `events.enabled` → 清空队列后重新开启（`Service.Close()` 会 flush in-flight）。
- Detection Engine 回滚：先 `detection.enabled=false`，再通过 release pipeline 替换二进制，最后重新启用。
- 前端 Mock：在故障或 API 不可用时，将 `VITE_USE_MSW` 设为 `true` 并部署，可快速恢复演示/培训环境。

> 所有 Feature Flag 变更建议记录到 `docs/release-notes/<stage>.md`，并在回滚时附带原因与影响范围。
