# 性能基线（任务调度 / Threat Intel / BAS / Ops Console）

Stage4 要求在发布前验证关键链路的性能基线。以下内容基于 `server/tools/perfcheck`、Prometheus 指标以及前端 perf 测试用例。

## 1. 基础设施

- Prometheus 需采集 `d_eyes_server_*` 指标（参见 `docs/observability-api.md`）。
- `server/tools/perfcheck` 用于对 CPU/内存/IO P95 与任务失败率进行守门验证。
- 前端 `tests/perf/taskLiveMonitor.baseline.test.tsx` 用于确保 Ops Console 关键视图的渲染性能。

## 2. 调度器与任务执行

运行：

```bash
PROM_URL="https://prom.example.com" scripts/perf-baseline.sh \
  --threshold.cpu 80 --threshold.mem 85 --threshold.io 80 --threshold.fail 0.01
```

默认窗口 5 分钟，可通过 `PERF_WINDOW=10m` 覆盖。脚本会调用 `server/tools/perfcheck` 并输出每个指标的 P95 / 阈值对比。

校验项：

| 指标 | 阈值 | 描述 |
|------|------|------|
| `d_eyes_server_agent_cpu_percent` P95 | < 80% | 调度器需要保证 Agent 资源占用在限额内。 |
| `d_eyes_server_agent_memory_percent` P95 | < 85% | 避免 OOM。 |
| `d_eyes_server_agent_io_util_percent` P95 | < 80% | 确保缓存/限速策略有效。 |
| 任务失败率 | < 1% | `sum(rate(tasks_completed_total{status="failed"})) / sum(rate(tasks_completed_total))`。 |
| 排队时间 P95 | < 5s | `task_time_to_lease_seconds`（perfcheck 输出 `queue_wait_p95`）。 |

## 3. Threat Intel / BAS 运行

1. 在 staging 环境运行内置 BAS 场景（如 `initial-access`），并记录 `server/tools/perfcheck --scenario initial-access` 输出的 `bas_success_rate`、`sandbox_fallback_count`。
2. Threat Intel 任务可通过 `agent/internal/tasks/respond` 中的 TI collector 自动生成笔记，可在 Prometheus 中观察 `d_eyes_server_ti_requests_total` 的成功率；如需脚本化，可扩展 `scripts/perf-baseline.sh --ti-endpoint <url>`（默认跳过）。
3. 若 BAS 成功率低于 98% 或 Sandbox 回退频繁 >5%，需阻断发布。

## 4. Ops Console 关键视图

- 前端 `pnpm vitest run tests/perf/taskLiveMonitor.baseline.test.tsx` 会输出：
  - SSE 事件间隔（目标：平均 < 250ms，最大 < 400ms）。
  - 渲染成本（DOM 结点 ~200 个、p95 渲染耗时 < 0.1ms）。
- 若需要更详细的 UI 指标，可在 `tests/perf` 下新增用例并在 CI 中运行。

## 5. 发布流程集成

1. 执行 `scripts/test-matrix.sh` 确认基础测试通过。
2. 运行 `scripts/perf-baseline.sh` 验证调度、TI、BAS 指标。
3. 在发布说明中记录 perf 结果（例如 `docs/release-notes/<version>.md`）。
4. 若任何指标失败，需排查对应模块并重新运行上述脚本。

> 建议将 `scripts/perf-baseline.sh` 与 `server/tools/perfcheck` 的输出上传到 CI artifact，以便回溯性能趋势。
