# Load Test 指南

`tools/loadtest` 提供最小可用的压测脚本，用于评估 Server 的任务提交、调度与 gRPC 回传链路。

## 1. 准备工作

1. 启动 Server（可使用 `make dev-up` 或本地运行）。
2. 确认 API Key/Agent Token（默认 `changeme`）。
3. Prometheus 若已接入，可同时观察 `docs/OBSERVABILITY.md` 中的核心指标。

## 2. 运行示例

```bash
cd server
go run ./tools/loadtest \
  --api http://127.0.0.1:8080 \
  --grpc 127.0.0.1:9090 \
  --api-key changeme \
  --concurrency 32 \
  --agents 16 \
  --duration 2m
```

参数说明：

| 参数 | 说明 |
| ---- | ---- |
| `--concurrency` | REST 任务创建并发数 |
| `--payload-bytes` | 每个任务 payload 中的随机字符串大小，用于模拟真实数据量 |
| `--agents` | 启动的模拟 Agent 数量；设置为 0 表示仅压测 REST 层 |
| `--pull-batch` | 每次 `PullTasks` 请求拉取的任务上限 |
| `--duration` | 运行总时长 |

脚本输出包括：

- 请求总数、成功/失败数、平均吞吐（req/s）
- 创建接口的 P50/P95/P99 延迟
- 模拟 Agent 完成的任务数与失败数

## 3. 指标联动

压测过程中建议结合 Prometheus 指标：

- `task_queue_depth`：队列是否持续堆积。
- `task_time_to_lease_seconds`：任务排队时间；压测后可评估调度延迟。
- `task_run_duration_seconds`：模拟 Agent 执行耗时，判断执行路径是否稳定。

## 4. 可靠性验证建议

1. **渐进式压测**：从 50 req/s 逐步提升到目标峰值，观察队列与延迟阈值。
2. **故障注入**：在压测期间临时关闭部分 Agent 或数据库，验证重试/租约回收是否生效。
3. **长时间跑批**：至少 30 分钟压测以暴露资源泄露或 goroutine 累积问题。

## 5. 资源效率基准与阈值校验（2.4）

1. 先按上文运行 `tools/loadtest` 覆盖核心路径，等待 Prometheus 指标稳定（建议 2-3 分钟窗口）。
2. 调用 `tools/perfcheck` 校验阈值（P95 CPU <80%、P95 内存 <85%、P95 IO <80%、任务失败率 <1%）：  
   ```bash
   cd server
   go run ./tools/perfcheck \
     --metrics-url http://127.0.0.1:8080/metrics \
     --cpu-p95-threshold 80 \
     --mem-p95-threshold 85 \
     --io-p95-threshold 80 \
     --failure-rate-threshold 0.01
   ```
3. 输出示例：  
   ```
   Agent CPU P95: 63.50% (limit 80.00%)
   Agent Memory P95: 71.20% (limit 85.00%)
   Agent IO Util P95: 58.75% (limit 80.00%)
   Task failure rate: 0.0030 (limit 0.0100)
   PASS: thresholds satisfied
   ```
4. 若 FAIL，可结合 `d_eyes_server_agent_cpu_percent_bucket`、`d_eyes_server_agent_memory_percent_bucket`、`d_eyes_server_agent_io_util_percent_bucket` 与 `d_eyes_server_tasks_completed_total{status="failed"}` 分布定位瓶颈。  
   **PromQL 模式**：Prometheus 若已聚合历史窗口，可直接向 API 查询，避免累积值掩盖突刺。  
   ```bash
   go run ./tools/perfcheck \
     --prom-url http://127.0.0.1:9090 \
     --window 10m \
     --cpu-p95-threshold 80 \
     --mem-p95-threshold 85 \
     --io-p95-threshold 80 \
     --failure-rate-threshold 0.01
   ```
   `--prom-url` 会启用 `histogram_quantile(rate(...[window]))` 计算方式，默认 `--window 5m`，可根据负载测试持续时间自行调整。
   若 metrics/Prometheus 需要鉴权，可加上 `--bearer-token "$PROM_TOKEN"`、`--ca-file /path/to/ca.pem`；`--json perfcheck-report.json` 可输出结构化摘要供 CI 存档。
5. CI 门禁示例：  
   ```bash
   # 结合压测输出在 CI/预发冒烟阶段执行，失败即退出
   go run ./tools/perfcheck \
     --metrics-url $METRICS_URL \
     --cpu-p95-threshold 80 \
     --mem-p95-threshold 85 \
     --io-p95-threshold 80 \
     --failure-rate-threshold 0.01
   ```

## 6. CI / Alert 集成

- **CI 目标**：压测完成后执行 `make perfcheck`（通过 `METRICS_URL` 指向 Prometheus/exporter），若触发阈值则流水线失败，阻断发布。
- **受保护环境**：可通过 `PROM_URL/PROM_WINDOW` 切换 PromQL 模式，`PERF_BEARER_TOKEN`、`PERF_CA_FILE` 注入鉴权，`PERF_JSON_OUT` 生成 JSON 报表，方便与 CI 产物/报警联动。
- **Alertmanager**：可直接将 `server/docs/OBSERVABILITY.md` 中的 CPU/内存/IO 告警表达式写入告警规则，并订阅到 Ops 渠道，实现自动化看护。

压测结果可作为上线前的可靠性验证材料，配合 `docs/OBSERVABILITY.md` 的告警草案形成交付闭环。
