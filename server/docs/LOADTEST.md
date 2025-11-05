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

压测结果可作为上线前的可靠性验证材料，配合 `docs/OBSERVABILITY.md` 的告警草案形成交付闭环。
