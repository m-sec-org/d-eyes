# 混沌 / 失效注入指南

Stage4 要求在发布前验证 Scheduler、消息队列、存储与 Agent 断连等场景的韧性。以下脚本均位于 `scripts/chaos/`，支持本地或 CI 集成。

## 1. Scheduler 租约突刺
- `scripts/chaos/inject-scheduler-burst.sh`
- 调用 scheduler 单元测试（租约/并发控制）模拟快速租约与回收，观察 `/metrics` 中的 `task_queue_depth`、`tasks_in_flight` 与日志，确保不会出现死锁或无限重试。

## 2. 队列延迟 / 无任务
- `scripts/chaos/inject-queue-delay.sh`
- 触发 `TestLeaseTask_NoTaskAvailable` 等路径，模拟队列暂时空转或 Redis 延迟，通过 Prometheus `BASBacklog`、`TaskQueueDepth` 观察恢复速度。

## 3. 存储异常
- `scripts/chaos/inject-storage-failure.sh`
- 运行 store 层的 retry/lease 测试，模拟 Postgres/MemStore 失败，确认自愈机制可重试且不会产生脏数据。

## 4. Agent 断连
- `scripts/chaos/inject-agent-disconnect.sh`
- 使用 gRPC Heartbeat 测试模拟 Agent 心跳中断，观察 `agent_heartbeats_total`、`agent status offline` 与 alert 通知是否触发。

## 5. 执行方式

```bash
scripts/chaos/inject-scheduler-burst.sh
scripts/chaos/inject-queue-delay.sh
scripts/chaos/inject-storage-failure.sh
scripts/chaos/inject-agent-disconnect.sh
```

或通过 CI：

```bash
for script in scripts/chaos/*.sh; do
  "$script"
done
```

> 建议在运行混沌脚本前，确保 `scripts/test-matrix.sh` 已通过，并在结束后监控 Prometheus 与日志，确认系统恢复正常。
