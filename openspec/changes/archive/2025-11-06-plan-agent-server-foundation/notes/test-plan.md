# Agent-Server 联合测试矩阵（B7）

## 1. 测试目标
- 验证 CLI 独立模式在最新改造后保持原有功能。
- 验证远程模式在不同网络/错误场景下的稳定性（注册、心跳、任务执行、结果回传）。
- 验证插件化 Runner 与远程模式的兼容性。

## 2. 场景矩阵

| 场景 | 步骤 | 期望结果 | 备注 |
| ---- | ---- | -------- | ---- |
| CLI 单机任务 | `go run ./cmd/agent respond --profile quick` | 本地输出摘要，退出码符合策略 | 覆盖 respond/baseline/inventory 等主命令 |
| 远程模式基础 | 启动 Server（Docker Compose）→ `go run ./cmd/agent remote` → 远程 API 创建任务 | Agent 注册成功，任务完成并在 Server 端 status=Succeeded | 使用内存模式或 PostgreSQL/Redis |
| 远程断线重连 | 运行远程模式 → 停止 Server → 恢复 Server | Agent 指数回退重连成功，缓存任务在恢复后上报且无重复 | 观察日志与缓存目录 |
| 远程失败重试 | 远程模式执行自定义错误 Runner（返回非 0） | Server 记录失败状态，Agent 输出错误摘要并清理缓存 | 验证 `remote.FileStore` 行为 |
| 插件 Runner | 注册示例插件命令 → 远程模式下创建对应任务 | 任务被远程执行并返回插件输出 | 验证 `TaskRunnerByName` 能识别插件 |
| 大量并发任务 | 利用 Server `tools/loadtest` 模拟 50+ 任务 | Agent 持续处理并回传；Server 队列深度无异常 | 确保 `task_queue_depth` 指标稳定 |
| 回滚检查 | 停止远程模式 → CLI 手动执行任务 | 本地行为不受远程改造影响 | 作为回滚手段验证 |

## 3. 自动化建议
- 在 `server/internal/app/app_integration_test.go` 基础上新增 Agent 端到端测试脚本（可使用 bufconn + in-memory store）。
- 引入 GitHub Actions（或内部 CI）执行 `go test ./agent/...` + e2e 脚本。
- 可选：构建 `scripts/e2e.sh` 启动 Docker Compose + 远程模式 + REST/FMD 验证。

## 4. 指标与日志
- Prometheus 指标：`task_queue_depth`、`task_time_to_lease_seconds`、`tasks_completed_total{status}`。
- Agent 日志：心跳重连、任务执行耗时、缓存写入/删除。
- Server 日志：gRPC 注册/上下线、任务调度、结果上报。

## 5. 上线检查表
1. CLI 命令冒烟测试（核心任务各执行一次）。
2. 远程模式在测试环境通过基础场景 + 断线重连测试。
3. 指标面板、日志告警验证。
4. 插件兼容性确认（官方 Runner + 至少一个示例插件）。
5. 失败任务回放验证（缓存目录清理、重复上报检查）。

## 6. 回滚方案
- 如远程模式异常：停止 Agent 远程守护 → 恢复 CLI 手动执行方式。
- 可在 Server 配置中暂停下发任务（清空调度队列），避免队列堆积。
- 保留 `remote.cache_dir` 中的结果文件以便人工回放。

