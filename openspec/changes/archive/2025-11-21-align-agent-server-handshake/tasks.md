## 1. Agent runtime & metadata
- [x] 1.1 扩展 `remote.Client.StartHeartbeat` 与 `grpc.AgentService` 调用链，确保 `HeartbeatRequest.metadata` 携带 `telemetry.*` 与 `cache.*` 键，并补充单元测试覆盖。
- [x] 1.2 在 `processLease`/`tasks.ExecuteWithResult` 中统一封装 `model.ExecutionResult`、`telemetry.Encode*` 与 `reportFailure`，保证 `summary_json`、`metadata`、`exit_code/error_code` 与 `remote.FileStore` 缓存格式完全对齐 spec。
- [x] 1.3 实现 Agent 端的 artifact presign/upload client（包括超时、重试、加密元数据），在 Respond/Baseline/BAS 模块检测高危样本时生成 `threatintel.artifact_tokens` 或直接附带 gRPC `artifacts`，并新增 e2e/单元测试。

## 2. Server gRPC/API surface
- [x] 2.1 更新 `server/internal/grpcsvc.Service.Register/Heartbeat` 以存储新的 metadata、刷新 `behavior`/`metrics`，并在需要时下发 `should_shutdown`；补充 store/interface 测试。
- [x] 2.2 强化 `ReportResult`：消费 `telemetry.*`/`threatintel.*` metadata、保留 artifacts、调用 `scheduler.CompleteTask` 与 `behavior.RecordTaskTelemetry`，为行为图/查询接口提供一致数据。
- [x] 2.3 提升 Artifact presign/upload API 的约束（大小/TTL/哈希），串联 Artifact Manager 与 Threat Intel Orchestrator，确保 `/api/v1/threat-intel/jobs` 可以关联上传的 artifact IDs。

## 3. Validation & docs
- [x] 3.1 补充跨进程集成测试或 contract 测试（mock gRPC + HTTP）验证 Register/Heartbeat/PullTasks/ReportResult 全链路，并同步 README/运维文档。
