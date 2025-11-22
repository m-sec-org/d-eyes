## Why
- `agent/internal/agent/daemon.go` 与 `remote/client.go` 已实现完整的 Register/Heartbeat/PullTasks/ReportResult 循环，但这些接口字段（metadata、telemetry、artifact token）在 `openspec/specs/agent-server-foundation` 与 `server-core` 中缺乏统一描述，跨团队协作只能靠读源码。
- Heartbeat payload 目前会在 Agent 侧拼装 `telemetry.*` 与 `cache.*` metadata，但 gRPC contract 与 Server 的行为/指标模块并未在规格中指明，导致 `HeartbeatRequest.metadata` 与 shutdown 语义长期悬空。
- Server 的 artifact presign + Threat Intel Orchestrator 管线需要 Agent 回传 `threatintel.artifact_tokens` 或 gRPC artifacts，可是 spec 里只有“Agent escrow 文件”描述，没有对 `/api/v1/artifacts/*`、`ReportResult.metadata` 与行为遥测 (`telemetry.process_tree` 等) 的要求，使得接口对齐和回归测试都缺乏依据。

## What Changes
- 扩写 `agent-server-foundation` 中的“注册/心跳”“远程任务循环”要求，明确 Register 校验、Heartbeat 遥测字段、PullTasks/ReportResult 的 `model.ExecutionResult`/metadata 合并、断线缓存与 sandbox/threatintel 配置合并机制。
- 新增“Result Metadata & Artifact Escrow”要求，约束 `telemetry.*`/`cache.*`/`threatintel.*` key 以及 gRPC `artifacts` 与 `/api/v1/artifacts/presign` token 流程，确保行为分析与 Threat Intel Orchestrator 能消费到完整上下文。
- 更新 `server-core` 规格，记录 gRPC 服务如何写入 store、行为管线与指标，Scheduler 如何构造/回收租约，以及 Threat Intel Orchestrator + Artifact Manager 的 ingestion 流程；新增 Artifact presign/upload API 的正式要求。

## Impact
- Affected specs: `agent-server-foundation`, `server-core`.
- Affected code: `agent/internal/agent`（remote runner/heartbeat）、`agent/internal/tasks` 与 `agent/internal/telemetry`（metadata/telemetry）、`server/internal/grpcsvc`、`server/internal/artifacts`、`server/internal/threatintel`、`server/internal/behavior`、`server/internal/api/v1`（artifact与任务 API）。
