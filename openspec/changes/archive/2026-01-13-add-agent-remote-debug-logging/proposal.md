## Why
当前 Agent 的 `remote` 模式在排障时可观测性不足：当 Server 下发任务、租约被领取、或执行失败/鉴权失败时，控制台/日志往往只看到一条泛化错误（例如 `invalid agent token`），难以快速定位问题发生在“连接/注册/心跳/拉取/执行/回传/HTTP 上传”中的哪一环、对应的 `task_id/lease_id` 是什么、以及失败的上下文参数。

## What Changes
- 在 Agent 以 `remote` 模式启动且启用 `--debug`（或 `DEYES_DEBUG=1`）时，**新增可过滤、可关联、可去敏** 的调试日志输出，覆盖与 Server 的关键交互（gRPC Register/Heartbeat/PullTasks/ReportResult）以及可选的 HTTP 上传（events/artifacts）。
- 调试日志必须包含用于关联排障的字段（至少 `agent_id/task_id/lease_id/task_type` 等），并遵守“不得输出 token/api key/敏感 payload”的红线。
- 调试日志必须写入 stderr（或与现有日志一致的输出通道），以避免破坏 stdout 的机器可读输出（例如 `--json`）。

## Impact
- Affected specs: `openspec/specs/agent-server-foundation/spec.md`
- Affected code (planned): `agent/internal/agent/daemon.go`, `agent/internal/agent/remote/client.go`, `agent/internal/agent/event_uploader.go`, `agent/pkg/artifacts/client.go`, 以及相关测试与文档
