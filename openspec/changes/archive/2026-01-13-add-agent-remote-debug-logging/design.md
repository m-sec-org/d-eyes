## Context
Remote 模式的联动链路包含 gRPC（注册/心跳/拉取/回传）与可选 HTTP（events/artifacts 上传）。当链路某一环失败时，需要在不泄漏敏感信息的前提下，提供足够的上下文与关联字段帮助定位问题。

## Goals / Non-Goals
- Goals:
  - Debug 模式下能在日志中追踪一次任务的完整生命周期：PullTasks → 执行 → ReportResult（以 `task_id/lease_id` 关联）
  - 让“鉴权失败/连通性问题/任务参数不合法/执行失败/回传失败”具备可行动的日志证据
  - 默认去敏（不输出 token / api key / 可疑 payload）
- Non-Goals:
  - 不在本次提案引入新的鉴权机制或协议变更
  - 不要求在非 debug 模式改变现有日志噪声水平

## Decisions
- 日志触发条件：以 CLI `--debug` 或环境变量 `DEYES_DEBUG=1` 为准（与现有 CLI debug 口径一致）。
- 日志格式：输出可过滤的“结构化文本”（例如固定前缀 + key=value），确保在终端、systemd/journal、以及重定向到文件时都易于检索。
- 去敏策略：
  - 永不输出 `remote.agent_token`、任何 `X-API-Key` 值、以及可能包含秘密的 header
  - 对 `payload/metadata` 默认只输出“字节大小 + top-level keys”，不输出 values
  - 错误信息允许输出但需限制长度（避免携带敏感内容的长串）
- 噪声控制：Heartbeat 属于高频交互；debug 模式下至少记录启动/失败/重连事件，避免每 tick 全量刷屏（如需更细粒度可后续扩展为单独开关）。

## Risks / Trade-offs
- 过度日志会影响性能与可读性 → 采用字段化 + 限流策略
- Debug 信息可能携带秘密 → 强制去敏 + 单测防回归

## Open Questions
- 是否需要额外提供“写入本地调试 trace 文件（JSONL）”的能力，便于离线分析（例如写入 `remote.cache_dir`）？
