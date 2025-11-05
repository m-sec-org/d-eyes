## Why
- 参考 `docs/design-next.md:11` 所描述的目标架构，现有 CLI 单体（如 `internal/app.go:21`、`internal/tasks/respond.go:1`）缺乏集中调度与多节点执行能力，难以支撑大规模场景。
- 现有任务执行链路耦合 CLI 生命周期（`internal/tasks/execute.go:17` 起），无法复用到 Server/Agent 模式，导致能力扩展与远程管理受限。
- 社区 roadmap 要求提供分阶段演进方案，首要目标是交付 Agent-Server 基础架构与最小可行功能，从而支撑后续功能迁移与高级能力建设。

## What Changes
- **规划三阶段演进路线**：梳理从单体 CLI 向分布式平台演进的阶段目标、关键里程碑、依赖关系与技术风险。
- **阶段一（MVP）设计**：定义 Agent-Server 基础能力的范围、组件拆分策略、接口规范、数据流/控制流，并明确如何复用现有 `internal/tasks` 能力。
- **落地任务拆解**：输出可执行的交付清单（服务端/Agent/基础设施/迁移改造/测试与运维），保证团队可据此进入实现。
- **需求沉淀为 Spec**：新增 `agent-server-foundation` 能力规范，定义阶段一最小可行要求与验收场景。

## Impact
- **代码结构**：需要为阶段一预留新的 `cmd/server`、`cmd/agent` 或 `internal/server`、`internal/agent` 包结构，并提取共享任务执行引擎。
- **技术选型**：确认服务端使用 Gin + gRPC + PostgreSQL + Redis 组合；消息/任务通信初期以内置队列实现，后续扩展到 Kafka。
- **运维与部署**：补充 Docker Compose 级别的最小部署方式，保证可在实验环境模拟完整链路。
- **测试策略**：要求引入端到端集成测试框架（可能基于 Go test + docker compose），验证注册、心跳、任务下发、结果回传全链路。
- **风险**：涉及大量代码拆分，需在 proposal 中明确兼容策略与渐进式落地路径，避免一次性重写导致交付不可控。

## Open Questions
- Agent 与 CLI 是否保持同一可执行文件（通过子命令区分）还是拆分二进制？阶段一默认采纳“多可执行”方案，后续可再评估。
- 现有 report manager (`pkg/reporting`) 在多租户场景的隔离策略需要进一步调研。
