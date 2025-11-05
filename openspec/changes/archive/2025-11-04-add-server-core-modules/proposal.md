## Why
- `docs/design-next.md:5-15` 明确指出需要构建 Server 核心服务层（注册、调度、数据管理）以支撑 Agent-Server 架构，而当前 server 目录仅有 `server/cmd/server/main.go:1` 的骨架，缺乏实际业务能力。
- `openspec/changes/plan-agent-server-foundation/design.md:44-88` 规划的组件（registry、scheduler、persistence）尚未落地，实现受阻于缺少统一任务模型与数据存储。
- 现有 Agent 已拆分至 `agent/`（`agent/internal/app.go:1` 仍依赖 CLI 模式），若不补齐 Server 端核心功能，无法完成注册与远程任务执行闭环，导致 `agent-server-foundation` Spec 无法通过验收。

## What Changes
- **定义任务与结果数据模型**：在 Server 端落地 Postgres schema 与 Redis 缓存结构，提供迁移脚本与 DAO。
- **实现 Agent 注册/心跳/任务拉取 gRPC 服务**：覆盖证书校验、能力标签、心跳状态更新与任务租约。
- **实现 REST 任务管理 API**：支持任务创建、查询、取消以及结果摘要获取，与 scheduler 对接。
- **构建调度器与执行协调层**：实现优先级队列、任务状态机、重试逻辑，并与持久化层联动。
- **补充配置、监控与测试设施**：统一配置加载、暴露基础指标，提供集成测试覆盖注册-执行-回传流程。

## Impact
- **代码结构**：将在 `server/internal/` 下新增 `config/`, `api/`, `grpc/`, `scheduler/`, `store/`, `model/` 等模块，引入 protobuf/gRPC 代码生成与数据库迁移工具。
- **依赖**：新增 `gorm.io/gorm` 或 `github.com/jackc/pgx/v5`、`github.com/go-redis/redis/v9`、`google.golang.org/protobuf` 等依赖，并引入 `proto` 目录与 `Makefile`/脚本协助生成代码。
- **运维**：提供 Docker Compose 示例，包含 `postgres`、`redis`、`server` 服务；新增 `config/server.yaml` 及环境变量说明。
- **测试策略**：引入端到端测试使用 testify + testcontainers（或 docker compose）验证 gRPC/REST 行为，单元测试覆盖 scheduler 与 store。

## Open Questions
- Scheduler 初期是否需要支持多租户/分区调度？默认实现按任务类型+优先级即可，后续再扩展。
- Agent 鉴权采用双向 TLS 还是 token + TLS？阶段一建议实现 token + TLS，并在设计文档中保留扩展点。
