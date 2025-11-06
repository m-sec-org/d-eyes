# 阶段一设计：Agent-Server 基础设施 MVP

## 1. 目标与非目标
- **目标**
  - 支撑最小可行的 Agent-Server 架构，实现 Agent 注册、心跳、任务调度、结果回传闭环。
  - 复用现有 CLI 能力（`internal/tasks/*.go`、`pkg/reporting` 等），保证 respond/baseline 等任务可在 Agent 端执行。
  - 为后续阶段扩展（任务模板、Web UI、插件市场）提供稳定的服务端与 Agent 抽象。
- **非目标**
  - 不交付完整的 Web 管理控制台，仅提供 REST API 与基础 Swagger 文档。
  - 不集成 Kafka、Elasticsearch 等重型依赖，阶段一以内置队列 + PostgreSQL/Redis 支撑。
  - 不重写各业务模块算法，优先保持现有扫描能力的行为一致性。

## 2. 现状分析
- CLI 入口由 `internal/app.go:21` 初始化，所有命令通过 `tasks.Execute`（`internal/tasks/execute.go:17`）串联报告输出与策略评估。
- 任务模块紧耦合终端参数/输出，缺乏远程执行抽象，报告保存逻辑内嵌于 `pkg/reporting/manager.go`。
- 配置加载与注入逻辑集中在 `pkg/config` 与 `internal/app.go:144`，需要提取为共享库以同时服务 Server 与 Agent。

## 3. 架构概览
- **Server 组件**
  - `API Gateway (Gin)`：暴露 REST API（任务管理、Agent 查询、作业状态），同时提供 Swagger/OpenAPI。
  - `gRPC Endpoint`：处理 Agent 注册、心跳、任务领取与结果上报。
  - `Task Scheduler`：维护任务队列（先用 Redis Stream 或内存队列），支持轮询/优先级调度。
  - `Persistence`：PostgreSQL 管理任务、结果、Agent 元数据；Redis 提供心跳与短期状态缓存。
- **Agent 组件**
  - `Runtime Manager`：负责启动、配置、生命周期管理。
  - `Transport Client`：封装与 Server 的 gRPC 交互、TLS 认证、重连。
  - `Task Executor`：对接共享 `task engine`，将任务落地到现有模块。
  - `Result Buffer`：在网络异常时缓存执行结果（BoltDB 或本地文件）。
- **Shared Libraries**
  - `pkg/runtime`：统一加载配置、日志、指标。
  - `pkg/taskmodel`：定义任务/结果 protobuf 与 Go 结构体。
  - `pkg/executor`：对 `internal/tasks.Execute` 进行封装，支持“本地 CLI”与“Agent 托管”两种模式。

### 控制流
1. 用户通过 REST API 创建任务（指定任务类型、配置、目标列表）。
2. Server 将任务写入队列，等待可用 Agent。
3. Agent 启动后与 Server 建立 TLS/gRPC 连接，提交注册元数据（平台、能力、标签）。
4. Agent 定期发送心跳，携带当前负载；Server 根据能力匹配分配任务。
5. Agent 领取任务后，通过共享执行器加载相应模块，执行并收集报告。
6. 执行结果通过 gRPC 流式回传，Server 落库并触发报告聚合。

## 4. 模块设计

### 4.1 Server
- `cmd/server/main.go`：解析配置 → 初始化依赖 → 启动 HTTP + gRPC。
- `internal/server/config`：封装环境变量/文件配置，兼容现有 `pkg/config`。
- `internal/server/registry`：维护 Agent 状态（内存 + Redis 缓存），提供查询接口。
- `internal/server/scheduler`
  - 初期实现优先级队列（内存 + Redis），支持简单 round-robin。
  - 任务模型包含：任务 ID、类型、payload（JSON/protobuf）、约束（超时、并发、目标）。
- `internal/server/handlers`
  - REST：任务 CRUD、模版展示（stub）、Agent 列表/状态。
  - gRPC：`Register`, `Heartbeat`, `PullTask`, `ReportResult`，采用流式接口降低长连接重复建立。
- `internal/server/persistence`
  - 使用 GORM 或 sqlc 定义 migration；表结构：`agents`, `tasks`, `task_runs`, `artifacts`.
  - 结果大对象（例如报告 JSON）可存储在 PostgreSQL JSONB 字段，保证查询能力。

### 4.2 Agent
- `cmd/agent/main.go`：加载配置 → 初始化组件 → 启动心跳与任务循环。
- `internal/agent/config`：支持本地 YAML + 环境变量 + 命令行 flag。
- `internal/agent/comm`
  - gRPC 客户端，具备 TLS、双向证书校验（阶段一可选单向 TLS + token）。
  - 实现带指数退避的重连策略。
- `internal/agent/runtime`
  - 维护任务执行线程池，根据 Server 分发的并发限制调整 Goroutine。
  - 引入 context 传递超时时间、取消信号。
- `internal/agent/executor`
  - 调用共享 `pkg/executor`，该模块负责把任务 payload 映射到 `tasks.TaskRequest`。
  - 支持钩子（before/after），为未来的审计与指标留接口。
- `internal/agent/storage`
  - 提供 BoltDB 实现的 `ResultStore`，缓存未上报/待重试任务结果。

### 4.3 公共抽象与协议
- 新建 `proto/task.proto`，定义：
  - `RegisterRequest/Response`, `HeartbeatRequest`, `TaskLease`, `TaskResult`.
  - 支持能力标签（`capabilities`）、Agent 属性、任务执行上下文。
- `pkg/taskmodel`：自动生成的 Go 代码 + 辅助转换函数（与 `tasks.TaskRequest` 双向转换）。
- `pkg/executor`
  - 将 CLI 中 `TaskRequest`/`TaskResult` 提升为公共接口。
  - 负责调用 `tasks.Execute` 并收集 `reporting.Manager` 输出；针对 Server 模式，提供 `ArtifactCollector`，将输出封装为可序列化结果。
- `pkg/config/runtime`
  - 从 `internal/app.go:144` 拆出的配置加载逻辑，支持 CLI/Server/Agent 共享。

## 5. 数据模型
- `agents` 表：`id`, `name`, `labels JSONB`, `platform`, `version`, `status`, `last_heartbeat`.
- `tasks` 表：`id`, `type`, `payload JSONB`, `priority`, `created_by`, `status`.
- `task_runs` 表：`id`, `task_id`, `agent_id`, `started_at`, `finished_at`, `status`, `summary JSONB`.
- Redis 键：`agent:<id>:heartbeat`, `queue:task:<type>`。
- BoltDB bucket：`pending_results`, `pending_tasks`.

## 6. 迁移与兼容策略
- CLI 保持可用：`d-eyes` 主程序继续支持本地执行，直至阶段二完成迁移。
- 复用策略
  - `internal/tasks` 保持 API 不变，新增 `Adapter` 层将 Server 任务 payload 转换为现有结构。
  - 报告输出：新增 `reporting.RemoteWriter`，将输出写入内存结构以便 gRPC 回传，同时保留文件写入能力（用于本地调试）。
- 渐进式引入
  - 阶段一交付后，先提供 respond/baseline 模块通过 Agent 执行，其余模块继续在 CLI 运行。
  - Server 端增设 `local-runner` 选项，允许无 Agent 时回退到单机模式。

## 7. 安全与配置
- **认证**：阶段一提供 token + TLS 方案；注册时验证 token，并在数据库记录 Agent 指纹。
- **授权**：REST API 以 JWT + RBAC 协议预留，实际实现采用静态角色映射。
- **配置管理**：Server/Agent 均支持 YAML + env；提供示例 `config/server.yaml`, `config/agent.yaml`。
- **审计**：记录任务创建、状态更新、Agent 操作日志（PostgreSQL）。

## 8. 测试与观测
- **单元测试**：针对 scheduler、registry、executor 的核心逻辑编写 go test。
- **集成测试**：使用 docker compose 启动 Server + Agent + PG + Redis，Go 测试通过 gRPC/REST 调用验证整链路。
- **性能基线**：模拟 50 并发任务，验证任务领取延迟 <1s，心跳丢失重试 <10s。
- **监控指标**：暴露 Prometheus metrics（任务等待时间、执行时长、Agent 在线数），同时记录结构化日志。

## 9. 风险与缓解
- **任务模型不兼容**：通过双向转换器保证旧模块继续使用 `TaskRequest`；先支持 respond/baseline，逐步扩展。
- **状态一致性问题**：Redis + PostgreSQL 双写风险，通过幂等 task_run ID、结果重放检测缓解。
- **网络不稳定**：Agent 侧本地缓存 + 重试队列 + 指数退避重连。
- **团队学习曲线**：提供脚手架、示例代码与详尽文档；采用最小可行依赖组合。

## 10. 里程碑
1. **M1（第 4 周）**：Server/Agent 骨架上线，可完成注册 + 心跳 + 手工任务注入。
2. **M2（第 8 周）**：respond 模块远程执行闭环完成，端到端集成测试通过。
3. **M3（第 12 周）**：baseline 模块接入、Docker Compose 与监控指标落地，阶段一验收。
