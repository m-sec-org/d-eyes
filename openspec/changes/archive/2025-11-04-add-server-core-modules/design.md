# D-Eyes Server 核心模块设计

## 1. 目标
- 将 `openspec/changes/plan-agent-server-foundation/design.md:44-121` 中规划的 Server 组件落地为可运行的 MVP。
- 支撑 Agent 的注册、心跳、任务领取与结果回传闭环，同时提供 REST 任务管理与持久化。
- 为后续高级功能（任务模板、Playbook、监控）奠定可扩展基础。

## 2. 架构概览

```
┌─────────────────────────┐
│        HTTP API         │ Gin (/api/v1)
└────────────┬────────────┘
             │
┌────────────▼────────────┐
│     Command Service      │ 任务创建/取消、状态查询
└────────────┬────────────┘
             │
┌────────────▼────────────┐          ┌──────────────────────┐
│      Scheduler Core      │◄─────────│ Redis Queue (lease) │
│ Priority Queue + Lease   │          └──────────────────────┘
└────────────┬────────────┘
             │
┌────────────▼────────────┐
│      gRPC Agent API      │ Register / Heartbeat / PullTask / ReportResult
└────────────┬────────────┘
             │
┌────────────▼────────────┐
│      Task Executor       │ Adapter to Agent tasks (future)
└────────────┬────────────┘
             │
┌────────────▼────────────┐
│    PostgreSQL Store      │ tasks, task_runs, agents, artifacts
└─────────────────────────┘
```

### 模块划分
- `internal/config`: 读取 YAML + env，提供结构体（Server, Database, Redis, Security, Scheduler）。
- `internal/logger`: 封装 zap/slog 初始化。
- `internal/model`: 定义 Agent、Task、TaskRun、Result 等领域模型。
- `internal/store`: 封装持久化（PostgreSQL via GORM 或 sqlc+pgx）& Redis 操作。
- `internal/scheduler`: 实现优先级队列、租约、心跳超时处理。
- `internal/grpc`: 实现 protobuf 生成的服务接口，依赖 scheduler/store。
- `internal/api`: Gin handler，调用 Command Service 与 scheduler/store。
- `internal/metrics`: 暴露 Prometheus 指标。
- `proto/agentservice.proto`: 定义 gRPC 协议，与 Agent 共享。

## 3. 数据模型
- `agents`
  - `id UUID PK`
  - `name`, `labels JSONB`, `platform`, `version`
  - `status (online/offline)`, `last_heartbeat TIMESTAMP`
  - `token_hash`, `capabilities JSONB`
- `tasks`
  - `id UUID PK`
  - `type`（枚举: respond/baseline/...）
  - `priority INT`
  - `payload JSONB`（任务参数、目标集合）
  - `status`（pending, leased, running, succeeded, failed, canceled）
  - `created_by`, `metadata JSONB`, `created_at`, `updated_at`
- `task_runs`
  - `id UUID PK`
  - `task_id` FK
  - `agent_id` FK
  - `lease_expires_at`
  - `started_at`, `finished_at`
  - `status`, `retry_count`, `error_msg`
  - `summary JSONB`（风险、输出路径）
- `artifacts`
  - `id UUID`
  - `task_run_id` FK
  - `name`, `content_type`, `storage_ref`

Redis 结构：
- `agent:heartbeat:<agentID>` 存 TTL（15s），存储状态/负载。
- `queue:task:<type>` Sorted Set `<priority, taskID>`。
- `lease:task:<taskID>` Hash 保存当前 Agent/截止时间。

## 4. gRPC 协议

```
service AgentService {
  rpc Register(RegisterRequest) returns (RegisterResponse);
  rpc Heartbeat(stream HeartbeatSignal) returns (stream HeartbeatAck);
  rpc PullTask(TaskLeaseRequest) returns (TaskLeaseResponse);
  rpc ReportResult(stream TaskResultChunk) returns (ReportAck);
}
```

- `RegisterRequest`: token, agent_metadata（name, platform, capabilities），supports optional certificate fingerprint。
- `HeartbeatSignal`: agent_id, load, running_tasks, timestamp。
- `TaskLeaseResponse`: task_id, type, payload (JSON bytes), timeout, lease_id。
- `TaskResultChunk`: 支持分块上传，含 chunk_id、artifact metadata。

Lease 流程：
1. Scheduler 根据 Redis 队列提取任务，持久化 lease 记录到 `task_runs`，设置 `lease_expires_at`。
2. `PullTask` 返回任务与 lease 信息给 Agent。
3. Agent 执行后，通过 `ReportResult` 上传 summary 与 artifacts。
4. `ReportResult` 结束时更新 `task_runs`、`tasks` 状态并清理 Redis lease。

## 5. 调度策略
- 默认优先级：0（最高）~ 10（最低），REST API 创建任务时提供。
- 公平分配：Scheduler 按 Agent 标签/能力匹配，避免同一 Agent 连续领取不同类型任务，可配置最大并发。
- 超时处理：若 `lease_expires_at` 超时且无结果，任务标记为 `pending` + `retry_count++`，并记录事件。
- 重试次数默认 3 次，可配置。

## 6. 安全
- gRPC：服务端 TLS，客户端使用 token（header/metadata）+ 可选证书指纹。
- REST：提供 API Key 中间件；后续扩展 OIDC。
- 数据存储：任务 payload/结果采用 JSONB，敏感字段可加密（预留接口）。

## 7. 配置
示例 `config/server.yaml`：
```yaml
server:
  http_addr: ":8080"
  grpc_addr: ":9090"
  tls:
    enabled: true
    cert_file: ./certs/server.crt
    key_file: ./certs/server.key
security:
  agent_token: "changeme"
database:
  dsn: postgresql://d-eyes:password@postgres:5432/d-eyes?sslmode=disable
redis:
  addr: redis:6379
scheduler:
  lease_ttl: 120s
  max_retries: 3
  heartbeat_timeout: 15s
```

## 8. 测试计划
- **单元测试**：使用 testify/mock 封装 store/scheduler 行为，覆盖状态机和输入验证。
- **集成测试**：使用 docker compose 或 testify + testcontainers 启动 Postgres & Redis，模拟 Agent 行为（go routines 调用 gRPC）。
- **负载测试**：简单基准脚本（wrk/k6）调用 PullTask/ReportResult，验证 50 并发任务下延迟 < 1s。

## 9. 部署示例
- `deploy/docker-compose.yml`（新增）：包含 `postgres`, `redis`, `server`，默认映射配置文件与证书。
- `Makefile` 目标：
  - `make proto`：生成 gRPC 代码。
  - `make run`：加载 dev 配置启动 server。
  - `make test`：运行单元 + 集成测试。

## 10. 风险与缓解
- **数据一致性**：任务状态跨 Redis 与 Postgres，需要幂等 lease ID；在 scheduler 中采用事务与 Lua 脚本确保队列原子性。
- **网络抖动**：Heartbeat 为双向流，Agent 断线时 gRPC 会触发关闭；Server 需监听 context cancel，及时释放 lease。
- **依赖复杂度**：引入 Postgres/Redis 需要本地开发便利；提供 Docker Compose 与内存模式（fallback）降低门槛。
