# D-Eyes Server —— 分布式安全管理平台

D-Eyes Server 是 D-Eyes 安全平台的核心管理组件，负责与多个 Agent 节点协同工作，提供任务调度、状态管理、结果汇总和可视化监控等功能。Server 采用微服务架构设计，支持高可用部署，为大规模环境下的安全检测与响应提供集中式管理能力。

## 功能概述

Server 作为 D-Eyes 平台的大脑和中心控制器，提供以下核心功能：

- **Agent 管理**：支持 Agent 节点的自动注册、状态监控和心跳检测
- **任务调度**：提供高优先级任务队列和分布式任务调度机制
- **结果汇总**：收集和分析来自多个 Agent 的任务执行结果
- **API 服务**：提供 RESTful API 和 gRPC 接口，支持系统集成
- **数据持久化**：支持任务、Agent 和结果数据的持久化存储
- **监控与可观测性**：集成 Prometheus 指标，支持系统运行状态监控
- **配置管理**：集中管理 Agent 配置，支持动态下发
- **BAS 场景管理**：提供入侵和攻击模拟场景的集中配置、调度和结果分析能力

## 系统架构

### 核心组件

- **HTTP API 服务**：基于 Gin 框架的 RESTful API，提供任务管理、状态查询等接口
- **gRPC 服务**：用于 Agent 节点通信，支持注册、心跳、任务租约和结果回传
- **任务调度器**：优先级队列 + 租约管理机制，支持任务超时回收与重试
- **数据存储层**：支持内存存储和 PostgreSQL 持久化存储
- **消息队列**：支持内存队列和 Redis 分布式队列，支撑任务调度
- **监控系统**：Prometheus 指标暴露，提供系统运行状态监控
- **配置管理**：集中管理 Agent 配置，支持动态更新
- **BAS 场景引擎**：管理入侵和攻击模拟场景库，支持场景编排和执行策略配置

### 代码结构

```
├── cmd/server/           # Server 命令行入口
├── config/               # Server 配置文件
├── deploy/               # 部署相关文件
├── docs/                 # Server 开发和使用文档
├── internal/             # Server 内部实现
│   ├── api/              # RESTful API 实现
│   ├── app/              # 应用程序入口和启动逻辑
│   ├── config/           # 配置管理
│   ├── grpcsvc/          # gRPC 服务实现，用于 Agent 通信
│   ├── logger/           # 日志功能
│   ├── metrics/          # 监控指标
│   ├── model/            # 数据模型定义
│   ├── monitor/          # 监控功能，如心跳监控
│   ├── queue/            # 任务队列实现
│   ├── queueprovider/    # 队列提供者接口
│   ├── scheduler/        # 任务调度器
│   ├── store/            # 数据存储接口
│   ├── storeprovider/    # 存储提供者实现
│   └── util/             # 工具函数
├── migrations/           # 数据库迁移文件
└── proto/                # gRPC 协议定义和生成的代码
```

## 快速开始

### 本地开发环境

快速运行（默认使用内存存储）：

```bash
cd server
go run ./cmd/server --config ./config/server.yaml
```

### Docker Compose 本地联调

通过 Docker Compose 启动完整依赖环境（PostgreSQL + Redis + Server）：

```bash
cd server
make dev-up        # 构建容器镜像并后台启动所有服务
make dev-down      # 停止并清理容器与数据卷
```

Compose 配置 `deploy/docker-compose.yaml` 会在 `postgres`、`redis` 健康检查通过后再拉起 server；镜像默认挂载 `config/server.yaml`，并通过环境变量启用 PostgreSQL + Redis 存储。

### 配置说明

核心配置选项（位于 `config/server.yaml`）：

```yaml
# Server 监听地址
server:
  http_addr: ":8080"     # HTTP API 服务地址
  grpc_addr: ":9090"     # gRPC 服务地址

# 鉴权配置
security:
  agent_token: "changeme"  # Agent gRPC 注册/心跳/租约鉴权
  api_keys:
    - "changeme"           # REST API Key（HTTP Header: X-API-Key）

# 数据库配置
database:
  in_memory: true        # 是否使用内存存储
  dsn: postgres://user:password@localhost:5432/d-eyes?sslmode=disable  # PostgreSQL 连接串（in_memory=false 时启用）

# Redis 配置
redis:
  enabled: false         # 是否启用 Redis
  addr: localhost:6379   # Redis 地址
  password: ""           # Redis 密码
  db: 0                  # Redis 数据库编号

# 调度器配置
scheduler:
  lease_ttl: 120s        # 任务租约 TTL
  max_retries: 3         # 任务最大重试次数
  heartbeat_timeout: 15s # Agent 心跳超时阈值

# Task Catalog（Profile + payload 校验）的持久化路径（可选）
# - 留空：catalog 仅存在于内存，进程重启后会回到空状态并再次导入内置 seed
# - 非空：Server 会在首次导入 seed / 通过 API 变更后写入该 JSON 文件（原子写入）
task_catalog:
  persist_path: "/var/lib/d-eyes/task_catalog.json"

# Collector 控制面配置
collectors:
  allowed_providers: ["Kernel", "Security"]
  allowed_probes: ["diag-ebpf", "diag-sysmon"]  # 未列出的 provider/probe 会被 REST API 拒绝
```

### Task Catalog：TaskType / Profile / Seed（运维要点）

Server 使用 **Task Catalog** 统一管理 “task type + profile schema”，用于在 `POST /api/v1/tasks` 阶段对 `payload` 做结构校验，避免联动时出现“Server 接受但 Agent 无法按预期解析”的口径漂移。

- **Profile 与校验触发条件**：仅当请求同时提供顶层 `type` 与顶层 `profile` 时，Server 才会按 catalog schema 校验 `payload`；运维与控制台侧 **建议始终带上 `profile`**，以获得稳定的合同与错误提示。
- **内置 seed**：Server 启动时若 catalog 为空（task types 与 task profiles 都为空），会自动导入内置 seed（默认覆盖 `respond/audit/inventory/supplychain/baseline/bas/action` 以及 `detect.diag`/`detect.memscan`）；若 catalog 非空则不会覆盖/迁移用户数据。
- **持久化**：设置 `task_catalog.persist_path` 后，导入 seed 与后续 API 修改会写入该 JSON 文件；留空则 catalog 仅在内存中，重启后会重新导入 seed（适合开发/演示，不建议生产）。
- **扩展/覆盖方式**：通过 catalog API 管理（见下文），推荐以“新增 profile（例如 respond.ransomware）”的方式演进；如需覆盖内置 profile，可用 `PUT /api/v1/task-profiles/:id` 更新 schema（生产场景建议先备份 persist 文件）。

## API 使用指南

### RESTful API

Server 提供完整的 RESTful API，支持任务管理、Agent 查询等功能：

```bash
# 创建任务（推荐：使用 profile 触发 task catalog 校验）
curl -X POST http://127.0.0.1:8080/api/v1/tasks \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: changeme' \
  -d '{
        "type":"respond",
        "profile":"default",
        "priority":1,
        "payload":{"targets":"/tmp,/var/log"},
        "metadata":{"required_capabilities":"respond"}
      }'

# 创建任务（audit 示例）
curl -X POST http://127.0.0.1:8080/api/v1/tasks \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: changeme' \
  -d '{
        "type":"audit",
        "profile":"audit",
        "priority":1,
        "payload":{"scope":"system"},
        "metadata":{"required_capabilities":"audit"}
      }'

# 列出最近任务（状态过滤可选）
curl -H 'X-API-Key: changeme' "http://127.0.0.1:8080/api/v1/tasks?status=pending,failed&limit=10"

# 查询单个任务（附带最近一次执行摘要）
curl -H 'X-API-Key: changeme' http://127.0.0.1:8080/api/v1/tasks/<TASK_ID>

# 触发重试
curl -X POST -H 'X-API-Key: changeme' http://127.0.0.1:8080/api/v1/tasks/<TASK_ID>/retry

# 查询在线 Agent
curl -H 'X-API-Key: changeme' http://127.0.0.1:8080/api/v1/agents?status=online
```

### Task Catalog API（扩展/覆盖默认 catalog）

以下接口用于查询与管理 task catalog（task types / profiles / schema）：

```bash
# 列出可用 task types（含内置 seed）
curl -H 'X-API-Key: changeme' http://127.0.0.1:8080/api/v1/task-types

# 列出某个 task type 的 profiles
curl -H 'X-API-Key: changeme' "http://127.0.0.1:8080/api/v1/task-profiles?task_type=respond"

# 查看某个 profile 的 schema（用于控制台/运维校对 payload 形态）
curl -H 'X-API-Key: changeme' http://127.0.0.1:8080/api/v1/task-profiles/default
```

> 说明：
> - 对 catalog 的修改是否跨重启生效取决于 `task_catalog.persist_path`（见上文）。
> - 若希望回到“内置 seed 基线”，可清空 persist 文件（或切换到新的 persist_path）后重启 Server；seed 仅在 catalog 为空时导入。

### Detect 远程调度指南（`detect.diag` / `detect.memscan`）

detect 任务已纳入 Server↔Agent 的远程调度面（task type：`detect.diag`、`detect.memscan`），其下发/查看报告/审批建议见：`docs/detect-remote-dispatch.md`。

### Collector 控制面示例

Server 暴露 `/api/v1/collector/*` 用于统一的采集配置下发与状态汇报，典型操作如下：

```bash
# 由运维/控制台更新指定 Agent 的采集配置（自动生成版本号）
curl -X POST http://127.0.0.1:8080/api/v1/collector/configs \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: changeme' \
  -H 'X-User: ops-admin' \
  -H 'X-User-Role: ops' \
  -d '{
        "agent_id": "b1d9ab8a-8134-45b3-83c7-592bb38d364f",
        "config": {
          "collectors": [
            {"name": "diag-ebpf", "kind": "ebpf", "sampling": {"rate": 0.05}}
          ]
        }
      }'

# Agent 通过轮询拉取最新配置
curl -H 'X-API-Key: changeme' \
  http://127.0.0.1:8080/api/v1/collector/configs/b1d9ab8a-8134-45b3-83c7-592bb38d364f

# Agent 上报运行状态（附带 tenant 维度、队列/丢包等指标）
curl -X POST http://127.0.0.1:8080/api/v1/collector/status \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: changeme' \
  -d '{
        "agent_id": "b1d9ab8a-8134-45b3-83c7-592bb38d364f",
        "agent_name": "agent-edge-01",
        "state": "running",
        "metadata": {"tenant": "acme-prod"},
        "stats": {"drop_rate": 0.03, "latency_ms": 120}
      }'

# 运维或 SOC 控制台可通过 SSE 订阅指定租户/状态的流式告警
curl -N -H 'X-API-Key: changeme' \
  "http://127.0.0.1:8080/api/v1/collector/status/stream?tenant=acme-prod&crit_drop_threshold=0.15"

> Prometheus 指标：`d_eyes_collector_config_updates_total` 用于统计配置下发次数，`d_eyes_collector_status_alerts_total{tenant,level}` 用于 Grafana 告警面板展示多租户 Collector 运行告警。

> 默认 RBAC：`sre` 角色具备 `collector.config.*` 与 `collector.status.*` 权限；`operator`/`auditor` 仅能读取状态，确保多租户控制面隔离。

更多 Grafana/Prometheus 面板建议见 `docs/collector-observability.md`。

> 说明：Agent 在 Remote 模式下会自动将采集到的事件通过 `/api/v1/events/ingest` 上传，CLI/Probe 可通过 `collectors[].output.mode` 选择 stdout/file/stream 输出，确保关键事件可落盘或远程回传。
```

### gRPC 接口

Agent 通过 gRPC 接口与 Server 通信，支持以下核心功能：

- **注册服务**：Agent 向 Server 注册自身信息
- **心跳服务**：维持 Agent 在线状态
- **任务租约服务**：获取待执行任务
- **结果回传服务**：上传任务执行结果

默认握手顺序为 `Register → Heartbeat → PullTasks → ReportResult`。注册响应会返回唯一 `agent_id` 及建议心跳间隔；心跳阶段应携带 `telemetry.*`、`cache.*` 等键值供行为分析/监控读取；租约响应保留 profile、任务 payload 与 metadata；结果回传则同时写入 `summary_json`、`metadata`、`artifacts` 和 `threatintel.artifact_tokens`，方便 REST API 与 Threat Intel Orchestrator 复用。

> 契约自检：运行 `cd server && go test ./internal/grpcsvc -run AgentLifecycleContract` 可模拟完整 gRPC/HTTP 流程，并验证 `/api/v1/tasks/{id}` 能读取刚刚回传的结果。

## 任务调度流程

1. **任务创建**：通过 REST API 或其他方式创建任务
2. **任务入队**：任务被加入优先级队列
3. **任务分发**：Agent 从队列获取任务（基于租约机制）
4. **任务执行**：Agent 执行任务并返回结果
5. **结果处理**：Server 处理并存储执行结果
6. **状态更新**：任务状态更新（成功/失败/重试）

### BAS 任务特殊调度

对于入侵和攻击模拟(BAS)任务，Server 提供额外的调度能力：

1. **场景编排**：支持复杂攻击链场景的编排和顺序执行
2. **权限控制**：对 BAS 任务执行提供更严格的权限验证
3. **流量监控**：集成网络流量监控，实时观察模拟攻击行为
4. **紧急终止**：支持在发现异常时紧急终止正在执行的 BAS 任务
5. **结果关联分析**：将多个 Agent 的 BAS 执行结果进行关联分析，构建完整攻击路径图

## 高可用设计

Server 支持以下高可用特性：

- **无状态设计**：支持多实例部署，通过 Redis 共享任务队列
- **数据持久化**：使用 PostgreSQL 存储任务和 Agent 信息
- **租约机制**：任务租约防止重复执行，支持节点故障恢复
- **超时回收**：长时间未完成的任务会自动回收并重试
- **健康检查**：支持 Agent 心跳检测和异常处理

### BAS 安全控制设计

针对入侵和攻击模拟功能，Server 提供额外的安全控制措施：

- **操作审计**：记录所有 BAS 任务的创建、执行和管理操作
- **安全边界**：支持设置攻击模拟的安全边界，防止影响生产系统
- **资源限制**：对 BAS 任务的资源使用进行限制，避免 DoS 风险
- **审批流程**：支持 BAS 任务执行的多级审批流程
- **沙箱隔离**：可选的沙箱隔离环境，提供更安全的攻击模拟执行环境

## 开发与测试

### 构建与测试

```bash
cd server
go test ./...
go build ./cmd/server
```

测试覆盖内存与 Postgres 接口的关键逻辑，包括 scheduler 队列、REST Handler、gRPC AgentService 以及 Bufconn 驱动的端到端流程。  
在修改 Agent 握手或任务存储路径后，推荐先运行 `go test ./internal/grpcsvc -run AgentLifecycleContract ./internal/api/v1`，确认 Register/Heartbeat/PullTasks/ReportResult 与任务查询接口保持一致。

### 代码规范

- 遵循 Go 语言标准规范
- 使用 `go fmt` 和 `go vet` 检查代码格式
- 关键功能必须有单元测试覆盖
- 新增功能需提供完整文档

## 性能与观测

### 性能测试

使用内置压测工具进行性能测试：

```bash
cd server
go run ./tools/loadtest --duration 60s --concurrency 16 --agents 8
```

该脚本可模拟大量 REST 任务提交和 Agent 拉取与执行，帮助评估系统性能。

### 监控指标

Server 集成 Prometheus 指标，通过 `/metrics` 端点暴露，包括：

- 队列深度和任务状态分布
- 任务排队时间和执行耗时
- Agent 心跳频率和在线状态
- API 请求延迟和错误率

详细指标说明请参考 `docs/OBSERVABILITY.md`。

### 日志系统

Server 使用结构化日志，支持多级别日志输出，便于问题排查和监控集成。

## 部署指南

### 环境变量

Server 支持以下环境变量配置：

- `D_EYES_SERVER_CONFIG`：配置文件路径
- `D_EYES_SERVER_DSN`：PostgreSQL 连接串
- `D_EYES_SERVER_REDIS_ADDR`：Redis 地址
- `D_EYES_SERVER_API_KEY`：API 密钥
- `D_EYES_SERVER_HTTP_PORT`：HTTP 服务端口
- `D_EYES_SERVER_GRPC_PORT`：gRPC 服务端口

### 生产部署建议

1. 使用 PostgreSQL 作为持久化存储
2. 配置 Redis 用于任务队列，支持多实例部署
3. 设置适当的租约超时和重试策略
4. 配置 Prometheus 和 Grafana 监控系统
5. 为 API 密钥设置强密码并定期轮换

## 相关文档

- [开发指南](docs/DEVELOPMENT.md)：Server 开发说明
- [负载测试](docs/LOADTEST.md)：性能测试和基准测试
- [可观测性](docs/OBSERVABILITY.md)：监控和日志配置
- [部署指南](deploy/docker-compose.yaml)：Docker Compose 部署示例

## 许可证

本项目采用开源许可证，详见 [LICENSE](../LICENSE)。
