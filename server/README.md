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
# 服务器配置
server:
  http_port: 8080        # HTTP API 服务端口
  grpc_port: 9090        # gRPC 服务端口
  api_key: changeme      # API 访问密钥

# 数据库配置
database:
  in_memory: true        # 是否使用内存存储
  dsn: postgres://user:password@localhost:5432/d-eyes?sslmode=disable  # PostgreSQL 连接串

# Redis 配置
redis:
  enabled: false         # 是否启用 Redis
  addr: localhost:6379   # Redis 地址
  password: ""           # Redis 密码
  db: 0                  # Redis 数据库编号

# 任务配置
tasks:
  max_retries: 3         # 任务最大重试次数
  lease_timeout: 30m     # 任务租约超时时间
  cleanup_interval: 24h  # 历史数据清理间隔
```

## API 使用指南

### RESTful API

Server 提供完整的 RESTful API，支持任务管理、Agent 查询等功能：

```bash
# 创建任务
curl -X POST http://127.0.0.1:8080/api/v1/tasks \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: changeme' \
  -d '{"type":"respond","priority":1,"payload":{"targets":["/tmp"]}}'

# 创建 BAS 入侵和攻击模拟任务
curl -X POST http://127.0.0.1:8080/api/v1/tasks \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: changeme' \
  -d '{"type":"bas","priority":1,"payload":{"profile":"auto","target":"192.168.1.0/24","report-format":"html"}}'

# 列出最近任务（状态过滤可选）
curl -H 'X-API-Key: changeme' "http://127.0.0.1:8080/api/v1/tasks?status=pending,failed&limit=10"

# 查询单个任务（附带最近一次执行摘要）
curl -H 'X-API-Key: changeme' http://127.0.0.1:8080/api/v1/tasks/<TASK_ID>

# 触发重试
curl -X POST -H 'X-API-Key: changeme' http://127.0.0.1:8080/api/v1/tasks/<TASK_ID>/retry

# 查询在线 Agent
curl -H 'X-API-Key: changeme' http://127.0.0.1:8080/api/v1/agents?status=online
```

### gRPC 接口

Agent 通过 gRPC 接口与 Server 通信，支持以下核心功能：

- **注册服务**：Agent 向 Server 注册自身信息
- **心跳服务**：维持 Agent 在线状态
- **任务租约服务**：获取待执行任务
- **结果回传服务**：上传任务执行结果

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
