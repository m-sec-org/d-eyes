## 1. 架构基建
- [x] 1.1 在 `server/internal/` 建立分层目录（config、logger、model、store、scheduler、grpc、api、queue、metrics）
- [x] 1.2 引入统一配置结构与加载逻辑，支持 `server/config/server.yaml`
- [x] 1.3 搭建 protobuf 生成脚本并替换临时 gRPC structs

## 2. 数据模型与持久化
- [x] 2.1 定义任务、任务运行、Agent 元数据模型（Go struct + migration）
- [x] 2.2 实现 PostgreSQL 存储层：AgentRegistryStore、TaskStore、ResultStore
- [x] 2.3 集成 Redis（或内存）用于心跳和任务队列缓存
- [x] 2.4 提供数据库迁移脚本与自动执行逻辑

## 3. gRPC 服务
- [x] 3.1 实现 `AgentService`（Register、Heartbeat、PullTask、ReportResult）
- [x] 3.2 支持 token + TLS 校验与心跳超时判定
- [x] 3.3 引入任务租约机制与结果去重校验

## 4. REST API
- [x] 4.1 使用 Gin 实现 `/api/v1/tasks` CRUD、任务状态查询、结果摘要查询
- [x] 4.2 提供任务取消/重试接口
- [x] 4.3 实现简单的 API 鉴权（API Key 或 JWT Stub）

## 5. 调度与队列
- [x] 5.1 实现优先级任务队列与调度器接口
- [x] 5.2 调度器与 gRPC `PullTask` 集成，支持公平分配与并发限制
- [x] 5.3 完成任务状态机（pending → leased → running → succeeded/failed），处理超时与重试

## 6. 观测与配置
- [x] 6.1 集成日志、Prometheus 指标（任务数、心跳、延迟）
- [x] 6.2 提供健康检查、就绪探针
- [x] 6.3 更新 Docker Compose 与部署脚本（新增 `server/Dockerfile`、Compose 健康检查与文档指引）

## 7. 测试与文档
- [x] 7.1 编写单元测试覆盖 store、scheduler、grpc handler、api handler
- [x] 7.2 实现端到端集成测试（启动真实或内存 PG/Redis，当前通过内存 Store/Queue + bufconn 校验 HTTP/gRPC 流程）
- [x] 7.3 更新 `server/README.md`、新增开发指南，补充 `docs/` 设计说明（README/开发指南已同步测试说明，后续可在 `docs/` 进一步扩展设计细节）
