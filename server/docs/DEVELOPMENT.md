# D-Eyes Server 开发指南

## 环境准备

- Go 1.21+（建议使用与仓库 go.mod 一致版本）
- Docker / Docker Compose（用于 Postgres + Redis 本地联调）

## 常用命令

```bash
# 本地运行全部单元测试
make test

# 启动 Postgres + Redis + Server（Docker Compose，后台运行）
make dev-up

# 查看服务日志
docker compose -f deploy/docker-compose.yaml logs -f server

# 关闭并清理 Compose 容器与数据卷
make dev-down

# 仅停止服务，保留数据
docker compose -f deploy/docker-compose.yaml down

# 重新生成 protobuf 代码
make proto

# 启动内置压测脚本（示例：16 并发创建任务，8 个模拟 Agent）
go run ./tools/loadtest --api http://127.0.0.1:8080 --grpc 127.0.0.1:9090 --concurrency 16 --agents 8 --duration 1m
```

> 提示：Compose 使用的 `pgdata` 卷会持久化 PostgreSQL 数据，如需完全重置请执行 `make dev-down`。

单元与集成测试可通过 `go test ./...` 运行，集成用例基于内存 Store/Queue 以及 gRPC bufconn，无需 Docker 依赖。

性能与可靠性验证建议：

- 通过 `tools/loadtest` 对 REST + gRPC 全链路进行压测，观察任务吞吐、延迟及错误率。
- 结合 Prometheus 指标（见 `docs/OBSERVABILITY.md`）监控队列深度、任务租约耗时、执行耗时等核心指标。


## 本地手动启动

若不使用 Docker Compose，可直接运行：

```bash
cd server
D_EYES_SERVER_DSN="postgresql://user:pass@localhost:5432/d-eyes?sslmode=disable" \
D_EYES_SERVER_REDIS_ADDR="localhost:6379" \
go run ./cmd/server --config ./config/server.yaml
```

镜像构建使用 `server/Dockerfile`，容器默认加载 `/etc/d-eyes/config/server.yaml` 并可通过环境变量覆盖数据库与 Redis 配置。`/healthz` 提供存活探针。

## 目录提醒

- `internal/monitor`：心跳离线监控
- `internal/queue`：任务调度队列（内存/Redis）
- `proto/`：gRPC 协议文件，后续会引入自动生成
- `deploy/docker-compose.yaml`：一键启动依赖服务

开发建议：修改后执行 `make test` 确保无回归，再根据需要运行 `make dev-up` 做集成验证。
