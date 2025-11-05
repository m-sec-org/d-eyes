# Agent 远程模式实现概览

## 功能概述
- 新增 `d-eyes remote` 子命令，读取 `config.remote` 配置后与 Server 建立 gRPC 会话。
- 通过 `internal/agent/daemon.go` 维护注册、心跳、任务拉取、结果上报及失败重连逻辑。
- 所有任务执行仍复用现有 CLI Runner（`tasks.ExecuteWithResult`），确保行为与本地一致。

## 关键组件
- `internal/agent/remote/client.go`：封装 Register/Heartbeat/PullTask/ReportResult，支持 TLS。
- `internal/agent/remote/cache.go`：文件缓存待上报结果，断线后自动重放。
- `internal/agent/daemon.go`：
  - 指数退避重连
  - 周期性心跳、任务拉取和缓存刷新
  - 将 gRPC 任务 payload 转换为 `tasks.TaskRequest`
  - 构造统一结果摘要并回传 Server

## 配置项（`config.yaml`）
```yaml
remote:
  enabled: true
  server_grpc_addr: 127.0.0.1:9090
  agent_token: changeme
  agent_name: edge-node-01
  heartbeat_interval: 10s
  task_poll_interval: 2s
  cache_dir: ~/.d-eyes/cache
  tls:
    enabled: false
    cert_file: ""
    key_file: ""
    ca_file: ""
```

## 后续工作
- 将任务 payload/summary 的结构与 Server 端模型正式对齐（B5）。
- 支持 artifacts 回传与大文件分片。
- 引入持久化缓存（BoltDB）及断线重试指标上报。
