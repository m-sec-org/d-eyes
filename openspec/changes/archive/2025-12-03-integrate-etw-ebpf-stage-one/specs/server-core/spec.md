## ADDED Requirements

### Requirement: System event ingestion service
Server MUST 暴露 `/api/v1/events/ingest`（或等价 gRPC）以接收 Agent `SystemEvent` 流，并提供可持久化的队列/存储、速率限制与监控指标，确保事件在 <100 ms 内进入后端处理管道。

#### Scenario: Successful ingestion
- **GIVEN** Agent 以流式方式推送 `SystemEvent`（含 collector metadata、payload）
- **WHEN** Server 接收到事件
- **THEN** 需验证签名、写入事件队列/存储，并更新指标（吞吐、延迟、丢弃数），供后续阶段（高级监测/异常检测）消费

#### Scenario: Backpressure & durability
- **WHEN** 队列达到高水位或后端不可用
- **THEN** Server MUST 返回明确的 429/503，携带推荐重试退避；还应通过观察指标与告警提示运维，避免 silent drop

#### Scenario: Event schema validation
- **WHEN** 收到缺失字段或超出配额的事件
- **THEN** Server MUST 返回 400/413，并记录拒绝原因供审计，确保下游数据质量

### Requirement: Collector control plane
Server MUST 维护 Collector 配置版本与状态，能够向 Agent 下发启停/过滤/采样率，并聚合每台 Agent 的 Collector 遥测（资源占用、丢包率、缓冲水位）。

#### Scenario: Configuration delivery
- **GIVEN** 运维在控制台更新“启用 eBPF syscall 监控 + 5% 采样率”
- **WHEN** Server 生成新的配置版本
- **THEN** 需通过 REST/SSE/gRPC 在 30 秒内推送到目标 Agent，并追踪应用结果（成功/失败/超时）

#### Scenario: State aggregation
- **WHEN** Agent 在心跳中附带 Collector 状态
- **THEN** Server MUST 存档最近一次状态、暴露查询 API/仪表盘（包含运行 Collector、采样率、事件速率、异常原因），并在状态异常（degraded/offline）时触发告警

#### Scenario: Audit & RBAC
- **WHEN** 控制面配置被修改或下发
- **THEN** Server MUST 记录操作人、变更内容、目标 Agent，并依据 RBAC 限制仅授权角色可执行该操作，满足安全与合规要求
