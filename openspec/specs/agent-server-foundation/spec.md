# agent-server-foundation Specification

## Purpose
TBD - created by archiving change plan-agent-server-foundation. Update Purpose after archive.
## Requirements
### Requirement: Agent Registration and Heartbeat
Server MUST expose a secure gRPC 接口以注册 Agent 并维持心跳，确保实时感知在线状态。

#### Scenario: TLS Enrolled Agent
- **GIVEN** Agent 配置了有效的 token 与 TLS 证书
- **WHEN** Agent 向 `/grpc.AgentService/Register` 提交注册请求并建立心跳流
- **THEN** Server 持久化 Agent 元数据并在 3 秒内返回成功响应
- **AND** 后续心跳周期内若 15 秒未收到数据，Server 将 Agent 标记为 offline

### Requirement: Remote Task Execution Loop
Agent MUST 能够领取 Server 下发的 respond/baseline 任务，执行后上报结果，Server 应追踪状态并保存摘要。

#### Scenario: Respond Task Roundtrip
- **GIVEN** REST API `/api/v1/tasks` 创建了 respond 任务且至少有一台在线 Agent
- **WHEN** Agent 通过 `PullTask` 获取任务并调用共享执行器运行 respond 模块
- **THEN** Agent 在任务完成 2 秒内通过 `ReportResult` 回传执行结果
- **AND** Server 将任务状态更新为 `succeeded` 并可通过 REST 查询到输出摘要

### Requirement: Resilient Result Delivery
Agent MUST 在网络中断时缓存未上报结果并在连接恢复后重放，以保证任务结果最终一致。

#### Scenario: Retry After Network Loss
- **GIVEN** Agent 执行任务后与 Server 的 gRPC 连接中断
- **WHEN** Agent 在 60 秒内恢复连接
- **THEN** Agent 会自动重放缓存的结果，Server 将去重并持久化，不得产生重复任务记录

