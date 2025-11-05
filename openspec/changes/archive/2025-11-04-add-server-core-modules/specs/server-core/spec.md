## ADDED Requirements

### Requirement: Agent Registration & Heartbeat Service
Server MUST 提供安全的 gRPC 服务供 Agent 注册与心跳同步，确保 Agent 状态实时可见。

#### Scenario: Token Authenticated Registration
- **GIVEN** 预配置的合法 token 与 TLS 证书
- **WHEN** Agent 调用 `AgentService.Register` 并建立心跳流
- **THEN** Server 在 3 秒内持久化 Agent 元数据并返回唯一 `agent_id`
- **AND** 若心跳在 15 秒内缺失，Server 将 Agent 标记为 offline 并记录事件

### Requirement: Task Dispatch & Lease Management
Server MUST 支持通过优先级队列向 Agent 分配任务，使用租约机制保证幂等与超时重试。

#### Scenario: Lease Renewal Failure
- **GIVEN** REST API 创建了 `respond` 类型任务，优先级为高
- **WHEN** Scheduler 将任务分配给满足能力的 Agent 并设置 120 秒租约
- **AND** Agent 未在租约期内报告结果
- **THEN** Server 自动回收租约并将任务状态恢复为 `pending`，同时 `retry_count` 增加 1

### Requirement: Result Persistence & Query
Server MUST 持久化任务执行结果与摘要，并通过 REST API 提供查询能力。

#### Scenario: Fetch Task Summary
- **GIVEN** Agent 通过 `ReportResult` 成功上传任务结果
- **WHEN** 客户端调用 `GET /api/v1/tasks/{id}`
- **THEN** Server 返回 `status=succeeded` 与结果摘要（风险计数、产出 artifact 列表）
- **AND** 结果应包含任务创建时的 metadata 与执行耗时
