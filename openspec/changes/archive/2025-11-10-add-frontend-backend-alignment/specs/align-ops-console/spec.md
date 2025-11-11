## ADDED Requirements
### Requirement: Task-Type Specific Configuration Contracts
Server MUST 提供统一的任务类型与 profile API，使前端能够针对 respond、audit、inventory、supplychain 等任务渲染专用表单并校验参数。

#### Scenario: Inventory Task Port Range Enforcement
- **GIVEN** 前端调用 `POST /api/v1/task-types/inventory/tasks` 并在 payload 中设置 `port_range: "1-1024"`
- **WHEN** Server 校验 profile schema 中的 `port_range` 与 `service_checks`
- **THEN** 若范围与受支持协议匹配，任务被创建并返回 profile 快照
- **AND** 若字段缺失或超出允许范围，Server 返回 422 并包含 schema 提示，前端得以提示用户

### Requirement: Rich Result Visualization Payloads
Server MUST 为每种任务类型返回结构化可视化数据，包括网络连通图、文件扫描风险分布及主机摘要，以驱动前端组件。

#### Scenario: Network Connectivity Graph Output
- **GIVEN** respond 任务完成且 Agent 报告 `connections` 数组与 `risk_scores`
- **WHEN** 客户端调用 `GET /api/v1/tasks/{id}/visuals?type=network`
- **THEN** Server 返回包含 `nodes`, `edges`, `severity_buckets` 的 JSON
- **AND** 结果中附带时间戳及 Agent 列表，供前端绘制拓扑与风险热力图

### Requirement: BAS Scenario Lifecycle Management
Server MUST 提供 BAS 场景创建、编排、审批及安全边界配置接口，支持按步骤顺序执行并进行权限控制。

#### Scenario: Scenario Approval Gate
- **GIVEN** 用户通过 `POST /api/v1/bas-scenarios` 创建包含多个 action 的场景
- **WHEN** 安全审核者调用 `POST /api/v1/bas-scenarios/{id}/approve`
- **THEN** Server 在记录审批轨迹后才允许调度执行，并确保 `resource_limits`、`network_boundaries` 已配置，否则拒绝执行

### Requirement: Agent Asset Management & Monitoring
Server MUST 暴露 Agent 列表、详情、心跳与能力指标，并支持标签/分组管理，以便前端监控和筛选。

#### Scenario: Agent Heartbeat Health View
- **GIVEN** Agent 通过 gRPC 心跳上报 `capabilities`, `latency_ms`, `packet_loss`
- **WHEN** 前端调用 `GET /api/v1/agents?group=production`
- **THEN** 响应包含每个 Agent 的在线状态、最近心跳时间、指标及标签
- **AND** 若心跳超时，Server 提供 `status: offline` 与原因，供前端高亮告警

### Requirement: Report Template & Multi-Format Export
Server MUST 支持报告模板管理、任务结果与模板合成，以及 PDF/HTML/JSON 多格式导出，支持受控分享。

#### Scenario: Template-Based Export
- **GIVEN** 管理员上传 `respond-risk` 模板并标记为最新版
- **WHEN** 用户调用 `POST /api/v1/reports` 指定 `template_id` 与 `task_id`
- **THEN** Server 生成报告 artifact，支持 `format=pdf|html|json`
- **AND** 返回下载链接与可选分享 token，供前端触发分享流程

### Requirement: Real-Time Monitoring & Intervention Stream
Server MUST 推送任务执行进度、关键操作、异常与人工干预事件，并允许前端通过安全通道触发暂停/重试等指令。

#### Scenario: Interactive Respond Task Control
- **GIVEN** 前端订阅 `wss://.../task-stream?task_id=123`
- **WHEN** 后端发送 `progress` 与 `alert` 事件，并收到用户 `POST /api/v1/tasks/123/actions` 请求 `pause`
- **THEN** Server 广播最新状态给所有订阅者，并在 2 秒内暂停任务且记录谁触发了干预

### Requirement: Fine-Grained RBAC & Audit Trails
Server MUST 实现资源级别 RBAC、敏感操作审批与可检索审计日志，以满足合规要求。

#### Scenario: Sensitive Action Approval & Audit
- **GIVEN** 用户尝试触发 BAS 场景执行，操作被标记为 `sensitive`
- **WHEN** RBAC 引擎发现用户缺少 `bas.execute` 权限并要求审批
- **THEN** Server 记录一条审计日志，通知审批人完成授权
- **AND** 审批通过后，日志应捕捉审批链与最终执行结果，可通过 `/api/v1/audit-logs` 查询和过滤
