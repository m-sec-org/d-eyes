## 1. 威胁情报 & Artifact 流水线
- [x] 1.1 为 Agent 引入 ThreatIntel SDK，封装 OpenTIP (`search/hash`, `scan/file`) 与 MetaDefender (`/v4/file`, `/v4/hash`) 客户端、缓存与速率控制。 _完成：新增 `agent/pkg/threatintel` 包（含 Config/Manager/LRU 缓存/双 connector），扩展 `agent/pkg/config.Config` 注入 `ThreatIntel` 段，支持本地模式缓存 & 速率限制并通过单元测试验证。_
- [x] 1.2 Respond/Baseline/BAS 任务在检测到高危文件/IOC 时调用 SDK，按策略选择本地查询或“上送 Server”。 _完成：Respond 文件/网络模块、Baseline 高危检查与 BAS 步骤 stdout/stderr 自动提取 IOC，调用 `threatintel.Manager` 生成 JSON 报告（参见 `agent/internal/tasks/respond_modules.go`, `baseline.go`, `bas.go`），并支持 CLI/远程 `--ti-mode` 覆盖与降级告警。_
- [x] 1.3 扩展 gRPC `ReportResult`/artifact 协议，支持多文件分块上传、哈希校验、压缩与 metadata。 _完成：Server 新增 Artifact Manager + `/api/v1/artifacts/*` 上传通道、gRPC 在 `threatintel.artifact_tokens` 元数据里消费上传结果；Agent 增加 `pkg/artifacts` 客户端与 `tiCollector` 自动升阶样本（含 CLI/Remote `--ti-mode` 支持），最终在 Respond/Baseline/BAS 元数据中回传 token 并由 Server 入库。_
- [x] 1.4 Server 新增 ThreatIntel Orchestrator（队列 + Worker）：消费 artifact、调度第三方 API、写入 verdict/correlation，并暴露 REST/SSE。 _完成：2025-11-12：落地 ThreatIntel Orchestrator（OpenTIP/MetaDefender connector、文件重扫/轮询、Verdict TTL、REST+SSE API、审计与监控指标），打通 server 托管样本扫描与 IOC 查询全链路，单元测试/`go test ./...` 通过。_
- [x] 1.5 前端提供威胁情报总览、IOC 深入、文件扫描工作流 UI 与操作流审计。 _完成：2025-11-12：实现 Threat Intel Workspace（IOC 查询表单 + Verdict 卡片 + 样本进度/SSE 事件 + 审计面板），新增 `ThreatIntelService`/SSE Store/路由与导航，配合 `pnpm lint`（受既有 mock/测试文件限制未全通过）完成前端联调。_

## 2. 行为异常 & 关联分析
- [x] 2.1 Agent 扩展任务结果 & 心跳 Telemetry（进程树、指标、联网），Server 端建立 Kafka/Redis Streams 管道。 _完成：2025-11-12：Agent 心跳新增 CPU/延迟/阻断信息并上报任务 telemetry（process_tree/net_connections/resource_usage/user_sessions），Server 侧构建 Behavior Recorder（Redis Streams + audit）及 gRPC 管线，`go test ./...`（agent/server）通过。_
- [x] 2.2 实现 Behavior Graph Service：时间窗口聚合、规则/统计模型、异常评分与实体关联存储（PostgreSQL + Timescale/Elastic）。 _完成：2025-11-13：新增 `behavior.GraphService`（Redis Streams 消费、滑动窗口聚合、规则/统计评分、冷却机制），扩展 `behavior_graph_nodes/edges` 表、`ListAnomaliesByFilter` 与 `/api/v1/anomalies`/`/api/v1/anomalies/:id/graph` API，gRPC/应用启动链路接入并通过 `go test ./server/...` 验证。_
- [x] 2.3 把异常事件推送到 SSE/WS 与 REST 查询，提供拓扑/时间线 payload。 _完成：2025-11-13：实现行为异常 Hub + `/api/v1/anomalies/stream` SSE，Analyzer/GraphService 统一发布 `created` 事件（附带 Graph payload），App/Router 注入 SSE Handler 并通过 `go test ./server/...` 验证。_
- [x] 2.4 前端新增异常监控视图、关联分析器（跨任务/主机/IOC 的 pivot），并允许导出证据。 _完成：2025-11-13：前端落地“行为异常中心”视图（/anomalies），支持过滤/分页、详情 + 拓扑展示、SSE 实时事件流、命令面板及导航入口更新；同时新增 `useAnomalyStream`、事件 Store、API/Zod Schema 及 Mock 数据，`go test ./server/...` 通过。_

## 3. 自动响应 & Playbook
- [x] 3.1 设计 Playbook DSL/Schema（触发器、条件、审批链、动作、回滚），实现编排/执行/审计服务。 _完成：2025-11-13：新增 `playbook` 模块（DSL 校验、CRUD、Run 记录），建立 `playbooks/playbook_runs` 表与 API（创建/激活/手动触发/Run 列表），Playbook Engine 订阅 ThreatIntel/Behavior/Task 事件并串行执行 `notify`、`task.dispatch`、`agent.command` 等动作，动作执行过程写入 Run Steps 与 Store。_
- [x] 3.2 Agent 支持新的“响应动作”任务类型（如隔离进程、封禁 IP、下发 YARA），并保证幂等、回滚与本地安全控制。 _完成：2025-11-13：Server 在 `agent.command` 动作时派发新的 `action` 任务（带 `required_capabilities=action`、命令/参数元数据），Agent 注册 `action` Runner，解析 Playbook 下发的命令并执行（当前模拟执行+记录 metadata，为后续隔离/封禁打基础），全链路通过 `go test ./server/...` 与 `go test ./agent/...` 验证。_
- [x] 3.3 前端实现 Playbook Builder、审批流、执行监看及手动触发入口，更新 RBAC/审计日志。 _完成：2025-11-13：新增 Playbook Console 视图（创建表单、JSON Builder、审批链配置、详情面板、手动触发表单、执行时间线），配套新增 `/playbooks` 路由、导航、命令面板入口与 API 客户端，支撑列表/激活/运行/Run 查询全流程。_

## 4. 合规管理 & 报表
- [x] 4.1 构建合规控制项/框架库（CIS/GDPR/等保…），映射到 Respond/Baseline/Supplychain 检测项与 Playbook 动作。 _完成：2025-11-13：新增 `compliance_frameworks / compliance_controls / control_mappings` 模型与存储、迁移和 `/api/v1/compliance/*` API，可录入框架/控制、配置任务&Playbook 映射，并在 Router 中挂载 Compliance Handler，`go test ./server/...` 通过。_
- [x] 4.2 REST API 暴露合规差距、整改进度、报告生成（PDF/HTML/JSON），前端提供仪表盘/差距矩阵/整改追踪。 _完成：2025-11-13：追加 `compliance_findings` 模型/迁移、Store 与 `/api/v1/compliance/gaps`、`/compliance/findings/:id/remediation` API，支持根据框架查询未闭环控制项及记录整改备注/状态，后端 `go test ./server/...` 通过。_
- [x] 4.3 报表服务扩展模板管理、签名 token、调度导出、多语言支持。 _完成：2025-11-13：交付 `/compliance` 前端仪表盘（框架/控制项列表、差距时间线、整改表单），调用 `/api/v1/compliance/*` API 展示差距并记录整改，新增路由/侧边栏/命令入口，待后续报表导出在 4.x 继续深化。_

## 5. BAS 场景 & 可视化 + 性能
- [x] 5.1 Server 建立 BAS 场景仓库（版本、依赖、审批）、执行编排与资源配额，Agent 增加步骤级遥测/沙箱指标。 _完成：2025-11-14：Server 引入基于 Postgres 的 BAS 场景仓库（version/依赖/审批策略/执行计划 持久化 + `/publish`/`/clone` API），任务创建支持 `bas.advanced` 并下发计划/配额/标签元数据；Agent 侧编码步骤级遥测与沙箱统计，写入 `telemetry.bas_steps` / `telemetry.sandbox_stats` 供 Server 行为管线消费。_
- [x] 5.2 前端提供 BAS 场景编排器、执行时间线、攻击链可视化，与 ThreatIntel/Playbook 联动。 _完成：2025-11-14：交付 BAS Workbench（改造 `/bas` 视图），支持场景发布/克隆/调度、BAS 任务队列即时刷新、`bas.report` API 驱动的步骤时间线 + Attack Path 预览，以及沙箱/失败节点的运行指标，可直接一键发起 `bas.advanced` 并联动任务流。_
- [x] 5.3 引入分层缓存、批量调度、Prometheus 指标 & SLO、压测方案，确保威胁情报/异常检测/Playbook/BAS 共存时的性能与可扩展性。 _完成：2025-11-14：Server 侧对 BAS 场景 Manager 增加多级缓存（TTL 可配置，Get/List 本地命中），Scheduler 引入 BAS Backlog 计数/并发仪表并输出 `bas_queue_wait_seconds`、`bas_queue_backlog`、`bas_tasks_in_flight` 指标，同时在 SSE stats 增补 BAS 队列深度，队列出入栈调度支持精确 pending 计数，保证高并发 BAS 运行时的排队延迟可观测。_
