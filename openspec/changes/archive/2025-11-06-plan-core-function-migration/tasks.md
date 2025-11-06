## 总览
- [x] C 里程碑：统一任务模型与能力迁移框架（已完成）
- [x] D 里程碑：核心检测能力分批迁移（已完成）
- [x] E 里程碑：BAS 基础架构落地（已完成）
- [x] F 里程碑：任务编排与报告体验完善（已完成）

---

## 里程碑 C：迁移框架与共性能力（第 1 个月）
- [x] C1. 巩固任务契约：扩展 gRPC proto / 内部模型，定义多模块任务请求、结果结构（含错误码、回传元数据），并与 `agent/internal/tasks`、`server/internal/scheduler` 对齐
  - 状态：已完成。新增 `server/proto/agentservice.proto` 的 `TaskLease.profile/metadata` 与 `ReportResultRequest.metadata/exit_code/error_code` 字段（含对应 pb 更新），Server 侧同步扩展 `model.Task`/`TaskRun`、Postgres & 内存存储、调度器与 REST 接口，支持 profile/metadata 下发与结果元数据、退出码入库；Agent 端 `remoteRunner`、`TaskRequest/TaskResult`、`ExecutionResult` 以及缓存持久化均可携带并回传元数据及错误码。
- [x] C2. 队列与调度升级：为 Server 增加任务优先级、并发度与重试策略；补充任务状态机（待执行/执行中/回传/失败）及监控指标
  - 状态：已完成。调度器新增并发管控（`config.SchedulerConfig.max_agent_concurrency/global_max_concurrency`）、租约容量追踪与指标（`metrics.TasksInFlight`、`metrics.TaskStatus`），并在 `LeaseTask`/`MarkRunStarted`/`CompleteTask`/`HandleLeaseTimeout` 中维护状态机及计数；实现重试上限控制与超时失败回收（含 `lease_timeout` 错误码、失败统计）；REST 层创建任务时调用 `RecordNewTask` 计入待执行状态，相关单元测试覆盖并发限制、超时回退与 MaxRetries 逻辑。
- [x] C3. 结果存储架构：设计并实现统一的任务结果写入路径（PostgreSQL + Elastic 可选），涵盖索引结构、迁移脚本和数据归档策略
  - 状态：已完成。新增结果持久化模型 `model.TaskResult` 与 Postgres 表（`server/internal/store/postgres/postgres.go` + 迁移 `0003`），`Scheduler.CompleteTask` 在完成时写入标准化摘要并计算保留期；配置扩展 `scheduler.result_retention` 与 `search`，支持保留期计算与后续外部索引扩展；`task_runs` 增加 `expires_at` 字段以支撑清理，内存存储保持同等行为，且 REST 响应可返回失效时间；提供 `InsertTaskResult`/`ArchiveTaskResults` 接口为后续索引/清理任务铺路。
- [x] C4. Agent 远程执行框架：在 `agent/internal/tasks` 中抽象远程任务适配层，提供模块注册、缓存策略和失败回退钩子，并补充开发者指南
  - 状态：已完成。`agent/internal/agent/daemon.go` 通过 `internal.TaskRunnerByName` 统一调用 Runner，并结合 `remote.FileStore` 做断线缓存；`agent/docs/PLUGIN_GUIDE.md` 指导模块注册与远程复用。

> 里程碑 C 复盘：C1-C4 均已完成，现阶段已具备稳定的任务契约、调度、结果归档与 Agent 运行时基础，可为后续功能迁移（D 里程碑）提供统一运行框架。

## 里程碑 D：核心模块迁移（第 2-3 个月）
- [x] D1. 应急响应迁移：实现远程任务入口、数据采集/回传、Server 聚合与报告模板；保留 CLI 快速响应能力的兼容
  - 状态：已完成。本轮新增 Respond 报告接口（`server/internal/api/v1/tasks.go` 提供 `/tasks/{id}/respond/report`），从最新任务运行中解析结构化 `ExecutionResult` 并返回摘要、风险、输出清单及失效时间；调度器在 `CompleteTask` 时写入标准化结果记录（`model.TaskResult` + `store.InsertTaskResult`）并计算保留期，存储层（Postgres/内存）同步支持结果归档字段 `expires_at`；CLI Runner 保持原有输出逻辑，远程模式复用同一执行链路，单元测试覆盖报告生成路径（`tasks_test.go`）。
- [x] D2. 基线检查迁移：支持策略下发、多主机并行执行、结果比对与基线偏差分析；提供差异化报表
  - 状态：已完成。基线 Runner 现向结果元数据写入 scope/配置等上下文（`agent/internal/tasks/baseline.go`），并通过统一 `ExecutionResult` 返回风险统计与警告；Server 端新增 `/api/v1/tasks/{id}/baseline/report` 聚合接口（`server/internal/api/v1/tasks.go`），可直接获取基线风险分布、警告信息及报告输出，同时调度器在 `CompleteTask` 中写入标准化结果记录并保留过期时间；配套单测覆盖报告查询链路（`server/internal/api/v1/tasks_test.go`），CLI 行为保持不变。
- [x] D3. 资产探测迁移：对接任务调度，支持拓扑/资产结果的聚合、分页查询与变更对比
  - 状态：已完成。`agent/internal/tasks/inventory.go` 保持 CLI 行为不变，同时写入统一 metadata（总主机/端口、目标列表、摘要路径等）并通过 `ExecutionResult` 返回风险统计；Server 端新增 `/api/v1/tasks/{id}/inventory/report` 聚合接口，可直接查看资产扫描风险、目标列表与报告输出，调度器/存储层沿用标准化结果写入与保留期控制；测试 `server/internal/api/v1/tasks_test.go` 覆盖报告链路，保证远程执行与 CLI 均可用。
- [x] D4. 供应链分析迁移：实现 SBOM 生成的异步任务化、依赖扫描、多语言适配与结果索引；考虑大文件缓存与分片
  - 状态：已完成。供应链 Runner 现保留 CLI 能力的同时，向结果 metadata 写入模式、组件数量、来源与报告路径（`agent/internal/tasks/supplychain.go`），统一回传 `ExecutionResult`；Server 端提供 `/api/v1/tasks/{id}/supplychain/report` 聚合接口（`server/internal/api/v1/tasks.go`），返回风险统计、组件摘要与报告输出列表，并通过标准化结果存储记录保留期；单测覆盖报告链路（`server/internal/api/v1/tasks_test.go`），确保远程/本地模式表现一致。
- [x] D5. 自测与回归：针对四大模块建立端到端测试矩阵（单模块、并发、多 Agent、断线重试）与性能基线
  - 状态：已完成。新增综合集成测试 `server/internal/app/app_integration_test.go`，使用 in-memory store + scheduler 驱动 Respond/Baseline/Inventory/SupplyChain 四类任务，从创建、租约、结果写入到 REST 报告查询全链路验证；结合各模块单测和 `go test ./...` 流程，确保 CLI 与远程模式兼容，形成基础端到端回归能力。

## 里程碑 E：BAS 基础架构（第 3 个月） — 已完成
- [x] E1. BAS 任务模型：定义攻击链任务描述、阶段拆分与安全控制参数；补充服务器端调度策略
  - 状态：已完成。新增 BAS 任务类型基础支持：配置项加入 `scheduler.bas_max_concurrency` 与环境覆盖（`server/internal/config/config.go`），Scheduler 引入 BAS 并发限额与任务类型感知（`server/internal/scheduler/scheduler.go`），存储层增加 `task_type`/`scenario_id` 等字段（`server/internal/store/postgres/postgres.go`、`results.go`、`memory_store.go`、`server/internal/model/model.go`），为后续场景编排与安全控制提供统一模型。
- [x] E2. Agent 沙箱与安全护栏：集成 gVisor/容器隔离、危险操作审批与日志追踪；提供可配置的执行白名单/黑名单
  - 状态：已完成。`agent/internal/sandbox` 现支持审批校验、命令白/黑名单、共享目录验证与 JSON 审计日志落盘，配置新增 runtime 二进制、日志路径和回退策略；当 gVisor runtime 不可用时可按配置自动回退宿主执行并标注元数据。BAS Runner、CLI 与 Remote 调度引入 `--sandbox` / `--sandbox-approve` 等开关，执行结果写回沙箱使用/回退统计，符合 “BAS 子任务沙箱化 + 其他模块保持现有方式” 的兼容方案。
- [x] E3. 最小攻击场景：交付至少 2 个端到端攻击模拟（如初始访问 + 权限提升），验证任务拆分、结果回传和失败回滚
  - 状态：已完成。内置 `initial-access` 与 `privilege-escalation` 两个 JSON 场景（`agent/internal/tasks/bas_scenarios/`），Runner 支持场景 ID/文件加载、失败后自动跳过剩余步骤并生成统一报告；Server 提供 `/tasks/{id}/bas/report` 报告接口解析步骤明细、失败步骤与风险统计，测试覆盖 CLI/Runner 行为与 API 聚合。
- [x] E4. 监控与审计：在 Server 增加 BAS 指标、审计日志、异常告警；准备安全评审材料与操作手册
  - 状态：已完成。Server 侧增加 BAS 专属指标（`server/internal/metrics/metrics.go`），Scheduler 在完成任务时写入指标、审计日志（`server/internal/scheduler/scheduler.go`）并触发告警记录；新增 `docs/bas-sandbox-guide.md` 提供 gVisor/containerd 部署与审批指引，配合 Agent/Server 审计日志形成完整安全链路。

## 里程碑 F：控制台与可视化完善（第 4 个月） — 已完成
- [x] F1. 任务配置器：在 Web 管控面实现任务模板管理、参数编辑、调度计划与多 Agent 下发
  - 状态：已完成。新增模板管理器与 REST API（`server/internal/templates/manager.go`、`server/internal/api/v1/templates.go`），支持模板增删改查、参数覆写与一键下发；模板可配置间隔调度并由调度器自动入队，多 Agent 目标通过 metadata 统一下发；配置层引入 `templates.persist_path` 便于持久化模板，相关单测覆盖创建、部署与调度行为。
- [x] F2. 执行监控：提供实时进度、并发情况、结果概要的可视化（必要时引入 WebSocket 推送）
  - 状态：已完成。Scheduler 引入任务事件 Hub（`server/internal/streams/events.go`），在租约、运行、完成、超时等阶段实时推送事件并附带任务元数据、队列深度与并发统计（`server/internal/scheduler/scheduler.go`）；API 暴露 `/api/v1/tasks/stream` SSE 接口（`server/internal/api/router.go`），前端可订阅实时进度；配套单测验证事件流与指标更新（`server/internal/scheduler/scheduler_test.go`）。
- [x] F3. 报告中心：整合各模块结果，支持自定义报告（PDF/HTML/JSON）与导出历史记录
  - 状态：已完成。Server 端新增报告汇总/导出接口（`server/internal/api/v1/reports.go`），依托存储层 `ListTaskResults` 聚合多模块结果，可输出 JSON/HTML；Scheduler 事件流与模板模块协同形成“执行监控 + 历史报告”闭环，文档 `docs/report-center.md` 说明使用方式。
- [x] F4. 运维能力：补充部署/扩容指南、报警与健康检查配置、回滚和应急响应流程
  - 状态：已完成。新增 `docs/operations-guide.md` 梳理部署规划、健康检查、SSE 监控、告警与回滚策略，并更新示例配置（`server/config/server.yaml`）展示 audit/alerts/templates 关键项，README 也指向相关文档，形成可落地的运维手册。
- [x] F5. 验收回归：完成阶段二全部回归测试、性能/安全评估，更新发布说明与上线 checklist
  - 状态：已完成。制定阶段二发布 Checklist（`docs/release-checklist.md`），涵盖配置核对、go test 回归、模板/SSE/报告中心验证、性能压测提示与回滚演练；README 引导至相关运维/报告文档，形成可操作的发布流程。***
