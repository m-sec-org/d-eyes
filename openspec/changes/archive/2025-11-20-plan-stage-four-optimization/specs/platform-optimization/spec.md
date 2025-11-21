## ADDED Requirements
### Requirement: Plugin Ecosystem Hardening & Marketplace
平台 MUST 提供受控插件生命周期（签名验证、元数据/schema、沙箱配额）以及 Server/Ops Console 插件市场，使第三方扩展可被安全分发并可观测。

#### Scenario: Signed plugin install with rollback
- **GIVEN** 第三方上传 `respond-risk-score` 插件包并附带符合规范的 manifest、签名与版本号
- **WHEN** 管理员通过 Ops Console 或 `POST /api/v1/plugins` 发起安装
- **THEN** Server 校验签名、依赖与资源限额，向目标 Agent 下发沙箱策略并在 60 秒内完成滚动加载
- **AND** 若插件在验证阶段崩溃/超限，系统将在 5 秒内回滚到上一版本并生成告警/审计记录

#### Scenario: Marketplace telemetry
- **GIVEN** 插件市场页面订阅 `/api/v1/plugins/stream`
- **WHEN** 插件被安装、升级或触发异常
- **THEN** Server 推送状态事件（版本、节点覆盖率、健康指标），前端可展示统计并允许运维一键禁用。

### Requirement: Agent Resource Optimization & Telemetry
Agent MUST 支持自适应限速、增量扫描与缓存，并在任务执行中上报资源占用指标以降低性能影响（P95 CPU <80%、失败率 <1%）。

#### Scenario: Adaptive throttle during peak load
- **GIVEN** Agent 在 `baseline` 任务中检测到 CPU > 75% 且 IO wait 占比上升
- **WHEN** 自适应调度器生效
- **THEN** 它自动降低并发度、延长扫描周期并记录节流原因，Server 指标面板显示节流事件，任务仍在 SLA 内完成且失败率不超过 1%

#### Scenario: Incremental scan cache hit
- **GIVEN** 上一次 `inventory` 扫描在 24h 内完成且缓存依然有效
- **WHEN** 新任务触发相同目标扫描
- **THEN** Agent 复用缓存结果，只重新扫描变更项并回传命中率/TTL，Server 汇总后可视化展示资源节省比例。

### Requirement: Security & Reliability Reinforcement
系统 MUST 支持证书轮换、RBAC/MFA 扩展、异常自愈与 BAS 安全边界控制，保障长期运行与合规。

#### Scenario: Automated certificate rotation
- **GIVEN** TLS 根证书将在 7 天后过期
- **WHEN** 运维触发 `POST /api/v1/certs/rotate`
- **THEN** 平台生成新证书链、逐步推送至 Agent；Agent 在不中断任务的情况下热更新，Server 记录审计，并在旧证书过期前完成切换

#### Scenario: BAS sandbox policy enforcement
- **GIVEN** BAS 场景请求高风险操作且需安全审批
- **WHEN** 审批通过并带有 `sandbox_policy_id`
- **THEN** Scheduler 仅允许符合策略的 Agent 执行；若步骤尝试突破资源/网络边界，系统立即终止并产生审计事件，保障隔离。

### Requirement: Documentation & SDK Delivery Pipeline
Docs-as-Code 流水线 MUST 版本化阶段四能力（插件、Playbook、运维、BAS）并自动发布，同时提供 SDK 示例与 API 参考。

#### Scenario: Docs pipeline gate
- **GIVEN** 开发者提交插件 SDK 更新与文档
- **WHEN** CI 运行 `docs lint`/`link check`
- **THEN** 若文档缺少版本标签或示例无法编译则阻断合并；通过后自动发布到文档站点并生成 release note 片段。

### Requirement: Unified Test, Performance & Chaos Gates
CI/CD MUST 引入统一测试矩阵、性能回归指标与故障注入，确保阶段四交付物在 Server/Agent/Ops Console/BAS 全链路稳定。

#### Scenario: Performance regression gate
- **GIVEN** 新增 Agent 优化代码
- **WHEN** CI 执行基准测试
- **THEN** 若 P95 API 延迟 >300ms 或 BAS 成功率 <98% 则流水线失败并输出对比报表；通过后生成性能快照供发布验证。

#### Scenario: Chaos drill for scheduler
- **GIVEN** 混沌测试注入消息队列延迟与 Agent 断连
- **WHEN** Scheduler 运行回放
- **THEN** 任务成功恢复且无数据丢失，并生成演练报告（RTO/RPO 指标）供运营确认。

### Requirement: Operations Tooling & Observability Suite
平台 MUST 提供可部署的监控仪表、集中日志/追踪以及一键部署/升级/回滚工具，覆盖多环境（dev/stage/prod/edge）。

#### Scenario: Ops dashboard rollout
- **GIVEN** 运维在新环境执行 `ops deploy monitoring`
- **WHEN** 脚本完成安装
- **THEN** Prometheus/Grafana 仪表包含 Agent/任务/TI/BAS 关键指标、预置告警规则，并在 5 分钟内开始接收数据

#### Scenario: Automated upgrade with rollback
- **GIVEN** 运维执行 `ops release apply --version v4`
- **WHEN** 灰度批次发现失败
- **THEN** 工具在 2 分钟内回滚至 `v3`, 保留审计日志，并通知订阅者（Webhook/Slack）确保生产稳定。
