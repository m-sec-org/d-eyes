## 1. 插件生态强化
- [x] 1.1 设计插件元数据/签名/版本规范，更新 Server/Agent 解析与校验逻辑
- [x] 1.2 实现沙箱隔离与资源限额、异常回滚以及插件级 observability hook
- [x] 1.3 Server & Ops Console 暴露插件市场、安装/升级 API 与 UI
- [x] 1.4 提供至少 3 个示例插件（检测/响应/BAS）与开发者指南

## 2. Agent 资源效率优化
- [x] 2.1 引入自适应扫描调度：CPU/IO 限速、任务优先级、动态退避
- [x] 2.2 增量扫描与缓存：实现结果缓存、差分扫描与 TTL 驱动的刷新策略（优先：为 respond/supplychain 等高 IO 模块提供缓存能力）
- [x] 2.2a 扩展 Heartbeat proto/storage 持久化 CPU/IO 元数据并在 Ops 可视化（依赖 2.2，为缓存命中率/资源指标提供观测数据；完成 2.2 后立即推进 2.2a）
- [x] 2.3 观测性：收集 per-task CPU/内存/网络指标并通过 Server 上报
- [x] 2.4 建立基准测试与报警阈值（P95 CPU <80%、任务失败率 <1%）
  - [x] 2.4.1 设计资源基准验证方案：扩展 `docs/LOADTEST.md`，将 `tools/loadtest` + 新增 `tools/perfcheck` 串联，明确采样窗口、阈值与诊断步骤。
  - [x] 2.4.2 实装可编程阈值校验器：新增 `server/tools/perfcheck`，消费 Prometheus 指标计算 Agent CPU P95 与任务失败率，支持参数化阈值并返回非 0 退出码。
  - [x] 2.4.3 指标/告警闭环：新增 `d_eyes_server_agent_cpu_percent` Histogram 并在 gRPC 心跳路径上报，更新 Observability 文档的 P95 <80% 告警公式。
  - [x] 2.4.4 扩展资源维度与 CI 门禁：心跳扩充内存/IO 采样与 Histogram、`perfcheck` 校验 CPU/内存/IO P95 与失败率，`Makefile` 提供 `perfcheck` 目标便于 CI/预发压测接入，文档补充 Alertmanager 表达式。
- [x] 2.5 基准校验收尾与 CI 适配
  - [x] 2.5.1 告警阈值对齐：将 `server/docs/OBSERVABILITY.md` 失败率告警（当前 5%）收紧到 1%，与 2.4 目标和 `perfcheck` 默认一致，并同步 CPU/内存/IO 阈值示例到 Alertmanager 模板。
  - [x] 2.5.2 采样窗口支持：为 `server/tools/perfcheck` 增加 `--window`/PromQL 查询模式，按 `histogram_quantile(rate(...[window]))` 计算 P95，避免长时间运行的累积值掩盖突刺，同时更新 `server/docs/LOADTEST.md` 的使用示例。
  - [x] 2.5.3 受保护环境访问与产物：`perfcheck` 支持 TLS/Token（Authorization 头或 CA 配置）访问受保护 metrics，输出 JSON 摘要便于 CI 存档/比对，并在 `Makefile`/文档中补充示例接入步骤。

## 3. 安全与可靠性增强
- [x] 3.1 TLS 证书轮换、双向认证自动化与凭证托管
- [x] 3.2 RBAC/MFA、Playbook 审批链扩展与细粒度权限校验
- [x] 3.3 异常自愈与灾备演练：心跳/任务恢复、Geo 级别灾备手册
- [x] 3.4 BAS 安全集控：场景审批、沙箱/资源边界策略、安全审计

## 4. 文档与 SDK/流程完善
- [x] 4.1 Docs-as-Code 流程：版本化、CI 校验、自动发布
- [x] 4.2 插件/Playbook/运维/BAS 指南更新，覆盖 Stage4 功能
- [x] 4.3 SDK & API 示例：插件 SDK、观测 API、运维脚本模板
- [x] 4.4 发布说明与变更日志模板同步 CI

## 5. 测试、性能与发布门禁
- [x] 5.1 构建统一测试矩阵：Server/Agent/BAS/前端 + 回归
- [x] 5.2 性能基线：任务调度、TI、BAS 运行、Ops Console 关键视图
- [x] 5.3 CI 门禁：覆盖率、性能回归、插件兼容性自动测试
- [x] 5.4 混沌/失效注入：Scheduler、消息队列、存储、Agent 断连

## 6. 运维工具与监控
- [x] 6.1 Prometheus/Grafana 仪表 + Alerting 模板（任务、Agent、TI、BAS）
- [x] 6.2 日志集中化、Trace 关联、任务调度追踪
- [x] 6.3 自动化部署/升级/回滚脚本与灰度策略
- [x] 6.4 支持多环境（dev/stage/prod）与边缘节点的运维手册
