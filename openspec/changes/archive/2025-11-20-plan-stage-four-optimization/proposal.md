## Why
阶段四（完善和优化）需要把插件生态、Agent 资源效率、安全可靠性、文档与测试、运维工具收口到可上线标准，确保分布式 Agent-Server 架构在生产环境稳定运行。

## What Changes
- 梳理插件体系：规范插件签名/元数据/沙箱隔离，提供示例插件与市场入口，强化第三方扩展路径。
- 优化 Agent 资源与扫描效率：自适应限速、增量/缓存、优先级队列与可观测指标，降低资源占用。
- 强化安全与可靠性：证书轮换、RBAC/MFA、异常自愈、BAS 隔离、灾备演练。
- 完善文档与发布门禁：插件/运维/Playbook/BAS 文档与 SDK，Docs-as-Code + 测试/性能准入门槛。
- 构建运维与监控工具链：统一指标/日志/追踪与多环境部署、升级/回滚流水线。

## Impact
- Affected specs: platform-optimization（新增阶段四完善与优化要求）
- Affected code: Server（调度、鉴权、TI/BAS/Playbook）、Agent（任务执行、资源与缓存、沙箱）、Ops Console（插件市场、观测性界面）、文档/CI（Docs-as-Code、性能与测试门禁）、运维脚本与监控栈。
