## Why
- `docs/design-next.md:272` 将阶段三（5 个月）目标聚焦在威胁情报、异常检测、自动化响应、合规管理、可视化与 BAS 全链路能力，但当前 Agent/Server/Frontend 仍停留在阶段二：缺少对外情报接口、缺乏跨任务事件关联与实时干预能力。
- Respond/Baseline/BAS 等任务在 Agent 侧已经能够发现恶意文件或异常动作，却只能把静态结果返回 Server，无法自动查询或上传样本到 OpenTIP、MetaDefender 等平台，亦无法在 Server 侧统一做情报缓存、配额控制与可信报告。
- Server 目前只提供任务调度和结果聚合（`server/README.md`），缺少威胁情报编排、自动响应 Playbook、合规多框架映射与异常行为检测服务，前端也只能依赖 Mock SSE，无法可视化新的高级分析指标。
- BAS 场景虽已提供 JSON 描述与沙箱控制（`agent/internal/tasks/bas.go`），但还没有跨 Agent 的场景管理、审批、编排、攻击链可视化，也无法与自动响应与 Playbook 融合。

## What Changes
1. **威胁情报双引擎集成**
   - 在 Agent 内置 OpenTIP（`https://opentip.kaspersky.com/api/v1/search/hash`、`scan/file` 通过 `x-api-key`）与 MetaDefender (`https://api.metadefender.com/v4/file|hash` 通过 `apikey`)，提供 IOC 查询、文件上传、缓存与配额控制。
   - Server 新增 ThreatIntel Orchestrator：接收 Agent 返回的“需上送” artifact，经对象存储与队列推送至 OpenTIP/MetaDefender，聚合 verdict/score，同步回任务与前端。

2. **行为异常检测与关联分析**
   - Agent 扩展 Respond/Baseline/BAS 任务在结果摘要中上报主机指标（CPU/IO、进程树、连接图等），Server 经 Kafka/Redis Streams 进入 Behavior Graph Service，使用滑动窗口 + 规则/统计模型输出异常事件。
   - 关联分析将威胁情报结果、Agent 心跳、任务输出与 BAS 步骤统一建图，支持“一个 IOC 关联哪些主机/任务/操作”的查询。

3. **自动化响应 & Playbook**
   - Server 引入 Playbook Engine：YAML/JSON DSL 定义触发条件、审批链、动作（暂停任务、下发隔离脚本、触发 BAS 验证、创建工单等）。
   - Agent 支持幂等化“自动响应动作”任务类型（如隔离进程、封禁 IP），前端提供低代码编辑器与审批 UI。

4. **合规管理与多框架映射**
   - 在 Server 侧维护 CIS/GDPR/等保等控制项库，映射到 Respond/Baseline/Supplychain 的检测项，生成合规差距矩阵、整改追踪与报告模板。
   - 前端提供合规仪表盘、差距视图、整改任务追踪，并允许导出多格式（PDF/JSON/HTML）。

5. **高级可视化与报表**
   - Server 生成威胁情报、异常、BAS、资产的结构化可视化 payload（拓扑、桑基、风险热力图），前端通过 WebGL/Canvas 组件渲染。
   - 报表引擎支持多模板、多语言、签名与分享 token。

6. **BAS 全链路与场景管理**
   - Server 维护 BAS 场景仓库（版本、步骤、审批、资源限制），支持跨 Agent 调度、步骤编排、临时访问凭证分发与安全控件。
   - Agent 提供步骤级别的遥测、异常上报、沙箱 fallback 统计，前端提供场景编排器与执行时间线。

7. **性能与扩展性优化**
   - 引入分层缓存（Agent 本地 LRU + Server Redis）、批量任务调度、事件驱动推送、Prometheus 指标与速率保护，确保威胁情报与异常检测在大规模环境中可用。

## Impact
- **Agent**：需要新的 ThreatIntel SDK、artifact 上传协议、响应动作执行器、BAS 遥测和异常指标采集；配置文件需扩展情报 API 密钥、安全策略与 Playbook 下发参数。
- **Server**：新增 ThreatIntel、Behavior Graph、Playbook、Compliance、Visualization、BAS Scenario 等子服务；REST/gRPC/proto 需扩展字段，持久化层需要新表或对象存储；需要 Kafka/Redis/对象存储等依赖。
- **Frontend**：命令面板、任务视图、Threat Intel 控制台、自动响应/Playbook、合规仪表盘、BAS 场景工作台、报表中心等需要真实 API、SSE/WS 通道与 UX 设计更新。
- **Infra/Security**：需管理第三方 API 秘钥/配额、敏感样本的加密存储、审计日志扩展、以及对播放引擎/自动响应的审批链与 RBAC 细化。

## Open Questions
1. OpenTIP/MetaDefender API 的正式配额/费用模型？是否需要区分内置免费额度与企业版？
2. 可疑样本在 Server 端的存储策略（本地加密磁盘 vs. S3 兼容存储）与保留期是否有监管要求？
3. 行为异常检测是否需要引入 ML/AI 模型（如 Isolation Forest），还是先以规则/统计阈值上线？
4. Playbook 自动响应涉及的外部系统（工单、CMDB、EDR）优先级如何排列？
