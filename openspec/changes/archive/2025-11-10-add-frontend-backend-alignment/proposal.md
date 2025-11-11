# Proposal: Frontend and Backend Capability Alignment

## Change ID
add-frontend-backend-alignment

## Context
前端控制台已经暴露任务模板化创建、任务流监控等基础能力，但后端 roadmap 规划与已有 gRPC/REST 接口更侧重 respond/baseline 场景，导致新建任务类型、BAS 场景、实时监控、可视化和审计等能力缺口。为了避免重复堆叠临时性前端逻辑，需要在 OpenSpec 侧梳理出一套覆盖任务类型、BAS 场景、Agent 管理、报告导出、实时监控、权限审计的统一能力蓝图，以指导后端 API、事件流和数据模型的演进。

## Problem
- 缺乏面向 respond/audit/inventory/supplychain 等任务类型的结构化配置接口和 profile 选择，导致前端无法提供精细表单。
- 任务结果仅有摘要，无法支撑网络连通性拓扑、文件扫描风险分布等可视化。
- BAS 场景配置、审批与安全边界缺失，前端无从编排模拟攻击剧本。
- Agent 节点没有统一的注册、状态、能力与心跳指标透出，无法做分组与筛选。
- 报告下载零散，缺少模板管理与多格式导出。
- useTaskStream 提供的事件不足以驱动实时进度、告警与人工干预。
- 权限模型只有粗粒度角色，缺乏 RBAC 细分与审计日志检索。

## Goals
1. 定义任务类型专属配置接口，包含 profile 选择和参数校验，支撑前端表单。
2. 明确任务结果可视化所需的数据契约，覆盖连通性、文件风险、主机摘要等结构化输出。
3. 规划 BAS 场景管理端点，含场景生命周期、编排、审批与安全边界限制。
4. 定义 Agent 资产管理与监控 API，实现分组、标签、心跳与能力指标。
5. 统一报告模板、生成与导出流程，支持 PDF/HTML/JSON、多渠道分享。
6. 扩展实时监控事件流，覆盖进度、关键操作、异常告警和人工干预控制面。
7. 补齐 RBAC 细粒度授权、敏感操作审批与可检索审计日志。

## Non-Goals
- 不在本次范围内实现具体 UI，专注于 Spec 与后端能力梳理。
- 不讨论 Agent 执行器内部实现；仅定义接口与数据面需求。
- 不对历史任务做迁移，新增能力对存量数据只要求向后兼容。

## Success Metrics
- 前端可以根据 Spec 补齐 7 类功能所需的接口字段和事件。
- 开发任务拆解后可形成迭代路线（至少两个迭代）并与后端团队共识。
- `openspec validate add-frontend-backend-alignment --strict` 通过，表示新增能力定义完备。

## Rollout & Validation
1. 完成 Spec+Proposal 并经评审确认范围。
2. 后端创建对应 API/事件，联调完成后逐步在前端开启灰度。
3. 对权限、BAS、实时监控等敏感模块引入 Feature Flag。
4. 回收旧的模板化 Hack，确保所有任务类型都走新配置管道。

## Risks & Mitigations
- **Scope 过大**：按任务类型/资源域切分迭代，proposal 中提供分期计划。
- **数据契约变更**：在 Spec 中对结构化输出给出字段定义与可选项，避免临时字段。
- **安全风险**：BAS 与权限相关功能默认关闭，加入审批与日志要求保障合规。
