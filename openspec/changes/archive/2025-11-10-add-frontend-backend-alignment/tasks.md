# Tasks – add-frontend-backend-alignment

## Phase 0 – Discovery & Contracts
- [x] 梳理现有 respond/baseline API 与事件，产出字段差异矩阵（FE+BE pair）。
- [x] 为 respond/audit/inventory/supplychain 任务类型补齐 profile schema 草案并获得安全团队签字。
- [x] 设计统一的任务结果数据契约（network graph、file risk、host summary），输出 protobuf/REST Schema 草案。

## Phase 1 – Task Types & Visualization
- [x] 后端：实现 `/api/v1/task-types` 及 `/api/v1/task-profiles` CRUD，支持 profile template + 参数校验。
- [x] 前端：为每种任务类型生成独立配置表单，消费 profile schema 自动渲染字段。
- [x] 后端：扩展任务结果存储结构并暴露 `/api/v1/tasks/{id}/visuals`，返回图形化数据所需 payload。
- [x] 前端：构建网络连通性拓扑、文件风险分布、主机摘要组件，复用任务结果 API。

## Phase 2 – BAS 场景管理
- [x] 后端：新增 `/api/v1/bas-scenarios`（创建/更新/编排/启停）和审批/权限字段。
- [x] 前端：实现 BAS 场景列表、编排器与审批流程 UI，支持拖拽排序与资源限制设置。
- [x] 安全：提供默认安全边界策略与资源配额，写入配置中心。

## Phase 3 – Agent & Report Capabilities
- [x] 后端：Agent Registry 扩展节点能力、心跳指标、分组/标签字段，并提供 `/api/v1/agents` 列表过滤。
- [x] 前端：实现 Agent 列表、筛选、标签管理及详情页（展示心跳/能力/连接质量）。
- [x] 后端：搭建报告模板服务（模板 CRUD、版本化），并实现多格式导出 API。
- [x] 前端：集成报告生成与分享 UI，支持下载/链接分享/协作邀请。

## Phase 4 – 实时监控 & 权限审计
- [x] 后端：扩展 useTaskStream 底层事件源，加入进度、关键操作、异常与人工干预事件；提供 websocket/gRPC 流接口。
- [x] 前端：实现实时进度面板、告警提醒与交互式指令（暂停/重试/终止）。
- [x] 后端：引入 RBAC 策略与权限矩阵 API，支持资源级别授权、审批工作流和审计日志查询。
- [x] 前端：构建权限配置界面、敏感操作审批流程，以及审计日志检索/过滤视图。

## Phase 5 – Validation & Rollout
- [x] 设计集成测试覆盖：任务类型配置→执行→实时监控→报告链路。
- [x] 建立 Feature Flag 清单，定义灰度策略与回滚预案。
- [x] 与 SecOps/CS 团队共同验收 BAS、权限、审计模块并更新 Playbook。
