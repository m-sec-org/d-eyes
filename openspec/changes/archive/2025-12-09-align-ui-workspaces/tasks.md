## 1. Design System & Layout
- [x] 1.1 引入 Sidebar 响应式（≤1280px icon-only、`clamp` 主内容 padding）与 Header 环境 Segmented，更新 `App.css`/layout 组件。
- [x] 1.2 抽象 `AppCard`/`AppTable`/`AppFormSection` 组件与 token 指南，并将 AgentDirectory、ReportWorkbench、BASScenarioConsole 等页面迁移为统一样式。

## 2. 运营控制台体验
- [x] 2.1 运营总览：快捷入口按权限过滤/禁用，Statistic 卡片新增趋势指标与颜色规范。
- [x] 2.2 任务指挥中心：`TaskFilters` 改为 Form+Grid 布局，提供 Sticky 工具栏；保存视图使用 Modal（含重名校验、loading 状态）。

## 3. 事件工作台与资产视图
- [x] 3.1 事件过滤分基础/高级组（高级 Collapse），时间线采用虚拟列表或 sticky list，右侧统计/检测/Respond 卡设置 `max-height`+Tabs+SSE 摘要。
- [x] 3.2 资产视图：搜索/批量操作表单化，按钮旁显示“已选 X 项”，启用 Table selection 提示条或 `tableAlertRender`。

## 4. 风险仪表盘与命令队列
- [x] 4.1 风险柱状图换统一色板并添加 Legend/Tooltip，状态卡片展示环比箭头 + icon。
- [x] 4.2 QueueMonitor：任务类型分布改水平条图，Agent 活动表格支持分页/总数提示并标记“显示 5/N”。

## 5. 威胁情报与行为异常
- [x] 5.1 威胁情报：IOC 查询表单拆分两行 Grid，样本/附件/Job 区块采用 `Descriptions`/`Collapse`，Tag 色阶统一。
- [x] 5.2 行为异常中心：列表/详情支持可调分栏与固定高度，关联图谱可视化（示例使用 `@ant-design/plots` 或 `vis-network`）。

## 6. 治理工作台（合规/Playbook/BAS）
- [x] 6.1 合规：框架列表高亮选中、控制项卡片展示框架信息，差距 Timeline 与整改表单分区（含固定高度/Affix）。
- [x] 6.2 Playbook：新增 CodeBlock 组件用于 JSON 展示、表单字段提供示例/校验提示。
- [x] 6.3 BAS 场景：审批/发布/运行操作改 Modal（含摘要/备注），步骤编排支持拖拽排序并展示动作/超时标签。

## 7. 工具页面一致化
- [x] 7.1 ReportWorkbench/SystemConfigCenter：使用 AntD message/loading，去除 `alert`/原生表格。
- [x] 7.2 PluginMarketplace：接入 tokens + AntD Form/Table；AuditLogView 使用 AntD Table + inline 过滤并提供排序/分页。

## 8. 文档与验证
- [x] 8.1 更新相关 spec（`ui-framework`, `ops-console`, `events-workspace`, `governance-console` 等）并记录新的组件/交互要求。
- [x] 8.2 编写/更新设计指南与测试计划，运行 `openspec validate align-ui-workspaces --strict`。
