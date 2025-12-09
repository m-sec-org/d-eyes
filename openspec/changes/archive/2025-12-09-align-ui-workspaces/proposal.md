## Why
- 运营与治理页面沿用自定义 `.card`、固定 sidebar/layout，不具备响应式能力，1280px 以下导航与内容拥挤，Header 环境徽标也无法交互，整体 UI 体系缺少一致的设计基线。
- 高频工作台（运营总览、任务指挥中心、事件、资产、风险、命令队列、威胁情报、行为异常等）存在过滤表单堆叠、列表滚动体验差、统计信息缺失趋势/Legend 等问题，用户效率和可读性均受影响。
- 治理工具（合规、Playbook、BAS、报告、系统配置、插件市场、审计）仍使用 `alert/prompt`、原生控件，缺乏统一消息反馈和可视化组件，造成样式割裂和可用性隐患。

## What Changes
- 建立统一的 UI 框架：响应式 Sidebar/Header、环境 Segmented 选择器、`AppCard/AppTable/AppFormSection` 基础组件与 token，对治理/运营页面逐步替换旧 `.card`。
- 升级运营控制台：运营总览权限过滤 + 趋势指标、任务指挥中心 Form/Grid + Modal 保存视图、事件/资产/风险/命令队列等工作台的过滤布局、虚拟时间线、统计/Legend/条形图等交互优化。
- 提升洞察/威胁/异常体验：威胁情报表单拆分、详情分区与 Tag 色阶统一；行为异常中心支持可调分栏与图谱可视化。
- 强化治理工具：合规高亮、Playbook CodeBlock、BAS Modal 操作与拖拽步骤；报告/系统配置/插件/审计迁移到 AntD 反馈与表单/表格组件。

## Impact
- **Specs**：需要在 `ui-framework`, `ops-console`, `events-workspace`, `governance-console` 等相关能力中新增/修改要求，定义响应式布局、组件一致性及关键页面交互。
- **Code**：影响 `frontend/src/App.css`, `components/layout/*`, 多个 `features/*` 页面与 hooks；需要新增基础 UI 组件与可视化实现，并更新对应测试/文档。
