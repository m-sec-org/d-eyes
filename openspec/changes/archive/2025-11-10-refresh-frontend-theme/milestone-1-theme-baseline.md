# Milestone 1 – Theme Baseline Audit

> Scope: 1.1「盘点控件样式差异」+ 1.2「整理 CSS/AntD 主题资产」

## 1. 现有主题资产

### 1.1 CSS 变量与全局样式
- `frontend/src/styles/tokens.css` 定义了 20 余个全局变量（背景、文本主/副色、卡片、强调色、圆角、阴影、过渡等），并提供 `data-theme=dark` 版本。但尚未覆盖字号、字体粗细、边框宽度、表单状态色、按钮高度等关键 Token。
- `frontend/src/App.css` 在多个组件中直接使用 `var(--color-*)`，同时出现未定义的变量（例如 `var(--color-border-muted)`，见 `frontend/src/App.css:315`），导致浏览器回退为 `initial`，无有效边框颜色。
- 目前没有集中管理的 `spacing`/`font` 尺寸刻度，页面中大量写死 `px` 数值，后续难以对齐。

### 1.2 Ant Design 主题配置
- `vite.config.ts` 未注入 `antd` 主题配置，也没有 `ConfigProvider` 级别的 `theme.token` 覆写；绝大部分 AntD 控件（`Button`, `Input`, `Select`, `Card`, `Segmented`, `Table`, `Statistic` 等）使用默认主题。
- 局部通过 CSS 覆写（例如 `.primary`, `.ghost`, `.drawer-form input` 等）来模拟品牌样式，但与 AntD 自带控件并未共享 Token，导致页面中出现两套视觉体系。

## 2. 控件使用盘点

| 控件类型 | 实现方式 | 主要引用 | 现状/问题 |
| --- | --- | --- | --- |
| 主/次按钮 | 自定义 `.primary`、`.ghost`、`.ghost danger`、`.command-trigger`、`.icon-button` 样式（`frontend/src/App.css:200-260`） | 任务抽屉、BAS 控制台、系统配置中心、报告工作台等 | 没有 focus/disabled/error 状态，Danger/Small 通过额外 class 实现，样式分散。 |
| AntD 按钮 | `<Button type="primary/ghost" />`（如 `frontend/src/features/overview/OverviewDashboard.tsx`, `AssetOverview.tsx`） | Dashboard、资产视图、风险中心 | 使用 AntD 默认色，不遵循自定义 Token，与 `.primary` 按钮风格冲突。 |
| 单行输入 | 自定义 `.drawer-form input`、`.filter-row input`（`App.css:802-845`）以及 AntD `Input`（`AssetOverview.tsx:187`, `TaskFilters.tsx:42`） | 任务抽屉、系统配置中心、审计过滤、资产筛选 | 自定义输入框缺少 hover/focus/error 提示，AntD 输入框仍用默认蓝色聚焦；占位符/字号不一致。 |
| 多行文本 & Textarea | `.drawer-form textarea`（`App.css:838`）用于任务描述、BAS 步骤等 | `CreateTaskDrawer.tsx`, `BASScenarioConsole.tsx` | 仅设置 padding/背景，无字数限制或错误提示，暗色模式下可读性不足。 |
| 下拉 / Select | 原生 `<select>`（任务 Profile、BAS 动作）+ AntD `Select`（`TaskFilters.tsx:54`） | 大量表单 | 原生下拉使用浏览器默认样式；AntD Select 沿用默认主题，易出现风格割裂。 |
| Segmented & Tag 等状态控件 | AntD `Segmented`, `Tag`, `Statistic` | Dashboards、资产页 | 成功/警告/危险色基于 AntD 默认色，与 `--color-risk-*` token 未对齐。 |
| Checkbox/Radio | 原生 `<input type="checkbox">` 包裹 `label.checkbox`（`CreateTaskDrawer.tsx:94`, `BASScenarioConsole.tsx:241`），但 `.checkbox` 未定义样式 | 任务抽屉、BAS 场景 | 目前完全依赖浏览器默认外观，缺失对齐/状态色。 |
| Upload/File | 业务尚未接入，后续需要统一策略 | — | 可提前在 Token 中预留拖拽/按钮样式。 |
| 表格/Table | AntD `Table` + 自定义 `.table`（非 AntD）并存（`SystemConfigCenter.tsx`, `AuditLogView.tsx`） | 配置、审计等 | 表头样式、行高不一致；部分自定义表无空态/hover。 |

## 3. 发现的问题与机会

1. **双轨视觉体系**：自定义按钮/输入（`App.css`）与 AntD 组件（例如 `Button`, `Input`, `Segmented`）彼此独立，缺乏共享 Token。用户在同一页面会见到两套不同的颜色/圆角/阴影。
2. **状态反馈缺失**：多数自定义控件仅定义默认态，没有 hover/focus/disabled/error 样式；表单校验提示只能通过浏览器默认红边，体验不一致。
3. **Token 覆盖范围有限**：仅有颜色/阴影/圆角，缺少字体、行高、间距刻度以及语义化状态 Token；还存在未定义变量的引用（`--color-border-muted`），需要补齐或移除。
4. **AntD 主题未配置**：由于未使用 `ConfigProvider`/`theme`, 无法让 AntD 控件继承 `tokens.css`，后续统一需要新增主题桥接层。
5. **缺少交互规范文档**：当前没有列出控件尺寸、对齐、辅助文本、图标间距等规则，BAS/任务/审计页面各自实现，维护成本高。

> 以上盘点将指导里程碑 2 的 Token/基础组件建设：先补齐 Token（含缺失变量），再用 `ConfigProvider` 驱动 AntD，与自定义控件同步迁移。
