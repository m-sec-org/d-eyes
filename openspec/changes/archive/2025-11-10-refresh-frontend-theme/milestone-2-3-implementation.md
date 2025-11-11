# Milestone 2 & 3 – Theme Token + 控件落地

## 1. 设计 Token 输出
- `frontend/src/styles/tokens.css`：扩展 30+ 语义变量（文本、边框、状态、控件背景、字号、间距、圆角、阴影等），并同步暗色模式数值，为后续响应式/无障碍提供基线。
- `frontend/src/theme/tokens.ts`：新增 `antdThemeConfig`，将 Token 映射到 Ant Design `ThemeConfig`（按钮、输入、Select、Table、Segmented、Statistic 等组件），确保 UI 包与自定义控件一致。
- 全局 `index.css` 采用 `--font-family-sans`，并引入新的 `styles/ui.css`，集中管理按钮/表单控件的类名与状态。

## 2. 基础控件封装
- 新增 `@/components/ui` 目录，提供 `Button`, `FormField`, `TextInput`, `Textarea`, `Select`, `Checkbox` 以及 `cn` 工具，全部走统一类名 `ui-*`。
- CSS 定义了 primary/secondary/ghost/ghost-danger/danger 等按钮变体，含 hover/active/focus/disabled 状态；输入类支持错误/禁用/多选下拉、统一焦点光环。

## 3. 页面改造
- **任务创建**：`CreateTaskDrawer` 迁移到 `FormField + TextInput/Select/Textarea/Checkbox`，参数区域新增 `field-grid` 布局与帮助文案，按钮改为 `Button` 组件。
- **BAS 场景**：创建表单、资源限制、步骤编排和卡片操作按钮全部换用统一组件；增加标签/输入 hint，危险操作使用 `ghost-danger`。
- **Agent 目录**：筛选器与标签编辑抽屉使用新控件，列表操作按钮对齐主题。
- **报告工作台 & 审计日志**：筛选/表单/生成面板迁移到新组件，按钮/输入态一致，并为数值/多行输入提供 hint。
- **系统配置中心**：全局参数输入使用 `FormField + TextInput`，操作按钮统一，模板列表操作按钮使用 `Button` 变体。
- **Task Live Monitor**：筛选下拉切换为 `Select`，操作按钮使用 `Button` 并区分危险态。

## 4. 行为统一
- 补齐 `.form-grid`、`.resource-grid`、`.field-grid` 等容器布局，`filter-row` 改用 `.ui-control`，旧的 `.primary/.ghost` 样式已清理。
- 全局配置 `pnpm tsc -b` 通过，确保新的组件/类型声明被编译器接受。
