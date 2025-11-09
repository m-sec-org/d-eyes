# D-Eyes 前端 UI 指南

本文档总结了当前选定的 UI 组件库、Design Token 与布局规范，供后续开发者参考。

## 1. 组件库与选型
- **组件库**：Ant Design 5.x（理由：主题定制、按需加载、可访问性与生态成熟）。
- **可替代备选**：Arco Design（如需更轻量或风格统一，可在后续阶段评估）。
- 引入方式：推荐使用 `vite-plugin-imp` 或官方按需引入方案，结合自定义 theme token。

## 2. Design Token
| Token | 默认值（Light） | 默认值（Dark） | 说明 |
|-------|-----------------|----------------|------|
| `color.primary` | `#1677ff` | `#4f9fff` | 主按钮、强调色 |
| `color.success` | `#52c41a` | `#6edb58` | 成功状态 |
| `color.warning` | `#faad14` | `#ffc53d` | 警告状态 |
| `color.danger` | `#ff4d4f` | `#ff7875` | 危险/错误 |
| `color.info` | `#13c2c2` | `#33d1d1` | 信息提示 |
| `color.text.primary` | `#0b1a33` | `#e6edf3` | 主文本 |
| `color.text.secondary` | `#627086` | `#9caec7` | 次文本 |
| `color.bg.default` | `#f5f7fb` | `#0a0f1c` | 页面背景 |
| `shadow.card` | `0 12px 30px rgba(15, 23, 42, 0.08)` | `0 12px 30px rgba(0, 0, 0, 0.4)` | 卡片阴影 |
| `radius.base` | `12px` | `12px` | 卡片圆角 |
| `space.base` | `8px` | `8px` | 基础间距（4px 为半单位） |

## 3. 排版与栅格
- 字体：`'Inter', 'PingFang SC', 'Helvetica Neue', sans-serif`
- 标题：`font-weight: 600`，正文：`font-weight: 400`
- 栅格/断点：沿用 Ant Design（`xs` <576, `sm` ≥576, `md` ≥768, `lg` ≥992, `xl` ≥1200, `xxl` ≥1600）。
- 移动端：侧栏折叠为抽屉；抽屉/Modal 在 `md` 以下全屏显示。

## 4. 可访问性
- 为主要卡片/表格/图表添加 `role` 与 `aria-label`，确保屏幕阅读器可识别。
- 命令面板、抽屉需管理焦点（打开时 focus 第一个可交互元素，关闭后回到触发按钮）。
- 提供快捷键说明（如 `Ctrl/Cmd + K`）并在 README 标注。

## 5. 图表与视觉
- 推荐使用 AntV G2Plot/ECharts；在空态、加载态、数据不足时提供提示。
- 图表配色应与 `color.primary`/`color.warning` 等 Token 保持一致。

本指南会随着 UI 优化迭代持续更新。
