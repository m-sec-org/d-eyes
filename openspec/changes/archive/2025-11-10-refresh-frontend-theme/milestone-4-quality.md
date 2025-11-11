# Milestone 4 – 文档 & 质量保障

## 1. 文档交付
- 新增《[UI 主题与组件指南](../../docs/ui-theme-guide.md)》，涵盖 Token 结构、AntD 主题映射、`ui` 组件使用流程及扩展步骤。
- 在 `docs/deployment-handbook.md` 增补 **3.4 主题与 UI 规范**，指向 `/ui-guide` 页面与主题配置入口，部署/运营同学可快速了解如何启用统一样式。

## 2. 示例页 / Storybook 替代
- 新增 `ThemeShowcase` 页面（`/ui-guide`），展示按钮各变体、表单控件组合与 Token 表，便于研发/设计联调及视觉验收。
- Sidebar 与权限体系已注册该入口，仅管理员可访问，确保示例环境不会影响普通用户。

## 3. 自动化回归
- 在 `frontend/src/components/ui/__tests__` 下加入 `Button`、`FormField` 的最小单测，覆盖 variant/block/disabled/error 等关键分支。
- 运行 `pnpm vitest run src/components/ui/__tests__/Button.test.tsx src/components/ui/__tests__/FormField.test.tsx` 均通过，保证自定义控件在样式重构后行为稳定。
