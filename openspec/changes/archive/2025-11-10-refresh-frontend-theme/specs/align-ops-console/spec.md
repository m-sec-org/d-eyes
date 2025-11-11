## ADDED Requirements
### Requirement: Unified Theme Tokens & Control Variants
Ops Console MUST expose a shared theme token system that drives buttons, inputs, selectors, radios, checkboxes and upload控件的主次状态、禁用/错误反馈与暗色模式基线，确保不同页面的视觉与交互一致。

#### Scenario: Primary Actions Use Shared Tokens
- **GIVEN** 主题层定义 `action.primary`, `action.secondary`, `danger` 等 Token，并指定 hover/focus/disabled 状态
- **WHEN** 任务创建页或 BAS 场景审批页渲染 “创建/执行/审批” 等主操作按钮
- **THEN** 这些按钮均使用相同的 Token、字号与圆角，hover/focus 状态保持一致
- **AND** 当按钮被禁用或呈现危险操作时，颜色/描边/提示与 Token 规范一致，提供 aria-label 说明

#### Scenario: Form Controls Share Validation Feedback
- **GIVEN** 输入框、Textarea、Select、Radio、Checkbox 与 Upload 控件引用统一的 `field.*` Token（边框、背景、辅助文本）
- **WHEN** 用户触发 focus、填写错误或查看禁用字段
- **THEN** 所有控件显示统一的高亮边框、错误提示颜色及帮助文本排版
- **AND** 无论位于任务、Agent 还是审计模块，控件高度、内边距与标签位置保持一致，便于无障碍与键盘操作
