## ADDED Requirements
### Requirement: Task Command Center Feed Stability & Controls
Ops Console MUST keep the实时监控流既可读又高性能，通过窗口化/虚拟化渲染、可配置的事件上限与冻结筛选控件，确保页面其他指挥组件始终可见。

#### Scenario: Virtualized Feed Caps DOM Growth
- **GIVEN** WebSocket 每分钟推送 ≥ 300 条事件
- **WHEN** 任务指挥中心渲染监控流
- **THEN** 客户端仅保留最近 150 条事件在 DOM 中，并将更早的记录折叠进按 1 分钟切片的时间段
- **AND** 顶部告警总览与干预操作区固定在视窗内，不因列表增长而被推下
- **AND** 滚动/重排耗时保持 < 16ms，从而不会打断用户交互

#### Scenario: Freeze & Time-Window Filters Preserve Context
- **GIVEN** 分析员在列表中滚动到 5 分钟前的事件
- **WHEN** 用户点击 “冻结” 或选择时间窗口（例如最近 10 分钟）
- **THEN** 前端暂停自动滚动，新的事件在计数角标中累积，待用户点击 “恢复” 后再批量插入
- **AND** 时间窗口过滤仅在本地状态生效，不会中断后台推送
- **AND** 释放冻结后，批量插入也遵循事件上限与虚拟滚动策略，避免跳回顶部
