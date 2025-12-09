# 事件工作台使用指南

事件工作台联合 `/api/v1/events`、`/api/v1/events/stats` 与 `/api/v1/detections/stream` 提供端到端的事件调查体验。以下步骤基于前端内置 MSW Mock，真实环境需确保 Collector 与 Server 均已开启事件采集。

## 筛选与时间线

1. 打开前端 `/events` 页面，顶部过滤器支持优先级、多 collector 类型、事件类型、来源、Agent ID。
2. 点击「刷新列表」可立即重拉当前过滤条件。
3. 时间线展示最近 40 条事件，标记 priority，辅助信息包含 Agent、存储层级与 `received_at` 相对时间。
4. 热图基于 `statsHistory`（每 45s 采样一次）渲染 12 个时间桶，可快速识别突发高峰。

## 统计面板

- 统计卡展示总事件量、过滤结果数量、Top event_type/source；该数据源自 `/api/v1/events/stats` 并与过滤条件一致。
- 历史列表记录最近 5 次 stats 快照，配合热图定位趋势。

## 实时检测 & Respond

1. SSE 面板消费 `/api/v1/detections/stream`，状态徽标反映连接状态。
2. 每条检测事件均可点击「触发 Respond」，前端会以 `metadata`（detection_id/agent_id/rule）构造 Respond 任务。
3. Respond 快捷操作卡片提供 Playbook 模板（阻断进程、内存扫描、网络隔离），可在高峰期快速下发。

## Collector 控制面

1. 侧栏「Collector 控制面」列出所有 collector（ID/Kind/Region/Tags 来源于 `/collectors` Mock）。
2. 表单可调整优先级、存储层级、采样率、lag 阈值及启停状态，点击「保存配置」即调用 `PATCH /collectors/:id`。
3. 最近心跳、状态标签（healthy/lagging/disabled）帮助定位 Collector 健康度。

## 测试与验证

- **Vitest**：`pnpm vitest run src/features/events/__tests__/EventsWorkspace.test.tsx src/hooks/__tests__/useCollectorConfigs.test.tsx` 验证 UI 联动与 Hook 行为。
- **Playwright**：`pnpm playwright test --config=playwright.config.ts tests/e2e/eventsWorkspace.spec.ts` 会自动启动 Vite Dev Server、访问 `/events` 并执行 Respond/Collector 操作路径。
- 如需更快启动，可设置 `VITE_USE_MSW=false` 切换为真实后端，Playwright 只需确保 `PLAYWRIGHT_BASE_URL` 指向可访问的 UI 域名。

## 常见问题

| 问题 | 排查建议 |
| --- | --- |
| 热图无数据 | 确认 `statsHistory` 是否开启（`includeStats: true`），或延长页面驻留时间以积累采样。 |
| Respond 调用失败 | 检查 `createTask` 返回的 4xx/5xx；MSW 下若看不到成功提示，可在控制台检查拦截日志。 |
| Collector 配置未更新 | 若真实环境 API 返回 403/409，可在页面消息提示中看到后端错误；Mock 场景下确保未禁用 MSW。 |
