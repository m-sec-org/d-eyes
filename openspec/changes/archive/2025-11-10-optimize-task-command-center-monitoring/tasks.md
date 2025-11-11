## 1. Diagnostics & Planning
- [x] 1.1 基准测试当前任务指挥中心列表的推送频率、DOM 节点数与 FPS  
  - `pnpm test tests/perf/taskLiveMonitor.baseline.test.tsx --run` 记录 SSE 模拟频率 4.9Hz（平均 203ms/条，最慢 215ms），在现有 `TaskLiveMonitor` 中一次性灌入 600 条事件会让 DOM 保持 25 可见行但节点数暴涨至 244，渲染平均耗时 0.01ms、P95 0.015ms，说明主要瓶颈来自 DOM 无界增长而非单次绘制。
- [x] 1.2 明确事件窗口大小、分段长度与性能验收指标  
  - 将实时列表硬上限设为 150 条，超过部分折叠为 1 分钟时间段（可展开查看）；冻结/本地时间窗口过滤需保证后台推送不中断。验收指标：滚动/重排预算 < 16ms、批量插入 50 条事件时平均渲染 < 8ms、SSE 推送延迟 < 250ms（与测得 203ms 均值对齐）。

## 2. UX & Spec Alignment
- [x] 2.1 设计虚拟列表、冻结控件与顶部状态区交互稿  
  - 列表主体采用 52px 行高的虚拟滚动容器（自研 padding/transform 方案），固定显示窗口默认为 150 条，可在 Summary 右上角调节；顶部 Summary 区包含事件速览（总数 + danger/warning/info）与任务分布图块，右侧放置冻结/恢复、时间窗口筛选（全部 / 5min / 10min / 30min）及任务/严重级别过滤器，整个区域 `position: sticky` 确保在大量事件时仍可见。
  - 冻结开启时停止自动滚动并显示 “新事件 +N” 徽标，点击“恢复”后批量插入（透传给虚拟列表）并重置计数；超过窗口上限的历史事件折叠为 1 分钟时间段的统计卡片，可展开查看 severity 分布，从而避免 DOM 无限制增长但仍保留上下文。
- [x] 2.2 更新前端状态管理/数据模型以支持批量写入与可配置窗口  
  - `useTaskEventStore` 扩展 `windowSize`、`setWindowSize` 与 `addEvents`（批量添加），内部缓冲区提升至 600 条以供时间窗口/统计使用，而渲染窗口则由组件控制；store 保持不可变追加顺序（最新在前），由组件负责根据时间窗口、任务过滤、冻结状态计算最终可视集合。

## 3. Implementation & Validation
- [x] 3.1 实现虚拟滚动、批量渲染、自动截断逻辑  
  - `frontend/src/features/tasks/components/TaskLiveMonitor.tsx` 重写渲染区域，固定 52px 行高并用自研虚拟滚动（translateY + overscan）只渲染最近 N 条；溢出事件以 1 分钟桶折叠展示；`frontend/src/store/taskEvents.ts` 将缓冲上限扩至 600，并暴露 `addEvents`/`setWindowSize` 以支撑批量写入和可配置窗口。
- [x] 3.2 添加冻结/筛选控件及固定 Summary 区  
  - 新增 `TaskLiveMonitor.css` 固定 Summary/Grid/操作区样式；组件内提供冻结/恢复、时间窗口、事件上限、任务/严重级别过滤器，并在冻结时累积“新事件 +N” 徽标，顶部 Summary 显示告警/任务概览（始终可见）。
- [x] 3.3 编写性能回归用例，验证高频事件下渲染时间与 DOM 上限  
  - `frontend/tests/perf/taskLiveMonitor.baseline.test.tsx` 更新为统计虚拟化后的 DOM 行数与节点数（rows≈11、节点 198），同时沿用 SSE 频率基准；CI 命令 `pnpm test tests/perf/taskLiveMonitor.baseline.test.tsx --run` 通过。
