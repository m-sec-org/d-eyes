## 1. Discovery & Scaffolding
- [x] 1.1 Finalize parser/sampler/filter interfaces and shared config schema updates (agent `collector` package + remote config plumbing).
- [x] 1.2 Define EBPF probe definition catalog + build scripts for modular CO-RE objects (add docs/examples).
  - [x] IPv6/Unix socket payload扩展、网络/文件 Probe 遥测增强，并在心跳中携带探针编译日志与对象版本号。
- [x] 1.3 Extend server config (`EventsConfig`, collector control plane) and API contracts for ingestion/search/UI.
  - [x] 为 `/api/v1/events/ingest` 增加 `priority/storage_tier` 契约，Server 侧实现多优先级队列、分层保留配置与指标，Collector 控制面返回 `lag_seconds/lagging` 便于 UI 呈现。
  - [x] `/api/v1/events` 查询接口支持 `priority`/`storage_tier` 过滤并输出 Prometheus 分层计数指标，便于前端直接消费。
  - [x] `/api/v1/events` 支持 `cursor_time/cursor_id` 游标分页、`sort=asc|desc` 以及 `next_cursor` 返回值，并新增 `/api/v1/events/stats` 以 event_type/source 维度输出聚合结果，满足 Events Workspace 热图/统计面板的同源数据需求。

## 2. Windows ETW Enhancements (P0)
- [x] 2.1 Implement `ETWParserManager`, provider-specific parsers (security/system/app/Defender/container), and rule-based filter engine with tests。
  - [x] Parser Manager 支持启用/禁用清单并注册多 Provider 解析器，新增安全/系统/应用/Defender/容器解析器，结合规则引擎与采样器完成过滤路径单测。
- [x] 2.2 Add dynamic sampler + async worker pool/object pool in `etwCollector`, including metrics reporting + monitor interface。
  - [x] 引入带缓冲事件队列、对象池复用 ETW 记录、工作协程池 + 热更新 monitor，采样/过滤统计与队列深度、掉队、CPU/内存指标均可在 `Status` 返回，队列溢出/停机场景具备降级与单测覆盖。
- [x] 2.3 Wire dynamic config updates + plugin loader (parser/processor) plus malicious-behavior detectors that forward Respond tasks/events.
  - [x] ETW collector 支持插件式解析器/处理器、热加载配置与检测引擎，同时 Remote Runner 自动注入 Respond sink，实现检测事件落盘与自动响应。

## 3. Linux EBPF Enhancements (P0)
- [x] 3.1 Implement probe registry/manager that can load/unload probes at runtime and expose kernel/BTF compatibility diagnostics.
  - [x] 构建 probe catalog/registry、运行时 probe manager，扩充文件/网络细粒度探针（unlink/rename/sendmsg 等）并带重试/日志的 attach 遥测，支持配置热更新时动态卸载/加载 Tracepoint，并在 CollectorStatus.Metadata 中上报 kernel/BTF/CO-RE/tracefs 诊断信息与最近 attach 日志。
- [x] 3.2 Expand EBPF programs (network/file/process/memory) with context-rich events and sampling/backpressure controls, including perf map tuning.
  - [x] 扩展 eBPF 程序捕获 exec/open/write/connect/mmap 等上下文（含 UID/GID、dirfd/flags、IPv6/FD、内存段信息），新增 Memory Parser 并统一解析器注入，Collector 端实现 perf ring watermark/overwrite 配置、丢样背压自适应采样（动态缩放 Sampler）、Status 暴露 buffer/scale/backpressure 诊断，完成 `perf_loss_threshold` 等热更新链路。
- [x] 3.3 Add malicious-behavior detectors (trojan upload, memory implant, remote command) and ensure Agent heartbeats expose collector stats.
  - [x] 引入 EBPF 检测引擎（木马上传/内存马/远程命令），利用文件/网络/内存事件的上下文实现关联检测并透传 Respond sink，同步在 CollectorStatus/心跳中输出 detection/perf/backpressure 元数据，保证 Server 能实时掌握 collector 运行态。

## 4. Server Event Pipeline (P1)
- [x] 4.1 Replace single queue with multi-priority queues + batching + backpressure policies, instrumented with metrics + alerts.
  - [x] Eventing Service 支持 per-priority 配置（容量/批量/Spillover），新增背压计数指标与日志告警，优先级车道可在饱和时自动降级或阻断，并通过 `/metrics` 公开 `events_backpressure_total`/queue 深度以驱动告警。
- [x] 4.2 Introduce parser/plugin registry + schema validation, storing normalized events with tiered retention and search APIs.
  - [x] Server 启动阶段构建 Parser Registry 并注入 ingest handler，事件入库前执行 schema 校验与默认 parser，失败返回 400；成功路径附带 storage_tier/retention metadata，单测覆盖无效事件拒绝与保留链路，同时将 parser registry 运行状态/失败指标暴露到 `/metrics`（含告警示例文档）、parser failure 与 `d_eyes_events_dropped_total` 打通，并通过 ingest→查询 端到端测试验证 tier metadata 在查询接口中可见。
- [x] 4.3 Build detection engine (rules + ML harness) that consumes ingested events and triggers Respond/threat intel workflows.
  - [x] 事件服务新增 DetectionEngine consumer，按配置的规则/ML 模型实时评估 ETW/EBPF 事件，生成 `detection.alert` 事件（持久化 + `/api/v1/events/detections` 查询 + `/api/v1/detections/stream` SSE），并依据规则/模型或全局 Auto Respond 策略自动下发 Respond 任务、汇报指标 (`detections_triggered_total`/`detections_auto_respond_total`)，同时将命中的 IOC 通过 Threat Intel Orchestrator 发起 lookup/审计。
- [x] 4.4 Extend collector control plane APIs to push config updates, monitor collector status, and audit changes.
  - [x] 新增 rollout API（创建/查询/回滚）、目标 selector、审计与指标（`d_eyes_collector_rollout_targets`、`rollout_actions_total`），并在心跳链路更新 ack/失败态，支持自动处理超时、回滚版本和 UI/Server SSE 查看实时状态。

## 5. Frontend Event Workspace (P1/P2)
- [x] 5.1 Create React services/hooks for `/api/v1/events` queries and SSE detection feeds, with Zustand stores mirroring metrics.
  - [x] 提供 `events` API service + zod schema/type、`useSystemEvents`/`useSystemEventStore` 以支撑游标分页与 stats 缓存，并新增 detection SSE `useDetectionStream` + store（含 mock SSE）让 UI 可直接消费 `/api/v1/detections/stream`。
  - [x] 事件工作台 UI 接入 useSystemEvents/useDetectionStream（导航/过滤/时间线/统计/告警馈送），增补 MSW mock、Zustand 行为单测与 EventsWorkspace 集成测试确保新 store/hook 稳定。
- [x] 5.2 Build Events workspace (timeline, filters, heatmap, detector feed) plus collector config forms and Respond shortcuts.
  - [x] 时间线/过滤器扩展至热图 + statsHistory 可视化，检测告警 Card 支持 Respond 按钮，新增 Respond 快捷操作卡执行模板化 Respond 任务调用。
  - [x] 落地 Collector 控制面（SWR + `/collectors` API mock + 表单）支持优先级/采样/存储层级配置提交并反馈状态，完善 Vitest 集成测试覆盖 Respond/Collector 行为。
- [x] 5.3 Add Vitest/Playwright coverage and documentation/tutorial content for the new workspace.
  - [x] 新增 Vitest Hook 覆盖 `useCollectorConfigs` 并扩展 EventsWorkspace 集成测试，确保 Respond/Collector 交互被单测覆盖。
  - [x] 引入 Playwright 配置与 `tests/e2e/eventsWorkspace.spec.ts` 场景（含时间线/Respond/Collector 表单路径），在 docs/events-workspace.md + operations-guide 中补充教程/操作手册。

## 6. Validation & Release
- [x] 6.1 Add Go integration tests for ETW/EBPF collectors, detection pipeline, and server ingestion; include perf baselines.
  - [x] `server/internal/eventing/integration_test.go` 组装 `Service + DetectionEngine + Scheduler + ThreatIntel`，模拟 ETW/EBPF 事件入库并校验 detection.alert/SSE/指标与 Threat Intel 调用链路。
  - [x] 同一测试内记录 200 条事件的 ingest 性能基线（平均耗时 <25ms/evt），并通过 `GOCACHE=/tmp/d-eyes-gocache go test ./internal/eventing -run TestIntegration` 运行以确保回归可重复。
- [x] 6.2 Document rollout/migration, feature flags, and operational runbooks; update README/docs + release notes.
- [x] 6.3 Run openspec validation + align tasks.md statuses before requesting proposal approval.
