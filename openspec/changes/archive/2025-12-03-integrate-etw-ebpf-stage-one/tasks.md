## 1. Collector 框架
- [x] 1.1 设计 `EventCollector` / `SystemEvent` 接口，增设 `collector.Manager` 管理多平台生命周期。
- [x] 1.2 定义 CLI & Probe 共用配置 schema（Provider/Probe、过滤、采样、输出），接入 agent 配置加载流程。
- [x] 1.3 在 CLI `deyes collect` 与 Probe 初始化流程中读取 Collector 配置，调用 `collector.Manager` 完成实例化/启停，并提供状态查询/错误回退。

## 2. Windows ETW 实现
- [x] 2.1 搭建 ETW Session（StartTrace/ControlTrace）与 RingBuffer 读写，支持多 Provider。
- [x] 2.2 实现事件解析、动态过滤、性能指标采集，并接入 CLI `deyes collect --backend=etw`。
- [x] 2.3 在 Probe 模式集成配置热更新、状态上报与错误恢复，编写 Windows 集成/性能测试。
- [x] 2.4 打通 ETW 事件 ring buffer → `collector.EventHandler` 路径，提供 CLI/Probe 输出通道与丢包/延迟指标。
- [x] 2.5 编写 Windows 平台集成/性能测试与脚本，验证多 Provider 负载下的延迟/丢包指标，并纳入 CI/手动回归。

## 3. Linux eBPF 实现
- [x] 3.1 使用 `cilium/ebpf` + CO-RE 构建 syscall/进程等基础探针，处理内核兼容校验。
- [x] 3.2 实现 ringbuffer/perf buffer 消费、采样率控制、CLI `deyes collect --backend=ebpf`。
- [x] 3.3 在 Probe 模式接入动态配置、状态遥测，并完成 Linux 集成/性能/降级测试。

## 4. 数据通路与 Server 能力
- [x] 4.1 Agent 事件管道接入 telemetry/gRPC 通道，提供 backpressure 与本地缓存策略。
- [x] 4.2 Server 实现 `/events/ingest` API、存储/队列、仪表盘指标，并校验性能/一致性。
  - 新增 `EventsHandler` + `eventing.Service`，提供带背压的 `/api/v1/events/ingest`，内置批量持久化、MaxBytes 限流、队列深度/时延指标，并将事件落地 `system_events` 表用于后续消费，队列饱和时返回 429。
- [x] 4.3 打通配置下发与状态汇报（REST/SSE），支持启停/过滤/采样率下发。
  - 新增 `CollectorHandler` + `collectorctrl.Hub`，提供 `/api/v1/collector/configs`（配置下发）与 `/api/v1/collector/status`（Agent 状态上报 / SSE 订阅），配置与状态分别持久化到 `collector_configs`、`collector_statuses`，并支持版本自增、APIs 返回最新快照，SSE 将状态流式推送给 UI/运维。
- [x] 4.4 在 CLI/Probe 中支持 file/stdout/stream 等输出后端与错误上报机制，并将 `collector.EventHandler` 与遥测/上传通道打通，确保事件可靠送达。

## 5. 运维与文档
- [x] 5.1 输出权限/安装/CLI 指南，覆盖 Windows 管理员、Linux CAP_BPF 要求。
- [x] 5.2 构建 Collector 诊断日志、健康检查，形成阶段验收与性能报告。
