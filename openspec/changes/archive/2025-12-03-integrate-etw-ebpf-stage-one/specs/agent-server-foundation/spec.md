## ADDED Requirements

### Requirement: Cross-platform System Event Collectors
Agent MUST 实现统一的 `EventCollector` 接口，以 Windows ETW 与 Linux eBPF 为底座采集核心系统事件（进程、文件、注册表、系统调用），并将事件格式化为 `SystemEvent{timestamp,event_type,source,payload,metadata}` 输送到现有 telemetry 通道。

#### Scenario: CLI capture session
- **WHEN** 操作者在受管节点运行 `deyes collect --backend=etw --providers=Kernel,Security --duration=300s --output=events.json`
- **THEN** Agent 启动短时 ETW 会话，按配置 Provider/过滤条件写入 JSONL/STDOUT，结束后清理会话与缓冲，并在失败时输出明确诊断

#### Scenario: Probe streaming session
- **GIVEN** Agent 以常驻模式运行在 Linux 节点并接收启用 eBPF 的配置（采样率、探针列表）
- **WHEN** `collector.Manager` 装配 `ebpfCollector`、加载 CO-RE 程序并把 ringbuffer 中的事件转换成 `SystemEvent`
- **THEN** 事件将通过 Agent telemetry/gRPC 通道实时上传，遇到 backpressure 时需启用本地缓存/丢弃策略并上报状态

#### Scenario: Performance guardrails
- **WHEN** 任一 Collector 处于运行状态
- **THEN** Agent 需持续采样 CPU、内存、丢包率，确保采集开销维持在 CPU<5%、内存<100 MB、事件延迟<100 ms，并在超过阈值时降低采样率或暂停会话并记录告警

### Requirement: Collector configuration and telemetry
Agent MUST 支持 CLI 与 Probe 双模式下的统一配置 schema（Provider/Probe、过滤、采样率、输出），能够动态应用 Server 下发的启停/过滤变更，并回传 Collector 状态与诊断日志。

#### Scenario: CLI configuration schema
- **WHEN** CLI 使用 `--config=collector.yaml` 指定 Provider/Probe、过滤字段、输出目标
- **THEN** Agent 解析并验证 schema（含权限检测、平台兼容性），在运行期间提供 `Ctrl+C` 安全退出与进度统计

#### Scenario: Probe dynamic reconfiguration
- **GIVEN** Server 通过配置通道下发“启用 Windows Sysmon Provider + 过滤 PID=1234”
- **WHEN** Agent 收到指令
- **THEN** 需在 60 秒内应用变更（必要时重建 Session/Probe）、保留队列中的在途事件，并把状态（启用的 Provider、采样率、缓冲水位）写入心跳/遥测

#### Scenario: Failure reporting
- **WHEN** Collector 因权限不足、内核不兼容或缓冲溢出而退出
- **THEN** Agent MUST 记录可诊断日志、在心跳中报告 `collector_status=degraded` 与错误详情，并提供 CLI/Probe 级别的退出码或告警，避免 silent failure
