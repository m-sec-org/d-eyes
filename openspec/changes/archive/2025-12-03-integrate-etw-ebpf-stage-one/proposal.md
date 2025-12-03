## Why
- 新阶段需要在 Windows/Linux 上引入统一的系统事件采集能力，支撑后续高级监控/异常检测工作流。
- 现有 Agent/Server 规范仅覆盖任务调度与威胁情报流程，缺少 ETW/eBPF Collector、事件摄取 API 与动态配置等契约。

## What Changes
- 为 Agent 规范补充跨平台 `EventCollector` 接口、ETW/eBPF 集成、CLI 与 Probe 双模式、性能/监控指标等要求。
- 为 Server 规范新增事件摄取 API、Collector 配置下发、状态遥测与持久化队列要求。
- 规划阶段性任务：框架搭建、平台实现、数据通路、配置/文档等。

## Impact
- 受影响 specs：`agent-server-foundation`、`server-core`
- 关联代码：agent CLI/daemon、collector 管理器、server events API/队列、配置分发、监控指标
