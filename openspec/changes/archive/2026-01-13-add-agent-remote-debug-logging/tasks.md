## 1. Implementation
- [x] 1.1 设计并实现 Remote debug 日志格式（可过滤/可关联/可去敏）
- [x] 1.2 在 gRPC 链路增加 debug 事件：Connect/Register/Heartbeat/PullTasks/ReportResult（含耗时与错误）
- [x] 1.3 在任务执行链路增加 debug 事件：租约解析、参数合并、runner 开始/结束、exit_code/error_code、回传结果
- [x] 1.4 在 HTTP 上传链路增加 debug 事件：events ingest 与 artifacts presign/upload（仅输出 method/path/status/latency，去敏）
- [x] 1.5 增加单测：debug 开启时包含 task_id/lease_id；并断言不泄漏 `agent_token`/`X-API-Key`
- [x] 1.6 更新文档：说明如何启用 remote debug、日志位置/重定向示例、常见排障字段
