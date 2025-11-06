## 里程碑 A：Server 能力交付（已验证）
- [x] A1. 建立 `cmd/server` 入口与 `internal/` 分层结构（配置、启动、依赖注入）
- [x] A2. 实现 Agent 注册/心跳 gRPC 接口与任务调度 REST API
- [x] A3. 集成 PostgreSQL/Redis 数据层与迁移脚本，提供 Docker Compose 示例
- [x] A4. 编写端到端集成测试（gRPC Register/Pull/Report + REST 查询），并在 README/开发指南中记录运行方式
- [x] A5. 补充负载与可靠性基准脚本、监控指标草案（新增 `tools/loadtest` 脚本、`docs/OBSERVABILITY.md` 指标草案 与 `docs/LOADTEST.md` 使用说明）

> 说明：A1-A4 已通过归档交付 `2025-11-04-add-server-core-modules` 验证，后续针对负载评估（A5）仍需补充。

## 里程碑 B：Agent/通用能力落地（进行中）
- [x] B1. 保留 CLI 独立模式，梳理现有 `agent/` 下命令行功能的核心能力与约束（详见 `notes/agent-cli-capabilities.md`）
- [x] B2. 建立 `cmd/agent` 与 `internal/agent` 结构，抽象配置、模块化执行入口（新增 `internal/agent/runtime` 与 `cmd/agent/main.go`，便于复用 CLI 实例与嵌入模式）
- [x] B3. 实现与 Server 的 gRPC 连接（注册、心跳、任务订阅）、身份认证与失败重连策略（`internal/agent/daemon.go` 集成远程客户端、心跳与重连循环）
- [x] B4. 集成任务消费循环与结果回传，复用 CLI 现有扫描/响应逻辑；设计本地缓存与失败重试（新增 `remote.FileStore` 以文件缓存结果，远程守护程序调用 `tasks.ExecuteWithResult` 实际执行与回传）
- [x] B5. 抽象任务描述与结果模型，统一 CLI、Agent、Server 数据结构；重构报告与策略评估逻辑，支持双模式（新增共享模型 `internal/model/task.go`、`tasks.ToExecutionResult` 以及 `specs/shared/task-model.json`，远程模式回传结构与 Server 拉取模型对齐）
- [x] B6. 设计最小插件扩展点，支持任务执行模块注册；为 Agent 开发者补充指南（新增任务、调试流程）（`internal/app` 暴露 `AttachCommand`、`TaskRunnerByName`；新增 `docs/PLUGIN_GUIDE.md`）
- [x] B7. 构建联合测试矩阵：包含 CLI 单机、Agent-Server 联动、以及 Agent 端专用集成测试；完善上线评审材料与回滚方案（详见 `notes/test-plan.md` 与 `notes/rollout-checklist.md`）
