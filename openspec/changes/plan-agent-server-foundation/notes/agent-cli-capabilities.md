# Agent CLI 能力梳理（里程碑 B1）

> 目的：确认现有 `agent/` 目录下命令行实现的能力与约束，指导后续“保留 CLI 独立模式，同时支持与 Server 联动”的改造工作。

## 1. 总体结构

- **入口**：`agent/d-eyes.go` ➜ 初始化日志/Logo，委托 `agent/internal.App`（urfave/cli）。
- **命令体系**：`agent/internal/app.go`
  - 基础子命令：`respond`、`audit`、`inventory`、`supplychain`、`baseline`（以及 `version`）。
  - 共享 Flag：`profile`、`output-dir`、`format`、`name`、`timeout`、`json`、`quiet`。
  - `RegisterCommand` 函数支持插件化追加 CLI 子命令（保留扩展点）。
- **任务执行核心**：`agent/internal/tasks/`
  - `TaskRunner` 接口、`TaskRequest`/`TaskResult` 结构体、通用执行流程 `Execute()`。
  - `ApplyDefaults()` 依据全局配置填充 Profile、输出目录、格式、超时等。
  - 各子命令 Runner（例如 `RespondRunner`、`BaselineRunner`）封装在独立文件中。
- **配置系统**：`agent/pkg/config`
  - 默认路径 `~/.d-eyes/config.yaml`，可通过 `--config` 或 `D_EYES_CONFIG` 覆盖。
  - 配置项涵盖输出、策略（`policy.fail_on`）、性能（超时/速率）等。
- **报告系统**：`agent/pkg/reporting`
  - `reporting.Manager` 提供输出目录管理与多格式写入。
  - 支持 JSON 摘要、HTML/Excel 等多种结果格式。

## 2. 任务能力概览

| 命令 | 目标场景 | 主要模块依赖 | 关键输出 |
| ---- | -------- | ------------ | -------- |
| `respond` | 应急响应、入侵排查 | `internal/detect/*`、YARA 规则、主机信息采集 | 文件扫描结果、网络连接、会话记录 |
| `audit` | 合规审计 | 复用基线检查，追加账号/系统信息采集 | 审计报告、整改建议 |
| `inventory` | 主机/端口资产梳理 | `internal/assets/*`，支持服务指纹 | 资产列表、端口服务指纹 |
| `supplychain` | SBOM 生成或依赖采集 | `internal/sbom/*`（语言子模块） | 组件清单、风险计数 |
| `baseline` | 系统/中间件基线评估 | `internal/benchmark/*` | 基线风险统计、细项评分 |

### 可复用特性
- 所有任务遵循统一 `TaskRunner` & `TaskRequest` 规范，可在 Server 模式下直接构造请求。
- 输出集中由 `reporting.Manager` 控制，可替换输出目录或挂接到远程存储。
- `TaskResult` 提供风险计数、附加提示，便于 Server 端再封装。

### 当前约束
- **权限**：多数检测依赖本地高权限（root/管理员），需保留 CLI 模式供人工执行；Server 联动时需考虑权限获取策略。
- **环境依赖**：YARA 规则、基线配置、资产指纹等均随仓库发布，需要打包或远程同步。
- **运行方式**：CLI 通过标准输出展示进度/提示（`quiet`/`json` Flag 可抑制输出）；在 Server 模式应默认静默。
- **资源控制**：`TaskRequest.Timeout` / 配置中的 `performance.rate` 控制执行时间与速率，适合同步复用。
- **状态存储**：目前无统一的任务状态持久化，结果依赖文件输出；与 Server 集成时需转为结构化上报。

## 3. CLI 模式 vs. Server 联动需求

| 维度 | CLI 模式 | Server 联动思路 |
| ---- | -------- | ---------------- |
| 调度 | 用户手动执行命令 | Server 通过 gRPC 下发任务 ➜ Agent 构造 `TaskRequest` 触发 Runner |
| 配置 | 本地 `config.yaml` | 优先使用远程下发参数，保留本地默认作为 fallback |
| 输出 | 本地目录 + 终端 | 收集 `TaskResult` + 报告文件，回传 Server / 上传对象存储 |
| 权限 | 用户自行保证 | Agent 进程需以足够权限运行，或在任务执行前检测并反馈 |
| 扩展 | `RegisterCommand` | 可用于加载定制 Runner（插件体系保持可用） |

## 4. 里程碑 B 后续建议

1. **B2/B3**：按 `TaskRequest` 接口实现 Agent gRPC 客户端，将 Server 下发参数直接映射。
2. **B4**：设计任务本地缓存（BoltDB/文件）存储待上报结果，确保断线重试。
3. **B5**：提炼 `TaskRequest`/`TaskResult` 为共享模型（单独包），供 CLI & Server/Agent 共用。
4. **B6**：梳理 `RegisterCommand`、Runner 工厂，定义最小插件生命周期与依赖注入。
5. **B7**：构建 CLI 基线测试（回归命令行） + Agent 联动测试（调用 gRPC Runner）。

本文件后续可作为 Agent 重构的参考基线，确保在保持 CLI 独立能力的同时，为 Server 联动提供清晰的技术接口。
