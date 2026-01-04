# D-Eyes Agent —— 多场景安全检测与响应工具

D-Eyes Agent 是 D-Eyes 安全平台的核心执行组件，由 M-SEC 社区驱动，提供面向安全响应、合规审计、资产梳理以及供应链安全的多场景检测能力。项目采用 Go 语言实现，关注可移植性与可扩展性，通过统一的任务式命令行体验帮助安全工程师快速落地各类检查流程。Agent 既可独立运行执行单机检测任务，也可与 D-Eyes Server 协同工作，支持分布式任务调度与管理。

## 功能概述

Agent 作为 D-Eyes 平台的执行引擎，负责安全检测任务的实际运行与结果收集，具备以下核心能力：

- **多场景安全检测**：提供应急响应、基线检查、合规审计、资产梳理、供应链安全五大核心任务场景
- **统一的任务执行框架**：所有任务共享配置加载、报告生成、风险评估等基础设施
- **插件化架构**：支持通过插件机制扩展检测能力，如自定义 YARA 规则和检测模块
- **分布式执行支持**：可与 Server 端协同，支持大规模环境下的任务分发与集中管理
- **离线工作能力**：支持断线重连和结果缓存，保证任务可靠执行

## 能力特性

### 1. 应急响应 (respond)

应急响应模块提供面向安全事件的快速排查能力，帮助用户在安全事件发生时快速定位问题。

- **主机概要分析**：收集主机基本信息、运行进程、启动项等数据
- **文件扫描**：基于 YARA 规则扫描可疑文件，支持常见恶意软件检测
- **网络连接分析**：检测异常网络连接、可疑端口和未授权通信
- **用户会话审计**：检查异常登录和可疑用户活动

支持多种检测模式，包括快速检查、勒索软件检测和持久化检查。

### 2. 基线检查 (baseline)

基线检查模块用于评估系统配置是否符合安全最佳实践，识别潜在的安全漏洞和配置缺陷。

- **操作系统基线**：检查系统安全配置、用户权限、密码策略等
- **数据库基线**：评估数据库安全配置、访问控制和审计设置
- **中间件基线**：检查 Web 服务器、应用服务器等中间件的安全配置

可按范围选择检查内容，支持操作系统、数据库或全量基线检查。

### 3. 合规审计 (audit)

合规审计模块整合基线检查结果、主机信息和用户会话数据，生成全面的合规审计报告。

- **自动基线执行**：自动运行相关基线检查项
- **主机信息汇总**：收集和整理主机关键信息
- **用户会话分析**：识别异常用户活动和权限问题
- **合规报告生成**：提供符合合规要求的详细报告和整改建议

### 4. 资产梳理 (inventory)

资产梳理模块用于发现和管理网络环境中的各类资产，帮助用户全面了解网络资产情况。

- **主机发现**：基于 ICMP、ARP、TCP SYN 等多种方式探测主机存活状态
- **端口扫描**：扫描目标主机的开放端口，支持自定义端口范围
- **服务识别**：识别开放端口上运行的服务及其版本信息
- **操作系统指纹识别**：通过多种特征推断目标主机的操作系统类型
- **网络自动发现**：自动识别本地网络并探测周边主机

支持快速模式、深度模式和隐蔽模式三种扫描策略。

### 5. 供应链安全 (supplychain)

供应链安全模块用于生成软件物料清单(SBOM)，分析第三方组件依赖风险。

- **多语言支持**：识别常见编程语言的依赖文件（package.json、requirements.txt、go.mod、pom.xml 等）
- **SBOM 生成**：生成符合 CycloneDX 标准的软件物料清单
- **环境捕获**：捕获当前运行环境中的已安装包信息
- **多格式输出**：支持 JSON、XML 等多种格式的 SBOM 输出

支持从源代码生成 SBOM 和捕获当前环境两种运行模式。

### 6. 入侵分析检测 (detect)

`detect` 是面向入侵分析的插件化子命令集合，内置了 YARA 扫描、后端诊断与（Windows）进程内存扫描能力：

- **YARA 后端双栈**：支持 `auto/native/portable`；默认 `auto` 优先 native（需 `-tags yara_native` + libyara），不可用时显式回退 portable 并暴露回退原因。
- **诊断命令**：`d-eyes detect diag --backend auto` 输出当前后端、规则版本、覆盖率、缺失家族与 `fallback_reason`，便于 CI/排障。
- **文件/进程扫描**：`detect filescan`、`detect processcan` 扫描文件/进程可执行文件内容，并统一输出 backend/coverage 摘要。
- **进程内存扫描（Windows）**：`d-eyes detect memscan` 读取进程内存 region（默认 RWX），支持 `--pid/--all`、限额（`--max-bytes/--max-regions/--timeout`），并可选启用证据保全（`--evidence`/`--minidump`，默认关闭）。

### 7. 检测插件系统

检测插件系统采用插件化架构设计，支持灵活扩展检测能力。

- **插件接口标准化**：提供统一的插件接口，便于开发自定义检测插件
- **子命令注册机制**：支持向 detect 命令注册子命令
- **多样检测能力**：可扩展支持各种检测场景，如恶意代码检测、异常行为分析等

### 8. 分布式管理能力

Agent 可与 D-Eyes Server 协同工作，支持分布式任务执行与管理。

- **自动注册与心跳**：向 Server 自动注册并保持心跳连接
- **任务自动拉取**：定期从 Server 拉取待执行任务
- **结果回传**：将任务执行结果上传至 Server
- **离线缓存**：支持断线重连和结果缓存，保证任务可靠执行

## 运行要求

- **Windows**：以管理员身份运行命令提示符 / PowerShell
- **Linux**：建议 root 或具备等效权限的账号
- **macOS**：执行基线检查时需管理员权限

## 全局配置

默认配置文件位于 `~/.d-eyes/config.yaml`（亦可通过 `--config` 或环境变量 `D_EYES_CONFIG` 指定）。示例：

```yaml
output:
  dir: ~/d-eyes/reports
  format: json
ui:
  color: true
logging:
  verbose: false
policy:
  fail_on: high
  severity_min: medium
performance:
  timeout: 600s
  rate: 200
```

命令行参数优先级高于配置文件，配置用于提供默认值以及策略控制（例如风险超阈值时的退出码）。

## 命令概览

| 命令 | 分类 | 必填参数（无默认时） | 默认 profile | 主要能力 |
|------|------|----------------------|--------------|----------|
| `respond` | Operations | `--targets` 或 `config.tasks.respond.targets` | 来自 `config.tasks.respond.profile`（默认 `default/quick`） | 主机概要、文件扫描、网络连接、用户会话等组合模块 |
| `detect` | Operations | 视子命令而定（如 `memscan` 需 `--pid`/`--all`） | - | 入侵分析检测：YARA 扫描、后端诊断、（Windows）内存扫描 |
| `audit` | Operations | 无（可通过 `config.tasks.audit.*` 设定范围） | `config.tasks.audit.scope`（默认 `system`） | 合规审计：基线结果 + 主机信息 + 账号会话汇总 |
| `inventory` | Operations | `--targets`, `config.tasks.inventory.targets` 或 `config.discovery.targets` | `config.tasks.inventory.profile`（默认 `fast`/`deep`） | 主机发现、端口扫描、服务识别、OS 指纹 |
| `supplychain` | Operations | `--path` / `--file` 或 `config.tasks.supplychain.paths|file` | `config.tasks.supplychain.mode`（默认 `generate`） | SBOM 生成或运行环境采集 |
| `baseline` | Operations | `--baseline-config` 或 `config.tasks.baseline.config` | `config.tasks.baseline.scope`（默认 `all`） | 系统/数据库/中间件基线评估 |
| `bas` | Operations | 场景来源（`--scenario-id/--scenario/--scenario-file`） | `default` | BAS 攻击模拟（可选沙箱、审计与遥测） |
| `action` | Automation | 无 | - | 执行来自 Server 的响应动作（占位任务） |
| `remote` | Integration | `remote.enabled=true` 且 Server 参数完整 | - | 连接 Server、任务拉取、结果回传，自动静默执行 |
| `version` | Integration | 无 | - | 输出版本号与运行平台信息 |

### 远程模式

`remote` 命令会根据 `config.yaml` 中的 `remote` 配置连接 D-Eyes Server，自动完成注册、心跳、任务拉取和结果回传：

```bash
d-eyes remote
```

核心配置示例：

```yaml
remote:
  enabled: true
  server_grpc_addr: 127.0.0.1:9090
  agent_token: changeme
  agent_name: edge-node-01
  heartbeat_interval: 10s
  task_poll_interval: 2s
  cache_dir: ~/.d-eyes/cache
  labels:
    network_boundary: dmz
    tenant: soc-blue
```

远程模式会将待回传结果写入本地缓存目录（默认 `~/.d-eyes/cache`），断线后自动重试。执行链路与 CLI 完全复用同一套 `TaskRunner`/`TaskRequest` 规范，区别在于：

- 默认启用静默模式（`--quiet`）并强制输出 JSON 摘要，方便 Server 解析。
- 任务参数映射与 CLI Flag 一致，Server 只需在 `payload.flags.*` 中填入对应的命令行参数即可。

所有任务命令共享以下 Flags：

- `--profile`：选择预设流程（默认为 `default`）
- `--output-dir`：报告输出目录
- `--format`：报告格式（如 `json`、`html` 等）
- `--name`：自定义任务名称前缀
- `--timeout`：任务超时时间
- `--json`：在终端输出任务摘要的 JSON 结构
- `--quiet`：静默模式，仅生成报告文件
- `--debug`：启用调试事件输出（亦可通过 `DEYES_DEBUG=1` 指定）
- `--ti-mode`：威胁情报模式：`auto` / `local` / `hybrid` / `server`（亦可通过 `D_EYES_TI_MODE` 指定）

> **提示**：全局 Flags 在 v1.4 之后统一提升到顶层命令。若某 Flag 未在 CLI 中显式传入，会从 `config.yaml` 的对应字段（如 `config.tasks.*`、`config.output` 等）回落获取默认值。

## 入侵检测 `detect`

```bash
# 诊断 YARA 后端与规则覆盖率（CI/排障优先）
d-eyes detect diag --backend auto

# Windows：扫描指定 PID 的进程内存（默认 RWX-only；显式触发）
d-eyes detect memscan --pid 1234 --backend auto
```

## 应急响应 `respond`

```bash
# 快速排查常见异常
 d-eyes respond --profile quick --targets /var/log,/tmp

# 勒索软件场景，含文件扫描与网络分析
 d-eyes respond --profile ransomware --targets /opt/app --json
```

Profile 说明：
- `quick`/`default`：主机概要 + 网络连接
- `ransomware`：文件扫描 + 网络分析 + 主机概要
- `persistence`：网络连接 + 用户会话 + 主机概要

输出文件示例：
- `respond/host-summary.json`
- `respond/filescan.json`
- `respond/network.json`

## 基线检查 `baseline`

```bash
# 针对操作系统维度
 d-eyes baseline --scope os --format html

# 全量基线并启用 JSON 摘要
 d-eyes baseline --scope all --baseline-config ./benchmark.yaml --json
```

执行结束会在 `baseline/` 目录生成基线报告，并依据 `policy.fail_on` 判断退出码。

## 合规审计 `audit`

```bash
# 标准合规流程
 d-eyes audit --profile compliance --output-dir ./reports

# 静默生成审计报告
 d-eyes audit --quiet --profile compliance
```

审计任务会自动运行基线检查并汇总主机信息、用户会话等内容，输出 `audit/*-summary.json`。

## 资产梳理 `inventory`

```bash
# 快速发现内网主机
 d-eyes inventory --profile fast --targets 10.0.0.0/24

# 深度扫描并识别服务
 d-eyes inventory --profile deep --targets 192.168.1.10,192.168.1.11 --service-detect --os-detect
```

Profile 说明：
- `fast`：常见端口扫描，适合快速盘点
- `deep`：全端口扫描 + 服务指纹
- `stealth`：低速扫描，降低嗅探风险

每个目标会生成独立报告，`inventory/*-summary.json` 给出总体统计。

## 供应链安全 `supplychain`

```bash
# 扫描目录生成 SBOM
 d-eyes supplychain --mode generate --path ./service --type json

# 捕获当前环境（pip list）
 d-eyes supplychain --mode capture --json
```

支持识别常见依赖清单（`package.json`、`requirements.txt`、`go.mod`、`pom.xml` 等），输出组件列表与计数。

## 退出码约定

| 退出码 | 含义 |
|--------|------|
| 0 | 成功完成 |
| 1 | 满足策略阈值（如 `policy.fail_on`） |
| 2 | 任务执行失败（参数错误、模块错误等） |
| 3 | 上下文取消或未知错误 |

## 迁移说明（v1.3 → v1.4 CLI）

为便于旧版本用户升级，以下变更需要重点关注：

- **全局 Flag 位置调整**：`--profile`、`--output-dir`、`--format`、`--name`、`--timeout`、`--json`、`--quiet` 等参数均提升为顶层全局 Flag，命令行语法统一为 `d-eyes [global] <command> [command options]`。
- **参数校验更严格**：各模块会在执行前校验必填参数（如 `inventory` 的 `--targets`、`supplychain` 的 `--path/--file`、`baseline` 的配置文件）。如遗漏参数将返回退出码 `64` 并提示对应配置项。
- **配置回落能力增强**：`config.tasks.*` 与 `config.discovery.targets` 提供 CLI 缺省值；当命令行未显式传参时，将自动填写并在非静默模式下打印 Notice。
- **远程模式输出统一**：Server 下发任务使用与 CLI 相同的 Flag 名称，Agent 默认启用静默模式并强制输出 JSON 摘要，便于 Server 侧收集。

升级步骤建议：
1. 按新格式更新 `config.yaml` 中的 `tasks.*` 与 `discovery.targets`，为常用命令提供缺省值。
2. 若存在自动化脚本，确认是否需要将旧的子命令级别 Flag 调整到全局位置。
3. 使用 `d-eyes --help` 查看新的命令矩阵，确认远程任务配置与 CLI 一致。

## 代码结构

Agent 采用清晰的模块化结构设计，代码组织如下：

- **cmd/agent/**：Agent 命令行入口
- **internal/**：内部实现，不对外暴露 API
  - **agent/**：Agent 核心实现
  - **app.go**：主应用程序入口和命令注册
  - **assets/**：资产探测模块
  - **benchmark/**：基准测试相关代码
  - **detect/**：检测模块实现
  - **model/**：数据模型定义
  - **sbom/**：SBOM 生成模块
  - **tasks/**：任务执行框架
  - **utils/**：工具函数
- **pkg/**：公共包，可被外部使用
  - **color/**：控制台颜色输出
  - **config/**：配置管理
  - **logs/**：日志功能
  - **reporting/**：报告生成
- **yaraRules/**：YARA 规则文件，用于恶意软件检测

## 开发与贡献

- 代码位于 `internal/` 和 `pkg/` 目录，任务逻辑集中在 `internal/tasks/`
- 插件开发指南：参见 `docs/PLUGIN_GUIDE.md`，了解如何注册自定义命令/Runner，并与远程模式联动
- 欢迎通过 Issue / PR 反馈需求或贡献模块
- 参考 `docs/` 目录中的设计文档与指南

### 覆盖率验证

- **远程链路 100%**：

  ```bash
  cd agent
  go test ./internal/agent/... ./internal/agent/remote/... \
    -covermode=count \
    -coverpkg=github.com/m-sec-org/d-eyes/agent/internal/agent,github.com/m-sec-org/d-eyes/agent/internal/agent/remote \
    -coverprofile=coverage-agent-remote.out

  go tool cover -func coverage-agent-remote.out | tail -n 1
  ```

  输出末行需为 `total: ... 100.0%`，否则补齐缺失用例。

- **CLI 覆盖率**（respond/audit/inventory/supplychain/baseline/bas/remote）：

  ```bash
  cd agent
  go test ./internal/agent \
    -run CLI \
    -covermode=count \
    -coverpkg=github.com/m-sec-org/d-eyes/agent/internal/agent \
    -coverprofile=coverage-agent-cli.out

  go tool cover -func coverage-agent-cli.out | tail -n 1
  ```

  确认 `total` 行为 100%，以防 CLI 命令与远程模式出现偏差。

- **核心任务 / 检测模块**（tasks、threatintel、检测后端）：

  ```bash
  cd agent
  go test ./internal/tasks ./pkg/threatintel ./internal/detect/backend ./internal/detect/engine/goengine/... \
    -covermode=count \
    -coverpkg=github.com/m-sec-org/d-eyes/agent/internal/tasks,github.com/m-sec-org/d-eyes/agent/pkg/threatintel,github.com/m-sec-org/d-eyes/agent/internal/detect/backend,github.com/m-sec-org/d-eyes/agent/internal/detect/engine/goengine,github.com/m-sec-org/d-eyes/agent/internal/detect/engine/goengine/metadata \
    -coverprofile=coverage-core.out

  go tool cover -func coverage-core.out | tail -n 1
  ```

  该命令确保任务 Runner、威胁情报、YARA 纯 Go 引擎均保持 100% 覆盖，提交前务必通过。

## 相关文档

- [插件开发指南](docs/PLUGIN_GUIDE.md)：了解如何开发自定义检测插件
- [编译指南](../docs/编译指南.md)：Agent 编译和部署说明
- [应急响应插件编写](../docs/应急响应-插件编写.md)：应急响应插件开发指南

## 许可证

项目采用开源许可证，详见 [LICENSE](../LICENSE)。

- **核心覆盖率**（tasks + threatintel + detect + assets/sbom + CLI）：

  ```bash
  cd agent
  go test ./... -coverpkg=./... -coverprofile=coverage-full.out
  go tool cover -func coverage-full.out | tail -n 1
  ```

  确保 `total` 行显示 100%，并在 CI 中强制执行上述命令。
