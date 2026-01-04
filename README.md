# D-Eyes - 综合性安全检测与响应平台

## 1. 工具概述

D-Eyes是一款由M-SEC社区驱动的综合性安全检测与响应工具，提供面向安全响应、合规审计、资产梳理以及供应链安全的多场景能力。项目采用Go语言实现，关注可移植性与可扩展性，通过统一的任务式命令行体验帮助安全工程师快速落地各类检查流程。

### 1.1 应用场景

- **安全应急响应**：在安全事件发生时快速排查系统异常，识别恶意文件、可疑网络连接和异常进程
- **安全基线检查**：评估系统、数据库、中间件等配置是否符合安全基线要求
- **合规审计**：为满足行业合规要求提供审计报告和整改建议
- **资产梳理与管理**：发现和管理网络环境中的各类资产，包括主机、端口和服务
- **供应链安全分析**：生成软件物料清单(SBOM)，分析第三方组件依赖风险
- **入侵和攻击模拟(BAS)**：主动模拟各类攻击场景，评估防御能力和检测有效性
- **分布式安全管理**：通过Server-Agent架构实现大规模环境的集中安全管理

### 1.2 核心能力

- **多场景任务支持**：提供 `respond`、`detect`、`baseline`、`audit`、`inventory`、`supplychain`、`bas` 等任务入口，覆盖主流安全检测场景
- **统一的执行框架**：所有任务复用全局配置、报告管理器与风险策略，提供一致的使用体验
- **强大的插件系统**：支持通过插件机制扩展功能，如检测插件、SBOM语言支持等
- **多平台兼容**：核心能力覆盖Linux、Windows、macOS等主流操作系统
- **分布式架构**：支持Agent-Server模式，可实现大规模环境的集中管理与分布式执行
- **丰富的YARA规则**：内置大量恶意软件检测规则，支持 `portable/native` 双后端（`auto` 优先 native、不可用显式回退），覆盖勒索软件、挖矿程序等多种威胁检测
- **文件less/注入类补充**：Windows 下支持进程内存扫描（`d-eyes detect memscan`，默认 RWX 聚焦与限额保护；证据保全默认关闭）
- **自动化攻击模拟**：提供可控的攻击链模拟能力，主动验证安全防护有效性

### 1.3 产品优势

- **全方位安全覆盖**：从资产发现、基线检查到入侵检测、攻击模拟，提供完整安全评估体系
- **主动防御验证**：通过BAS能力主动模拟攻击场景，验证防御有效性，而非仅被动检测
- **高度可扩展架构**：模块化设计与插件系统相结合，支持快速定制和功能扩展
- **轻量高效部署**：单机部署快速启动，分布式架构支持大规模环境管理
- **一体化安全视图**：整合多源安全数据，提供统一的安全态势感知
- **灵活的报告机制**：支持多格式输出，便于自动化集成和安全流程对接
- **开源社区生态**：持续更新的规则库和功能模块，保持对最新威胁的响应能力

## 2. Agent 核心能力

D-Eyes Agent 以 `agent/internal/app.go` 中的 CLI 框架为中心，所有任务共享统一的配置加载、报告管理、威胁情报和沙箱控制逻辑。CLI 与 `remote` 守护进程共用 Runner、Collector、缓存和遥测能力，可在本地一次性执行与 Server 下发模式间自由切换。

威胁情报支持 `--ti-mode auto/local/hybrid/server`：`hybrid` 可在配置 API Key 后直连 OpenTIP/MetaDefender，遇到无 Key、限额（429）或 Provider 异常时会自动退化为 local，并输出稳定的 `threatintel.*` 元数据用于 CI/排障；`server` 模式下仅上传 artifacts/token 交由 Server orchestrator 统一编排。

### 2.1 应急响应 (respond)

应急响应模块提供面向安全事件的快速排查能力，帮助用户在安全事件发生时快速定位问题。

- **主机概要分析**：收集主机基本信息、运行进程、启动项等数据
- **文件扫描**：基于YARA规则扫描可疑文件，支持常见恶意软件检测
- **网络连接分析**：检测异常网络连接、可疑端口和未授权通信
- **用户会话审计**：检查异常登录和可疑用户活动

**支持的执行模式**：
- `quick`：快速模式，主机概要+网络连接检查
- `ransomware`：勒索软件检测模式，文件扫描+网络分析+主机概要
- `persistence`：持久化检查模式，网络连接+用户会话+主机概要

### 2.2 基线检查 (baseline)

基线检查模块用于评估系统配置是否符合安全最佳实践，识别潜在的安全漏洞和配置缺陷。

- **操作系统基线**：检查系统安全配置、用户权限、密码策略等
- **数据库基线**：评估数据库安全配置、访问控制和审计设置
- **中间件基线**：检查Web服务器、应用服务器等中间件的安全配置

**支持的检查范围**：
- `os`：操作系统维度检查
- `db`：数据库维度检查
- `all`：全量基线检查

### 2.3 合规审计 (audit)

合规审计模块整合基线检查结果、主机信息和用户会话数据，生成全面的合规审计报告。

- **自动基线执行**：自动运行相关基线检查项
- **主机信息汇总**：收集和整理主机关键信息
- **用户会话分析**：识别异常用户活动和权限问题
- **合规报告生成**：提供符合合规要求的详细报告和整改建议

### 2.4 资产梳理 (inventory)

资产梳理模块用于发现和管理网络环境中的各类资产，帮助用户全面了解网络资产情况。

- **主机发现**：基于ICMP、ARP、TCP SYN等多种方式探测主机存活状态
- **端口扫描**：扫描目标主机的开放端口，支持自定义端口范围
- **服务识别**：识别开放端口上运行的服务及其版本信息
- **操作系统指纹识别**：通过多种特征推断目标主机的操作系统类型
- **网络自动发现**：自动识别本地网络并探测周边主机

**支持的扫描模式**：
- `fast`：快速模式，常见端口扫描，适合快速盘点
- `deep`：深度模式，全端口扫描+服务指纹识别
- `stealth`：隐蔽模式，低速扫描，降低嗅探风险

### 2.5 供应链安全 (supplychain)

供应链安全模块用于生成软件物料清单(SBOM)，分析第三方组件依赖风险。

- **多语言支持**：识别常见编程语言的依赖文件（package.json、requirements.txt、go.mod、pom.xml等）
- **SBOM生成**：生成符合CycloneDX标准的软件物料清单
- **环境捕获**：捕获当前运行环境中的已安装包信息
- **多格式输出**：支持JSON、XML等多种格式的SBOM输出

**支持的运行模式**：
- `generate`：从源代码或依赖文件生成SBOM
- `capture`：捕获当前运行环境的包信息

### 2.6 检测插件扩展 (detect)

检测插件系统采用插件化架构设计，支持灵活扩展检测能力。

- **插件接口标准化**：提供统一的插件接口，便于开发自定义检测插件
- **子命令注册机制**：支持向detect命令注册子命令
- **多样检测能力**：可扩展支持各种检测场景，如恶意代码检测、异常行为分析等
- **内置能力示例**：`detect diag`（YARA 后端/覆盖率诊断）、`detect filescan/processcan`（文件/进程扫描）、`detect memscan`（Windows 进程内存扫描，默认 RWX 聚焦与限额保护；`--evidence/--minidump` 默认关闭）

### 2.7 入侵和攻击模拟 (bas)

入侵和攻击模拟模块提供主动验证安全防御有效性的能力，通过模拟真实攻击场景，评估系统和网络的安全防护水平。

- **攻击链模拟**：支持完整攻击链的模拟，包括侦察、入侵、横向移动和持久化等阶段
- **漏洞利用验证**：验证已知漏洞的可利用性，评估系统实际安全风险
- **权限提升测试**：测试系统权限控制有效性，发现潜在的权限提升途径
- **防御检测绕过**：模拟高级威胁尝试绕过常见安全防御机制的行为
- **安全告警验证**：测试安全监控系统对各类攻击行为的检测能力

**支持的模拟类型**：
- `reconnaissance`：侦察阶段模拟，包括信息收集和目标发现
- `exploitation`：漏洞利用模拟，针对常见漏洞进行安全验证
- `privilege`：权限提升测试，评估权限控制有效性
- `lateral`：横向移动模拟，测试网络隔离和访问控制
- `persistence`：持久化机制测试，验证系统自防护能力
- 
### 2.8 操作系统事件采集分析 Collector

跨平台 Collector（Windows ETW、Linux eBPF）需要额外的系统权限与依赖，可参考《[Collector 安装与权限指南](docs/collector-installation-guide.md)》。Collector 管道支持：

- **多后端采集**：ETW Provider、eBPF Probe、文件/网络采样器通过 `collector.NewService` 统一管理。
- **过滤与抽样**：内建过滤引擎、采样规则、动态禁用/启用策略，支持按事件类型、标签与字段匹配。
- **检测回调**：Collector 命中规则后会将 `DetectionResult` 通过 DetectionSink 注入任务流水线，可配置自动 Respond、打标签或仅记录。
- **事件流导出**：所有事件写入 `eventstream.Pipeline`，既能排队上报 Server，也能在本地堆栈调试或落盘。

### 2.9 Agent-Server联动

D-Eyes 提供 Agent-Server 分布式架构，`agent/internal/agent/daemon.go` 的远程 Runner 负责：

- **注册与心跳**：Agent 启动后携带能力、标签向 Server 注册，实时上报负载、Collector 状态与遥测指标。
- **任务调度**：自动轮询 gRPC 任务租约，支持并发运行、优先级自适应和 BAS 沙箱标记，未识别任务会以失败结果回报。
- **断点续传**：本地 FileStore 缓存所有执行结果与工件，网络抖动时会自动补报并跟踪重试次数。
- **配置热更新**：守护进程附带配置文件 watch，远程模式下也能动态加载 Collector 与任务配置。
- **自动化联动**：Collector 检测可触发 Respond 任务，通过 `tasks.ExecuteWithResult` 直接复用 CLI 逻辑，保证在线与离线体验一致。

### 2.10 任务执行框架与扩展能力

- **Runner 工厂**：`agent/internal/app.go` 注册 respond/baseline/bas 等 Runner，可被测试或插件通过 `OverrideRunnerFactoryForTesting` 和 `TaskRunnerByName` 替换。
- **TaskRequest 统一参数**：`agent/internal/tasks/types.go` 负责配置默认值、Threat Intel 管理器、报告目录以及策略校验，所有命令复用同一套元数据字段。
- **威胁情报与沙箱注入**：`tasks.SetThreatIntelProvider`、`sandbox.SetControllerFactory`、`detect/rules.SetRuleEngineFactory` 支持在测试、企业定制或插件内替换底层实现。
- **结果缓存与策略控制**：`tasks.Execute` 默认启用资源采样、策略评估、JSON 摘要打印，并利用 `taskcache` 在 respond/inventory/supplychain 等任务中做去重与增量扫描。

### 2.11 遥测、情报与Artifact流水线

- **系统遥测**：`agent/internal/telemetry` 周期性采集 CPU、内存、IO 与任务资源，打入每次心跳及执行结果，Server 可直接复现现场。
- **Artifact 上传**：远程模式根据 `remote.ServerAPIBase` 自动创建 `artifacts.Client`，将报告/样本通过 `/api/v1/artifacts` 安全上传，再由 Server 统一入库或提交情报。
- **事件与情报桥接**：`event_uploader` 将 Collector 事件批量推送到 `/api/v1/events/ingest`，Server 的检测引擎、Playbook、威胁情报编排都以此为触发源。
- **调试时间线**：开启 `--debug`（或 `DEYES_DEBUG=1`）后，Runner、Collector 会把阶段/进度事件实时输出到 `stderr`，同时写入 `TaskResult.Metadata` 的 `telemetry.debug_*` 字段。远程 `ExecutionResult.metadata` 会携带同样的数据，便于 Server 端复盘；`collect` 命令还会在 `<output-dir>/collect/debug-timeline-*.json` 额外持久化时间线。

## 3. Server 核心能力

Server 端 (`server/internal/app`) 会在启动时初始化数据库存储、任务队列、调度器、事件服务、威胁情报、行为分析、Playbook 与 API。各模块之间通过 Hub/SSE、队列或存储解耦，便于水平扩展与压测。

### 3.1 调度与任务编排

- **多队列调度**：`scheduler.Scheduler` 将任务落盘在 PostgreSQL（或内存）后，再写入内存/Redis 队列，按 Agent 能力、标签、并发上限与 BAS 专属配额发放租约。
- **自愈与监控**：支持心跳超时判定、任务 Lease 续租、`ops/self-heal` 接口手动恢复，以及 Prometheus 监控 `TasksInFlight`、BAS 队列深度等指标。
- **结果写回**：`grpcsvc.Service` 负责接收执行摘要、工件与遥测，并驱动审计记录、威胁情报样本提交与行为图谱更新。
- **多租使用例**：BAS 场景管理器 (`internal/basscenarios`) 内置审批策略与资源上限，可按租户/网络边界缓存场景定义，支持跨 Agent 协同。

### 3.2 事件采集、检测与响应

- **优先级事件管道**：`internal/eventing.Service` 把 `/api/v1/events/ingest` 接收到的事件按优先级堆积、溢写与缓存，支持自定义溢出策略、告警与限流。
- **解析与保留**：可配置多种 Parser 插件/禁用列表，事件持久化后按租户、优先级和保留策略清理。
- **检测引擎**：`DetectionEngine` 支持规则匹配与轻量 ML 模型，命中后可以触发 Respond 任务、提交威胁情报、发送 SSE 告警并统计指标。
- **Collector 控制面**：`collectorctrl.Hub` 与 `/api/v1/collector` API 可实时查看 Agent 上的 Collector 运行、下发禁用或审批策略。

### 3.3 自动化、模板与扩展

- **Playbook 引擎**：`internal/playbook.Engine` 监听任务、行为、情报 Hub，支持按触发条件执行多步骤操作（如隔离、补采、BAS 触发），并可通过 API 手动执行。
- **任务模板/目录**：`templates.Manager` 与 `taskcatalog.Manager` 提供任务元数据、Profile 校验与版本化，方便 Ops/前端构建任务向导。
- **插件生命周期**：`internal/plugins.Manager` 维护插件 Manifest、回滚历史和 SSE 事件，可配合 Server API 进行安装、回退与准入审查。
- **报告中心**：`reporttemplates`、`/api/v1/reports` 支持 HTML/JSON 模板渲染与归档，便于审计和导出。

### 3.4 威胁情报与行为分析

- **情报编排**：`threatintel.Orchestrator` 将 Agent 上传的样本与指标派发到 OpenTIP、MetaDefender 等 Provider，聚合 verdict 后写入数据库与 SSE Hub。
- **行为分析**：`behavior.Recorder/Analyzer/GraphService` 接收心跳与任务遥测，生成异常 (Anomaly) 事件、图谱和趋势数据，供 Playbook 与前端订阅。
- **事件回溯**：`auditlog.Manager`、`audit.Logger`、BAS 审计记录共同构成全过程轨迹，支持 API 查询与文件留存。

### 3.5 运维与安全治理

- **认证授权**：`rbac`、`security.MFAStore`、`security.Principal` 提供角色权限、MFA 头校验与上下文注入，敏感接口可要求管理员级别+MFA。
- **工件与密钥管理**：`artifacts.Manager` 通过分片上传、TTL、哈希校验保护大文件，`certmanager` 统一发放 TLS 与 Agent 证书。
- **运维接口**：`/api/v1/ops/self-heal`、`/api/v1/queue`、`/api/v1/metrics`、`streams.SSE` 帮助快速定位调度瓶颈、审批阻塞与 Collector 状态。

## 4. 代码组织结构

D-Eyes项目采用清晰的代码组织结构，将Agent和Server功能分离，便于独立开发和部署。

### 4.1 整体结构

```
├── agent/               # Agent端代码，包含命令行工具实现
│   ├── cmd/             # Agent命令行入口
│   ├── docs/            # Agent相关文档
│   ├── example/         # 示例代码
│   ├── internal/        # Agent内部实现
│   ├── pkg/             # 公共包，可被外部使用
│   └── yaraRules/       # YARA规则库
├── server/              # Server端代码，提供集中管理功能
│   ├── cmd/             # Server命令行入口
│   ├── config/          # Server配置文件
│   ├── deploy/          # 部署相关文件
│   ├── docs/            # Server相关文档
│   ├── internal/        # Server内部实现
│   ├── migrations/      # 数据库迁移文件
│   └── proto/           # gRPC协议定义
├── docs/                # 项目文档
└── openspec/            # 规范文档
```

### 4.2 Agent端详细结构

Agent端采用模块化设计，各功能模块相对独立，便于维护和扩展。

- **cmd/agent/**：Agent命令行入口
- **internal/**：内部实现，不对外暴露API
  - **agent/**：Agent核心实现
  - **app.go**：主应用程序入口和命令注册
  - **assets/**：资产探测模块
  - **benchmark/**：基准测试相关代码
  - **config_runtime.go**：运行时配置
  - **constant/**：常量定义
  - **detect/**：检测模块实现
  - **detect.go**：检测模块接口和命令定义
  - **model/**：数据模型定义
  - **progress/**：进度展示相关代码
  - **sbom/**：SBOM生成模块
  - **sbom.go**：SBOM模块接口和命令定义
  - **tasks/**：任务执行框架
  - **utils/**：工具函数
- **pkg/**：公共包，可被外部使用
  - **color/**：控制台颜色输出
  - **config/**：配置管理
  - **exit/**：退出码处理
  - **logo/**：Logo展示
  - **logs/**：日志功能
  - **reporting/**：报告生成
- **yaraRules/**：YARA规则文件，用于恶意软件检测

### 4.3 Server端详细结构

Server端采用微服务思想设计，各组件通过接口交互，便于扩展和维护。

- **cmd/server/**：Server命令行入口
- **config/**：Server配置文件
- **deploy/**：部署相关文件，如Docker Compose配置
- **docs/**：Server开发和使用文档
- **internal/**：内部实现，不对外暴露API
  - **api/**：RESTful API实现
  - **app/**：应用程序入口和启动逻辑
  - **config/**：配置管理
  - **grpcsvc/**：gRPC服务实现，用于Agent通信
  - **logger/**：日志功能
  - **metrics/**：监控指标
  - **model/**：数据模型定义
  - **monitor/**：监控功能，如心跳监控
  - **queue/**：任务队列实现
  - **queueprovider/**：队列提供者接口
  - **scheduler/**：任务调度器
  - **store/**：数据存储接口
  - **storeprovider/**：存储提供者实现
  - **util/**：工具函数
- **migrations/**：数据库迁移文件
- **proto/**：gRPC协议定义和生成的代码

## 5. 运维与监控

- [沙箱部署与审批指南](docs/bas-sandbox-guide.md)：介绍 BAS 子任务沙箱化、审批与回退配置。
- [任务模板 API 说明](docs/task-template-api.md)：模板管理、调度下发与多 Agent 目标配置。
- [报告中心接口说明](docs/report-center.md)：查询历史任务、导出 JSON/HTML 报告。
- [运维与扩容指南](docs/operations-guide.md)：部署规划、健康检查、SSE 监控、告警与回滚流程。
- [插件 SDK 与示例](docs/plugin-sdk.md)：TaskRunner、Manifest、注入接口与最小示例。
- [观测 API 与指标集成](docs/observability-api.md)：Prometheus/SSE/API 调用清单与告警模板。
- [运维脚本模板](docs/ops-scripts.md)：部署、回滚、审批巡检脚本样板，可直接接入 CI/CD。
- [Collector 安装与权限指南](docs/collector-installation-guide.md) & [Collector 诊断与验收](docs/collector-diagnostics.md)：跨平台依赖、权限、CLI、自检及性能验收步骤。
- [发布说明模板](docs/release-notes-template.md) & [`scripts/check-release-notes.sh`](scripts/check-release-notes.sh)：保证 `docs/release-notes/<version>.md` 与 `docs/changelog.md` 与版本同步。
- [统一测试矩阵](docs/test-matrix.md) & [`scripts/test-matrix.sh`](scripts/test-matrix.sh)：一次执行 Server/Agent/BAS/前端测试与 Docs 校验。Server 部分需至少完成以下三组命令，确保核心模块、BAS 调度与审批/RBAC 错误分支都被覆盖：
  - `cd server && go test ./...`
  - `cd server && go test -run BAS -count=1 ./internal/scheduler ./internal/basscenarios ./internal/store/postgres`
  - `cd server && go test -run '(BAS\|Playbook\|Plugin\|Cert)' -count=1 ./internal/api/v1`
- [性能基线指南](docs/perf-baseline.md) & [`scripts/perf-baseline.sh`](scripts/perf-baseline.sh)：依托 Prometheus/`server/tools/perfcheck` 校验调度、TI、BAS、Ops Console 指标。
- [CI 门禁](docs/ci-gates.md) & [`scripts/ci-gates.sh`](scripts/ci-gates.sh)：一站式运行测试矩阵、覆盖率、插件兼容性、性能基线与发布说明校验。
- [混沌/失效注入](docs/chaos-guide.md) & `scripts/chaos/*.sh`：模拟 Scheduler/队列/存储/Agent 断连，验证恢复能力。
- [监控与告警](docs/monitoring-guide.md) & `monitoring/grafana/*`, `monitoring/alerts/*`：提供 Stage4 Prometheus/Grafana 仪表板与 Alertmanager 模板。
- [日志与 Trace](docs/logging-trace-guide.md) & `scripts/logging/*.sh`：集中化审计日志、追踪任务调度与 SSE Trace 关联。
- [阶段二发布 Checklist](docs/release-checklist.md)：回归测试、性能/安全评估与上线记录模板。

## 6. 开发规范

### 6.1 代码规范

1. **Go语言规范**
   - 遵循Go官方代码规范和惯例
   - 使用`go fmt`和`go vet`检查代码格式和潜在问题
   - 代码注释应清晰描述函数用途、参数和返回值

2. **命名规范**
   - 包名使用小写，简短且有意义
   - 函数名使用驼峰命名法，首字母大写表示可导出
   - 变量和常量使用有意义的名称，避免缩写

3. **错误处理**
   - 不忽略错误，所有错误必须被处理或返回
   - 使用`errors.Wrap`添加上下文信息
   - 定义明确的错误类型，便于上层处理

4. **并发安全**
   - 共享数据必须考虑并发安全
   - 使用适当的同步原语（mutex、channel等）
   - 避免死锁和资源竞争

### 6.2 架构规范

1. **模块化设计**
   - 功能模块间低耦合、高内聚
   - 定义清晰的接口，便于替换实现
   - 避免循环依赖

2. **接口优先**
   - 先定义接口，后实现
   - 依赖抽象而非具体实现
   - 接口设计简洁明确

3. **插件系统**
   - 遵循现有插件接口设计
   - 注册机制标准化
   - 提供清晰的插件开发文档

4. **配置管理**
   - 统一的配置加载和管理机制
   - 支持配置文件、环境变量和命令行参数
   - 提供合理的默认值

### 6.3 测试规范

1. **单元测试**
   - 关键功能必须有单元测试
   - 测试代码与生产代码分开
   - 使用表驱动测试方法

2. **集成测试**
   - 测试模块间的交互
   - 使用模拟对象隔离依赖
   - 验证端到端功能

3. **测试覆盖率**
   - 核心功能测试覆盖率不低于80%
   - 定期检查测试覆盖率
   - 新增代码必须添加相应测试

### 6.4 文档规范

1. **代码文档**
   - 包、函数和类型必须有文档注释
   - 文档应清晰描述用途、参数和返回值
   - 使用Go doc格式

2. **使用文档**
   - 提供详细的安装和使用说明
   - 包含常见问题和解决方案
   - 提供示例代码

3. **设计文档**
   - 架构设计和变更需有文档说明
   - 包含流程图和组件关系图
   - 说明设计决策和权衡

### 6.5 版本控制规范

1. **Git工作流**
   - 使用功能分支开发
   - 提交消息清晰描述变更内容
   - 定期合并主分支到功能分支

2. **版本管理**
   - 遵循语义化版本规范
   - 关键版本需创建标签
   - 版本发布需包含详细的变更日志

3. **依赖管理**
   - 使用Go Modules管理依赖
   - 锁定依赖版本
   - 定期更新依赖以修复安全漏洞

## 7. 快速开始

### 7.1 安装

```bash
# 从源码编译
cd agent
go build -o d-eyes ./cmd/agent

# 或下载预编译二进制文件
```

### 7.2 基本使用

```bash
# 查看版本
d-eyes version

# 运行快速资产扫描
d-eyes inventory --profile fast --targets 192.168.1.0/24

# 执行基线检查
d-eyes baseline --scope os

# 应急响应快速排查
d-eyes respond --profile quick

# 生成项目SBOM
d-eyes supplychain --mode generate --path ./project

# 执行入侵和攻击模拟
d-eyes bas --profile reconnaissance --targets 192.168.1.0/24
```

### 7.3 分布式模式

1. 启动Server端：
```bash
cd server
go run ./cmd/server --config ./config/server.yaml
```

2. 配置Agent连接：
```yaml
# ~/.d-eyes/config.yaml
remote:
  enabled: true
  server_grpc_addr: 127.0.0.1:9090
  agent_token: your_token
  agent_name: your_agent_name
  labels:
    network_boundary: dmz
    tenant: soc-blue
```

3. 启动Agent：
```bash
d-eyes remote
```

## 8. 核心服务注入

为了方便测试与高级扩展，Agent 暴露了三个核心 service 的注入接口：

- `tasks.SetThreatIntelProvider`：允许替换默认的 `threatintel.Manager` 构造逻辑，可用于注入 fake provider 或自研情报后端。
- `sandbox.SetControllerFactory`：替换沙箱控制器工厂，实现第三方沙箱执行器或纯内存 mock。
- `detect/rules.SetRuleEngineFactory`：注入自定义 YARA 规则引擎，便于在测试中使用合成规则或实验性引擎。

不调用这些 setter 时，CLI 与远程运行仍使用默认实现，行为保持一致。

## 9. 贡献指南

我们欢迎社区贡献！如果您有兴趣参与D-Eyes的开发，请遵循以下步骤：

1. Fork项目仓库
2. 创建功能分支
3. 提交代码变更
4. 运行测试确保代码质量
5. 创建Pull Request

详细的贡献指南请参考项目文档。

## 10. 许可证

本项目采用开源许可证，详见LICENSE文件。
