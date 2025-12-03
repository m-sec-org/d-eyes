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

- **多场景任务支持**：提供`respond`、`baseline`、`audit`、`inventory`、`supplychain`、`bas`六大任务入口，覆盖主流安全检测场景
- **统一的执行框架**：所有任务复用全局配置、报告管理器与风险策略，提供一致的使用体验
- **强大的插件系统**：支持通过插件机制扩展功能，如检测插件、SBOM语言支持等
- **多平台兼容**：核心能力覆盖Linux、Windows、macOS等主流操作系统
- **分布式架构**：支持Agent-Server模式，可实现大规模环境的集中管理与分布式执行
- **丰富的YARA规则**：内置大量恶意软件检测规则，支持勒索软件、挖矿程序等多种威胁检测
- **自动化攻击模拟**：提供可控的攻击链模拟能力，主动验证安全防护有效性

### 1.3 产品优势

- **全方位安全覆盖**：从资产发现、基线检查到入侵检测、攻击模拟，提供完整安全评估体系
- **主动防御验证**：通过BAS能力主动模拟攻击场景，验证防御有效性，而非仅被动检测
- **高度可扩展架构**：模块化设计与插件系统相结合，支持快速定制和功能扩展
- **轻量高效部署**：单机部署快速启动，分布式架构支持大规模环境管理
- **一体化安全视图**：整合多源安全数据，提供统一的安全态势感知
- **灵活的报告机制**：支持多格式输出，便于自动化集成和安全流程对接
- **开源社区生态**：持续更新的规则库和功能模块，保持对最新威胁的响应能力

## 2. 功能与特性

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

### 2.6 检测插件系统 (detect)

检测插件系统采用插件化架构设计，支持灵活扩展检测能力。

- **插件接口标准化**：提供统一的插件接口，便于开发自定义检测插件
- **子命令注册机制**：支持向detect命令注册子命令
- **多样检测能力**：可扩展支持各种检测场景，如恶意代码检测、异常行为分析等

### 2.6 入侵和攻击模拟 (bas)

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

### 2.7 分布式管理能力

D-Eyes提供Agent-Server分布式架构，支持大规模环境的集中管理与分布式执行。

- **Agent注册与心跳**：Agent自动向Server注册并保持心跳连接
- **任务分发与执行**：Server可向多个Agent分发任务并监控执行状态
- **结果收集与汇总**：自动收集和汇总各Agent的执行结果
- **离线工作能力**：支持断线重连和结果缓存，保证任务可靠执行
- **集中配置管理**：通过Server统一管理Agent配置
- **BAS场景协调**：支持跨Agent的协同攻击模拟，实现复杂场景验证

### 2.8 Collector 部署与权限

跨平台 Collector（Windows ETW、Linux eBPF）需要额外的系统权限与依赖，可参考《[Collector 安装与权限指南](docs/collector-installation-guide.md)》：

- Windows：以管理员身份运行 `d-eyes collect --backend=etw` 或配置服务账户，确保 Provider 注册与 ETW Session 权限。
- Linux：内核 ≥5.8，安装 `clang/llvm` 与 `linux-headers-$(uname -r)`，为二进制授予 `CAP_BPF/CAP_SYS_RESOURCE` 或以 root 启动，并调大 `memlock` 限制。
- CLI 可通过 `--backend`、`--output-mode`、`--stream-*` 等参数快速调试 Collector，状态会上报到 Server `/api/v1/collector/status`/SSE。

## 3. 代码组织结构

D-Eyes项目采用清晰的代码组织结构，将Agent和Server功能分离，便于独立开发和部署。

### 3.1 整体结构

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

### 3.2 Agent端详细结构

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

### 3.3 Server端详细结构

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

## 4. 开发规范

### 4.1 代码规范

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

### 4.2 架构规范

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

### 4.3 测试规范

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

### 4.4 文档规范

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

### 4.5 版本控制规范

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

## 5. 快速开始

### 5.1 安装

```bash
# 从源码编译
cd agent
go build -o d-eyes ./cmd/agent

# 或下载预编译二进制文件
```

### 5.2 基本使用

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

### 5.3 分布式模式

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

## 6. 核心服务注入

为了方便测试与高级扩展，Agent 暴露了三个核心 service 的注入接口：

- `tasks.SetThreatIntelProvider`：允许替换默认的 `threatintel.Manager` 构造逻辑，可用于注入 fake provider 或自研情报后端。
- `sandbox.SetControllerFactory`：替换沙箱控制器工厂，实现第三方沙箱执行器或纯内存 mock。
- `detect/rules.SetRuleEngineFactory`：注入自定义 YARA 规则引擎，便于在测试中使用合成规则或实验性引擎。

不调用这些 setter 时，CLI 与远程运行仍使用默认实现，行为保持一致。

## 7. 贡献指南

我们欢迎社区贡献！如果您有兴趣参与D-Eyes的开发，请遵循以下步骤：

1. Fork项目仓库
2. 创建功能分支
3. 提交代码变更
4. 运行测试确保代码质量
5. 创建Pull Request

详细的贡献指南请参考项目文档。

## 8. 许可证

本项目采用开源许可证，详见LICENSE文件。
