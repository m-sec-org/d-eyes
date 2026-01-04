# D-Eyes Agent CLI 使用手册

D-Eyes Agent CLI（`d-eyes`）是平台在终端环境中的统一入口：所有检测、审计、资产梳理与 BAS 攻击模拟任务都通过同一套命令行协议执行，并可无缝切换至远程（Server 下发）模式。本手册梳理 CLI 的整体结构、全局选项、配置文件、各子命令语义以及常见报错，帮助你快速定位 `flag provided but not defined: -profile` 等使用问题。

> **提示**：CLI 仅接受 POSIX 风格的长参数（例如 `--profile`），传入单短横线（`-profile`）会被 `urfave/cli` 判定为不存在的短 Flag，从而触发 `flag provided but not defined` 报错。

---

## 快速开始

- 查看版本与运行环境：

  ```bash
  d-eyes version
  ```

- 诊断 YARA 后端与规则覆盖率（CI/排障优先执行）：

  ```bash
  d-eyes detect diag --backend auto
  d-eyes detect diag --backend auto --json | jq .
  ```

- 查看命令矩阵及全局 Flag：

  ```bash
  d-eyes --help
  d-eyes respond --help   # 某个子命令的专属 Flag
  ```

- 运行一次快速应急响应（指定目标列表，注意使用 `--profile` 而非 `-profile`）：

  ```bash
  d-eyes --profile quick respond --targets /var/log,/tmp
  ```

执行所有命令前建议确保具备管理员（Windows/macOS）或 root（Linux）权限，以便访问系统级证据。

---

## 命令结构与可用子命令

通用语法遵循：`d-eyes [global options] <command> [command options]`。下表列出现有命令：

| 命令 | 场景 | 关键参数 |
|------|------|----------|
| `respond` | 主机应急响应（文件扫描、网络分析、用户会话） | `--targets`, `--profile` |
| `detect` | 入侵分析检测（YARA 扫描/导出/诊断等，子命令随平台变化） | `detect diag --backend/--json`, `detect memscan --pid/--all` |
| `audit` | 合规审计（串联基线 + 主机信息 + 用户会话） | `--profile`, `--scope`（自动补默认值） |
| `inventory` | 资产梳理（主机/端口发现） | `--targets`, `--profile`, `--ports`, `--service-detect`, `--os-detect` |
| `supplychain` | SBOM 生成 / 依赖捕获 | `--mode`, `--path`, `--file`, `--type`, `--offline`（预留） |
| `baseline` | 安全基线检查 | `--scope`, `--baseline-config`, `--format` |
| `bas` | BAS（攻击模拟） | `--scenario`, `--scenario-id`, `--scenario-file`, `--sandbox`, `--no-sandbox`, `--sandbox-approve` |
| `action` | Playbook 动作占位任务 | 无额外 Flag，当前输出占位报告 |
| `remote` | 连接 D-Eyes Server、执行远程任务 | 依赖 `config.yaml` 中的 `remote.*` |
| `version` | 输出 CLI 版本、运行时架构 | 无 |

---

## 全局选项

所有命令共享以下 Flag，必须放在子命令之前。单个命令如果未显式传参，会从 `~/.d-eyes/config.yaml` 中回落对应字段，并在非静默模式下打印 `[NOTICE]`。

| Flag | 说明 | 默认值 / 来源 | 备注 |
|------|------|---------------|------|
| `--config` | 指定配置文件路径 | `~/.d-eyes/config.yaml` 或 `D_EYES_CONFIG` | 缺失时载入内置默认配置 |
| `--profile` | 选择任务配置档案 | 默认 `default`（任务自有） | 长参数写法 `--profile xxx`，单横线会报错 |
| `--output-dir` | 报告输出根目录 | `config.output.dir` | 若覆盖，当前命令所有报告写入该目录 |
| `--format` | 默认报告格式 | `config.output.format`（JSON） | `baseline` 会使用该值决定 `json/html/csv` |
| `--name` | 自定义任务名称前缀 | `<command>-<profile>` | 也影响报告文件名 |
| `--timeout` | 任务超时时长 | `config.performance.timeout`（10m） | 支持 `30s`、`5m` 等语法 |
| `--json` | 将执行摘要输出为 JSON | 关闭 | 仍会在终端打印报告路径（除非 `--quiet`） |
| `--quiet` | 静默模式，仅生成报告 | 关闭 | Remote 任务会自动启用 |
| `--debug` | 启用调试时间线与进度事件 | 关闭 (`DEYES_DEBUG=1` 亦可启用) | 事件以结构化行写入 `stderr`，同时压缩到 `telemetry.debug_*` 元数据；若同时启用 `--quiet`，终端不再打印但仍会写入 metadata |
| `--ti-mode` | 威胁情报模式：`auto` / `local` / `hybrid` / `server` | `hybrid` | 也可通过 `D_EYES_TI_MODE` 控制 |

调试模式补充说明：

- `--debug` 会实时在 `stderr` 输出 `[phase] progress/notice` 行，并在任务结束后将压缩后的时间线 (`telemetry.debug_timeline`, `telemetry.debug.summary`, `telemetry.debug.error_phase`) 写入 `TaskResult.Metadata` 以及远程 `ExecutionResult.metadata`，便于 Server/自动化排障。
- 与 `--json` 并用时，JSON 摘要仍写入 `stdout`，调试行写在 `stderr`，互不干扰。
- 与 `--quiet` 并用时，CLI 不再打印调试行，但元数据仍会保留完整事件以供远程分析。

> CLI 会在首次执行时显示 ASCII Logo、初始化 `d-eyes.logs`（位于二进制同目录），随后按上述 Flag 配置 Runner。

---

## 输出目录、日志与退出码

- 报告目录：`reporting.Manager` 会在 `output-dir/<command>/` 下创建 `YYYYMMDD-HHMMSS-<name>.<ext>` 文件。命令执行完毕后会输出生成的路径清单与风险统计。
- 日志：`d-eyes.logs` 写在可执行文件所在目录；如需同时输出到控制台，可修改 `agent/pkg/logs/log.go` 中相应注释。
- JSON 摘要：`--json` 会将 `{command,status,duration_seconds,outputs,risks,notes}` 写到 `stdout`，便于自动化采集。
- 策略评估：若 `config.policy.fail_on=critical` 且结果包含等同或更高风险等级，命令会以退出码 `1` 结束，并提示 `policy violation`。
- 通用退出码：
  | 码值 | 含义 |
  |------|------|
  | `0` | 成功 |
  | `1` | 命中策略阈值（如基线高危超过 `fail_on`） |
  | `2` | 任务执行失败，或参数校验失败并返回 `exit.New(64, …)` |
  | `3` | 被取消/超时 (`context.Canceled`/`DeadlineExceeded`) |
  | `64` | 用户输入缺失或无效（`respond` 未提供 `--targets` 等） |
  | `65` | 沙箱审批缺失（`--sandbox-approve` 或 `metadata.sandbox_approved` 未设置） |

---

## 配置文件 (`~/.d-eyes/config.yaml`)

`config.Load` 会将磁盘配置与 `config.Default()` 合并。常用字段示例如下：

```yaml
output:
  dir: ~/d-eyes/reports
  format: json
performance:
  timeout: 10m
policy:
  fail_on: critical
discovery:
  targets: ["10.0.0.0/24", "192.168.1.10"]
tasks:
  respond:
    profile: quick
    targets: ["/var/log","/tmp"]
  inventory:
    profile: fast
    ports: "1-1024,443"
  supplychain:
    mode: generate
    paths: ["./service"]
  baseline:
    scope: os
    config: ./baseline.yaml
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
threat_intel:
  mode: hybrid
  opentip_api_key: ""
sandbox:
  enabled: true
  runtime: gvisor
  runtime_binary: runsc
  require_approval: false
```

关键行为：

- **缺省值回落**：若命令未提供 `--targets` / `--profile`，CLI 会尝试读取 `tasks.<command>` 或 `discovery.targets`，并在终端打印 `[NOTICE] 未指定 --targets，使用配置项默认值...`。
- **威胁情报**：`--ti-mode`（或 `D_EYES_TI_MODE`）支持 `auto/local/hybrid/server`。当未配置 API Key、触发限额（`429`）或 Provider 暂不可用时，Agent 会**降级为 local** 并在 metadata 中输出稳定口径字段：`threatintel.mode_effective`、`threatintel.remote_enabled`、`threatintel.notice`（稳定 code）与 `threatintel.notice_detail`（短摘要，已脱敏/截断）。
- **沙箱**：`sandbox.enabled` + `tasks.bas.sandbox_enabled` 控制 BAS 步骤是否默认运行在 gVisor（`runsc`）。若 `require_approval=true`，CLI 必须附带 `--sandbox-approve` 或在 `metadata.sandbox_approved` 中显式允许。

---

## 远程模式 `remote`

`d-eyes remote` 复用同一批 TaskRunner，通过 gRPC 向 D-Eyes Server 注册、心跳、拉取任务并回传结果。要启用：

1. 在 `config.yaml` 中设置 `remote.enabled=true`，填好 `server_grpc_addr`、`agent_token`、`agent_name`、TLS 证书（可选）以及 `cache_dir`。
2. 执行 `d-eyes remote`，Agent 会：
   - 注册获取 `agent_id`，根据 `heartbeat_interval` 汇报在线状态；
   - 以 `task_poll_interval` 频率拉取任务，解析 `payload.flags.*` 到 CLI 同名 Flag；
   - 将执行结果写入本地缓存（`remote.cache_dir`），即便网络抖动也会在链路恢复后补发；
   - 默认启用 `--quiet` 与 JSON 摘要，避免干扰服务端日志。

Remote 模式同样尊重策略评估、沙箱限制与威胁情报配置。

---

## 子命令详解

### `detect`

- **用途**：入侵分析检测入口（插件化子命令集合），覆盖 YARA 扫描、系统取证汇总与诊断等能力；不同平台可用的子命令可能不同。
- **常用子命令**：
  - `d-eyes detect diag`：诊断 YARA 后端、规则版本、覆盖率与回退原因（CI/排障优先）。
  - `d-eyes detect filescan`：对文件/目录执行 YARA 扫描（跨平台）。
  - `d-eyes detect processcan`：扫描进程可执行文件内容（Linux/Windows）。
  - `d-eyes detect memscan`：扫描进程内存（**Windows only**；默认只扫 RWX 段；显式触发能力）。

#### `detect diag`

- **场景**：确认当前实际使用的 YARA backend（`auto/native/portable`）、覆盖率、规则家族缺失与 `fallback_reason`。
- **提示**：`native` 后端依赖 `-tags yara_native`（CGO + libyara）。若构建环境不满足，`auto/native` 会显式回退到 `portable` 并输出回退原因。
- **示例**：

  ```bash
  d-eyes detect diag --backend auto
  d-eyes detect diag --backend auto --json
  ```

#### `detect memscan`（Windows）

- **用途**：对进程内存做 YARA 扫描，默认聚焦 **RWX** 区域并启用 guardrails（`--max-bytes/--max-regions/--timeout`）。
- **必填**：必须二选一：
  - `--pid <pid>`：扫描指定 PID
  - `--all`：扫描所有进程（建议搭配更严格的限额）
- **安全默认值**：
  - `--rwx-only=true`（只扫 RWX commit 区域）
  - `--evidence=false`、`--minidump=false`（证据保全默认关闭；需显式启用）
- **示例**：

  ```bash
  # 扫描指定进程（建议管理员权限）
  d-eyes detect memscan --pid 1234 --backend auto

  # 扫描所有进程（限制成本，避免卡顿）
  d-eyes detect memscan --all --max-bytes 16777216 --max-regions 64 --timeout 60s

  # 显式启用证据保全（敏感；建议在受控环境使用）
  d-eyes detect memscan --pid 1234 --evidence --evidence-max-bytes 2048
  ```

### `respond`

- **用途**：面向应急响应的组合分析，按 Profile 调度多个模块。
- **必需参数**：`--targets`（逗号分隔路径或 `config.tasks.respond.targets`）。
- **Profiles**（`selectRespondProfile`）：
  | Profile | 模块组合 |
  |---------|---------|
  | `default`/`quick` | `HostSummary`（主机信息）+ `NetworkConnections`（网络连接） |
  | `ransomware` | `HostSummary` + `FileScan`（可疑文件启发式 + TI 查询）+ `NetworkConnections` |
  | `persistence` | `HostSummary` + `NetworkConnections` + `UserEnumeration`（登录会话） |
- **输出**：每个模块生成 `<command>/<name>-{host-summary|filescan|network|users}.json`，可附带 `威胁情报 - *` 报告。
- **示例**：

  ```bash
  d-eyes --profile ransomware respond \
    --targets /opt/app,/var/log \
    --json
  ```

### `audit`

- **用途**：生成合规审计报告；流程内嵌一次 `baseline`。
- **行为**：
  1. 调用 `baselineRunner`（默认 `scope=all`，可用 `--scope` 覆盖）；
  2. 采集主机概要与用户会话；
  3. 汇总为 `<output-dir>/audit/<task>-summary.json`（含输出列表、风险统计、Notes）。
- **示例**：`d-eyes --profile compliance audit --output-dir ./reports --quiet`

### `inventory`

- **用途**：网络资产梳理，支持主机发现 + 端口扫描。
- **必需参数**：`--targets`（CIDR、IP、域名）。未指定会回落到 `config.discovery.targets`，否则退出码 `64`。
- **Profiles（`buildInventoryOptions`）**：
  | Profile | 特性 |
  |---------|------|
  | `fast` | 扫描 `fastPorts`（`80,443,22,3389,...`），超时 2s，速率 1000 pps |
  | `deep` | 端口 `1-65535`，启用服务/OS 指纹 |
  | `stealth` | 降低速率（50 pps），停用服务识别、Banner 抓取 |
- **Flag 说明**：`--ports` 覆盖端口列表（支持 `80,443,8000-8100`），`--service-detect`、`--os-detect`、`--resolve` 控制指纹识别。
- **输出**：为每个 target 生成 `<target>.json` 与汇总 `*-summary.json`（含 host/port 统计、风险等级）。

### `supplychain`

- **用途**：生成或捕获 SBOM。
- **模式**：
  - `--mode generate`（默认）：递归扫描 `--path`（可多值）或解析 `--file`，识别 `package.json`、`requirements.txt`、`go.mod`、`pom.xml` 等，输出组件清单。
  - `--mode capture`：执行 `pip list --format=freeze` 捕获当前环境依赖。
- **Flags**：`--type` 目前支持 `json`（默认）或 `xml`；`--offline` Flag 已在 CLI 注册但尚未在 Runner 中使用，仅作为未来扩展预留。
- **示例**：

  ```bash
  d-eyes supplychain \
    --mode generate \
    --path ./service,./lib \
    --type json
  ```

缺少 `--path/--file` 会导致退出码 `64`。

### `baseline`

- **用途**：执行操作系统 / 数据库 / 中间件基线检查。
- **Flags**：
  - `--scope`: `all`（默认）、`os`、`db` 等；
  - `--baseline-config`: 指向自定义基线配置文件（若提供会先检查文件存在性）。
- **输出格式**：继承全局 `--format`，支持 `json`（结构化）、`html`/`csv`（写入文本内容）。
- **威胁情报**：对高危检查项自动查指标，额外生成 `baseline/*threatintel*.json`。

### `bas`

- **用途**：执行 BAS 攻击模拟场景（来自内置目录 `agent/internal/tasks/bas_scenarios/*.json` 或自定义 JSON）。
- **场景来源优先级**：
  1. `--scenario`（内联 JSON / YAML / Base64）；
  2. `--scenario-id`（内置 `initial-access`、`privilege-escalation` 或 `tasks.bas.scenario_dir` 下的同名文件）；
  3. `--scenario-file`（外部 JSON/YAML）。
- **沙箱控制**：
  - 默认遵循 `config.sandbox.enabled && config.tasks.bas.sandbox_enabled`；
  - `--sandbox` / `--no-sandbox` 显式覆盖；
  - 若配置 `require_approval=true` 则必须添加 `--sandbox-approve`，否则返回退出码 `65`。
- **输出**：生成 `<output-dir>/bas/<scenario-id>.json`，包含每步 `status`、`stdout/stderr`、沙箱执行情况、失败列表以及 `telemetry`。
- **示例**：

  ```bash
  d-eyes bas \
    --scenario-id initial-access \
    --sandbox \
    --sandbox-approve
  ```

### `action`

- 当前实现为占位 Runner（`newStubRunner("action")`），用于验证 Server Playbook 集成链路。执行后会生成占位报告和 `Notes`。

### `remote` / `version`

- `remote`：见前文“远程模式”章节。
- `version`：输出 `D-Eyes vX.Y.Z` 及 `GOOS/GOARCH`。

---

## 常见错误与排查

| 症状 | 原因 | 处理方法 |
|------|------|----------|
| `flag provided but not defined: -profile` | 使用单短横线传递多字符 Flag | 将命令改为 `d-eyes --profile quick respond ...` |
| `memscan: either --pid <pid> or --all is required` | `detect memscan` 未指定目标范围 | 显式添加 `--pid` 或 `--all`（二选一） |
| `memscan: specify exactly one of --pid or --all` | 同时传了 `--pid` 与 `--all` | 移除其一，保持互斥 |
| `respond 命令需要提供 --targets` | CLI 未提供 `--targets` 且配置中也无默认值 | 在命令或 `config.tasks.respond.targets` / `config.discovery.targets` 中填充目标 |
| `inventory 命令需要 --targets 或配置` | 同上 | 同上 |
| `supplychain generate 需要 --path 或 --file` | 未传任何输入位置 | 添加 `--path`/`--file` 或在配置中设置默认值 |
| `BAS 任务需要提供 --scenario...` | 没有任何场景来源 | 使用 `--scenario-id`、`--scenario` 或 `--scenario-file` |
| `沙箱执行需要审批` | `sandbox.require_approval=true` 但 CLI 未传 `--sandbox-approve` | 在命令中增加 `--sandbox-approve` 或在远程任务 `metadata.sandbox_approved=true` |
| `pip list 执行失败` | `supplychain --mode capture` 依赖系统 `pip` | 安装 pip 或切换到 `--mode generate` |

排查建议：

1. **查看日志**：检查 `d-eyes.logs` 了解内部模块错误。
2. **Inspect NOTICE**：非静默模式下 `ExtractFlags` 回填配置时会打印 `[NOTICE]`。这能帮助识别到底使用了哪些默认值。
3. **确认权限**：`respond`/`audit` 在缺少管理员权限时可能无法读取某些路径，导致报告为空。
4. **威胁情报模式**：优先查看 `threatintel.*` 元数据（`mode_effective/remote_enabled/notice/notice_detail`）判断是否发生降级；需要 Server 编排时使用 `--ti-mode server`（此模式 Agent 不直连 OpenTIP/MetaDefender，仅上传 artifacts/token）。
5. **输出路径**：使用 `--output-dir $(pwd)/reports` 将报告写到当前目录，方便在 CI 中打包。

---

## 最佳实践

- 将常用目标 / Profile 写入 `config.yaml`，命令行仅覆盖差异化参数，可减少脚本复杂度。
- 在自动化脚本中结合 `--json` 输出与 `jq` 提取 `outputs[].path`，再将报告上传或入库。
- 长时间运行的扫描（`inventory --profile deep` 或 `bas` 场景）建议搭配 `--timeout`，以防止作业占用资源。
- 在远程模式运行前先本地执行同命令，确保输入参数通过 `ValidateRequest`，避免任务在 Server 端频繁失败。
- 若需扩展 CLI，可参考 `docs/PLUGIN_GUIDE.md` 注册自定义命令或为现有任务注入 Runner。

通过上述指南，可以系统化掌握 `d-eyes` CLI 的参数、配置与执行路径，避免再次遇到 `-profile` 等语法问题，并持续输出可审计的检测结果。
