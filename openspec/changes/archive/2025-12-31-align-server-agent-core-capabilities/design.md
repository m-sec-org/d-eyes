# Agent ↔ Server Core Capabilities 对齐矩阵（0.x 盘点产出）

本文件为 `align-server-agent-core-capabilities` 的 **0.1~0.3 盘点交付物**：汇总当前已落地的 Agent“可执行任务面”与约束（core tasks + profile/flags/metadata），并标注 Server 与 Docs 的覆盖现状与缺口，作为后续 0.4 / 1~4 阶段实现的输入。

## 统一合同：任务、Payload、Metadata（现状）

### Server：创建任务（REST）

- `POST /api/v1/tasks` 主要字段：`type`、`profile`、`payload`、`metadata`（`server/internal/api/v1/tasks.go`）。
- **Task catalog 校验触发条件**：仅当 `profile` 与 `type` 非空时才会调用 `Catalog.ValidateTaskPayload(type, profile, payloadMap)`；若把 `profile` 放进 `payload.profile`，Server 侧不会校验（但 Agent 侧仍可能读取该字段）。
- **BAS 特殊约束**：当 `type=bas` 时必须提供 `metadata.scenario_id`，并要求场景处于激活且（如需）已审批状态；Server 会补充 `scenario_name/.../sandbox_approved` 等 metadata（`server/internal/api/v1/tasks.go`）。

### Agent：执行任务（Remote runner）

Remote 任务执行入口：`agent/internal/agent/daemon.go` 的 `processLease`/`applyRemotePayload`。

- **Runner 解析**：`internal.TaskRunnerByName()` 支持 `foo.bar` 通过 base `foo` 解析（`agent/internal/app.go` 的 `TaskRunnerByName`）。
- **Payload → Flags 规则**（`agent/internal/agent/daemon.go:extractFlagMap/applyRemotePayload`）：
  - 若 payload 顶层包含 `flags: {k:v}`：该 map 直接作为 flags 来源；
  - 否则：payload 顶层除保留键以外的所有字段，均视为 flags；
  - 保留键：`profile`、`name`、`timeout`、`quiet`、`json`、`output-dir`、`format`、`flags`；
  - `profile/name/timeout/quiet/json/output-dir/format` 既可放在 payload 顶层，也可放在 `flags` 里。
- **Metadata**：`lease.metadata` 会合并进 `ExecutionResult.metadata` 回传 Server（`agent/internal/agent/daemon.go:processLease`）。

### Server：调度能力匹配（Capabilities）

- Server 侧使用 `task.metadata["required_capabilities"]`（逗号分隔）与 `agent.Capabilities` 匹配（`server/internal/queue/queue.go:MatchCapabilities`）。
- Agent 侧当前注册上报：`Capabilities = internal.TaskNames()`（仅内置 core task registry；不包含 `detect.*`），且 `Version = runtime.Version()`（Go 版本而非 CLI 版本）（`agent/internal/agent/daemon.go:runOnce`）。
- **现状风险**：
  - 若调用方未显式设置 `required_capabilities`，调度会放行（可能下发给不支持该任务的 Agent，最终由 Agent 侧报 “unsupported task type”）。
  - `detect` 系列目前是 CLI 子命令（非 remote task），因此即使 Server 下发 `detect.*`，Agent 也无法执行（runner 不存在）。

## 对齐矩阵：Agent 内置 Core Tasks（已落地）

> 说明：下表以 “Server 任务类型/能力名（Capability）” 为主键，包含 Agent 侧约束（profile/flags/metadata/配置回落）以及 Server/Docs 现状。

| TaskType / Capability | Agent 本地入口 | Agent Remote payload/flags（关键字段 + 类型） | Agent 配置回落（默认） | Agent 校验/约束（关键点） | Server 侧调度/读取面（现状） | Docs 覆盖 | 主要缺口/风险（0.1 发现） |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `respond` | `d-eyes respond` | `targets` **必须为 string**（逗号分隔）；`profile` 可选 | `config.tasks.respond.profile`（默认 `default`）；targets 回落 `config.tasks.respond.targets` → `config.discovery.targets` | 未提供 targets 且配置也无 targets → 退出码 `64`；targets 解析仅接受 string（`agent/internal/tasks/respond_modules.go:parseTargets`） | 需 `metadata.required_capabilities=respond` 才能能力过滤；有专用报告读取：`GET /api/v1/tasks/:id/respond/report` | `agent/README.md`（respond/任务表）；`server/README.md` 有创建示例 | `server/README.md` 示例 `payload.targets` 为数组（`["/tmp"]`），Agent 侧不会识别（需 string）；required_capabilities 未在示例中体现 |
| `audit` | `d-eyes audit` | 可选：`scope`(string)、`targets`(string, 逗号分隔)（Remote 下发可用） | `config.tasks.audit.scope`（默认 `system`）；targets 回落 `config.tasks.audit.targets` | `scope` 缺省补成 `system`；CLI 未声明 `--scope/--targets` flag（仅能通过 config/remote payload 影响） | 需 `metadata.required_capabilities=audit`；**无专用 report/read API**（0.2 重点盘点/补齐） | `agent/README.md`（audit/任务表） | Server 侧缺少与其他 core task 对齐的 report 读取路径；能力/任务类型虽然存在但平台消费链路不完整 |
| `inventory` | `d-eyes inventory` | `targets` **必须为 string**（逗号分隔）；`ports`(string) 可选；`service-detect/os-detect/resolve`(bool) | `config.tasks.inventory.profile`（默认 `fast`）；targets 回落 `config.tasks.inventory.targets` → `config.discovery.targets`；ports 回落 `config.tasks.inventory.ports` | targets 缺失且无配置回落 → 退出码 `64`；ports 需满足格式（`80,443,1000-2000`） | 需 `metadata.required_capabilities=inventory`；有专用报告读取：`GET /api/v1/tasks/:id/inventory/report` | `agent/README.md`（inventory/任务表） | 同 `respond`：targets 解析仅接受 string；Server 侧创建任务时需统一 payload 形态 |
| `supplychain` | `d-eyes supplychain` | `mode`(string: `generate|capture`)；`path`(string) 或 `file`(string)（`generate` 必需其一）；`type`(string)；`offline`(bool) | `config.tasks.supplychain.mode/type`（默认 `generate/json`）；`path` 回落 `config.tasks.supplychain.paths`（以逗号拼接）；`file` 回落 `config.tasks.supplychain.file` | `mode` 非法 → 退出码 `64`；`generate` 且无 `path/file`（含配置回落）→ 退出码 `64` | 需 `metadata.required_capabilities=supplychain`；有专用报告读取：`GET /api/v1/tasks/:id/supplychain/report` | `agent/README.md`（supplychain/任务表） | 远程 payload 字段目前偏 “flags” 风格（string/bool），需要与 Server catalog/schema 统一 |
| `baseline` | `d-eyes baseline` | `scope`(string)；`baseline-config`(string path) 可选 | `config.tasks.baseline.scope`（默认 `all`）；`baseline-config` 回落 `config.tasks.baseline.config` | `baseline-config` 若提供则必须为可访问文件，否则退出码 `64` | 需 `metadata.required_capabilities=baseline`；有专用报告读取：`GET /api/v1/tasks/:id/baseline/report` | `agent/README.md`（baseline/任务表） | baseline-config 在 Server payload/schema 侧需体现“文件路径存在性”无法纯静态校验（应作为运行时约束） |
| `bas`（含 `bas.advanced` 变体） | `d-eyes bas` | 必须提供其一：`scenario`(string/json)、`scenario-id`(string)、`scenario-file`(string path)；可选：`sandbox/no-sandbox/sandbox-approve`(bool) | `config.tasks.bas.scenario_dir`（默认空，表示使用内置场景）；沙箱默认由 `config.sandbox` 与 `config.tasks.bas.sandbox_enabled` 决定 | 缺少场景参数 → 退出码 `64`；当 `config.sandbox.require_approval=true` 且请求沙箱执行但未批准 → 退出码 `65`；通过 `metadata.sandbox_approved=true` 或 `--sandbox-approve` 走批准路径 | 需 `metadata.required_capabilities=bas`；创建任务时 **必须** `metadata.scenario_id`（Server BAS 场景）；有专用报告读取：`GET /api/v1/tasks/:id/bas/report` | `agent/README.md`、`docs/bas-sandbox-guide.md`、`docs/operations-guide.md` | Agent 的 BAS “场景输入”与 Server 的 BAS “scenario_id + policy”是两套来源，需要在 contract 测试中固定映射；`bas.advanced` 目前只在 Agent 校验分支里出现，Server 侧未定义 |
| `action` | `d-eyes action`（Automation） | 目前无固定 flags；playbook 侧通常通过 metadata 传递 `command/args/playbook_*` | 无 | **占位实现**：`agent/internal/tasks/action.go` 返回 `ErrNotImplemented` | playbook 下发时要求 `metadata.required_capabilities=action`（`server/internal/playbook/engine.go`）；无专用报告读取 | Docs 较少（偏实现内部） | Agent 侧 action 尚未实现，Server 下发将失败；需要明确 action 的稳定 payload/metadata 契约与权限边界 |

## 对齐矩阵：Detect 系列（已落地于 CLI，但未纳入 Remote 调度）

> 说明：本变更已确认 scope：`detect` 需纳入 “可远程调度任务面”。当前仅盘点已落地的 CLI 能力与约束；远程调度模型在 0.4/3.3 才实现。

| Detect 能力（建议 TaskType/Capability） | Agent 本地入口 | 关键参数/约束（现状） | 平台范围 | 远程可调度现状 | 主要缺口/风险（0.1 发现） |
| --- | --- | --- | --- | --- | --- |
| `detect.diag` | `d-eyes detect diag` | `--rule`(path/dir) 可选；`--backend`(auto/native/portable)；`--json` | Linux/Windows/macOS（build tag + 代码路径） | **不可**（无 task runner、capability 未上报） | 需要定义远程 task payload/schema 与 report/read 读取面；并将能力名加入 capabilities 合同 |
| `detect.memscan` | `d-eyes detect memscan` | 必须 `--pid` 或 `--all`；默认 `--rwx-only=true`；默认限额 `--max-bytes=32MiB`、`--max-regions=128`、`--timeout=2m`；`--evidence/--minidump` 默认关闭 | **Windows-only（运行时强校验）**：非 Windows 直接返回 `unsupported platform` | **不可**（无 task runner、capability 未上报） | 远程调度必须做到 “Windows-only 能力广告”；证据保全（evidence/minidump）涉及敏感与大体积 artifacts，需要明确默认策略与 RBAC/审批 |

## 0.1 关键结论（为后续任务提供输入）

1. **payload 形态不一致是首要风险**：Agent 多处校验/解析（如 `targets`）只接受 string；但 Server 文档/直觉更偏向数组。这会直接导致远程任务因参数缺失而失败。
2. **profile 字段位置需统一**：Agent 可从 payload 读 `profile`，但 Server catalog 校验只看顶层 `profile`；建议后续明确 contract：REST/gRPC 一律使用顶层 `profile` 字段，payload 仅承载 flags。
3. **report/read 覆盖不完整**：Server 已有 respond/baseline/inventory/supplychain/bas 的专用 report endpoint，但 `audit`/`action`/`detect.*` 缺口明显（0.2 将展开盘点并形成补齐方案）。
4. **capabilities/version 口径问题需纳入对齐**：Agent 注册 `Capabilities`/`Version` 的来源与 Server 期望的“可调度能力合同/版本展示”不一致，需要在 3.1/3.2 统一。

## 0.2 Server 侧 report/read API 覆盖矩阵（盘点产出）

### 0.2.1 任务读取面（Tasks / Runs / Visuals）

> 目标：明确“所有任务结果至少能被读到哪里”，以及哪些读取面是稳定 contract。

- `GET /api/v1/tasks`（`tasks.read`）：任务列表读取（支持 `status/search/limit/cursor`），返回每个 task 的 `LastRun`（若存在）。
- `GET /api/v1/tasks/:id`（`tasks.read`）：读取单个 task + 最近一次 run（`LastRun.Summary` 为 `server/internal/model.ExecutionResult` JSON）。
- `GET /api/v1/tasks/:id/visuals`（`tasks.read`）：从 `ExecutionResult.metadata` 或 `TaskRun.metadata` 中提取 `visual.*` JSON 生成可视化；若没有任何 `visual.*` 且未指定过滤，会回退生成 `host_summary`。
  - 现状：代码具备读取面（`server/internal/api/v1/tasks.go:getTaskVisuals`），但 Agent 侧暂未发现产出 `visual.*` 的实现（0.1 盘点）。

### 0.2.2 类型化任务报告面（按任务类型的 `/tasks/:id/*/report`）

> 这些 endpoint 的价值是 **稳定 JSON shape + 前端直接消费**（相对 `LastRun.Summary` 更“面向场景”）。

统一特征：
- RBAC：均要求 `reports.view`（`server/internal/api/v1/tasks.go:get*Report`）。
- 数据来源：读取 `TaskRun.Summary` 并反序列化为 `ExecutionResult`，并补充少量派生字段（如 totals/mode/steps）。

已覆盖的 core task：
- `respond`：`GET /api/v1/tasks/:id/respond/report`
- `baseline`：`GET /api/v1/tasks/:id/baseline/report`（输出 `severity/warnings/outputs` 等）
- `inventory`：`GET /api/v1/tasks/:id/inventory/report`（从 metadata 派生 totals/targets）
- `supplychain`：`GET /api/v1/tasks/:id/supplychain/report`（从 metadata 派生 mode/component_count/sources）
- `bas`：`GET /api/v1/tasks/:id/bas/report`（依赖 `TaskRun.metadata["scenario_summary"]` 等字段解析 steps）

缺口（直接影响 2.x 实现与 contract 测试）：
- `audit`：**无** `/tasks/:id/audit/report`，目前只能通过通用读取面（`/tasks/:id` 的 `LastRun.Summary`）消费结果。
- `action`：**无**专用 report；且 Agent 侧 `action` runner 仍为占位实现，Server 下发后会以 “未实现” 失败回传（见 0.1 盘点）。
- `detect.*`：**无**专用 report（且目前也未纳入 task runner/能力广告）。

### 0.2.3 通用报告面（聚合 / 导出 / 模板化生成）

> 用于“按时间窗口/任务类型”的聚合视图与导出，而非某个 task 的场景化报告。

- `GET /api/v1/reports/summary`：基于 `TaskResult` 聚合统计与趋势（支持 `type/limit/window_hours`），输出 `items/totals/status/trends`（`server/internal/api/v1/reports.go:summary`）。
- `GET /api/v1/reports/export`：导出 `TaskResult` 列表（`format=json|html`）（`server/internal/api/v1/reports.go:export`）。
- `POST /api/v1/reports/generate`：按模板对单个 task 生成报告（加载 `task + latest run + ExecutionResult`）（`server/internal/api/v1/reports.go:generateReport/loadExecution`）。
- 模板 CRUD（如启用）：`/api/v1/reports/templates`（list/create/update/delete）。

现状缺口（RBAC/审计一致性）：
- `ReportHandler` 当前**未接入 RBAC**（struct 无 RBAC 字段），以上 `/reports/*` 读取面仅受 API key + principal middleware 影响；与 `/tasks/:id/*/report` 的 `reports.view` 要求不一致，需要在后续 1.x/2.x 对齐。

### 0.2.4 关联读取面（审计 / 流式）

- `GET /api/v1/audit/events`：读取 **Server 自身审计日志**（非 `audit` 任务结果），当前未做 RBAC 鉴权（`server/internal/api/v1/audit.go`）。
- `GET /api/v1/tasks/stream`：SSE 推送 task 状态/统计事件（用于控制台实时视图）；当前未做 RBAC 鉴权（`server/internal/streams/events.go:SSEHandler` + `server/internal/api/router.go`）。

### 0.2.5 覆盖矩阵（按 core task / detect）

| TaskType | `/tasks/:id`（LastRun.Summary） | `/tasks/:id/*/report`（reports.view） | `/reports/summary|export` | `/reports/generate` | 主要缺口/备注 |
| --- | --- | --- | --- | --- | --- |
| `respond` | ✅ | ✅ | ✅ | ✅ | 文档示例 payload 形态需与 Agent 解析对齐（0.1 风险） |
| `baseline` | ✅ | ✅ | ✅ | ✅ | `baseline-config` 属运行时约束；结果内容主要在 `ExecutionResult` 与 outputs 中 |
| `inventory` | ✅ | ✅ | ✅ | ✅ | totals/targets 依赖 `ExecutionResult.metadata` 的约定键 |
| `supplychain` | ✅ | ✅ | ✅ | ✅ | mode/component_count/sources 依赖 `ExecutionResult.metadata` 的约定键 |
| `bas` | ✅ | ✅ | ✅ | ✅ | steps/summary 强依赖 `TaskRun.metadata["scenario_summary"]` 等键；需在 contract 中固化 |
| `audit` | ✅ | ❌ | ✅ | ✅ | 缺少场景化 report/read；容易导致前端/聚合口径分裂 |
| `action` | ✅（若有 run） | ❌ | ✅ | ✅ | Agent 侧 runner 未实现；需先定义可执行合同再谈 report/read |
| `detect.diag` | （理论上✅） | ❌ | （理论上✅） | （理论上✅） | 尚未纳入 task runner 与能力广告；也无 report/read 合同 |
| `detect.memscan` | （理论上✅） | ❌ | （理论上✅） | （理论上✅） | Windows-only + 证据保全敏感；必须先定义权限/审批与 artifacts 策略 |

## 0.3 Task Catalog Seed 导入策略（决策）

### 0.3.1 背景与目标

背景：
- Server 侧 `POST /api/v1/tasks` 仅在顶层 `profile` 非空时才启用 task catalog 校验；但 catalog 初始为空会导致 profile 任务创建失败（`ErrUnknownProfile`）。
- 若允许绕过 catalog（例如把 profile 放进 payload 或直接不填 profile），会导致前后端 contract 不稳定、且难以统一约束。

目标（与 tasks.md 0.3 对齐）：
- **首次启动导入**：当 catalog 为空（fresh server / 空持久化文件）时自动导入内置 seed，给出一个可用的基线 catalog。
- **持久化优先**：若配置了 `task_catalog.persist_path`，seed 导入后应落盘，后续重启复用；否则 seed 仅存在于内存（每次启动都会重新导入）。
- **不覆盖用户自定义**：一旦 catalog 非空（表示已有运维/控制台写入或历史数据），启动时不对其做“自动覆盖/迁移”。

### 0.3.2 Seed 内容范围（0.x 阶段约束）

- Seed 的最小集合（用于让阶段一 core task 可被 profile+校验创建）：
  - Task types：`respond`、`audit`、`inventory`、`supplychain`、`baseline`、`bas`、`action`
  - Profiles：每个 task type 至少 1 个可用 profile（`default` 或等价），并包含能表达关键必填参数的 schema（例如 `respond.targets`）。
- detect 系列的 seed（`detect.diag`/`detect.memscan`）属于 0.4/1.3/2.3 的工作范围：在 0.3 只明确导入策略，不强行规定其 schema 细节。

### 0.3.3 导入触发条件与判定标准

导入触发（Server 启动时）：
- 在 `taskcatalog.NewManager(...PersistPath...)` 完成 `load()` 之后执行导入判定。
- **判定为 “空 catalog” 的标准**：`taskTypes == 0 && taskProfiles == 0`。
  - 说明：只要两者任意一方非空，即视为“存在用户数据”，启动时不自动导入/补齐，避免对用户意图做猜测。

### 0.3.4 不覆盖原则（保护用户自定义）

当 catalog 非空时：
- 不执行任何自动写入（不新增、不更新、不删除）。
- 不对 “缺少某个内置 task type/profile” 做自动修复；缺口应通过显式运维动作处理（API/控制台/后续提供的迁移工具）。

设计理由：
- catalog 本质是“合同/策略/校验”数据：用户可能基于合规或业务需求做裁剪/改造；自动补齐会改变其控制面。

### 0.3.5 持久化与幂等性

持久化：
- `task_catalog.persist_path != ""`：导入后通过现有 `persistLocked()` 写入（原子写临时文件 + rename），保证不会产生半写文件。
- `task_catalog.persist_path == ""`：导入仅影响进程内存；适用于开发/演示环境，但重启后 catalog 会回到空（再由导入逻辑恢复）。

幂等性与并发：
- 导入过程需做到幂等：多次启动重复导入不会造成重复记录（由于导入仅发生在“空 catalog”，且写入目标是全量 seed）。
- 多实例并发启动写同一 persist_path 时：可能同时判定为空并写入，但写入内容一致，最终落盘文件应等价（rename 原子）。

### 0.3.6 运维与升级建议（非本阶段实现）

- 若未来版本引入新的内置 task type/profile（例如 detect），在“已有用户 catalog”场景下不自动迁移；建议提供显式的迁移/导入机制（例如：管理 API 或 `d-eyes-server seed --merge-missing`），由运维确认后执行。
- 2.4 回归测试应覆盖：首次导入成功、重复启动不覆写、已有 catalog 不被改写、并发启动不会生成破损文件。

## 0.4 Detect 远程调度模型（决策）

### 0.4.1 TaskType / Capability 命名

- 远程可调度任务类型（Server `task.type`）统一使用 dot 命名：
  - `detect.diag`
  - `detect.memscan`
- Agent 注册 `capabilities` 使用同名字符串（与 `required_capabilities` 同口径）。

### 0.4.2 远程 Payload（flags）与默认值

通用约定：
- Server 下发 payload 字段会被 Agent 侧 `applyRemotePayload` 合并到 `TaskRequest.Flags`（保留字段除外）。
- 远程 detect 任务的结果以结构化 JSON 报告落盘，并通过 `ExecutionResult` 的 `outputs/metadata` 回传摘要（不依赖 stdout）。

`detect.diag`（低风险诊断任务）：
- payload keys（建议最小集）：
  - `rule`（string，可选）：自定义规则文件/目录；空表示使用内置规则集
  - `backend`（string，可选）：`auto|native|portable`，默认 `auto`
- 默认值：`backend=auto`，`rule=""`

`detect.memscan`（高风险敏感任务，Windows-only）：
- payload keys（建议最小集）：
  - 目标选择（必须二选一）：
    - `pid`（number > 0）
    - `all`（boolean=true）
  - 规则/后端：
    - `rule`（string，可选）
    - `backend`（string，可选）：`auto|native|portable`，默认 `auto`
  - 扫描 guardrails（可选）：
    - `rwx_only`（boolean，默认 `true`）
    - `max_bytes`（number，默认 `33554432` / 32MiB）
    - `max_regions`（number，默认 `128`）
  - 证据保全（可选、默认禁用）：
    - `evidence`（boolean，默认 `false`）：输出 hexdump 证据片段
    - `minidump`（boolean，默认 `false`）：对命中的进程生成 minidump
- 任务超时：优先复用 `TaskRequest.Timeout`（Server 顶层 `timeout` 字段，Go duration 字符串），默认 `2m`。
- 证据保全限额默认值（当 `evidence=true` 时生效，保持与 CLI 一致）：
  - `evidence_max_bytes=4096`、`evidence_context_bytes=256`、`evidence_max_offsets=128`
  - `evidence_max_artifacts=8`、`evidence_max_total=64`
  - `evidence_max_bytes_per_process=32768`、`evidence_max_bytes_total=262144`
  - `minidump_max_processes=1`

### 0.4.3 Windows-only 能力广告（Capability 宣称）

原则：**非 Windows 平台不得宣称 `detect.memscan` capability**，避免 Server 错误调度；即使被强制下发，Agent 也必须返回明确的 “unsupported platform” 错误。

决策（用于后续 3.2/3.3 实现）：
- `detect.diag`：全平台可宣称（当远程 runner 可用时）。
- `detect.memscan`：仅在满足以下条件时宣称：
  1) `GOOS == windows`
  2) Agent 明确 opt-in（建议使用 `remote.labels.allow_memscan=true` 作为开关；未设置则默认不宣称）

### 0.4.4 权限 / 审批策略（Server + Agent）

> 目标：把 memscan 的高风险操作从“默认可用”改为“默认不可用 + 显式批准”。

统一约定：
- 所有 detect 任务创建时都应设置 `metadata.required_capabilities=<taskType>`，保证 scheduler 的 capability filtering 生效。

`detect.diag`：
- 权限：沿用 `tasks.create`（创建）+ `reports.view`（读取）即可。
- 审批：不需要额外审批字段。

`detect.memscan`（敏感）：
- 权限（建议）：
  - 创建/下发：额外要求一个专用权限（建议命名 `detect.memscan.execute`）；默认仅 `admin` 拥有。
  - 证据保全（evidence/minidump）：额外要求更高权限（建议命名 `detect.memscan.evidence`），用于显式授权敏感 artifacts 的生成。
- 审批（建议，最小可落地且可审计）：
  - task metadata 约定键：
    - `memscan_approval_required`：`true`
    - `memscan_approved`：`true|false`
    - `memscan_evidence_approved`：`true|false`（当 `evidence=true` 或 `minidump=true` 时必须为 true）
  - 行为：
    - 若 `memscan_approval_required=true` 且 `memscan_approved!=true`：Agent 必须拒绝执行并返回明确错误（建议沿用 BAS 的 exit code=65 语义）。
    - 若请求 `evidence/minidump` 且 `memscan_evidence_approved!=true`：Agent 必须拒绝或强制降级为 `evidence=false/minidump=false`（建议“拒绝”，便于控制面可观测）。

### 0.4.5 证据保全默认值与结果回收策略

默认值（安全优先）：
- `evidence=false`、`minidump=false`（远程调度默认不生成任何敏感 artifacts）。
- 仅当同时满足 “权限允许 + 审批字段通过” 时，才允许开启证据保全能力。

结果回收策略（结合当前 Server 能力现状）：
- 当前 Server 尚未提供通用的 “task 输出 artifacts 下载” 面；且 gRPC `ReportResult` 的 inline artifacts 不适合承载 minidump。
- 因此：即使开启 evidence/minidump，也应默认 **仅在 Agent 本地落盘** 并通过 `outputs` 暴露路径；后续如需集中回收，再在 2.x 引入通用 artifact 上传/下载与配额策略。
