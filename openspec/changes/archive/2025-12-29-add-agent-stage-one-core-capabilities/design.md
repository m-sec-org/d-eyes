## Context

阶段一目标来自 `docs/d-eyes_agent_enhance_plan.md`：补齐内存对抗、Windows 侧 native 能力与威胁情报联动，使 Agent 在“文件less/注入类”与“对抗性环境”中具备可用的基线能力。

当前代码现状（与目标存在落差）：

- `detect processcan` 仅扫描进程可执行文件内容，并不读取进程内存（无法覆盖注入/反射加载）。
- YARA backend 目前仅实现 portable 引擎；`native` 模式会回退，且 `auto` 展示与实际不一致。
- Windows 特权判断存在 stub/外部命令依赖，影响 inventory/端口扫描的特权能力开关准确性。
- Threat Intel 目前仅本地启发式；`hybrid` 无 key 时整体禁用，且缺少 OpenTIP/MetaDefender 的远程查询实现。

## Goals / Non-Goals

- Goals
  - 提供可控、可退化、可排障的 **进程内存扫描**（RWX 优先）能力。
  - 完成 **YARA 后端** 的 native/portable 双栈与 `auto` 选择，并提供诊断输出。
  - 以 **Windows native API** 替换外部命令与 stub，降低暴露面并提升功能正确性。
  - 实现 **威胁情报远程查询**（OpenTIP/MetaDefender）与 `hybrid` 退化策略，落盘报告与元数据一致。
- Non-Goals（阶段一不做）
  - Prefetch/ShimCache/LNK 等深度取证解析（计划放入后续阶段）。
  - 攻击图谱 DOT/HTML 可视化（阶段二/三）。
  - 全量堆栈回溯与 Unbacked Code 检测（可作为 memscan 的后续增强点，但不作为阶段一硬交付）。

## Decisions

### Decision: 阶段一交付平台范围与默认启用策略

- **目标平台（阶段一验收范围）**
  - Windows: `amd64`（优先保证；`arm64` 仅保证 portable 路径可构建，native/memscan 不作为阶段一硬指标）
  - Linux: `amd64`、`arm64`（portable 必须可用；native 取决于 libyara/CGO 环境）
- **YARA 后端默认策略**
  - 默认 `backend=auto`：尽可能使用 `yara_native`（若构建 tag/依赖可用），否则回退 `portable`，并在 CLI/日志/诊断中输出明确回退原因。
  - `portable` 作为所有平台的保底路径（保持纯 Go 构建能力）。
- **memscan 默认策略**
  - `detect memscan` 为显式触发能力：阶段一不默认集成到 `respond/audit/inventory/baseline/bas` 的默认执行链路。
  - 运行时要求显式选择目标（`--pid` 或 `--all`），默认仅扫描 RWX（或等价高风险）region，并启用 guardrails（字节/region/时间上限）。
  - 非 Windows 平台在阶段一提供清晰的“不支持/已降级”行为（命令可见但提示不支持，避免静默缺失）。

### Decision: Memory scan 采用“region 级枚举 + 受控读取 + 规则扫描”的 guardrail 方案

- Windows 侧通过 `VirtualQueryEx` 枚举内存 region，并过滤 `MEM_COMMIT` + RWX（默认）。
- 对每个 region 进行 **分块读取**（例如 64KB/256KB）并累计上限，避免一次性读取大内存导致卡顿。
- 通过参数化限额（max-bytes/max-regions/timeout）控制扫描成本，并在达限后输出 `degraded` 标记与原因。

### Decision: 复用现有 `rules.Manager` 的 factory 注入机制实现 native YARA

`rules.Manager` 已支持 `RuleEngineFactory` 注入，可在 `yara_native` tag 下提供基于 libyara 的实现，同时保持 portable 路径不变：

- `portable`：继续走 `goengine.FromDirectory`。
- `native`：引入 libyara binding，编译规则并实现 `engine.RuleBundle.Scan`。
- `auto`：优先 native，失败时显式回退 portable 并记录原因（CLI + logs）。

### Decision: Threat Intel 采用“本地启发式永远可用，远程能力可选”的 hybrid 语义

- `local`：仅本地启发式。
- `hybrid`：本地启发式 +（若配置 key）远程查询；无 key 时不报错禁用，而是降级为 local 并输出 notice。
- `server`：不做远程查询；按既有逻辑上传 artifacts/token 交由 Server 编排。

### Decision: Threat Intel 数据源契约与 Server orchestrator 分工边界

#### 数据源与默认配置（对齐 Agent/Server）

- OpenTIP
  - 默认 `base_url`: `https://opentip.kaspersky.com/api/v1`
  - 配置项：`threat_intel.opentip_api_key`、`threat_intel.opentip_base_url`
  - 鉴权：HTTP Header `x-api-key: <key>`
- MetaDefender
  - 默认 `base_url`: `https://api.metadefender.com/v4`
  - 配置项：`threat_intel.metadefender_api_key`、`threat_intel.metadefender_base_url`
  - 鉴权：HTTP Header `apikey: <key>`

> 原则：Agent 与 Server 对外部数据源的默认 base_url 与鉴权头保持一致，且实现需支持通过配置覆盖；日志/诊断输出不得泄漏 API Key。

#### Endpoint 规范（用于 Agent 直连与 Server orchestrator 复用）

- OpenTIP
  - Hash lookup：`GET {base}/search/hash?request=<sha256>`
  - Sample scan：`POST {base}/scan/file`（`Content-Type: application/octet-stream`，可选 query `filename`）
- MetaDefender
  - Hash lookup：`GET {base}/hash/<sha256>`
  - Sample upload：`POST {base}/file`（`Content-Type: application/octet-stream` → 返回 `data_id`）
  - Poll result：`GET {base}/file/<data_id>`（直到 `progress_percentage >= 100` 或超时）

#### 配额/退避与 TTL

- 配额/退避：以 `HTTP 429` + `Retry-After` 为主信号；如服务返回 `X-RateLimit-*` 头，可作为预判辅助，但实现必须能在缺失该头时工作。
- Agent 缓存：以 `ThreatIntel.CacheTTL` 作为缓存上限（默认 24h）；如响应/头部提供更短 TTL，则优先采用更短值避免过期数据。
- Server 缓存：由 `ThreatIntel.VerdictTTL` 控制 verdict 过期（默认 24h），避免重复调度外部扫描。

#### 与 Server orchestrator 的分工边界

- `ti-mode=server`（Server 编排优先）
  - Agent **不直接调用** OpenTIP/MetaDefender。
  - Agent 通过 `/api/v1/artifacts/presign` + `/api/v1/artifacts/upload/{id}` 上传样本，写入 `metadata["threatintel.artifact_tokens"]`（JSON token 列表）并随 `ReportResult` 上报。
  - Server 在 `ReportResult` 中消费 `threatintel.artifact_tokens`，创建 Sample 并调用 `threatintel.Orchestrator.SubmitSample`，由 Server 侧 provider 执行外部扫描与 verdict 落库/TTL 管理。
- `ti-mode=local/hybrid`（Agent 直连优先）
  - Agent 对 IOC/文件 hash 执行本地启发式与（若配置 key）远程查询，生成可立即落盘的 findings。
  - 当 API Key 缺失或触发限额/不可用时，必须降级为本地启发式并输出可诊断 notice，不能因为情报模块失败而中断核心任务链路。

## Risks / Trade-offs

- **性能风险**：内存扫描可能造成 CPU/IO 抖动 → 通过限额、分块、默认仅 RWX、可选 PID 白名单缓解。
- **权限风险**：读取其他进程内存通常需要管理员权限 → 通过准确的特权检测与清晰提示降级。
- **供应链/构建复杂度**：native YARA 引入 CGO/libyara → 使用 build tags 隔离；默认仍可纯 Go 构建。
- **误报/敏感数据**：扫描内存可能包含敏感内容 → 默认不输出 raw bytes；证据保全需显式开启并做最小化输出。

## Migration Plan

1. 先落地 YARA backend 的 `auto/native/portable` 行为一致性与诊断命令，确保后续 memscan 可复用。
2. 落地 Windows memscan（RWX + guardrails + 报告格式），先以 CLI 形式交付；后续按需集成到 respond profile。
3. 完成 Windows 特权检测与 shell-free 采集替换，减少外部命令依赖。
4. 落地 Threat Intel 远程连接器与 hybrid 退化策略；完善测试矩阵与文档。

## Open Questions

- memscan 是否要默认集成到 `respond` 的某个 profile（例如新增 `fileless`/`deep`），还是保持独立命令？
- 内存扫描规则集是否需要从现有 `yaraRules` 中拆分出 “memory-safe” 子集，以降低误报与性能压力？
- native YARA 规则编译是否需要引入 `.yarac` 缓存（离线/加速），以及缓存的发布形态（build artifact vs embed）？
