## Why

当前 Agent 在“对抗性主机检测/响应”能力上仍存在明显短板，导致真实攻防场景中覆盖不足、排障成本高：

- **深度内存对抗缺失**：仅支持基于文件的 YARA 扫描（例如 `detect filescan/processcan`），缺少针对进程内存（RWX 段、注入载荷、fileless）的一线能力（参考 `docs/d-eyes_agent_enhance_plan.md` §2.1）。
- **Native API 与隐蔽性不足**：Windows 上仍存在少量外部命令依赖与权限判断 stub（例如 `ipconfig`、`net session`、`isPrivilegedUser`），在高对抗环境会增加暴露面、并影响功能准确性（参考 `docs/d-eyes_agent_enhance_plan.md` §2.6）。
- **威胁情报联动不完整**：当前 `pkg/threatintel` 仅提供本地启发式；`hybrid` 模式在缺失 API Key 时会被整体禁用，且未实现 OpenTIP/MetaDefender 的真实查询与 quota/退化逻辑，无法为 `respond/baseline/bas` 输出提供可复用情报结论（参考 `docs/d-eyes_agent_enhance_plan.md` §2.3）。

本变更聚焦“阶段一：核心能力补足”，以最小可落地的方式补齐上述 P0/P1 能力，并为后续阶段二（分布式协同、图谱等）预留扩展点。

## What Changes

- **新增进程内存扫描能力（P0）**：增加 `d-eyes detect memscan` 子命令（阶段一以 Windows 为主），支持按 PID 或全量进程扫描 RWX（或可配置）内存段，并复用现有 YARA 规则/风险评分输出结构化报告；默认不集成到 `respond/audit/...` 任务链路，需显式调用。
- **补齐 YARA 后端能力（P0）**：在不破坏现有 pure-Go 便携模式的前提下，引入可选 `yara_native`（libyara）后端，并完善 `auto` 选择/回退与诊断输出，使 CLI 展示的 backend 与实际一致。
- **Windows Native API 重构（P0）**：替换 Windows 侧少量外部命令依赖（如 `ipconfig`/`net session`）与权限判断 stub，统一改为 native/库调用，并确保资产探测的特权能力开关准确。
- **威胁情报联动增强（P1）**：实现 OpenTIP/MetaDefender 远程查询客户端（含超时、缓存、并发/配额控制），并修正 `hybrid` 模式在无 Key 时的退化策略（至少保留本地启发式）。

## Impact

- Affected specs:
  - `openspec/specs/agent-detect-engine/spec.md`（新增内存扫描能力要求）
  - `openspec/specs/agent-server-foundation/spec.md`（新增 shell-free 采集/特权判断与 hybrid 情报退化要求）
- Affected code (expected):
  - `agent/internal/detect/*`（新增 memscan + YARA backend/diag）
  - `agent/internal/assets/*`（Windows 特权判断、host discovery）
  - `agent/pkg/threatintel/*`、`agent/internal/tasks/*`（情报查询与结果落盘）
- Build/runtime considerations:
  - `yara_native` 模式将引入可选 CGO/libyara 依赖；未启用该 tag 时保持纯 Go 构建路径不变。
