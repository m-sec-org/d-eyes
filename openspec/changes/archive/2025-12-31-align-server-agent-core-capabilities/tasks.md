## 0. Research & Alignment
- [x] 0.1 盘点 `add-agent-stage-one-core-capabilities` 中落地的 Agent 任务面与约束（core tasks + profile/flags/metadata），形成对齐矩阵（Agent/Server/Docs）。
- [x] 0.2 盘点 Server 侧现有 report/read API 覆盖范围与缺口（尤其是 `audit` 等 core task）。
- [x] 0.3 明确 task catalog 的“seed 导入”策略（首次启动导入/持久化优先/不覆盖用户自定义）。
- [x] 0.4 确定 detect 远程调度模型：task type 命名（`detect.diag`/`detect.memscan`）、Windows-only 能力广告、以及 memscan 的权限/审批/证据保全默认值。

## 1. Specs（对齐合同）
- [x] 1.1 在 `server-core` spec delta 中新增 “Seeded Task Catalog for Core Tasks” 要求与场景。
- [x] 1.2 在 `server-core` spec delta 中新增或修改 “Core Task Report Surface” 要求，覆盖 `audit`/`detect` 等任务。
- [x] 1.3 在 `server-core` spec delta 中补齐 detect 远程调度要求：task catalog seed（profiles/schema）与结果读取面（report/read）。
- [x] 1.4 在 `agent-server-foundation` spec delta 中补齐/修订 Register metadata.version 的语义（必须与 CLI 版本一致）与可选 build 信息字段，并定义 detect 远程调度语义（尤其是 memscan Windows-only）。

## 2. Server Implementation
- [x] 2.1 增加内置 task catalog seed（task types + profiles），并在 Server 启动时对空 catalog 执行一次性导入（不覆盖已有数据）。
- [x] 2.2 补齐 `audit` 的 report 读取/聚合 API（或提供通用 report endpoint 兜底），并对齐 RBAC 与审计记录。
- [x] 2.3 增加 `detect` 的 report 读取/聚合 API（至少覆盖 `detect.diag`/`detect.memscan` 结果），并对齐 RBAC 与审计记录。
- [x] 2.4 增加必要的回归测试：seed 导入幂等、已有 catalog 不覆盖、audit/detect report endpoint 结构稳定。

## 3. Agent Implementation
- [x] 3.1 Remote 注册上报 version 改为 CLI 版本（并可选附带 commit/build tags），补充单测/contract 测试断言。
- [x] 3.2 校验 Agent 上报 capabilities 与 Server core task types 命名一致（含 `audit/action`），必要时补齐/规范化。
- [x] 3.3 增加 detect 远程执行入口：为 `detect.diag`/`detect.memscan` 提供可被 remote runner 调度的任务实现（不影响现有 `d-eyes detect ...` CLI 子命令），并确保 memscan 仅在 Windows builds 宣称 capability。

## 4. Contract / E2E Tests
- [x] 4.1 增加/更新 agent↔server contract 测试：覆盖 `audit` 与 `detect.diag` 任务从 REST 创建 → gRPC Lease → Agent 执行 → ReportResult → Server report/read 的闭环。
- [x] 4.2 增加 best-effort Windows 端到端回归：`detect.memscan` 远程调度可成功落盘并被 Server 查询（非 Windows 平台应被能力过滤或明确拒绝）。

## 5. Docs
- [x] 5.1 更新 Server/Agent 运维文档：解释 core task types、profile 与 task catalog seed 的关系，以及如何通过 API/配置扩展/覆盖默认 catalog。
- [x] 5.2 补充 detect 远程调度指南：如何下发 `detect.diag`/`detect.memscan`、如何查看报告、以及权限/审批建议。
