# Detect 远程调度指南（`detect.diag` / `detect.memscan`）

本文说明如何通过 D-Eyes Server 下发 detect 任务到 Agent（remote 模式），并通过 Server 的 report/read API 查看结果与排障。

## 1. 前置条件

### 1.1 Server：Task Catalog seed（profile/schema）

Server 在启动时若 task catalog 为空，会自动导入内置 seed（包含 `detect.diag` 与 `detect.memscan` 的 task type + profile schema），用于在 `POST /api/v1/tasks` 阶段校验 `payload` 形态。

建议生产启用持久化（否则重启后 catalog 会回到空并再次导入 seed）：

```yaml
task_catalog:
  persist_path: "/var/lib/d-eyes/task_catalog.json"
```

验证 seed 是否可用：

```bash
# task types（应包含 detect.diag / detect.memscan）
curl -H 'X-API-Key: changeme' http://SERVER:8080/api/v1/task-types

# profiles（应至少各有 1 个 seeded profile）
curl -H 'X-API-Key: changeme' "http://SERVER:8080/api/v1/task-profiles?task_type=detect.diag"
curl -H 'X-API-Key: changeme' "http://SERVER:8080/api/v1/task-profiles?task_type=detect.memscan"

# 查看具体 profile schema（用于对齐 payload 结构）
curl -H 'X-API-Key: changeme' http://SERVER:8080/api/v1/task-profiles/detect.diag
curl -H 'X-API-Key: changeme' http://SERVER:8080/api/v1/task-profiles/detect.memscan
```

### 1.2 Agent：remote 模式 + capabilities

- `detect.diag`：全平台可宣称并可被远程调度。
- `detect.memscan`：**Windows-only**，且 Agent 必须显式 opt-in 才会宣称该 capability（否则 Server 不应调度）。

在 Agent 配置中启用 opt-in（**必须是字符串 `true`**）：

```yaml
remote:
  enabled: true
  labels:
    allow_memscan: "true"
```

> 注意：Server 侧对 Agent labels 的手工编辑不应被视为持久的控制信号；Agent 下次 Register 会用本地配置覆盖回写。若要启用/禁用 memscan，请修改 Agent 本地配置并重启/等待重注册。

### 1.3 Ops Console（前端）入口与操作要点

本指南的 API 示例可用 `curl` 复现；若通过 Ops Console（Web 前端）操作，建议按以下路径验证链路：

- **任务创建入口**：左侧导航「任务」→ 点击「创建」打开创建抽屉 → 选择 `detect.diag` / `detect.memscan` 的 task type 与 profile → 填写 payload 并提交。
  - UI 会按 task catalog schema 渲染字段，并在 `POST /api/v1/tasks` 时默认写入 `metadata.required_capabilities`（优先使用 catalog `capabilities[]`）。
- **报告查看入口**：在任务详情抽屉中查看 `exit_code` / `error_code` / 报告结构化结果。
  - 报告读取依赖 `/api/v1/tasks/{id}/audit/report`、`/api/v1/tasks/{id}/detect/report`，需要 `reports.view` 权限；若无权限会显示 403 提示；报告未产出会显示 404 提示。
- **Agent 标签入口**：左侧导航「Agent」→ 列表中点击「标签」。
  - UI 会明确提示：Server-side label edits **非权威**（可能被下次 Agent Register 覆盖）。
  - `allow_memscan` / `mode` / `build.*` 属于保留键（Agent-managed），UI 会以只读方式高亮并限制编辑；如需变更应修改 Agent 本地配置 `remote.labels.*`。

## 2. 下发 `detect.diag`（低风险诊断）

### 2.1 创建任务

建议创建任务时显式设置 `metadata.required_capabilities`，让调度器做 capability filtering（避免下发到不支持该任务的 Agent）。

> 兼容性说明：若 `metadata.required_capabilities` 缺省且 task type 可在 catalog 中解析到 `capabilities[]`，Server 会自动补齐默认值（不影响显式传入者）。

```bash
curl -X POST http://SERVER:8080/api/v1/tasks \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: changeme' \
  -d '{
        "type": "detect.diag",
        "profile": "detect.diag",
        "priority": 1,
        "payload": {
          "backend": "auto",
          "rule": "",
          "timeout": "1m"
        },
        "metadata": {
          "required_capabilities": "detect.diag"
        }
      }'
```

说明：
- `backend`：`auto|native|portable`（seed schema 会校验）。
- `rule`：自定义规则路径；空表示使用内置规则集。
- `payload.timeout`：Go duration（例如 `30s`/`1m`/`2m`），由 Agent 侧解析并作为任务超时。

### 2.2 查看报告

任务执行完成后，读取 detect 报告：

```bash
curl -H 'X-API-Key: changeme' http://SERVER:8080/api/v1/tasks/<TASK_ID>
curl -H 'X-API-Key: changeme' http://SERVER:8080/api/v1/tasks/<TASK_ID>/detect/report
```

- `GET /api/v1/tasks/{id}/detect/report` 需要 `reports.view` 权限，并会落审计事件 `report.read`。
- 报告响应中 `result.outputs[]` 会返回报告文件路径（**Agent 本地路径**）。当前 Server 不提供通用 artifacts 下载面；如需集中回收，需要后续引入通用上传/下载与配额策略。

## 3. 下发 `detect.memscan`（高风险，Windows-only + 审批）

### 3.1 调度 gating（必须设置 `required_capabilities`）

建议创建 `detect.memscan` 任务时设置：

- `metadata.required_capabilities = "detect.memscan"`

这样调度器只会把任务 lease 给宣称 `detect.memscan` capability 的 Agent（Windows + `allow_memscan=true`）。

### 3.2 审批 metadata（Agent 强制校验）

Agent 在执行 `detect.memscan` 前会强制检查任务 metadata（字符串布尔值，推荐用 `true`/`false`）：

- 必需：
  - `memscan_approval_required = "true"`
  - `memscan_approved = "true"`
- 当请求生成证据（`evidence=true` 或 `minidump=true`）时额外必需：
  - `memscan_evidence_approved = "true"`

审批缺失/不通过时：
- Agent 会拒绝执行并返回 `exit_code=65`
- `error_code` 建议值：
  - 缺少基础审批：`detect.memscan.approval_required`
  - 缺少证据审批：`detect.memscan.evidence_approval_required`

Ops Console 行为（对齐口径）：
- UI 会在创建表单中强制校验：`pid` 与 `all` 必须二选一；且提交前必须显式勾选审批字段（`evidence/minidump` 会触发额外审批）。
- 若任务执行后返回上述 `error_code`，任务详情会给出可操作建议（补齐审批字段，或关闭 `evidence/minidump` 重新下发）。

### 3.3 创建任务示例（不含证据，扫描指定 PID）

```bash
curl -X POST http://SERVER:8080/api/v1/tasks \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: changeme' \
  -d '{
        "type": "detect.memscan",
        "profile": "detect.memscan",
        "priority": 1,
        "payload": {
          "pid": 1234,
          "backend": "auto",
          "rule": "",
          "rwx_only": true,
          "max_bytes": 33554432,
          "max_regions": 128,
          "evidence": false,
          "minidump": false,
          "timeout": "2m"
        },
        "metadata": {
          "required_capabilities": "detect.memscan",
          "memscan_approval_required": "true",
          "memscan_approved": "true"
        }
      }'
```

> 目标选择约束：`pid` 与 `all` 必须二选一（seed schema 使用 `xor(pid, all)` 约束表达该语义）。

### 3.4 创建任务示例（启用 evidence/minidump）

```bash
curl -X POST http://SERVER:8080/api/v1/tasks \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: changeme' \
  -d '{
        "type": "detect.memscan",
        "profile": "detect.memscan",
        "priority": 1,
        "payload": {
          "pid": 1234,
          "evidence": true,
          "minidump": true
        },
        "metadata": {
          "required_capabilities": "detect.memscan",
          "memscan_approval_required": "true",
          "memscan_approved": "true",
          "memscan_evidence_approved": "true"
        }
      }'
```

证据保全说明：
- 默认 `evidence=false`、`minidump=false`（远程调度默认不生成敏感 artifacts）。
- 即使启用 evidence/minidump，产物也默认 **仅在 Agent 本地落盘**，并通过 `result.outputs[]` 返回路径；Server 默认不会上传/集中存储这些文件。

## 4. error_code 与排障建议（Ops Console 口径）

Ops Console 会在任务详情中展示 `exit_code` / `error_code` / `result.error`，并按“可操作动作”给出指引。以下为常见口径：

| error_code / 状态 | 含义（简述） | 建议动作 |
|---|---|---|
| `detect.memscan.approval_required` | 缺少基础审批 metadata | 重新下发任务并补齐 `memscan_approval_required/memscan_approved`（或由具备权限的人员审批后再下发） |
| `detect.memscan.evidence_approval_required` | 缺少证据/转储审批 metadata | 补齐 `memscan_evidence_approved`，或关闭 `evidence/minidump` 重新下发 |
| `agent.remote_execution_failed`（或 `agent.*`） | Agent 侧远程执行失败 | 确认 Agent 在线/网络可达，查看 Agent 日志与运行时依赖（Runner/插件/权限），必要时重启并重试 |
| HTTP 403（读取 report） | 缺少 `reports.view` 权限 | 申请权限或切换具备权限的角色 |
| HTTP 404（读取 report） | 报告尚未产出/summary 不可用 | 等待任务完成后重试；必要时查看 task `last_run` 与调试信息 |

排障技巧：
- 若需要更多上下文，建议在任务详情的调试区展开查看 `result.metadata`、`run_metadata`（必要时可展开 `result`/`result.summary` 全量 JSON）以辅助复现与定位。

## 5. 权限 / RBAC 建议（控制面口径）

- Server 侧已提供：
  - 创建任务：`tasks.create`
  - 读取报告：`reports.view`（`/audit/report`、`/detect/report` 等 report/read 面一致）
- 对 `detect.memscan` 的建议（高敏能力）：
  - 在上层控制台或自定义 RBAC 策略中，将“创建/下发 memscan”收敛到专用权限（建议命名 `detect.memscan.execute`），并要求人工审批后才允许写入 `memscan_*` metadata。
  - 对 evidence/minidump 再单独加一道更高权限（建议命名 `detect.memscan.evidence`），避免运维误开敏感产物。
