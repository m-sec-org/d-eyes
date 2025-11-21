# Server 端测试盘点（Stage4）

本节聚焦 `server/internal` 五大关键模块，梳理现状、缺口与优先级，为后续补测提供依据。

## 1. API Handler (`server/internal/api/v1`)

### 现状
- 已有：`tasks_test.go`, `reports_test.go` 覆盖任务创建/查询、报告导出等路径。
- 缺失：`bas_scenarios.go`, `playbooks.go`, `plugins.go`, `certs.go`, `security.go`, `ops.go`, `threatintel.go` 等 handler 基本无测试。

### 缺口与优先级
| 模块 | 场景 | 黄色=中、红色=高 |
|------|------|------------------|
| BAS 场景 API | 发布/审批/激活 happy & error flows | 🔴 高：BAS 安全集控的核心入口 |
| Playbook API | 审批链、执行控制 | 🟠 中：RBAC/MFA 逻辑需验证 |
| Plugins API | 安装/回滚/事件流 | 🟠 中：确保插件市场稳定 |
| Certs/Security | TLS 轮换、MFA Secret 更新 | 🔴 高：安全功能回归风险 |
| ThreatIntel/Ops | 自愈、TI orchestrator | 🟡 低：主要用于运维，但建议覆盖基础校验 |

## 2. Scheduler (`server/internal/scheduler`)

### 现状
- `scheduler_test.go` 涵盖 Lease/Retry/Timeout 等核心逻辑。
- 仍缺：BAS 并发限制、混沌（队列延迟）、Task Hub 事件推送等场景。

### 缺口与优先级
- 🔴 高：BAS max concurrency + approval gating（确保 `IsScenarioApproved` 路径有回归测试）。
- 🟠 中：Streams/Hub 事件、Audit/Alert 记录。
- 🟡 低：Self-heal / backlog metric 更新（可在混沌脚本中覆盖）。

## 3. Store (`server/internal/store`)

### 现状
- `memory_store.go` 部分结构具备测试，但缺乏针对 Postgres 实现的集成测试。
- 关键 SQL（BAS Scenario、Playbook、Task results）未在单元测试中校验。

### 缺口与优先级
- 🔴 高： `postgres/bas.go`, `postgres/playbook.go`, `postgres/results.go` 针对 JSONB/审批记录的序列化逻辑。
- 🟠 中：`store` 接口的错误传播（确保 ErrNotFound/ErrInvalidStatus）。
- 🟡 低：`memory_store` 仅用于单测，可按需补充。

## 4. BAS Scenarios Manager (`server/internal/basscenarios`)

### 现状
- 当前无单元测试。

### 缺口与优先级
- 🔴 高：审批流 `UpdateApproval`、`Publish`、`Clone`、`SetStatus` 需要覆盖 happy path + invalid transitions。
- 🟠 中：`ensureApprovalRecords`、`IsScenarioApproved`、`cache` 逻辑需要验证。

## 5. gRPC Service (`server/internal/grpcsvc`)

### 现状
- `service_test.go` 覆盖注册/心跳/任务拉取的基础流程。

### 缺口与优先级
- 🟠 中：Agent 断连/heartbeat failover + TLS/mTLS 验证（配合 Stage4 安全增强）。
- 🟡 低：Artifact upload/stream 错误场景。

---

## 行动优先级总结
1. **BAS Manager + API handler（BAS/Certs）**：阻断回归风险，优先编写单元测试。
2. **Scheduler (BAS gating + Streams)** & **Store (Postgres)**：确保 CI 具备关键断言与覆盖率。
3. **Plugin/Playbook API 与 gRPC 扩展场景**：在基础完成后补充。

建议在接下来的任务中按以上顺序实现测试，并同步更新 `scripts/test-matrix.sh` 及 CI 报告。
