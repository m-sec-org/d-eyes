# Advanced Security & Automation Design

## Goals & Non-Goals
- **Goals**
  - 满足阶段三目标：威胁情报、异常检测、自动化响应、合规管理、可视化、BAS 场景管理。
  - 将 OpenTIP (`https://opentip.kaspersky.com/api/v1`) 与 MetaDefender (`https://api.metadefender.com/v4`) 接入 Agent/Server，覆盖 IOC 查询与恶意样本重扫。
  - 构建统一的行为事件管道，实现异常检测、关联分析与 Playbook 触发。
  - 前后端共享的合规/报表/可视化契约，驱动 Ops Console 真正联动 Server。
- **Non-Goals**
  - 不在本阶段落地 ML 训练平台；异常检测优先基于规则 + 统计模型，后续再引入 ML。
  - 不重写 Agent CLI 主流程；新增能力以插件/任务扩展方式融入。

## 1. Threat Intelligence Fabric

### 1.1 Connector 能力
| 平台 | 关键 REST | 认证 | 备注 |
|------|-----------|------|------|
| OpenTIP | `GET /api/v1/search/hash?request=<sha>`、`GET /api/v1/search/ip|domain|url`、`POST /api/v1/scan/file?filename=<sha>` | `x-api-key` | `OpenTIP-scanner` 客户端显示可选上传（默认上传未知文件）；最大 10 MB 上传窗口，可通过 `--no-upload` 禁止 |
| MetaDefender Cloud v4 | `POST /v4/file`（二进制）、`GET /v4/file/{data_id}`、`GET /v4/hash/{sha}`、`POST /v4/hash`、`GET /v4/ip/{ip}` | `apikey` header；`X-RateLimit-*` 报头提供配额信息 | `mdcloud-go` 客户端演示了速率限制、poll 机制与 sanitized download |

### 1.2 Agent 工作流
1. **ThreatIntel SDK**：在 `agent/pkg/threatintel` 下实现 connector 抽象，支持：
   - `Lookup(hash|ip|domain|url, sourcePolicy)`：带缓存与回退；缓存层为本地 LRU + sqlite，可配置 TTL。
   - `ScanFile(path, policy)`：决定直接上传（OpenTIP/MetaDefender）还是标记“需要上送 Server”。
   - 统一的 `RateLimiter`，结合 OpenTIP `429` 与 MetaDefender `X-RateLimit-Remaining`。
2. **任务集成**：
   - Respond/Baseline：当命中高危 IOC 或未知文件时，调用 `Lookup`，并把 verdict/score 写入任务摘要。
   - `--ti-mode local|server|hybrid`：`local` 表示 Agent 直接调用外部 API；`server` 表示只计算 hash 并把 artifact 上传 Server，由 Server 执行外部查询；`hybrid` 根据文件大小/配额动态选择。
3. **Artifact 上传协议**：
   - 复用 `ReportResult` 的 `Artifact`，但为大文件新增 `UploadArtifact` 流程：Agent 先调用 Server `POST /api/v1/artifacts/presign` 获取临时 URL，再将加密压缩包上传，最后在 `ReportResult` 中附带 metadata（hash、size、encryption）。
   - 支持 chunked 上传（gRPC streaming 或 HTTP multipart），保证 50MB+ 样本也可传输。

### 1.3 Server ThreatIntel Orchestrator
```
Agent ──(artifact/pointer)──> Artifact Store (S3/MinIO + envelope encryption)
      └─(metadata)──────────> gRPC ReportResult
                                   │
                                   ▼
                          ThreatIntel Queue (Kafka topic `ti.jobs`)
                                   │
                          Workers (per source)
             ┌─────────────────────┴─────────────────────┐
             ▼                                           ▼
      OpenTIP Worker                              MetaDefender Worker
 (hash lookup + file scan)                (POST /file → poll GET /file/{data_id})
             │                                           │
             └────────────► Verdict DB ◄─────────────────┘
                                   │
                           Result Fan-out
                             │          │
                        Task summary    SSE/WS (`/threat-intel/stream`)
```
- **Workers**：使用共享 backoff、幂等 key（hash），并记录 `queue_jobs`, `success`, `failed`, `rate_limited` 指标。
- **Verdict Store**：PostgreSQL 表（`threat_ioc`、`threat_sample`），字段包含 `source`, `classification`, `confidence`, `ttl`, `task_id`。
- **API**：
  - `POST /api/v1/threat-intel/lookup`：查询缓存或触发新扫描。
  - `GET /api/v1/threat-intel/iocs/:hash`：返回多源结果 + 关联任务/主机。
  - `GET /api/v1/threat-intel/samples/:id`：返回文件扫描进度、报告下载链接。

### 1.4 安全 & 合规
- API 密钥存储在 Server 端 Vault/KMS，Agent 仅在 `ti-mode=local` 时读取用户自定义 key。
- Artifact 上传默认开启 AES-256-GCM 加密；Server 端持有 DEK（KMS envelope），并设置生命周期（默认 30 天）。
- 全链路审计：记录谁触发了查询/上传、外部 API 响应码、Playbook 是否因为 verdict 被触发。

## 2. 行为异常检测 & 关联分析

### 2.1 数据采集
- Agent 在 `ReportResult` 元数据中追加：
  - `process_tree`（压缩 JSON）、`net_connections`、`resource_usage`、`user_sessions`。
  - 心跳中附带 `latency_ms`, `cpu_percent`, `blocked_actions`。
- 这些事件通过 Server 的 `streams` 模块推送到 Kafka（或 Redis Streams）Topic：`behavior.events`, `heartbeat.metrics`, `bas.steps`.

### 2.2 Behavior Graph Service
- **Ingestion Worker**：消费事件 → 归一化 → 写入
  - 熔断：单 Agent 超过 QPS 限制会降级为采样。
  - 数据落地：PostgreSQL + TimescaleDB (时序) 存基础指标，Elastic/Opensearch 存全文日志，Neo4j/JanusGraph 存关联图。
- **Detection Engine**
  - 规则层：YARA-L + Sigma-like DSL（例如“同一主机 5 分钟内出现在 3 个黑名单 IP”）。
  - 统计层：滑动窗口 + Z-score/ MAD, 支持 `baseline` 训练（7 天滚动）。
  - 输出 `anomaly_event`（id、score、entities、linked_task、linked_ioc）。
- **Correlation API**
  - `GET /api/v1/anomalies?agent_id=&ioc=&task_id=`。
  - `GET /api/v1/anomalies/:id/graph`：返回 nodes/edges 供前端画 Attack Path。
  - SSE：`/api/v1/anomalies/stream` 推送 `created|updated|closed` 事件。

## 3. 自动化响应 & Playbook

### 3.1 DSL 与存储
```yaml
id: isolate-ransomware
trigger:
  type: threat_intel.verdict
  filter:
    source: opentip
    confidence: high
conditions:
  - agent.labels.env == "prod"
approvals:
  - role: security.lead
    timeout: 30m
actions:
  - type: notify
    target: slack://sec-ops
  - type: task.dispatch
    task_type: respond
    payload:
      profile: ransomware
  - type: agent.command
    command: isolate_process
    args:
      pid: "{{ event.metadata.pid }}"
rollback:
  - type: agent.command
    command: resume_process
```
- 存储：`playbook` 表（版本、状态、approver、最近执行），`playbook_run` 表记录事件链。

### 3.2 Runtime
1. Trigger Listener 订阅 ThreatIntel、Anomaly、Task 状态事件。
2. Rule Evaluator 匹配触发条件 -> 创建 PlaybookRun。
3. Approval Workflow（整合现有 RBAC/Audit）：
   - 通过 `POST /api/v1/playbooks/{id}/approve` 完成；支持多级审批与超时自动拒绝。
4. Action Dispatcher：
   - `task.dispatch`：调用现有任务 API。
   - `agent.command`：新增 gRPC `ExecuteAction`（按 Agent capability 执行隔离/封锁等），带幂等 `action_id`。
   - `http.webhook`：用于外部系统。
5. 状态反馈至 SSE/WS + 审计日志。

### 3.3 前端
- Playbook Builder：基于拖拽/表单的 DSL 编辑器，实时校验。
- 审批/执行控制台：显示触发事件、审批链、动作结果、回滚按钮。
- RBAC：新增 `playbook.create`, `playbook.approve`, `playbook.execute`.

## 4. 合规管理 & 报表

### 4.1 控制项模型
- 表：`compliance_framework`（如 CIS v8）、`compliance_control`（控制项，字段：id, title, severity, framework_id）、`control_mapping`（控制项 ↔︎ 任务检测项/Playbook）。
- Agent/Server 在任务结果中附带 `control_evidence`（检测项 id、结果、证据链接）。

### 4.2 API & 报表
- `GET /api/v1/compliance/frameworks`，`GET /api/v1/compliance/gaps?framework_id=...`
- `POST /api/v1/compliance/findings/:id/remediation` 记录整改进度。
- 报表服务 `POST /api/v1/reports` 支持 `template_id`（新增合规模板）、`format=pdf|html|json`、`locale`.
- 生成的报告存储在对象存储，带签名分享 token（支持失效时间、一次性下载）。

### 4.3 前端
- 仪表盘：按框架展示合规得分、开放风险、整改进度。
- 差距矩阵：行=控制项，列=站点/系统，支持过滤/导出。
- 整改追踪：甘特/时间线模式，联动 Playbook/任务工单。

## 5. BAS 场景编排与可视化

### 5.1 场景仓库
- Server `basscenarios` 模块扩展：
  - 场景实体：版本、步骤列表（引用 Agent JSON）、依赖、所需标签、资源配额、安全边界、审批策略。
  - 审批：与 Playbook 审批共享组件，支持多级 reviewer。
  - 运行计划：支持串行/并行步骤、跨 Agent 分发、超时/重试。
- API：`POST /api/v1/bas-scenarios`、`POST /api/v1/bas-scenarios/{id}/publish|approve|clone`、`POST /api/v1/tasks` type=`bas.advanced`.

### 5.2 Agent 增强
- `basRunner` 记录每个步骤的 stdout/stderr、沙箱使用、fallback、耗时、风险等级，实时推送到 SSE。
- 新的 `step hook`：在步骤开始/结束时调用 server `PATCH /bas-runs/{run_id}/steps/{step_id}`，用于实时进度。

### 5.3 可视化
- Server 生成 Attack Path Payload（nodes: assets/processes, edges: 操作/IOC），前端使用 DAG/桑基图渲染。
- 场景编排器：拖拽步骤、定义条件/变量、引用情报或 Playbook 输出。

## 6. 性能、扩展性与可观测性
- **缓存策略**：Agent LRU + Server Redis；ThreatIntel、Anomaly、Compliance 均优先命中缓存。
- **队列/并发控制**：ThreatIntel 与 Playbook Worker 池可根据配额动态扩缩容；BAS 任务队列独立（防止占满 respond）。
- **观测**：Prometheus 指标涵盖 API 延迟、队列堆积、外部 API 状态；Grafana Dashboard + Alertmanager。
- **压测**：模拟 1k Agent、每小时 2k 情报查询 + 200 Playbook 触发 + 20 BAS 运行，验证 SLO。

## 7. 前端契约与集成
- 所有新 API 需提供 zod schema，MSW mock 将下线，改为可切换真实 API（`VITE_USE_MSW=false`）。
- SSE/WS 通道：
  - `/api/v1/threat-intel/stream`
  - `/api/v1/anomalies/stream`
  - `/api/v1/playbooks/stream`
  - `/api/v1/bas-runs/:id/stream`
- 组件：
  - Threat Intel 控制台：IOC 搜索、Verdict 时间线、文件扫描表。
  - Automation Studio：Playbook builder + 运行面板。
  - Compliance Workspace：仪表盘、差距矩阵、整改任务板。
  - BAS Workbench：场景编排、执行时间线、攻击链图。

## 8. 交付阶段（建议）
1. **Milestone A (月 1-2)**：完成 ThreatIntel SDK + Orchestrator、Artifact 流水线、基础前端视图。
2. **Milestone B (月 2-3)**：行为事件管道、异常检测、ThreatIntel ↔︎ Anomaly 可视化。
3. **Milestone C (月 3-4)**：Playbook 引擎、自动响应动作、合规控制项模型。
4. **Milestone D (月 4-5)**：BAS 场景管理、攻击链可视化、性能调优、全链路观测。
