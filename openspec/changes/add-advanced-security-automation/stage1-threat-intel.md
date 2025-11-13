# Stage 1 – Threat Intelligence & Artifact Pipeline Plan

## 1. Scope & Objectives
- **Deliverables**: 双情报引擎（OpenTIP + MetaDefender）SDK、Agent 端策略控制、可疑样本上送协议、Server ThreatIntel Orchestrator、REST/SSE API、Ops Console 情报工作台初版。
- **Success Criteria**
  1. Agent 可以在 `ti-mode=local|server|hybrid` 下完成 IOC 查询、文件上传，并把 verdict/警告写入任务摘要。
  2. Server 能够接收 artifact、调度双引擎扫描、缓存 verdict 并通过 `/api/v1/threat-intel/*` / SSE 推送状态。
  3. 前端可以查询 IOC、查看样本扫描进度和相关任务。
  4. 全链路具备重试、速率控制、审计、加密存储与最少 500 并发查询的性能保障。

## 2. Architecture Overview
```
┌────────┐    lookup/scan    ┌──────────────┐
│ Agent  │ ────────────────► │ ThreatIntel  │
│ (SDK)  │ ◄───────────────  │ Orchestrator │
└────────┘   verdict/cache   └─────┬────────┘
    │                               │
    │ artifacts (encrypted)         │ queue jobs
    ▼                               ▼
┌─────────┐                   ┌─────────────┐
│ Artifact│  presign/upload   │ Workers     │──► OpenTIP API
│ Store   │◄────────────────► │ (OpenTIP/   │──► MetaDefender API
└─────────┘                   │ MetaDef.)   │
                               └────┬────────┘
                                    │
                         verdict db / SSE / REST
```

### 2.1 Agent Components
- `pkg/threatintel`：`Client` 接口 + `opentipConnector`、`metadefConnector` 实现。
- `CacheLayer`：LRU + sqlite（持久 24h），key=`source|type|indicator`。
- `RateLimiter`：基于 `golang.org/x/time/rate` + Header 反馈（MetaDefender `X-RateLimit-Remaining`, `X-RateLimit-Reset-In`）。
- `ArtifactUploader`：
  1. 调用 `POST /api/v1/artifacts/presign`（参数：hash、size、content-type、encryption）。
  2. 使用返回的 PUT URL 上传 AES-256-GCM 加密包（chunked，5 MB）。
  3. 调用 `ReportResult` 时在 metadata 中附带 `artifact_id`, `hash`, `ti_mode`.
- 任意 Respond/Baseline/BAS 任务在命中条件时：`Lookup` →  verdict else `Escalate`.

### 2.2 Server ThreatIntel Orchestrator
- **API Extensions**
  - `POST /api/v1/artifacts/presign`
  - `POST /api/v1/threat-intel/jobs`（Agent/Server 内部使用）
  - `GET /api/v1/threat-intel/iocs/:indicator`
  - `GET /api/v1/threat-intel/samples/:id`
  - `GET /api/v1/threat-intel/stream` (SSE)
- **Services**
  - `ArtifactStore`：MinIO/S3 兼容 + envelope encryption (KMS)。
  - `JobQueue`：Kafka topic `ti.jobs`（fallback Redis streams）。
  - `WorkerPool`：每源 5 worker，自动 backoff；OpenTIP Worker 负责 `GET search`, `POST scan/file`；MetaDefender Worker 负责 `POST /file` + polling。
  - `VerdictDB`：PostgreSQL tables (`threat_ioc`, `threat_sample`, `artifact_upload`)，附 TTL。
  - `Notifier`：推送 SSE + 触发 playbook event bus。

### 2.3 Frontend Integrations
- 新增 `ThreatIntelService`（axios + zod）对应 REST/SSE。
- Threat Intel Workspace UI：
  - IOC 搜索表单 + 结果卡片（多源 verdict）。
  - 样本进度面板（OpenTIP/MetaDefender 状态、下载/禁止按钮）。
  - 关联任务列表、操作审计。

## 3. Workstreams & Task Breakdown

| Task | Description | Owner | Outputs |
|------|-------------|-------|---------|
| 1.1 TI SDK | 连接器 + 缓存 + 速率控制 + config flags (`ti-mode`, `opentip.api_key`, `metadefender.api_key`) | Agent | `pkg/threatintel`, config schema, unit tests |
| 1.2 Task Integration | Respond/Baseline/BAS hooking + policy (local/server/hybrid), severity mapping | Agent | updated runners, docs |
| 1.3 Artifact Protocol | Pre-sign API + uploader + encryption helper + metadata schema (`artifact_id`, `hash`, `encryption_profile`) | Agent/Server | presign handler, server config, integration tests |
| 1.4 Orchestrator | Artifact ingestion, queue, dual workers, verdict store, SSE broadcast, metrics | Server | new modules `threatintel`, migrations, worker deploy manifests |
| 1.5 Frontend Workspace | API SDK, IOC search UI, status timeline, SSE consumption | Frontend | new pages/components, e2e mocks |

## 4. Timeline & Milestones
1. **Week 1**: finalize configs, implement TI SDK + unit tests (Task 1.1).
2. **Week 2**: integrate tasks & artifact uploader; deliver presign API + server storage (Tasks 1.2–1.3).
3. **Week 3**: build Orchestrator workers, migrations, SSE; bench against 500 concurrent jobs (Task 1.4).
4. **Week 4**: Frontend workspace + end-to-end smoke tests; observability dashboards; doc updates (Task 1.5).

## 5. Security, Compliance & Observability
- **Secrets**：Server 端通过 Vault/KMS 管理 API key；Agent 仅在 local mode 读取本地配置。
- **Encryption**：Artifact AES-256-GCM + per-upload DEK；DEK 由 Server KMS 生成并通过 presign API 返回。
- **Audit**：记录 `lookup`, `scan`, `artifact_upload`, `verdict_publish` 事件（actor, indicator, source, status, latency）。
- **Metrics**：Prometheus counters for job queue depth, worker success/failure, API latency、cache hit率。
- **Rate/Limits**：configurable concurrency per source；agent fallback when HTTP 429/5xx。

## 6. Risks & Mitigations
| Risk | Impact | Mitigation |
|------|--------|------------|
| 外部 API 速率受限或故障 | 阻塞任务 | 双缓存 + exponential backoff + 失败重试（最大 3），同时 fallback 到另一引擎 |
| 大文件上传占用带宽 | 任务延迟 | 采用 chunked + gzip 压缩，限制并发 + 配额提示 |
| 敏感样本泄露 | 合规风险 | 强制加密、KMS、严格 RBAC + 审计、可配置自动删除 |
| 前端 SSE 断连 | UI 信息不一致 | SSE 自动重连 + 保存最近状态 via Zustand store |

## 7. Validation Plan
1. **Unit Tests**：Connector mock (HTTP test server) covering success, 401/429, malformed JSON。
2. **Integration Tests**：
   - Agent ↔ Server artifact 上传（包含故障重试）。
   - Worker hitting mocked OpenTIP/MetaDefender endpoints。
3. **Load Test**：模拟 1k artifact uploads + 500 并发 IOC lookup，验证 queue < 2k backlog、p95 < 5s。
4. **Security Review**：加密密钥流转、API key 存储、自签证书/TLS 校验。
5. **UX Validation**：Threat intel workspace 2 flows（IOC 查询、样本追踪），含 accessibility review。

## 8. Implementation Checklist & Review Notes

| # | 交付内容 | 主要实现步骤 | 完成验证 & 点评 |
|---|----------|--------------|-----------------|
| 1.1 | Agent ThreatIntel SDK | `pkg/threatintel`: 抽象接口 + OpenTIP/MetaDefender connector；`pkg/cache` LRU/sqlite；`pkg/config` 新增 `ti_mode` 与 API key | 单元测试覆盖 401/429/5xx；压测确保缓存命中率 >80%；代码评审关注 API key 安全与并发锁 |
| 1.2 | 任务集成策略 | Respond/Baseline/BAS runner 注入 SDK；根据策略分支（local/server/hybrid）；在任务 summary 中写入 verdict/警告 | E2E 测试：模拟命中高危 IOC、未知文件；确保 fallback 时 artifact 标记正确；评审侧重失败可观测性 |
| 1.3 | Artifact 上传协议 | Server `POST /api/v1/artifacts/presign` (KMS/DEK)；Agent `ArtifactUploader`（AES-256-GCM + chunked PUT）；`ReportResult` metadata 扩展 | 集成测试验证上传失败重试、哈希校验、DEK 生命周期；安全评审确认加密/日志不泄露 |
| 1.4 | ThreatIntel Orchestrator | 新增 `artifact store` 接口、`ti.jobs` 队列、OpenTIP/MetaDefender worker、Verdict DB、SSE (`/threat-intel/stream`) | 端到端测试覆盖成功、外部 API 限流返工；Prometheus 监控 metrics；代码评审聚焦幂等和错误处理 |
| 1.5 | 前端情报工作台 | `services/api/threatIntel.ts` + SSE hook；IOC 搜索组件、样本进度面板、操作审计表；Zustand 状态存储 | UI/UX 审查（暗色、键盘导航）；MSW/mock → 真实 API；E2E (Playwright) 验证两个核心流程 |

> 交付完成后，请在 `openspec/changes/add-advanced-security-automation/tasks.md` 对应条目添加完成日期 + 简短点评（示例：“2025-11-12：完成 SDK 与缓存链路，覆盖率92%，待观察高并发限流效果”）。
