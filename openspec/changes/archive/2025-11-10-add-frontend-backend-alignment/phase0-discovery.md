# Phase 0 Discovery & Contracts – add-frontend-backend-alignment

## 1. Respond/Baseline API & Event 差异矩阵
| 关注点 | Respond（后端实现） | Baseline（后端实现） | 前端影响 / 缺口 |
| --- | --- | --- | --- |
| 报告接口 | `GET /api/v1/tasks/{id}/respond/report` 返回 `respondReportResponse`（仅 `ExecutionResult` + metadata）[server/internal/api/v1/tasks.go:405-489] | `GET /api/v1/tasks/{id}/baseline/report` 返回 `baselineReportResponse`，额外暴露 `severity`、`warnings`、`outputs` 字段 [server/internal/api/v1/tasks.go:492-620] | FE 需要统一接口来渲染 Severity/Pivot 卡片。当前 respond 缺少聚合字段，需透出 `Result.Summary.risks/notes/outputs` 的快捷入口以减少前端深层解析。 |
| Profile/Metadata 回传 | Respond 仅把 `task.profile`、`run.metadata` 原样带回，缺少 `scenario`、`policy` 上下文。 | Baseline 同样只透出 `profile`，但 `ExecutionResult.Summary` 默认包含 policy 触发信息。 | FE 无法根据 respond 结果判定执行策略、profile 快照。需要在 respond 路径补充 `profile_snapshot`、`policy_trigger`。 |
| 事件流 (TaskEvent) | Scheduler 在 `leased/running/completed` 时广播 `TaskEvent`，字段为 `task_id/type/status/agent_id/metadata` [server/internal/scheduler/scheduler.go:120-340]，对 respond 没有额外字段。 | Baseline 事件同结构，但 metadata 通常包含 `scope` 等键；无结构化字段区分。 | FE useTaskStream 只能靠 metadata 自行解析，无法区分 respond/baseline 特有进度。需要为各任务类型补充标准化 `Metadata` key 集，或扩展 `TaskEvent` 字段。 |
| 失败/超时语义 | Respond 失败仅返回 `error_code`，无风险评估。 | Baseline 失败仍可包含 `severity`/`warnings`。 | FE 在 respond 失败时无法得知风险是否已部分产出。需要使 respond 失败时仍返回 `partial_summary`（参考 baseline 处理）。 |

## 2. 任务 Profile Schema 草案（含安全签字）
每种任务类型暴露统一结构：
- `profile_id`：字符串，唯一标识版本化 Profile。
- `display_name`：给 UI 的可读名称。
- `defaults`：Server 侧准备的默认参数。
- `parameters[]`：字段定义（key、label、type、required、options、validation）。
- `constraints`：跨字段约束与范围说明。

### 2.1 Respond Profile Schema (`respond_profile_v1`)
```json
{
  "$schema": "https://d-eyes.m-sec/org/schemas/task-profile.json",
  "task_type": "respond",
  "profile_id": "respond_profile_v1",
  "display_name": "应急响应",
  "defaults": {
    "modules": ["host-summary", "network"],
    "targets": [],
    "artifact_retention_hours": 168,
    "sensitive_path_globs": ["/var/log/**", "/tmp/**"],
    "isolation_level": "none"
  },
  "parameters": [
    {"key": "modules", "label": "执行模块", "type": "multiselect", "required": true, "options": ["host-summary", "network", "filescan", "user-session", "malware"], "max": 5},
    {"key": "targets", "label": "调查路径/主机", "type": "string_list", "required": true, "pattern": "^(/[\\w.-]+|[0-9.]+)$"},
    {"key": "collection.window_minutes", "label": "数据采集时间窗", "type": "number", "min": 5, "max": 1440, "default": 60},
    {"key": "policy.fail_on", "label": "失败阈值", "type": "enum", "options": ["none", "medium", "high", "critical"], "default": "critical"},
    {"key": "network.capture_enabled", "label": "采集网络连接", "type": "boolean", "default": true},
    {"key": "filescan.hash_algos", "label": "Hash 算法", "type": "multiselect", "options": ["md5", "sha1", "sha256"], "default": ["sha256"] },
    {"key": "runtime.timeout_minutes", "label": "超时", "type": "number", "min": 5, "max": 240, "default": 30 }
  ],
  "constraints": [
    {"if": "modules contains filescan", "then": "targets MUST include at least one filesystem path"},
    {"if": "isolation_level = \"sandbox\"", "then": "require security.approval_id"}
  ]
}
```

### 2.2 Audit Profile Schema (`audit_profile_v1`)
```json
{
  "task_type": "audit",
  "profile_id": "audit_profile_v1",
  "display_name": "合规审计",
  "defaults": {"scope": ["cis", "sox"], "evidence_retention_hours": 720},
  "parameters": [
    {"key": "scope", "label": "审计范围", "type": "multiselect", "options": ["cis", "sox", "iso27001", "custom"], "required": true},
    {"key": "scope.custom_rulepack", "label": "自定义规则包", "type": "string", "format": "uri"},
    {"key": "targets", "label": "主机/资产列表", "type": "asset_selector", "required": true},
    {"key": "evidence.output_format", "label": "证据格式", "type": "enum", "options": ["json", "html", "csv"], "default": "json"},
    {"key": "approvals.required", "label": "是否需要审批", "type": "boolean", "default": false}
  ],
  "constraints": [
    {"if": "scope contains custom", "then": "scope.custom_rulepack MUST be present"}
  ]
}
```

### 2.3 Inventory Profile Schema (`inventory_profile_v1`)
```json
{
  "task_type": "inventory",
  "profile_id": "inventory_profile_v1",
  "display_name": "资产梳理",
  "defaults": {"port_range": "1-1024", "service_detect": true, "os_detect": false},
  "parameters": [
    {"key": "targets", "label": "扫描目标", "type": "cidr_list", "required": true},
    {"key": "port_range", "label": "端口范围", "type": "string", "pattern": "^(\\d+)-(\\d+)$", "required": true},
    {"key": "service_detect", "label": "服务识别", "type": "boolean", "default": true},
    {"key": "os_detect", "label": "OS 指纹", "type": "boolean", "default": false},
    {"key": "rate_limit_pps", "label": "速率限制 (pps)", "type": "number", "min": 10, "max": 10000, "default": 500},
    {"key": "exclude_targets", "label": "排除目标", "type": "cidr_list"}
  ],
  "constraints": [
    {"rule": "port_range.end - port_range.start <= 10000", "message": "单次扫描端口跨度 <= 10k"},
    {"rule": "rate_limit_pps <= 2000 when stealth profile"}
  ]
}
```

### 2.4 SupplyChain Profile Schema (`supplychain_profile_v1`)
```json
{
  "task_type": "supplychain",
  "profile_id": "supplychain_profile_v1",
  "display_name": "供应链安全",
  "defaults": {"mode": "generate", "type": "json"},
  "parameters": [
    {"key": "mode", "label": "执行模式", "type": "enum", "options": ["generate", "capture", "diff"], "required": true},
    {"key": "sources.code_path", "label": "源码路径", "type": "string", "format": "path"},
    {"key": "sources.package_manager", "label": "包管理器", "type": "enum", "options": ["npm", "pip", "gomod", "maven", "gradle", "other"]},
    {"key": "sbom.type", "label": "SBOM 类型", "type": "enum", "options": ["json", "spdx", "cyclonedx"], "default": "json"},
    {"key": "attestation.sign", "label": "签名输出", "type": "boolean", "default": false},
    {"key": "attestation.key_ref", "label": "KMS Key", "type": "string", "format": "arn", "required_if": {"attestation.sign": true}}
  ],
  "constraints": [
    {"if": "mode = diff", "then": "require sbom.baseline_id"},
    {"if": "mode = capture", "then": "sources.package_manager MUST be set"}
  ]
}
```

### 2.5 安全团队签字记录
| 任务类型 | Reviewer | 日期 | 备注 |
| --- | --- | --- | --- |
| Respond | He Jia (SecOps) | 2025-11-09 | 限定 modules 白名单，敏感路径默认启用脱敏。 |
| Audit | Sun Lei (Compliance) | 2025-11-09 | `custom_rulepack` 需走制品扫描。 |
| Inventory | Xu Ran (NetSec) | 2025-11-09 | 端口跨度与速率限制满足内网隔离策略。 |
| SupplyChain | Chen Yu (AppSec) | 2025-11-09 | SBOM 生成默认关闭签名，仅在 KMS 集成场景启用。 |

## 3. 任务结果数据契约（Network Graph / File Risk / Host Summary）
为实现 Spec 中的 `GET /api/v1/tasks/{id}/visuals`，定义统一响应：
```json
{
  "task_id": "uuid",
  "task_type": "respond",
  "visual_type": "network_graph",
  "generated_at": "2025-11-09T05:42:00Z",
  "payload": { /* 对应类型结构 */ }
}
```

### 3.1 NetworkGraphVisual
> 用于 respond/inventory 任务的网络连通性与端口拓扑。

```json
{
  "nodes": [
    {"id": "host-1", "label": "10.0.0.8", "kind": "host", "risk": "medium", "metadata": {"os": "linux"}},
    {"id": "svc-3306", "label": "3306/tcp", "kind": "service", "risk": "high", "metadata": {"banner": "MySQL"}}
  ],
  "edges": [
    {"source": "host-1", "target": "svc-3306", "protocol": "tcp", "state": "established", "first_seen": "2025-11-09T05:30:00Z", "last_seen": "2025-11-09T05:41:50Z"}
  ],
  "severity_buckets": {"critical": 1, "high": 2, "medium": 4, "low": 6},
  "agent_scope": ["agent-a", "agent-b"],
  "filters": {"port_range": "1-1024", "service_detect": true}
}
```

对应 Proto 草案：
```proto
message NetworkNode {
  string id = 1;
  string label = 2;
  string kind = 3; // host/service/process
  string risk = 4;
  map<string,string> metadata = 5;
}
message NetworkEdge {
  string source = 1;
  string target = 2;
  string protocol = 3;
  string state = 4;
  google.protobuf.Timestamp first_seen = 5;
  google.protobuf.Timestamp last_seen = 6;
}
message NetworkGraphVisual {
  repeated NetworkNode nodes = 1;
  repeated NetworkEdge edges = 2;
  map<string,int32> severity_buckets = 3;
  repeated string agent_scope = 4;
  map<string,string> filters = 5;
}
```

### 3.2 FileRiskDistribution
> respond/audit 任务的文件扫描风险分布。

```json
{
  "total_files": 1240,
  "risk_counts": {"critical": 2, "high": 12, "medium": 54, "low": 118},
  "top_hits": [
    {"path": "/opt/app/bin/run.sh", "risk": "high", "reason": "modified in last 5 min", "hash": "sha256:..."},
    {"path": "/tmp/dropper", "risk": "critical", "reason": "YARA match ransomware"}
  ],
  "blocked_actions": ["quarantine", "delete"],
  "filters": {"modules": ["filescan"], "hash_algos": ["sha256"]}
}
```

Proto：
```proto
message FileRiskHit {
  string path = 1;
  string risk = 2;
  string reason = 3;
  string hash = 4;
}
message FileRiskDistribution {
  int32 total_files = 1;
  map<string,int32> risk_counts = 2;
  repeated FileRiskHit top_hits = 3;
  repeated string blocked_actions = 4;
  map<string,string> filters = 5;
}
```

### 3.3 HostSummaryVisual
> respond/baseline/audit 统一的主机摘要。

```json
{
  "hosts": [
    {
      "id": "host-1",
      "hostname": "web-01",
      "ip": "10.0.0.8",
      "os": "Ubuntu 22.04",
      "kernel": "5.15",
      "uptime_seconds": 86400,
      "agent_version": "1.4.2",
      "risk_score": 72,
      "tags": ["prod", "pci"],
      "stats": {"cpu": 62, "memory": 78, "disk": 55}
    }
  ],
  "aggregations": {
    "risk_percentiles": {"p50": 40, "p90": 80},
    "os_distribution": {"linux": 12, "windows": 4}
  }
}
```

Proto：
```proto
message HostStats {
  double cpu = 1;
  double memory = 2;
  double disk = 3;
}
message HostSummaryItem {
  string id = 1;
  string hostname = 2;
  string ip = 3;
  string os = 4;
  string kernel = 5;
  int64 uptime_seconds = 6;
  string agent_version = 7;
  int32 risk_score = 8;
  repeated string tags = 9;
  HostStats stats = 10;
}
message HostSummaryVisual {
  repeated HostSummaryItem hosts = 1;
  map<string,double> risk_percentiles = 2;
  map<string,int32> os_distribution = 3;
}
```

### 3.4 交付与兼容性说明
- 所有 Visual payload 通过 `payload` 字段透出 JSON；同时在 gRPC/Proto 中通过 oneof：
  ```proto
  message TaskVisualPayload {
    string task_id = 1;
    string task_type = 2;
    string visual_type = 3; // network_graph | file_risk | host_summary
    google.protobuf.Timestamp generated_at = 4;
    oneof visual {
      NetworkGraphVisual network = 10;
      FileRiskDistribution file_risk = 11;
      HostSummaryVisual host = 12;
    }
  }
  ```
- Server 存储层应将 `ExecutionResult.Summary` 中已有的 `risks/notes/outputs` 与新结构映射，避免重复计算。
- 前端可根据 `visual_type` 动态加载组件，实现任务类型与可视化的解耦。
