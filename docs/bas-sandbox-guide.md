# BAS 沙箱部署与审批指南

本指南介绍如何在 D-Eyes Agent 环境中启用 BAS 子任务沙箱能力、集成 gVisor/containerd 以及配置审批与回退策略，以兼顾安全与兼容性。

## 1. 沙箱运行时准备

### 1.1 安装 gVisor（runsc）

```bash
curl -fsSL https://gvisor.dev/install.sh | sudo sh
sudo mv runsc /usr/local/bin/
sudo chmod +x /usr/local/bin/runsc
```

> 若采用 containerd，请确保为 Agent 节点提供 `runsc` runtime，并在配置中指定 `sandbox.runtime=gvisor` 与 `sandbox.runtime_binary=/usr/local/bin/runsc`。

### 1.2 共享目录与缓存

沙箱默认仅挂载配置中的 `sandbox.shared_paths` 目录。建议：

- 将 `agent` 报告输出目录添加为只写共享目录；
- 单独为沙箱配置临时目录，例如 `/var/lib/d-eyes/sandbox/tmp`。

## 2. Agent 配置示例

```yaml
sandbox:
  enabled: true
  runtime: gvisor
  runtime_binary: /usr/local/bin/runsc
  shared_paths:
    - /var/lib/d-eyes/reports
  temp_dir: /var/lib/d-eyes/sandbox/tmp
  allowed_commands:
    - bash
    - sh
    - python3
  denied_commands:
    - rm
    - mkfs
  require_approval: true
  log_path: /var/log/d-eyes/sandbox-audit.log
  fallback_to_host: true

tasks:
  bas:
    sandbox_enabled: true
```

关键点：

- `require_approval: true` 时，远程任务需在 metadata 中携带 `sandbox_approved=true`，CLI 可通过 `--sandbox-approve` 快速审批。
- `fallback_to_host: true` 允许在 gVisor 不可用时回退宿主执行，并在元数据与审计日志中标记。
- `allowed_commands` / `denied_commands` 控制可执行二进制；若 `allowed_commands` 非空，则表示白名单模式。

## 3. 运行时审批与 CLI 开关

- CLI 本地：`d-eyes bas --scenario-id initial-access --sandbox --sandbox-approve`
- Server 下发：在任务 payload metadata 中加入 `"sandbox_approved": "true"`；或保持审批缺省，待人工确认后重试。

审批失败时 Agent 将返回错误码 `65` 并提示需要审批。

## 4. 审计与告警

- 审计日志 (JSON Lines)：由 Agent 侧 `sandbox.log_path` 与 Server 侧 `audit.log_path` 共同记录。字段包含 `scenario_id`、`sandbox_used`、`approval_required` 等。
- 告警策略：Server 配置 `alerts` 段落，可将 BAS 失败或沙箱回退事件写入系统日志，后续可接入外部告警平台。

```yaml
alerts:
  enabled: true
  channel: log
  notify_bas_failure: true
  notify_sandbox_fallback: true

audit:
  enabled: true
  log_path: /var/log/d-eyes/bas-audit.log
```

## 5. 常见问题

| 问题 | 说明与处理 |
| ---- | ---------- |
| `sandbox runtime unavailable` | 检查 `runsc` 是否存在，或开启 `fallback_to_host`。 |
| `沙箱执行需要审批` | 为远程任务添加 `sandbox_approved=true`，或使用 CLI `--sandbox-approve`。 |
| 命令被拒绝 | 根据日志中 `command denied` 信息，调整 `allowed_commands` 或 `denied_commands`。 |

通过以上步骤，可在保持非 BAS 模块原有执行方式的同时，为 BAS 子任务提供细粒度的沙箱隔离与审计能力。
