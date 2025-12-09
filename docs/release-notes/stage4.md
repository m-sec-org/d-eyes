# D-Eyes stage4 发布说明

## 1. 概述
- 完成阶段四（优化收口）目标，覆盖插件生态、安全审批、Docs-as-Code 与观测闭环。
- 引入 BAS 多级审批、Agent 资源效率优化及自动化运维脚本模板。

## 2. 关键能力
- ✅ 插件市场 + SDK：Manifest 校验、示例 Runner、Docs-as-Code 快照。
- ✅ BAS 审批 / Sandbox 强化：多角色审批、Agent 标签匹配、安全审计。
- ✅ Observability：Prometheus 指标 + `server/tools/perfcheck` 阈值脚本。
- ✅ 运维模板：部署、回滚、巡检脚本与 release checklist。
- ✅ 事件工作台：ETW/EBPF 事件查询、热图、实时检测＋Respond 快捷操作，Collector 控制面热更新。
- ✅ 集成测试：`server/internal/eventing/integration_test.go` 验证 ETW/EBPF→检测→SSE→ThreatIntel 闭环并附带 ingest 性能基线。

- **事件采集/检测**：
  - 新增 `events.detection.rules[].enabled`、`events.detection.auto_respond.enabled` 等 Feature Flag，详见《docs/feature-flags.md》；滚动升级时可先禁用 auto respond 再逐步放量。
  - `events.parsers` 默认开启 schema 校验，如需回滚可设置 `enabled=false` 或改用 `strict_payload=false`。
- **Collector Rollout**：`/api/v1/collector/configs/rollouts` 在 stage4 中启用心跳追踪及自动回滚，可用来批量禁用/启用 ETW/eBPF Collector；演练流程见《docs/dr-runbook.md》。
- 远程 Agent 必须在 `remote.labels` 中声明 `network_boundary` 等标签，否则 BAS 任务无法调度。
- 插件 Manifest 必须提供签名与资源预算，旧版未签名插件将被拒绝安装。

## 4. 升级步骤
1. 升级 Server/Agent 到 stage4 版本，执行 `scripts/docs-lint.sh`、`scripts/check-release-notes.sh`。
2. 跑通 `server/tools/perfcheck --window 5m`，确认 CPU P95 <80%、失败率 <1%，并补充 `server/internal/eventing/integration_test.go` 中的 ingest/检测集成测试（`GOCACHE=/tmp/d-eyes-gocache go test ./internal/eventing -run TestIntegration`）以校验 ETW/EBPF→Detection→SSE 闭环。
3. 参考 `docs/ops-scripts.md` 运行部署脚本并生成 `docs/releases/stage4` 快照，使用《docs/feature-flags.md》中的 Feature Flag 清单规划灰度。

## 5. 验证清单
- [x] `scripts/docs-release.sh stage4` 已生成快照
- [x] BAS 审批、Playbook 审批链路通过冒烟测试
- [x] Prometheus / Alertmanager 指标正常，Agent 队列无积压
- [x] `GOCACHE=/tmp/d-eyes-gocache go test ./internal/eventing -run TestIntegration` 通过，记录 ingest 性能基线日志
- [x] `docs/collector-diagnostics.md`/`docs/dr-runbook.md` 中的 collector 健康检查脚本完成一次演练
