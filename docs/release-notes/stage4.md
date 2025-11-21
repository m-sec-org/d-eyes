# D-Eyes stage4 发布说明

## 1. 概述
- 完成阶段四（优化收口）目标，覆盖插件生态、安全审批、Docs-as-Code 与观测闭环。
- 引入 BAS 多级审批、Agent 资源效率优化及自动化运维脚本模板。

## 2. 关键能力
- ✅ 插件市场 + SDK：Manifest 校验、示例 Runner、Docs-as-Code 快照。
- ✅ BAS 审批 / Sandbox 强化：多角色审批、Agent 标签匹配、安全审计。
- ✅ Observability：Prometheus 指标 + `server/tools/perfcheck` 阈值脚本。
- ✅ 运维模板：部署、回滚、巡检脚本与 release checklist。

## 3. Breaking Changes / 注意事项
- 远程 Agent 必须在 `remote.labels` 中声明 `network_boundary` 等标签，否则 BAS 任务无法调度。
- 插件 Manifest 必须提供签名与资源预算，旧版未签名插件将被拒绝安装。

## 4. 升级步骤
1. 升级 Server/Agent 到 stage4 版本，执行 `scripts/docs-lint.sh`、`scripts/check-release-notes.sh`。
2. 跑通 `server/tools/perfcheck --window 5m`，确认 CPU P95 <80%、失败率 <1%。
3. 参考 `docs/ops-scripts.md` 运行部署脚本并生成 `docs/releases/stage4` 快照。

## 5. 验证清单
- [x] `scripts/docs-release.sh stage4` 已生成快照
- [x] BAS 审批、Playbook 审批链路通过冒烟测试
- [x] Prometheus / Alertmanager 指标正常，Agent 队列无积压
