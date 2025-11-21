# 发布说明模板

发布前请复制本模板并保存为 `docs/release-notes/<version>.md`。`scripts/check-release-notes.sh` 会在 CI 中校验目标版本的发布说明与 `docs/changelog.md` 是否同步。

```
# D-Eyes <版本号> 发布说明

## 1. 概述
- 用 2~3 行说明本次发布的核心目标（示例：Stage4 收尾、BAS 审批 GA 等）。

## 2. 关键能力
- ✅ 能力 1（对应 PR/Issue/`openspec` 变更 ID）
- ✅ 能力 2

## 3. Breaking Changes / 注意事项
- 若存在破坏性变更、配置项迁移、审计策略调整，请列出。没有则写 “无”。

## 4. 升级步骤
1. 更新 Server/Agent 版本，并执行 `scripts/docs-lint.sh` 与 `scripts/check-release-notes.sh`。
2. 跑通 `server/tools/perfcheck`（见 `server/docs/LOADTEST.md`），确认观测指标在阈值内。
3. 结合 `docs/ops-scripts.md` 完成部署/回滚脚本更新。

## 5. 验证清单
- [ ] 通过 `scripts/docs-release.sh <version>` 生成文档快照
- [ ] Prometheus 告警处于 green 状态
- [ ] BAS 审批/Playbook 审批链路通过
```
