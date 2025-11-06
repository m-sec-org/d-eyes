# 阶段二发布 Checklist（F5）

本清单用于 D-Eyes Agent/Server 阶段二交付的回归、性能与安全验收，执行完成后可归档至发布记录。

## 1. 环境与配置核对
- [ ] Server 配置 `server/config/server.yaml` 已按生产要求设置 `security.agent_token`、`security.api_keys`、数据库/Redis 连接、`audit.log_path` 与告警/模板路径。
- [ ] Agent 侧 `remote`、`sandbox`、BAS 场景目录等配置已对齐运维指南（参见 `docs/bas-sandbox-guide.md`）。
- [ ] 数据库迁移：若启用 PostgreSQL，执行 `migrations/` 全量迁移并确认 `task_results` 表存在。

## 2. 功能回归
执行以下命令并确保全部通过：

```bash
cd agent && go test ./...
cd server && go test ./...
```

场景级验证（可多 Agent 并行）：
- [ ] Respond/Baseline/Inventory/SupplyChain 任务可通过模板下发、SSE 实时查看状态、报告中心可查询结果。
- [ ] BAS 任务在启用沙箱时可运行内置场景，审批/回退记录写入审计日志。
- [ ] 模板调度（`schedule.interval_minutes`）能按时自动触发，并在 `reports/summary` 中看到记录。

## 3. 性能与容量
- [ ] 使用 `server/tools/loadtest` 对 REST 接口压测（默认 50 并发、持续 5 分钟），监控 `/metrics` 中 `task_queue_depth`、`tasks_in_flight`，确认无明显堆积。
- [ ] SSE `/api/v1/tasks/stream` 在 5 分钟压测内保持稳定连接；若经反向代理，确保 Keep-Alive 超时 > 300s。
- [ ] 记录当前资源占用（CPU/内存/磁盘），作为后续扩容基线。

## 4. 安全与审计
- [ ] BAS 审批流：验证未审批任务会返回错误码 65，审批后可执行，并在 `audit.log` 中生成记录。
- [ ] 沙箱白/黑名单策略经抽样验证（例如禁止 `rm`，允许 `/bin/sh`），如触发回退需确认告警已记录。
- [ ] API Key / Agent Token 轮换策略已执行（老 Key 失效、新 Key 生效），相关敏感配置存储在安全位置。

## 5. 运维与回滚
- [ ] 参考 `docs/operations-guide.md`，完成健康检查、SSE 监控、告警通道验证。
- [ ] 备份 PostgreSQL 数据、模板持久化文件、审计日志，并在非生产环境演练回滚（停止新版本 -> 恢复旧二进制 + 配置 -> Agent 重连）。
- [ ] 更新值班/应急联系人，记录在运维手册。

## 6. 发布记录
- [ ] 填写版本号、Git Commit、构建产物（Agent/Server 二进制、容器镜像）。
- [ ] 输出阶段性 Release Note：概述模板管理、SSE 监控、报告中心、沙箱安全等新能力，可引用 `docs/report-center.md`、`docs/task-template-api.md` 等文档。
- [ ] 将本 Checklist、测试结果和 Release Note 归档到运维知识库或 Wiki，作为阶段二验收凭证。

完成以上步骤后，可宣告里程碑 F5（验收回归）达成，并进入后续规划。
