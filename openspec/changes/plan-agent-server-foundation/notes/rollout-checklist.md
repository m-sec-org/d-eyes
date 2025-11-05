牵头: Agent/Server 负责人
目标版本: plan-agent-server-foundation
最晚出方案: 发布前一周

## 上线检查项
1. **功能回归**
   - [ ] CLI 命令（respond/baseline/audit/inventory/supplychain）在目标环境运行通过
   - [ ] Server 端 REST/gRPC 冒烟通过，指标暴露正常
   - [ ] 插件示例与远程模式兼容

2. **远程模式准备**
   - [ ] Server 生产环境开启任务队列与安全凭据配置（Agent Token/TLS）
   - [ ] Agent 配置 `remote` 段（地址、token、cache 目录）并验证 `d-eyes remote` 正常注册
   - [ ] 指标面板及告警规则就绪（心跳缺失、失败率、队列深度）

3. **数据迁移与兼容**
   - [ ] Server 数据库迁移脚本执行（如有 schema 变更）
   - [ ] Redis/缓存清理策略确定，避免历史任务影响
   - [ ] CLI 输出格式未变更，兼容既有自动化脚本

4. **回滚策略**
   - [ ] CLI 独立模式可作为 fallback（停止远程守护）
   - [ ] Server 可暂停下发任务（清空调度队列、关闭 Agent 注册）
   - [ ] 远程缓存目录保留，可人工补回结果

5. **文档与培训**
   - [ ] `agent/docs/PLUGIN_GUIDE.md`、`agent/README.md` 已更新
   - [ ] `docs/OBSERVABILITY.md`、`docs/LOADTEST.md` 与新的指标/压测脚本保持同步
   - [ ] 测试矩阵与结果归档（见 `notes/test-plan.md`）

6. **运营验证**
   - [ ] 试运行环境验证（至少 24 小时），观察远程模式的重连与缓存行为
   - [ ] 业务方确认任务执行日志与报告格式
   - [ ] 发布窗口、值班支持安排

## 发布动作
1. 初始化 Server 环境（Docker Compose 或 K8s）并运行 `make dev-up`/部署脚本。
2. Agent 节点部署新版二进制，加载配置后执行 `d-eyes remote`。
3. Server REST/API 发起任务，验证远程执行与结果回传。
4. 开启监控告警，观察 1-2 个任务周期无异常后宣布上线完成。

