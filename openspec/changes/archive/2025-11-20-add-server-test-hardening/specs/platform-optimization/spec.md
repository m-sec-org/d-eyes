## MODIFIED Requirements
### Requirement: Unified Test, Performance & Chaos Gates
CI/CD MUST 引入统一测试矩阵、性能回归指标与故障注入，确保阶段四交付物在 Server/Agent/Ops Console/BAS 全链路稳定。

#### Scenario: Performance regression gate
- **GIVEN** 新增 Agent 优化代码
- **WHEN** CI 执行基准测试
- **THEN** 若 P95 API 延迟 >300ms 或 BAS 成功率 <98% 则流水线失败并输出对比报表；通过后生成性能快照供发布验证。

#### Scenario: Chaos drill for scheduler
- **GIVEN** 混沌测试注入消息队列延迟与 Agent 断连
- **WHEN** Scheduler 运行回放
- **THEN** 任务成功恢复且无数据丢失，并生成演练报告（RTO/RPO 指标）供运营确认。

#### Scenario: Server regression coverage gate
- **GIVEN** Server 在 `internal/api`、`internal/scheduler`、`internal/store`、`grpcsvc` 或 BAS 管理等模块发生改动
- **WHEN** CI 运行统一测试矩阵
- **THEN** 必须执行 server 端单元/集成测试、生成覆盖率报告（含 API handler、scheduler 与 store 关键路径），并将结果纳入门禁；若覆盖率或关键断言未满足阈值，则阻断合并/发布。
