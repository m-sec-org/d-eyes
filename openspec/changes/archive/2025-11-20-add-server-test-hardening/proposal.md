## Why
当前 Server 端（API/调度器/存储）在补充 Stage4 能力后新增了大量逻辑，但缺乏系统化的单元/集成测试与配套文档，导致插件变更或性能优化后难以及时发现回归。

## What Changes
- 深入分析 server/internal 关键模块，梳理目前的测试缺口（API handler、store、scheduler/BAS manager 等）。
- 为识别出的薄弱模块补充单元/集成测试，并将执行方式纳入测试矩阵/CI 门禁。
- 更新 Docs（测试矩阵、开发指南）记录新增测试与运行方法，确保后续版本遵循统一流程。

## Impact
- Affected specs: platform-optimization
- Affected code: server/internal/*（API、scheduler、store、basscenarios、grpcsvc 等）、docs/test-matrix.md、README.md
