## 1. 规则覆盖度 & 诊断
- [x] 1.1 为 `rules.Manager` 与 `goengine.FromDirectory` 增加解析成功/失败计数、原因枚举，并输出到日志/metrics。
- [x] 1.2 新增 `d-eyes detect diag`（或 `--diag`）选项，展示当前后端、规则版本、覆盖率、关键家族缺失情况，并在覆盖率 <80% 时返回非零状态。

## 2. 后端抽象与 native 驱动
- [x] 2.1 提取 `EngineBackend` 接口与选择器，支持 `auto|native|portable` 配置及 gRPC/CLI 透传。
- [x] 2.2 在 CGO 构建下实现基于 `github.com/hillu/go-yara/v4` 的 `native` 驱动，支持加载 `.yar` 与 `.yarac`，并与现有 CLI 集成。
- [x] 2.3 为 `auto` 模式添加后端探测、失败回退与事件/指标上报（含覆盖率对比）。

## 3. 便携模式兼容增强
- [x] 3.1 实现 PE/ELF/Dotnet/Hash 元数据采集器，在扫描前解析文件结构并缓存。
- [x] 3.2 扩展 goengine condition/parser，使其可识别 `pe.*`, `elf.*`, `dotnet.*`, `math.*`, `hash.*` 常见表达式，并将其映射到预计算元数据。
- [x] 3.3 对无法完全支持的表达式添加 `partial` 标记与降级策略，确保规则可部分执行且结果带有置信度标签。
- [x] 3.4 建立针对典型样本的 native vs portable 回归测试矩阵，确保 portable 模式命中率 ≥80%。

## 4. 文档 & 交付
- [x] 4.1 更新 `docs/编译指南.md`、插件开发与运维文档，说明后端切换、依赖与诊断步骤。
- [x] 4.2 在 CI/CD 中增加 libyara 可用性检测、`.yarac` 产物缓存及便携模式测试。
