## Why
- `docs/编译指南.md:50-128` 明确要求在编译 Agent 时启用 `CGO_ENABLED=1` 并链接 `github.com/hillu/go-yara/v4`，否则无法复现 YARA 的完整语义；然而当前 CLI 默认的 detect 流水线在禁用 CGO 时仍继续运行，导致用户误以为检测能力等同于启用 CGO 的版本。
- `agent/internal/detect/yara_scan_file.go:214-245` 的 `loadRuleBundle` 永远通过 `rules.Manager` → `goengine` 加载内置规则，即使存在 libyara 也不会被利用；因此 CGO 关闭时与开启时实际使用的是同一套简化引擎，缺少 PE/ELF 模块、模块函数以及 `matches for` 等高级条件。
- `agent/internal/detect/engine/goengine/condition.go:129-196` 只允许 `any/all/number of ($a, $b*)` 这类字符串量词，`pe.entry_point`, `math.entropy`, `dotnet.version` 等标识符会命中 `unsupported identifier expression` 并让整个规则解析失败；`agent/internal/detect/engine/goengine/engine.go:125-140` 随后把包含失败的 `.yar` 文件整体跳过，直接丢失包含勒索/挖矿等高危规则的整包内容。
- `agent/internal/detect/rules/manager.go:48-139` 在热加载和内置/自定义目录合并时没有记录“共加载/跳过多少规则、原因是什么”，也没有把覆盖率暴露给 CLI 或 Server；检测准确率下降时既没有指标，也没有可视化告警，排障难度高。

## What Changes
1. **规则覆盖度可观测性**
   - 为 `rules.Manager`、`goengine.FromDirectory` 增加统计：按文件/规则计数解析成功、跳过原因（语法不支持/文件损坏/自定义错误），并通过 `d-eyes detect diag`/日志/Prometheus 暴露“可用规则数、覆盖率、回落原因”。
   - 在检测 CLI 启动时打印当前后端、规则版本、覆盖率，并在覆盖率 <80% 或关键家族（ransom/apt）全被跳过时以非零退出码阻止误用，避免“空跑”。

2. **混合 YARA 后端抽象**
   - 定义 `EngineBackend` 接口（加载、编译、扫描、统计），实现 `native`（基于 `go-yara`/libyara，需 CGO）和 `portable`（现有 goengine）两个驱动，允许在启动参数或环境中指定 `detect.yara.backend=auto|native|portable`。
   - `auto` 模式下：探测 libyara 是否可用，若成功则用 `native`，否则回退 `portable` 并附带告警；同一份规则源在两个后端编译成功数差异 >5% 时，需要落日志并上报指标。
   - 引入“规则 bundle 版本 + backend”缓存，避免重复编译；支持在 CGO 版本中优先装载编译后的 `.yarac`（若存在）以减少启动耗时。

3. **可移植条件兼容层**
   - 扩展 goengine 解析与执行：支持 `pe.*`, `elf.*`, `dotnet.*`, `math.entropy`, `hash.md5` 等最常用模块，通过新增的 `metadata extractor` 在扫描前解析文件头、节表、导出表，并把结果注入条件求值上下文，避免因缺少模块而跳过规则。
   - 为无法完全转写的表达式提供“部分类似”策略：记录不支持的模块函数，把规则标记为 `partial`，允许在 portable 模式下继续匹配字符串（但将置信度下降/附带提示），并把“部分匹配”结果带回 Server。
   - 新增回归测试：对典型勒索/挖矿/木马样本（至少 10 条规则）验证 portable 模式的匹配率 ≥ 80%，并校验 native/portable 命中集差异。

## Impact
- 需要重构 `agent/internal/detect` 下的规则加载、扫描、匹配逻辑，引入新的 backend 抽象与 metadata 抽象；部分代码要根据 `build tags` 拆分（`native` 驱动只在 CGO 可用时编译），并把 `github.com/hillu/go-yara/v4` 重新纳入依赖与构建脚本。
- 需要在 Agent CLI 与后续 gRPC 任务执行路径中传递“检测后端/覆盖率/部分匹配”信息，Server/前端也要显示检测准确度与警告；Prometheus/日志 schema 也要更新。
- 构建与发布流程会多出“libyara 可选依赖 + 预编译 `.yarac` artifact”这一步，需要更新 `docs/编译指南.md`、CI 镜像、以及插件开发指南；同时需要新增若干单元测试/集成测试验证 native & portable 行为一致性。

## Open Questions
1. 是否需要在发布包中附带预编译的 `.yarac`（减少启动时间但增大体积），还是继续在 Agent 启动时自行编译？
2. 便携模式支持的模块范围是否只覆盖 PE/ELF/Dotnet，还是还要引入 `cuckoo`、`math` 全家？需要与规则维护者确认优先级。
