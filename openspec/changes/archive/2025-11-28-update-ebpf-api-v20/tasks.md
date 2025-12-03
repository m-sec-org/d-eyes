## 1. 依赖与基础设施
- [x] 1.1 将 `github.com/cilium/ebpf` 升级至 v0.20.x，运行 `go mod tidy`，确保 go.sum 干净。
- [x] 1.2 检查 eBPF 相关构建脚本/CI（如 `scripts/perf/ebpf-load-test.sh`）是否需要环境说明更新。

## 2. eBPF Collector 适配
- [x] 2.1 重构 `ebpf_collector_linux.go`，使用 v0.20 的 `ProgramOptions`/`LogLevel`/`perf` API，修复 `LogSize`、`LogLevel*`、`Utsname` 相关编译错误。
- [x] 2.2 回归 ETW/eBPF 共享辅助函数（filter、sampler 等），确保新依赖无破坏性变更。
- [x] 2.3 更新/新增单元测试覆盖关键分支（事件解码、perf 缓存、环境探测），保证在新依赖下通过。

## 3. 验证与文档
- [x] 3.1 本地运行 `go test ./agent/...` 与 `go build ./agent`，确认 Linux eBPF collector 正常编译。
- [x] 3.2 复核 `openspec/changes/integrate-etw-ebpf-stage-one` 的相关任务状态，如无影响则记录兼容性说明。
  - 兼容性说明：该阶段 1.x–3.x Collector 任务已在 `integrate-etw-ebpf-stage-one` 中完成，4.x（Server ingest/config）与 5.x（运维文档）仍待实现。本次仅升级 Linux eBPF Collector 依赖并修复 `collector.Manager`/事件管道相关测试，不改变 Collector 配置契约或新增 Server 端需求，`go test ./agent/...` 与 `go build ./agent` 验证结果表明与现有 ETW/eBPF 设计保持兼容。
