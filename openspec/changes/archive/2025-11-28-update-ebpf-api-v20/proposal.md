## Why
- `github.com/cilium/ebpf` 升级到 v0.20 引入了新的 `ProgramOptions`、`LogLevel`、`unix.Utsname` 结构，现有 `ebpf_collector_linux.go` 基于旧版 API，导致 `go build` 报错。
- Agent 需要适配新 API，以便继续在最新依赖上编译、运行并保留现有性能/功能。

## What Changes
- 重写 eBPF Collector 的编译/加载逻辑，使其使用 v0.20 提供的 `ProgramOptions`, `LogLevel`, `link` 包 API。
- 更新内核版本检测、`unix.Utsname` 解析、perf reader 以及相关测试，确保在新依赖下通过。
- 调整 go.mod/go.sum，锁定新的 `cilium/ebpf` 版本，并回归验证 Linux eBPF 路径。

## Impact
- 受影响 specs：`agent-server-foundation`（Collector 实现细节），无需 Server 端改动。
- 受影响代码：`agent/internal/collector/ebpf_*`、相关测试，以及 `agent/go.mod/go.sum`。
