# ETW 性能/集成测试

`scripts/perf/etw-load-test.ps1` 用于在 Windows 环境下对 ETW Collector 进行集成/性能验证，覆盖以下目标：

- 同时启用多个 Provider（默认包含 Kernel、Security Provider）。
- 通过 `deyes collect` CLI 按配置拉起 Collector，并把事件输出到 stdout/file，便于统计吞吐、延迟分布与丢包情况。
- 运行结束后自动汇总事件总数、平均/最大延迟等指标，生成 JSON 报告，便于纳入手动回归或 CI 产物。

## 先决条件

- Windows 10/11 或 Server 2019/2022，具有管理员权限（ETW 需要）。
- 已安装 Go 1.21+、PowerShell 5+。
- 仓库根目录具备 `agent` 源码（脚本会自动构建 `agent.exe`）。

## 使用方法

```powershell
cd C:\path\to\d-eyes
powershell -ExecutionPolicy Bypass -File .\scripts\perf\etw-load-test.ps1 `
  -DurationSeconds 120 `
  -Providers "{9E814AAD-3204-11D2-9A82-006008A86939}","{54849625-5478-4994-A5BA-3E3B0328C30D}" `
  -OutputPath ".\artifacts\etw-events.jsonl" `
  -ReportPath ".\artifacts\etw-report.json"
```

### 参数

| 参数 | 说明 |
| ---- | ---- |
| `-DurationSeconds` | 采集持续时间（默认 60 秒）。 |
| `-Providers` | 逗号分隔的 Provider GUID 列表，脚本会写入临时配置。 |
| `-AgentBinary` | 可选，指定已构建的 `agent.exe`，默认为 `.\bin\agent.exe`。 |
| `-OutputPath` | JSONL 事件输出路径，默认 `artifacts\etw-events.jsonl`。 |
| `-ReportPath` | 指标报告路径（JSON），默认 `artifacts\etw-report.json`。 |
| `-MinEvents` | 期望的最小事件数（默认 100，低于该值即失败）。 |
| `-MaxAvgLatencyMs` | 平均延迟阈值，超过则失败（默认 500 ms）。 |
| `-MaxMaxLatencyMs` | 最大延迟阈值，超过则失败（默认 2000 ms）。 |
| `-EnforceThresholds` | 置为 `-EnforceThresholds:$false` 可跳过阈值校验。 |

### 输出

- `OutputPath`：按行存储的 `SystemEvent` JSON，便于复盘。
- `ReportPath`：包含事件总数、平均/最大延迟、吞吐（events/sec）等指标，可上传至 CI 或对比历史基线。
- PowerShell 控制台会增加汇总表格，若出现异常（采集失败、无事件等）会返回非 0 ExitCode。

## CI/手动回归建议

1. 在 CI Windows 任务中执行脚本，例如：

   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/perf/etw-load-test.ps1 `
     -DurationSeconds 120 `
     -Providers "{9E814AAD-3204-11D2-9A82-006008A86939}","{54849625-5478-4994-A5BA-3E3B0328C30D}" `
     -MinEvents 500 `
     -MaxAvgLatencyMs 200 `
     -MaxMaxLatencyMs 1500 `
     -OutputPath artifacts\etw-events.jsonl `
     -ReportPath artifacts\etw-report.json
   ```

   脚本若命中阈值将返回非 0 ExitCode，CI 即可判定失败。
2. 将 `ReportPath` 和 `OutputPath` 归档为 CI 工件，便于历史对比或手动分析。
3. 若需要更高负载，可调整 `-Providers` 列表或同时运行其他 ETW 负载（如 Sysmon），观察丢包指标。

## Linux eBPF 集成/性能测试

`scripts/perf/ebpf-load-test.sh` 负责在 Linux 上验证 eBPF Collector，在 Probe/CLI 模式下对 `deyes collect --collector ebpf` 进行快速基准：

- 自动构建/复用 `bin/agent`，写入临时配置，启用 `sys_enter_execve`、`sched_process_exit` 等探针。
- 将 JSONL 事件输出到 `--output` 路径，并从 `payload.kernel_timestamp_ns` 计算平均、P99、最大延迟。
- 生成 `--report` JSON 文件，包含事件数、吞吐、延迟指标，并根据阈值（事件数、平均/P99 延迟）返回非 0 ExitCode，方便纳入 CI。

### 使用方法

```bash
sudo ./scripts/perf/ebpf-load-test.sh \
  --duration 90 \
  --probes sys_enter_execve,sched_process_exit \
  --min-events 500 \
  --max-avg-latency-ms 200 \
  --max-p99-latency-ms 1200
```

若只想生成报告而不校验阈值，可追加 `--no-enforce`。

#### 先决条件

- Linux kernel ≥ 5.8，并具备 root 或 CAP_BPF 权限。
- Go 1.21+（满足 `github.com/cilium/ebpf v0.20.x` 要求），脚本会在缺少 go 命令时报错。

### eBPF 依赖/降级测试

`scripts/smoke-ebpf-prereqs.sh` 可在 CI/手动环境中验证缺失 Clang/BTF 时的错误回退路径，确保 Probe 模式能够清晰提示 `clang not found`、`kernel BTF file not accessible` 等诊断信息。结合 `ebpf-load-test.sh` 可覆盖「性能」「降级」两条路径。
