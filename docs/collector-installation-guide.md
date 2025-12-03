# Collector 安装与权限指南

本指南覆盖 Collector 在 Windows（ETW）与 Linux（eBPF）上的权限、依赖与 CLI 操作，帮助运维在 Probe/CLI/Remote 模式下快速完成部署并排查常见错误。

## 1. Windows（ETW）前提条件

| 项目 | 说明 |
| --- | --- |
| 操作系统 | Windows 10 21H2 / Windows Server 2019 及以上，启用 Event Tracing for Windows |
| 权限 | 运行 `d-eyes.exe` 或 Probe 服务的账户必须具备管理员权限（建议使用 `LocalSystem` 或已加入「性能日志用户」组的帐户） |
| 依赖 | 无额外驱动；若需采集第三方 Provider，确保 Provider 已经通过 `wevtutil im` 或安装包正确注册 |

### 1.1 CLI 启动示例

在「以管理员身份运行」的 PowerShell 中执行：

```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process
cd C:\Program Files\d-eyes
.\d-eyes.exe collect --backend=etw `
  --collector diag-etw `
  --output-mode=file `
  --output-path="C:\d-eyes\logs\etw-events.jsonl"
```

### 1.2 常见问题

| 错误 | 处理方式 |
| --- | --- |
| `enable provider ... access denied` | 确认当前 PowerShell 以管理员运行，或服务账户已授予 `SeSystemProfilePrivilege` |
| `StartTrace failed (Session in use)` | 系统存在同名 Session，执行 `logman delete diag-etw` 或重启服务释放 |

## 2. Linux（eBPF）前提条件

| 项目 | 说明 |
| --- | --- |
| 操作系统 | Kernel ≥ 5.8，建议启用 BTF（`/sys/kernel/btf/vmlinux`）以获得最佳兼容性 |
| 依赖 | 需要 clang/llvm、内核头文件、build-essential、libelf-dev |
| 权限 | 运行账号必须具备 root 权限或 `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_ADMIN` + `CAP_SYS_RESOURCE` |
| 资源限制 | `memlock` 至少 256MB，避免 `map create: operation not permitted` |

### 2.1 依赖安装（以 Debian/Ubuntu 为例）

```bash
sudo apt-get update
sudo apt-get install --yes \
  clang llvm build-essential pkg-config libelf-dev \
  linux-headers-$(uname -r) linux-libc-dev
```

### 2.2 设置二进制能力（可选）

```bash
sudo setcap cap_bpf,cap_perfmon,cap_sys_admin,cap_sys_resource+ep /usr/local/bin/d-eyes
```

若以 systemd 运行 Probe，建议在 Unit 中添加：

```ini
[Service]
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE
LimitMEMLOCK=infinity
```

### 2.3 CLI 启动示例

```bash
sudo env PATH=$PATH \
  go run d-eyes.go collect \
    --backend=ebpf \
    --output-mode=file \
    --output-path=/var/log/d-eyes/ebpf.jsonl \
    --duration=300s
```

> 若 CLI 显示 `clang not found`，请确认 `clang --version` 正常；若提示 `asm/types.h file not found`，表示缺少内核头文件，可重新安装 `linux-headers-$(uname -r)` 并确保 `/usr/include/asm` 链接到对应目录。

## 3. CLI 快速参考

| 场景 | 命令示例 |
| --- | --- |
| Windows ETW 调试 | `d-eyes.exe collect --backend=etw --collector diag-etw --output-mode=stdout` |
| Linux eBPF 调试 | `sudo d-eyes collect --backend=ebpf --output-mode=stream --stream-url=https://ops.example.com/api/v1/events/ingest --stream-api-key=$TOKEN` |
| 指定 Provider/Probe | `--providers="{9e814aad-3204-11d2-9a82-006008a86939}"`、`--probes=sys_enter_execve,sched_process_exit` |

CLI 会将 `collector` 状态与错误写入 `/api/v1/collector/status`，可在 Server 侧通过 REST/SSE 查看。

## 4. 故障排查速查表

| 现象 | 原因 | 处理方式 |
| --- | --- | --- |
| `clang not found` | 系统未安装 clang | 安装 clang/llvm 或通过配置 `collectors[].settings.clang_path` 指向自定义路径 |
| `asm/types.h file not found` | 缺少内核头文件 | 安装 `linux-headers-$(uname -r)` 并确保 `/usr/include/asm` 正确链接 |
| `operation not permitted (MEMLOCK)` | memlock 限制过低 | 执行 `ulimit -l unlimited`、设置 systemd `LimitMEMLOCK=infinity` 或以 root 运行 |
| `ebpf collectors require root or CAP_BPF` | 权限不足 | 使用 root、为可执行文件设置 capabilities、或在 systemd 中授予 `AmbientCapabilities` |
| `ETW enable provider ... access denied` | 未以管理员运行或缺少权限 | 以管理员启动 CLI/服务或授予 `SeSystemProfilePrivilege` |

完成以上准备后，即可结合 Server 的 `/api/v1/collector/configs`、`/status/stream` 控制面，实现跨平台 Collector 的统一部署与运维。
