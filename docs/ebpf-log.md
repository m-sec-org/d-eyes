# eBPF verifier log（cilium/ebpf v0.20 迁移）

ebpf v0.20版本虽然把 ProgramLogOptions 和 Log 字段干掉了，但换了一种方式来拿 verifier log，不是完全没法用了。

核心变化是：

现在只在 库内部 把 verifier 输出写到 buffer 里

然后把结果挂在 Program.VerifierLog 这个字段上，由你自己决定往哪儿打印（比如 os.Stderr）

加载失败时，会返回一个带完整 log 的 VerifierError，可以用 errors.As 抽出来打印

下面是把老代码迁移到 v0.20 的典型做法。

# 1. 成功加载时打印 verifier log

老版本大概是类似这样（伪代码）：

opts := ebpf.ProgramOptions{
    Log: ebpf.ProgramLogOptions{
        Level:    ebpf.LogLevelInstruction,
        LogWriter: os.Stderr,
    },
}
prog, err := ebpf.NewProgramWithOptions(spec, opts)


在 v0.20 里改成：

package main

import (
    "errors"
    "fmt"
    "os"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/asm"
)

func main() {
    spec := &ebpf.ProgramSpec{
        Type: ebpf.SocketFilter,
        Instructions: asm.Instructions{
            asm.LoadImm(asm.R0, 0, asm.DWord),
            asm.Return(),
        },
        License: "MIT",
    }

    prog, err := ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
        // 关键：打开 verifier log
        LogLevel: ebpf.LogLevelInstruction, // 或组合其他 LogLevel*
        // LogSizeStart: 可选，默认即可
    })
    if err != nil {
        var ve *ebpf.VerifierError
        if errors.As(err, &ve) {
            // %+v 会把完整 log 打出来
            fmt.Fprintf(os.Stderr, "verifier error: %+v\n", ve)
        }
        // 其他错误处理
        return
    }
    defer prog.Close()

    // 成功加载的情况下，verifier log 会在这里
    if prog.VerifierLog != "" {
        fmt.Fprintln(os.Stderr, "verifier output:")
        fmt.Fprintln(os.Stderr, prog.VerifierLog)
    }
}


关键点：

ProgramOptions.LogLevel 非零时，库会申请一块 buffer，把 verifier 日志写进去，并填充到 prog.VerifierLog 字段
Go Packages
+1

你想重定向到哪里，就自己 fmt.Fprintln(os.Stderr, prog.VerifierLog) 即可，相当于自己接管了“LogWriter”。

# 2. 加载失败时打印完整 verifier log

新版本对错误路径做得更统一：

NewProgram / NewProgramWithOptions 如果因为 verifier 拒绝而失败，会返回一个 VerifierError，这个 error 本身就带了完整 log
Go Packages
+1

标准用法（官方 Example 也是这么写的）：

prog, err := ebpf.NewProgram(spec)
if err != nil {
    var ve *ebpf.VerifierError
    if errors.As(err, &ve) {
        // %+v 打所有行；%+1v 只打第一行，等等
        fmt.Fprintf(os.Stderr, "verifier error: %+v\n", ve)
    } else {
        fmt.Fprintf(os.Stderr, "load program failed: %v\n", err)
    }
    return
}


如果只是为了 debug verifier 拒绝，甚至可以不设 LogLevel，直接依赖 VerifierError 的日志。

# 3. 是否还能“流式重定向”到任意 io.Writer？

这一点确实没了——在公开 API 里：

不再暴露类似 ProgramLogOptions{Writer io.Writer} 的接口

统一走内部缓冲 + Program.VerifierLog / VerifierError 这条路

所以现在能做的是：

成功加载路径：

用 NewProgramWithOptions + LogLevel

之后 os.Stderr.Write([]byte(prog.VerifierLog))

失败路径：

用 errors.As 抽 *VerifierError，fmt.Fprintf(os.Stderr, "%+v\n", ve)

如果你强需求是“像以前一样，边 verify 边把每一行往某个 writer 写”（比如 very large log + 想提前中断），那就只有两条路：

要么自己 fork 一份 cilium/ebpf，在内部恢复类似 LogWriter 的钩子；

要么不用库封装，自己走 syscall.Syscall/unix.BPF() 直接调用 bpf(BPF_PROG_LOAD, ...)，把 log_buf 映射成你想要的输出方式（代价就是要自己处理 feature probe、CO-RE 等一堆细节）。

# 4. 小结

结论：

ProgramLogOptions / Log 确实被干掉了。

但 verifier 日志并没有丢：

成功时：prog.VerifierLog

失败时：VerifierError（errors.As + %+v）

“重定向到 os.Stderr” 的新写法就是：先让库把 log 收进字符串，再自己往 os.Stderr 打。
