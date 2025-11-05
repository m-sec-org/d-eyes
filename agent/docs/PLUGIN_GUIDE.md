# D-Eyes Agent 插件开发指南

本指南说明如何在保留 CLI 独立运行能力的同时，为远程模式复用现有 TaskRunner 接口，快速扩展新的检测/响应能力。

## 1. 插件机制概览

- 核心入口 `agent/internal/app.go` 使用 `urfave/cli` 构建命令体系。
- 每个功能通过 `tasks.TaskRunner` 暴露主业务逻辑，CLI 与远程守护程序均调用同一 Runner。
- 插件可调用 `internal.RegisterCommand`（默认实例）或 `internal.AttachCommand(customApp, cmd)`（自定义实例）注册新的 CLI 命令。
- 远程模式 (`d-eyes remote`) 会根据任务类型调用 `internal.TaskRunnerByName` 查找 Runner，并复用 `tasks.ExecuteWithResult` 执行任务。

## 2. 创建新的 TaskRunner

```go
// 示例：新增 simple runner
package simple

type runner struct{}

func NewRunner() tasks.TaskRunner { return &runner{} }

func (r *runner) Run(ctx context.Context, req tasks.TaskRequest) (tasks.TaskResult, error) {
    // TODO: 填写业务逻辑
}
```

将实现文件放在 `agent/internal/tasks/` 或单独模块中导出。

## 3. 注册 CLI 命令

```go
func init() {
    internal.RegisterCommand(&cli.Command{
        Name: "simple",
        Usage: "执行自定义任务",
        Action: func(c *cli.Context) error {
            req := tasks.TaskRequest{Profile: c.String("profile")}
            req.ApplyDefaults("simple")
            runner := simple.NewRunner()
            return tasks.Execute(c.Context, "simple", runner, req, internal.GetReportManager())
        },
    })
}
```

- `RegisterCommand` 会将命令附加到默认 `App`，CLI 即可直接使用。
- 避免在 init 中执行复杂逻辑，确保插件延迟加载。

## 4. 远程任务对接

- 远程任务由 Server 下发任务类型、Profile、Payload 等信息。
- 只要任务类型名称与注册命令一致，即可被远程守护程序识别并执行。
- Runner 应遵循 `tasks.TaskResult` 约定，同时通过 `Tasks.ExecuteWithResult` 返回 summary，实现本地/远程统一摘要。

## 5. 测试建议

```bash
# 本地运行插件命令
cd agent
D_EYES_CONFIG=./config.yaml go run ./cmd/agent simple --profile default

# 远程模式（需启动 Server）
go run ./cmd/agent remote
```

## 6. 发布注意事项

- 确保插件依赖在 `agent/go.mod` 中显式声明，避免影响主仓库构建。
- 如需共享库组件，可在 `agent/internal/` 或 `agent/pkg/` 下新增模块，并为远程模式提供必要的数据结构转换。
- 更新 `PLUGIN_GUIDE.md` 与 `README.md` 描述新增命令和使用方式。

