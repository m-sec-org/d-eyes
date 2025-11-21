# 插件 SDK 与任务扩展示例

本文面向希望在 Stage4 阶段扩展自定义任务/插件的开发者，梳理 Agent 内置 SDK（TaskRunner、Manifest、依赖注入）的使用方式，并给出最小可运行示例。

## 1. SDK 能力概览

- **TaskRunner 接口**：位于 `agent/internal/tasks`，所有任务（respond/inventory/baseline/BAS 等）都实现 `Run(ctx, TaskRequest) (TaskResult, error)`。
- **运行时注入**：通过 `internal.RegisterCommand`/`TaskRunnerByName` 统一注册 CLI 命令与远程 Runner，CLI 与 `d-eyes remote` 共享同一实现。
- **Manifest + 签名**：插件在打包时附带 `docs/plugin-manifest.md` 规范的清单，Server/Agent 在安装或加载前自动校验版本、资源、签名。
- **沙箱与资源策略**：借助 `metadata.sandbox`、`resources.cpu/memory/timeout` 控制安全边界，BAS/高危插件可以直接复用 Stage4 的审批与沙箱链路。

> 完整编写指南可参考 `agent/docs/PLUGIN_GUIDE.md`，本文聚焦 SDK 接口与示例代码。

## 2. 快速入门示例

### 2.1 目录结构

```
agent/internal/plugin/examples/myplugin/
├── myplugin.go        # TaskRunner 实现
├── manifest.yaml      # Manifest + 签名
└── Makefile           # 构建脚本
```

### 2.2 Runner 实现

```go
package myplugin

import (
	"context"

	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
)

type Runner struct{}

func (Runner) Run(ctx context.Context, req tasks.TaskRequest) (tasks.TaskResult, error) {
	req.ApplyDefaults("myplugin")
	return tasks.TaskResult{
		Outputs: []tasks.OutputRecord{
			{Label: "检测报告", Path: "/tmp/myplugin-report.json"},
		},
		Risks: map[string]int{"info": 1},
		Metadata: map[string]string{
			"plugin":   "myplugin",
			"scenario": req.Metadata["scenario_id"],
		},
	}, nil
}
```

在 `init()` 中注册 CLI 命令：

```go
func init() {
	internal.RegisterCommand(&cli.Command{
		Name:  "myplugin",
		Usage: "执行自定义任务",
		Action: func(c *cli.Context) error {
			req := tasks.TaskRequest{
				Profile:  c.String("profile"),
				Metadata: map[string]string{"scenario_id": c.String("scenario")},
			}
			req.ApplyDefaults("myplugin")
			return tasks.ExecuteWithResult(c.Context, "myplugin", Runner{}, req, internal.GetReportManager())
		},
	})
}
```

- CLI 运行：`go run ./cmd/agent myplugin --scenario initial-access`
- 远程任务：Server 创建 `type="myplugin"` 的任务即可由 Agent 执行。

### 2.3 Manifest 模板

```yaml
apiVersion: v1
name: myplugin
version: 0.1.0
entry: ./myplugin.so
artifactDigest: <shasum>
tasks:
  - name: myplugin
    kind: respond
resources:
  cpu: 250m
  memory: 128Mi
  timeout: 5m
metadata:
  sandbox: required
signature:
  algorithm: ed25519
  publicKey: <base64>
  value: <base64-signature>
```

签名流程与示例可参考 `docs/plugin-samples.md`。

## 3. SDK API 速查

| 模块 | 关键 API | 用途 |
|------|---------|------|
| `tasks.TaskRequest` | `ApplyDefaults(name)` | 套用 `config.yaml` 中的 profile、输出目录、超时、Sandbox 审批信息。 |
| `tasks.ExecuteWithResult` | `ExecuteWithResult(ctx, name, runner, req, manager)` | 执行 Runner 并将结果写入报告目录，CLI/远程共用。 |
| `internal.RegisterCommand` | `RegisterCommand(*cli.Command)` | 注入 CLI 命令，使 `d-eyes <name>` 能调用插件。 |
| `internal.TaskRunnerByName` | `TaskRunnerByName("myplugin")` | 远程守护或测试可通过名字找到 Runner。 |
| `tasks.BASRunnerWithDeps` | `BASRunnerWithDeps(loader, factory, encoder)` | 若插件扩展 BAS，可注入自定义步骤加载与沙箱执行。 |

## 4. SDK 最佳实践

1. **模块化**：将业务逻辑拆分到 `pkg/<module>`，Runner 中仅处理参数解析与结果封装。
2. **依赖注入**：利用 `tasks.SetThreatIntelProvider`、`sandbox.SetControllerFactory`、`detect/rules.SetRuleEngineFactory` 替换默认实现，便于测试与扩阶。
3. **覆盖率**：`go test ./agent/internal/plugin/...` + `scripts/docs-lint.sh` 作为插件 PR 的必备检查。
4. **审计与 metadata**：在 `TaskResult.Metadata` 中写入 `plugin`, `version`, `targets` 等信息，便于 Server/Audit 聚合。
5. **发布整合**：在 `docs/version.yaml` 中记录插件文档版本，发布前运行 `scripts/docs-release.sh` 复制快照。

通过以上步骤，插件即可在 Stage4 平台上获得统一的检测、沙箱、审批与观测能力。
