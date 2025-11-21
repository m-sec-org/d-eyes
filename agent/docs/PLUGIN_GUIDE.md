# D-Eyes Agent 插件开发指南

本指南说明如何在保留 CLI 独立运行能力的同时，为远程模式复用现有 TaskRunner 接口，快速扩展新的检测/响应能力。

## 1. 插件机制概览

- 核心入口 `agent/internal/app.go` 使用 `urfave/cli` 构建命令体系。
- 每个功能通过 `tasks.TaskRunner` 暴露主业务逻辑，CLI 与远程守护程序均调用同一 Runner。
- 插件可调用 `internal.RegisterCommand`（默认实例）或 `internal.AttachCommand(customApp, cmd)`（自定义实例）注册新的 CLI 命令。
- 远程模式 (`d-eyes remote`) 会根据任务类型调用 `internal.TaskRunnerByName` 查找 Runner，并复用 `tasks.ExecuteWithResult` 执行任务。

## 2. 插件 Manifest 与签名

Stage 4 起，所有插件必须携带符合 `docs/plugin-manifest.md` 的清单文件：

- `apiVersion=v1`、`name`、`version`、`entry`、`artifactDigest`
- 任务声明（`tasks[].name/kind`）、受支持的平台（`targets`）、资源预算（`resources`）
- `signature`（ed25519，64 字节 Base64 编码）

Agent 会在加载前调用 `plugin.LoadManifestFromPath` 校验字段与签名，Server 侧同样使用该规范审批第三方插件。失败会阻止插件进入任务注册流程。

示例：

```yaml
apiVersion: v1
name: respond-risk-score
version: 1.2.3
entry: ./plugin.so
artifactDigest: <sha256>
tasks:
  - name: respond-risk-score
    kind: respond
signature:
  algorithm: ed25519
  publicKey: <base64-key>
  value: <base64-signature>
```

### 沙箱、资源与回滚

- 使用 `metadata.sandbox=required` 显式声明插件需沙箱执行；平台配置也可全局强制沙箱。
- `resources.cpu/memory/timeout` 会与平台上限对比，超限即拒绝加载。
- `plugin.Manager`（`internal/plugin/runtime_policy.go`）在安装/拒绝/回滚时触发 observability hook，可接入市场/监控。

## 3. 示例插件

仓库下的 `agent/internal/plugin/examples/` 提供三个可直接运行/扩展的示例：

- `respond_example`：模拟响应任务，输出日志与 metadata。
- `detect_example`：触发风险计数并生成 JSON 报告。
- `bas_example`：演示 BAS 步骤执行与沙箱 metadata。

每个示例都包含：

1. `Runner` 实现 `tasks.TaskRunner`
2. `manifest.yaml`（示例见下文）供打包和签名
3. 打包指引（Makefile / shell 示例）

### 3.1 Respond 示例 Runner

```go
// agent/internal/plugin/examples/respond_example/respond_example.go
type Runner struct{}

func (Runner) Run(ctx context.Context, req tasks.TaskRequest) (tasks.TaskResult, error) {
    return tasks.TaskResult{
        Outputs: []tasks.OutputRecord{{Path: "/tmp/respond-example.log", Label: "示例输出"}},
        Risks: map[string]int{"info": 0},
        Metadata: map[string]string{"plugin": "respond-example"},
    }, nil
}
```

### 3.2 示例 Manifest

```yaml
apiVersion: v1
name: respond-example
version: 0.1.0
entry: ./respond-example.so
artifactDigest: <sha256>
tasks:
  - name: respond-example
    kind: respond
metadata:
  sandbox: required
signature:
  algorithm: ed25519
  publicKey: <base64>
  value: <base64-signature>
```

签名步骤：

```bash
GOOS=linux GOARCH=amd64 go build -buildmode=plugin -o respond-example.so ./agent/internal/plugin/examples/respond_example
shasum -a256 respond-example.so | awk '{print $1}'
# 将 digest 写入 manifest 后使用签名工具生成带签名清单
```

## 4. 注册 CLI 命令

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

## 5. 远程任务对接

- 远程任务由 Server 下发任务类型、Profile、Payload 等信息。
- 只要任务类型名称与注册命令一致，即可被远程守护程序识别并执行。
- Runner 应遵循 `tasks.TaskResult` 约定，同时通过 `Tasks.ExecuteWithResult` 返回 summary，实现本地/远程统一摘要。

## 6. 测试建议

```bash
# 本地运行插件命令
cd agent
D_EYES_CONFIG=./config.yaml go run ./cmd/agent simple --profile default

# 远程模式（需启动 Server）
go run ./cmd/agent remote
```

## 7. BAS Runner 扩展

BAS 模块现支持依赖注入，便于在测试或自定义场景中重用场景加载、沙箱执行、遥测编码逻辑。

- `BASRunnerWithDeps(loader, factory, encoder)`：允许注入自定义 `ScenarioLoader`（解析场景文件/ID）、`SandboxExecutorFactory`（包装自定义沙箱或 mock 执行器）、`TelemetryEncoder`（自定义步骤/统计编码）。
- 默认实现仍使用内置的 `loadScenario`、`sandbox.Manager` 与 `telemetry.EncodeBASteps/EncodeSandboxStats`，CLI 与远程模式行为保持一致。
- 在编写单元测试或集成第三方沙箱时，可实现这些接口并注入，避免真实沙箱依赖，示例：

```go
loader := &myScenarioLoader{}
factory := &mySandboxFactory{}
encoder := &myTelemetryEncoder{}
runner := tasks.BASRunnerWithDeps(loader, factory, encoder)
```

## 8. RunnerFactory 与核心服务注入

为提升可测性与可插拔能力，Agent 在 v1.4 引入 RunnerFactory 以及多处核心服务注入点：

- **RunnerFactory**（`internal.RunnerFactory`）统一生成 respond/inventory/supplychain/baseline/BAS/action 等 Runner。CLI 与远程守护进程会自动调用 `DefaultRunnerFactory`，并通过 `TaskRunnerByName` 共用同一个注册表。
- **测试/插件注入**：在 CLI 集成测试中可使用 `NewRuntime(WithRunnerFactory(factory))` 注入自定义工厂；远程端到端测试可利用 `internal.OverrideRunnerFactoryForTesting` 动态替换 Runner，避免真实扫描。
- **ThreatIntel/Sandbox/RuleEngine**：`tasks.SetThreatIntelProvider`、`sandbox.SetControllerFactory`、`detect/rules.SetRuleEngineFactory` 允许在测试或插件场景中替换威胁情报来源、沙箱控制器、规则引擎，实现一致的依赖注入模式。

示例：

```go
factory := customRunnerFactory{respond: fakeRespondRunner}
runtime := agent.NewRuntime(agent.WithRunnerFactory(factory))
exitCode, err := runtime.Run([]string{"d-eyes", "respond", "--targets", "/tmp"})
```

若仅需在局部测试替换依赖，可调用 `tasks.SetThreatIntelProvider(fakeTI)` 或 `sandbox.SetControllerFactory(fakeFactory)` 并在 `t.Cleanup` 中恢复缺省实现。

## 9. 发布注意事项

- 确保插件依赖在 `agent/go.mod` 中显式声明，避免影响主仓库构建。
- 如需共享库组件，可在 `agent/internal/` 或 `agent/pkg/` 下新增模块，并为远程模式提供必要的数据结构转换。
- 更新 `PLUGIN_GUIDE.md` 与 `README.md` 描述新增命令和使用方式。
