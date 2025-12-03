package agent

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/urfave/cli/v2"

	internal "github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/pkg/color"
	"github.com/m-sec-org/d-eyes/agent/pkg/logo"
	"github.com/m-sec-org/d-eyes/agent/pkg/logs"
)

// Runtime 封装 CLI 运行入口，便于复用/集成。
type Runtime struct {
	App                  *cli.App
	runnerFactory        internal.RunnerFactory
	runnerFactoryRestore func()
}

type runtimeOptions struct {
	runnerFactory internal.RunnerFactory
}

// RuntimeOption 自定义 Runtime 行为（目前支持 Runner 工厂注入）。
type RuntimeOption func(*runtimeOptions)

// WithRunnerFactory 允许调用方为 CLI 注入自定义 Runner 工厂（主要用于测试）。
func WithRunnerFactory(factory internal.RunnerFactory) RuntimeOption {
	return func(opts *runtimeOptions) {
		opts.runnerFactory = factory
	}
}

// NewRuntime 创建新的运行时，默认复用 internal.App。
func NewRuntime(opts ...RuntimeOption) *Runtime {
	config := runtimeOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(&config)
		}
	}
	app := internal.App
	ensureRemoteCommand(app)
	ensureCollectCommand(app)
	return &Runtime{App: app, runnerFactory: config.runnerFactory}
}

// Run 执行 CLI 应用，返回退出码与错误。
func (r *Runtime) Run(args []string) (int, error) {
	if r.App == nil {
		return 1, errors.New("agent runtime: cli app is nil")
	}
	if r.runnerFactory != nil {
		r.applyRunnerFactory()
		defer r.restoreRunnerFactory()
	}

	logo.ShowLogo()
	logs.InitLog()

	start := time.Now()
	if err := r.App.Run(args); err != nil {
		exitCode := 1
		if exitCoder, ok := err.(interface{ ExitCode() int }); ok {
			exitCode = exitCoder.ExitCode()
		}
		if !internal.IsQuietMode() {
			fmt.Fprintln(os.Stderr, color.Magenta.Sprintf("任务执行失败: %v", err))
		}
		return exitCode, err
	}

	if !internal.IsQuietMode() {
		fmt.Println()
		fmt.Println(color.Green.Sprintf("Thank you for using d-eyes, this run took %f seconds.", time.Since(start).Seconds()))
	}
	return 0, nil
}

func (r *Runtime) applyRunnerFactory() {
	if r.runnerFactoryRestore != nil || r.runnerFactory == nil {
		return
	}
	r.runnerFactoryRestore = internal.OverrideRunnerFactoryForTesting(r.runnerFactory)
}

func (r *Runtime) restoreRunnerFactory() {
	if r.runnerFactoryRestore == nil {
		return
	}
	r.runnerFactoryRestore()
	r.runnerFactoryRestore = nil
}

func ensureRemoteCommand(app *cli.App) {
	for _, cmd := range app.Commands {
		if cmd.Name == "remote" {
			return
		}
	}
	internal.AttachCommand(app, remoteCommand())
}

func remoteCommand() *cli.Command {
	return &cli.Command{
		Name:     "remote",
		Usage:    "以远程模式连接 D-Eyes Server 并执行任务",
		Category: "Integration",
		Action: func(c *cli.Context) error {
			cfg := internal.GetGlobalConfig()
			if err := RunRemote(c.Context, cfg.Remote); err != nil {
				return cli.Exit(err.Error(), 1)
			}
			return nil
		},
	}
}
