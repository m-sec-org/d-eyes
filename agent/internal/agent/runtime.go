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
	App *cli.App
}

// NewRuntime 创建新的运行时，默认复用 internal.App。
func NewRuntime() *Runtime {
	app := internal.App
	ensureRemoteCommand(app)
	return &Runtime{App: app}
}

// Run 执行 CLI 应用，返回退出码与错误。
func (r *Runtime) Run(args []string) (int, error) {
	if r.App == nil {
		return 1, errors.New("agent runtime: cli app is nil")
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
		Name:  "remote",
		Usage: "以远程模式连接 D-Eyes Server 并执行任务",
		Action: func(c *cli.Context) error {
			cfg := internal.GetGlobalConfig()
			if err := RunRemote(c.Context, cfg.Remote); err != nil {
				return cli.Exit(err.Error(), 1)
			}
			return nil
		},
	}
}
