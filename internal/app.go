package internal

import (
	"fmt"
	"runtime"

	"github.com/urfave/cli/v2"

	// 导入资产探测模块
	"github.com/m-sec-org/d-eyes/internal/assets"
)

var App *cli.App
var version = "v1.3.1"

func init() {
	App = cli.NewApp()
	App.Name = "d-eyes"
	App.Usage = "The Eyes of Darkness from Nsfocus spy on everything."
	App.Description = "D-Eyes 是一款综合性安全扫描工具，用于发现和识别潜在的安全风险。"
	App.Commands = []*cli.Command{
		{
			Name:    "version",
			Aliases: []string{"v"},
			Usage:   "Show the version of d-eyes",
			Action: func(c *cli.Context) error {
				fmt.Printf("D-Eyes %s\n", version)
				fmt.Printf("操作系统: %s\n", runtime.GOOS)
				fmt.Printf("架构: %s\n", runtime.GOARCH)
				return nil
			},
		},
	}

	// 注册资产探测模块子命令
	App.Commands = append(App.Commands, assets.NewAssetsCommand())
}

// RegisterCommand 注册插件
func RegisterCommand(c *cli.Command) {
	if c == nil {
		panic("plugin: Register plugin is nil")
	}
	App.Commands = append(App.Commands, c)
}
