package internal

import (
	"github.com/urfave/cli/v2"
)

var DetectCommand *cli.Command

func init() {
	DetectCommand = &cli.Command{
		Name:    "detect",
		Aliases: []string{"de"},
		// 应急响应模块，入侵检测
		Usage:       "Emergency response module, intrusion detection",
		Subcommands: make([]*cli.Command, 0),
	}
	// 注册到App中
	RegisterCommand(DetectCommand)
}

type DetectPlugin interface {
	InitCommand() []*cli.Command
	Action(c *cli.Context) error
}

// todo 添加一个所有插件的变量，添加一个命令用来执行所有插件

// RegisterDetectSubcommands 注册detect子命令
func RegisterDetectSubcommands(d DetectPlugin) {
	DetectCommand.Subcommands = append(DetectCommand.Subcommands, d.InitCommand()...)
}

type BaseOption struct {
	// 插件名称
	Name string
	// 作者名称
	Author string
	// 检测插件描述
	Description string
}
