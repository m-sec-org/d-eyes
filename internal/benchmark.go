package internal

import "github.com/urfave/cli/v2"

var BenchmarkCommand *cli.Command

func init() {
	BenchmarkCommand = &cli.Command{
		Name:    "benchmark",
		Aliases: []string{"bm"},
		// 基线检测模块，
		Usage:       "Baseline detection module",
		Subcommands: make([]*cli.Command, 0),
	}
	// 注册到App中
	RegisterCommand(BenchmarkCommand)
}

// todo 待添加入侵检测模块相关内容
