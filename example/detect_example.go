//go:build linux || windows

package example

import (
	"fmt"
	"github.com/m-sec-org/d-eyes/internal"
	"github.com/urfave/cli/v2"
)

var DetectExampleOption *DetectExampleOptions

func init() {
	// 初始化插件
	DetectExampleOption = NewDetectPluginExample()
	// 注册插件到detect中
	internal.RegisterDetectSubcommands(DetectExampleOption)
}

type DetectExampleOptions struct {
	internal.BaseOption
	ExampleString string
}

func NewDetectPluginExample() *DetectExampleOptions {
	return &DetectExampleOptions{
		BaseOption: internal.BaseOption{
			// 插件名称
			Name: "Example plug-in of Detect",
			// 插件作者
			Author: "msec",
			// 插件描述
			Description: "This is a Example plug-in of Detect",
		},
		ExampleString: "",
	}
}
func (example *DetectExampleOptions) InitCommand() []*cli.Command {
	return []*cli.Command{
		{
			// 插件运行要执行的命令,比如当前插件执行的命令为： D-Eyes de example
			// 注意这里的命令不能和 internal/detect 已有的命令重复，
			// 如果重复了请查看您当前编写的插件是否已经存在，或者存在的插件有需要进行改进的地方
			Name: "example",
			// 插件-h --help 显示的帮助信息
			Usage: "This is a example",
			// 插件运行激活函数
			Action: example.Action,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "example",
					Aliases: []string{"e"},
					// 参数例子
					Usage:       "Parameter example",
					Destination: &DetectExampleOption.ExampleString,
				},
			},
		},
	}
}

func (example *DetectExampleOptions) Action(c *cli.Context) error {
	// 插件运行激活函数，插件运行用到的函数名，使用的辅助函数建议使用小写，全部写在当前文件中，
	// utils包中提供了一些工具函数，如果想要新增工具函数请在提交插件的时候一起提交pr
	// 插件应当有test函数，具体参考 detect_example_test.go
	// 如果您在上一步定义了一些参数，可以在这里取到您需要的参数,比如 example 参数
	fmt.Println(example.ExampleString)
	return nil
}
