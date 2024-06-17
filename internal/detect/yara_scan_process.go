//go:build linux || windows

package detect

import (
	"github.com/hillu/go-yara/v4"
	"github.com/m-sec-org/d-eyes/internal"
	"github.com/urfave/cli/v2"
)

var Compiler *yara.Compiler
var Err error
var exErr error
var YaraProcessScanOption *YaraProcessScanOptions

func init() {
	YaraProcessScanOption = NewDetectPluginYaraScan()
	internal.RegisterDetectSubcommands(YaraProcessScanOption)
}

type YaraProcessScanOptions struct {
	// 要扫描的pid
	Pid int
	// 自定义rule
	RulePath string
	// yara规则
	Rules *yara.Rules
	// yara规则是否获取到
	RulesErr error
	// 线程
	Thread int
	internal.BaseOption
}

func NewDetectPluginYaraScan() *YaraProcessScanOptions {
	return &YaraProcessScanOptions{
		RulePath: "",
		Rules:    nil,
		RulesErr: nil,
		Thread:   0,
		BaseOption: internal.BaseOption{
			Name:        "yara process scan",
			Author:      "msec",
			Description: "msec community love to develop, yara scan system process plug-in",
		},
	}
}

type Result struct {
	Risk     string
	RiskPath string
}

func (scan *YaraProcessScanOptions) InitCommand() []*cli.Command {
	return []*cli.Command{
		{
			// 进程扫描，待完成
			Name: "processcan",
			// 使用yara规则扫描指定的文件或文件夹
			Usage:   "Command for scanning processes",
			Aliases: []string{"ps"},
			Action:  scan.Action,
			Flags: []cli.Flag{
				&cli.IntFlag{
					Name:        "pid",
					Aliases:     []string{"p"},
					Value:       -1,
					Usage:       "--pid 666 or -p 666 ('-1' means all processes.)",
					Destination: &YaraProcessScanOption.Pid,
				},
				&cli.StringFlag{
					Name:    "rule",
					Aliases: []string{"r"},
					// 指定yara规则进行扫描,默认为内置yara规则
					Usage:       "Specifies the yara rule for scanning. The default is the built-in yara rule\n                     example: --rule C:\\Botnet.BlackMoon.yar or -r C:\\Botnet.BlackMoon.yar",
					Destination: &YaraProcessScanOption.RulePath,
				},
				&cli.IntFlag{
					Name:    "thread",
					Aliases: []string{"t"},
					// 指定扫描线程
					Usage:       "Assigned scan thread\n                       example: --thread 50 or -t 50",
					Destination: &YaraProcessScanOption.Thread,
					// 默认线程数量
					Value: 20,
				},
			},
		},
	}
}
func (scan *YaraProcessScanOptions) Action(c *cli.Context) error {
	// todo 待完成进程扫描
	return nil
}
