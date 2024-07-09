//go:build linux

package detect

import (
	"fmt"

	"github.com/urfave/cli/v2"

	"github.com/m-sec-org/d-eyes/internal"
	"github.com/m-sec-org/d-eyes/internal/detect/check"
	"github.com/m-sec-org/d-eyes/pkg/color"
)

var CheckOption *CheckOptions

type CheckOptions struct {
	internal.BaseOption
}

func init() {
	CheckOption = NewDetectPluginCheck()
	internal.RegisterDetectSubcommands(CheckOption)

}
func NewDetectPluginCheck() *CheckOptions {
	return &CheckOptions{
		internal.BaseOption{
			// 检测常规异常,命令，用于检查一些可能有后门的文件
			Name:        "Detect routine anomalies",
			Author:      "msec",
			Description: "Command for checking some files which may have backdoors",
		},
	}
}
func (check *CheckOptions) InitCommand() []*cli.Command {
	return []*cli.Command{
		&cli.Command{
			Name:   "check",
			Usage:  "Command for checking some files which may have backdoors",
			Action: check.Action,
		},
	}
}

func (check *CheckOptions) Action(c *cli.Context) error {
	trigger()
	return nil
}
func trigger() {
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("空密码账户检测中··· "))
	if !check.Empty() {
		fmt.Println(color.Yellow.Sprint("空密码账户检测: [safe]"))
	}
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("主机 Sudoer 检测中··· "))
	if !check.Sudo() {
		fmt.Println(color.Yellow.Sprint("主机 Sudoer 检测: [safe]"))
	}
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("SSH Server wrapper 检测中··· "))
	if !check.SshWrapper() {
		fmt.Println(color.Yellow.Sprint("SSH Server wrapper 检测: [safe]"))
	}
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("SSH用户免密证书登录检测中··· "))

	if !check.AuthorizedKeys() {
		fmt.Println(color.Yellow.Sprint("SSH用户免密证书登录检测: [safe]"))
	}
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("SSH登录爆破检测中··· "))
	check.SSHLog()
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("LD_PRELOAD 检测中··· "))

	if !check.LdPreloadCheck() {
		fmt.Println(color.Yellow.Sprint("LD_PRELOAD 检测: [safe]"))
	}
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("LD_AOUT_PRELOAD 检测中··· "))
	if !check.LdAoutPreloadCheck() {
		fmt.Println(color.Yellow.Sprint("LD_AOUT_PRELOAD 检测: [safe]"))
	}

	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("LD_ELF_PRELOAD 检测中··· "))
	if !check.LdElfPreloadCheck() {
		fmt.Println(color.Yellow.Sprint("LD_ELF_PRELOAD 检测: [safe]"))

	}
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("LD_LIBRARY_PATH 检测中··· "))

	if !check.LdLibraryPathCheck() {
		fmt.Println(color.Yellow.Sprint("LD_LIBRARY_PATH 检测: [safe]"))

	}
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("ld.so.preload 检测中··· "))
	if !check.LdSoPreload() {
		fmt.Println(color.Yellow.Sprint("ld.so.preload 检测: [safe]"))

	}
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("PROMPT_COMMAND 检测中··· "))

	if !check.PromptCommandCheck() {
		fmt.Println(color.Yellow.Sprint("PROMPT_COMMAND 检测: [safe]"))

	}
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("自定义环境变量检测中··· "))

	if !check.ExportCheck() {
		fmt.Println(color.Yellow.Sprint("自定义环境变量检测: [safe]"))

	}
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("inetd.conf 检测中··· "))

	if !check.InitedCheck() {
		fmt.Println(color.Yellow.Sprint("inted.conf 检测: [safe]"))

	}
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("xinetd.conf 检测中··· "))

	if !check.XinetdCheck() {
		fmt.Println(color.Yellow.Sprint("xinetd.conf 检测: [safe]"))

	}
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("系统启动服务检测中··· "))

	if !check.StartupCheck() {
		fmt.Println(color.Yellow.Sprint("系统启动服务检测: [safe]"))

	}
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("主机计划任务检测中··· "))
	check.CrontabCheck()
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("TCP Wrappers 检测中··· "))
	if !check.TcpWrappersCheck() {
		fmt.Println(color.Yellow.Sprint("TCP Wrappers 检测: [safe]"))
	}

	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("alias 检测中··· "))
	if !check.AliasConf() {
		fmt.Println(color.Yellow.Sprint("alias 检测: [safe]"))
	}
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("主机历史命令检测中··· "))
	check.HistoryCheck()
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("主机最近成功登录信息: "))
	check.SuccessLoginDetail()
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("主机Rootkit检测中··· "))
	check.RootkitCheck()
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	fmt.Println(color.Green.Sprint("Setuid检测中··· "))
	if !check.SetUid() {
		fmt.Println(color.Yellow.Sprint("Setuid检测: [safe]"))
	}
	fmt.Println(color.Green.Sprint("=============================================================================================="))
}
