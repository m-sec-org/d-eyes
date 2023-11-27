package check

import (
	"github.com/gookit/color"
)

func Trigger() {
	color.Greenp("==============================================================================================\n")
	color.Greenp("空密码账户检测中··· \n")
	if !Empty() {
		color.Infoln("空密码账户检测: [safe]")
	}
	color.Greenp("==============================================================================================\n")
	color.Greenp("主机 Sudoer 检测中··· \n")
	if !Sudo() {
		color.Infoln("主机 Sudoer 检测: [safe]")
	}
	color.Greenp("==============================================================================================\n")
	color.Greenp("SSH Server wrapper 检测中··· \n")
	if !SshWrapper() {
		color.Infoln("SSH Server wrapper 检测: [safe]")
	}
	color.Greenp("==============================================================================================\n")
	color.Greenp("SSH用户免密证书登录检测中··· \n")
	if !AuthorizedKeys() {
		color.Infoln("SSH用户免密证书登录检测: [safe]")
	}
	color.Greenp("==============================================================================================\n")
	color.Greenp("SSH登录爆破检测中··· \n")
	SSHLog()

	color.Greenp("==============================================================================================\n")
	color.Greenp("LD_PRELOAD 检测中··· \n")
	if !LdPreloadCheck() {
		color.Infoln("LD_PRELOAD 检测: [safe]")
	}
	color.Greenp("==============================================================================================\n")
	color.Greenp("LD_AOUT_PRELOAD 检测中··· \n")
	if !LdAoutPreloadCheck() {
		color.Infoln("LD_AOUT_PRELOAD 检测: [safe]")
	}
	color.Greenp("==============================================================================================\n")
	color.Greenp("LD_ELF_PRELOAD 检测中··· \n")
	if !LdElfPreloadCheck() {
		color.Infoln("LD_ELF_PRELOAD 检测: [safe]")
	}
	color.Greenp("==============================================================================================\n")
	color.Greenp("LD_LIBRARY_PATH 检测中··· \n")
	if !LdLibraryPathCheck() {
		color.Infoln("LD_LIBRARY_PATH 检测: [safe]")
	}
	color.Greenp("==============================================================================================\n")
	color.Greenp("ld.so.preload 检测中··· \n")
	if !LdSoPreload() {
		color.Infoln("ld.so.preload 检测: [safe]")
	}
	color.Greenp("==============================================================================================\n")
	color.Greenp("PROMPT_COMMAND 检测中··· \n")
	if !PromptCommandCheck() {
		color.Infoln("PROMPT_COMMAND 检测: [safe]")
	}
	color.Greenp("==============================================================================================\n")
	color.Greenp("自定义环境变量检测中··· \n")
	if !ExportCheck() {
		color.Infoln("自定义环境变量检测: [safe]")
	}
	color.Greenp("==============================================================================================\n")
	color.Greenp("inetd.conf 检测中··· \n")
	if !IntedCheck() {
		color.Infoln("inted.conf 检测: [safe]")
	}
	color.Greenp("==============================================================================================\n")
	color.Greenp("xinetd.conf 检测中··· \n")
	if !XinetdCheck() {
		color.Infoln("xinetd.conf 检测: [safe]")
	}
	color.Greenp("==============================================================================================\n")
	color.Greenp("系统启动服务检测中··· \n")
	if !StartupCheck() {
		color.Infoln("系统启动服务检测: [safe]")
	}
	color.Greenp("==============================================================================================\n")
	color.Greenp("主机计划任务检测中··· \n")
	CrontabCheck()
	color.Greenp("==============================================================================================\n")
	color.Greenp("TCP Wrappers 检测中··· \n")
	if !TcpWrappersCheck() {
		color.Infoln("TCP Wrappers 检测: [safe]")
	}
	color.Greenp("==============================================================================================\n")
	color.Greenp("alias 检测中··· \n")
	if !AliasConf() {
		color.Infoln("alias 检测: [safe]")
	}
	color.Greenp("==============================================================================================\n")
	color.Greenp("主机历史命令检测中··· \n")
	HistoryCheck()
	color.Greenp("==============================================================================================\n")
	color.Greenp("主机最近成功登录信息: \n")
	SuccessLoginDetail()
	color.Greenp("==============================================================================================\n")
	color.Greenp("主机Rootkit检测中··· \n")
	RootkitCheck()
	color.Greenp("==============================================================================================\n")
	color.Greenp("Setuid检测中··· \n")
	if !SetUid() {
		color.Infoln("Setuid检测: [safe]")
	}
	color.Greenp("==============================================================================================\n")
}
