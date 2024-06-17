//go:build windows

package detect

import (
	"fmt"
	"github.com/m-sec-org/d-eyes/internal"
	deUtils "github.com/m-sec-org/d-eyes/internal/detect/utils"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/urfave/cli/v2"
	"os"
	"os/exec"
	"os/user"
)

var SummaryOption *SummaryOptions

func init() {
	SummaryOption = NewDetectPluginSummary()
	internal.RegisterDetectSubcommands(SummaryOption)
}

type SummaryOptions struct {
	internal.BaseOption
}

func NewDetectPluginSummary() *SummaryOptions {
	return &SummaryOptions{
		BaseOption: internal.BaseOption{
			// 导出基本信息
			Name:        "export info",
			Author:      "msec",
			Description: "exporting basic host information",
		},
	}
}
func (summary *SummaryOptions) InitCommand() []*cli.Command {
	return []*cli.Command{
		&cli.Command{
			Name:   "export",
			Usage:  "Command for exporting basic host information",
			Action: summary.Action,
		},
	}
}

func (summary *SummaryOptions) Action(c *cli.Context) error {
	SaveSummaryBaseInfo()
	return nil
}
func SaveSummaryBaseInfo() {
	f, err := os.Create("SummaryBaseInfo.txt")
	if err != nil {
		fmt.Println(err)
		return
	}

	baseInfo := getBaseInfo()
	_, err = f.WriteString("HostInfo: \n" + baseInfo)

	users := deUtils.GetWindowsUser()
	_, err = f.WriteString("AllUsers: \n")
	for _, userInfo := range users {
		_, err = f.WriteString("    * " + userInfo + "\n")
	}

	crontab := GetCronTab()
	crontabString := ""
	crontabString += "Os Crontab: \n==============================================================================================\n"
	for _, item := range crontab {

		crontabString += "*NAME:        " + item.Name + "\n" +
			"*COMMAND:     " + item.Command + "\n" +
			"*ARG:         " + item.Arg + "\n" +
			"*USER:        " + item.User + "\n" +
			"*RULE:        " + item.Rule + "\n" +
			"*DESCRIPTION: " + item.Description + "\n" +
			"==============================================================================================\n"
	}
	_, err = f.WriteString(crontabString)
	_, err = f.WriteString("InterfaceInfo: ")

	if err == nil {
		path, _ := os.Getwd()
		fmt.Println("Summary file to ", path+"\\SummaryBaseInfo.txt")
		fmt.Println("Summary Base Info file created!")
	} else {
		fmt.Println(err)
		return
	}
	f.Close()
	c := exec.Command("cmd", "/C", "ipconfig /all>>SummaryBaseInfo.txt")

	if err := c.Run(); err != nil {
		fmt.Println("Error: ", err)
	}

}

func getBaseInfo() string {
	infoStat, _ := host.Info()
	platform := infoStat.Platform + " " + infoStat.PlatformVersion
	OsKernel := infoStat.KernelArch + " " + infoStat.KernelVersion

	userInfo, _ := user.Current()

	baseInfo := ""
	baseInfo += "    * OS VERSION:         " + platform + "\n" +
		"    * KERNEL VERSION:     " + OsKernel + "\n" +
		"    * CURRENT USER:       " + userInfo.Username + "\n"

	return baseInfo
}
