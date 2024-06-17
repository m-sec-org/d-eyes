//go:build linux

package detect

import (
	"fmt"
	"github.com/m-sec-org/d-eyes/internal"
	deUtils "github.com/m-sec-org/d-eyes/internal/detect/utils"
	"github.com/m-sec-org/d-eyes/pkg/color"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/urfave/cli/v2"
	"os"
	"os/exec"
	"os/user"
	"strconv"
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
			//
			Name:        "export info",
			Author:      "msec",
			Description: "exporting basic host information",
		},
	}
}
func (summary *SummaryOptions) InitCommand() []*cli.Command {
	return []*cli.Command{
		&cli.Command{
			// 导出基本信息
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
	f, err := os.Create("SummaryBaseInfo")

	if err != nil {
		fmt.Println(color.Magenta.Sprint(err.Error()))
	}

	baseInfo := GetBaseInfo()
	_, err = f.WriteString("HostInfo: \n" + baseInfo)

	users := deUtils.GetLinuxUser()
	_, err = f.WriteString("AllUsers: \n")
	for _, u := range users {
		_, err = f.WriteString("    * " + u + "\n")
	}

	crontab := GetCronTab()
	crontabString := ""
	crontabString += "Os Crontab: \n==============================================================================================\n"
	taskSum := 0
	for _, item := range crontab {
		taskSum++
		crontabString += "* task " + strconv.Itoa(taskSum) + "\n" +
			"" + item + "\n" +
			"==============================================================================================\n"
	}
	_, err = f.WriteString(crontabString)
	_, err = f.WriteString("InterfaceInfo: \n")
	if err == nil {
		path, _ := os.Getwd()
		fmt.Println(color.Green.Sprint("Summary file to ", path+"/SummaryBaseInfo"))
		fmt.Println(color.Green.Sprint("Summary Base Info file created!"))
	} else {
		fmt.Println(color.Magenta.Sprint(err.Error()))
	}
	_ = f.Close()
	c := exec.Command("/bin/bash", "-c", "ifconfig -a>>SummaryBaseInfo")

	if err := c.Run(); err != nil {
		fmt.Println(color.Magenta.Sprint("Error: ", err.Error()))
	}

}

func GetBaseInfo() string {
	infoStat, _ := host.Info()
	platform := infoStat.Platform + " " + infoStat.PlatformVersion
	OsKernel := infoStat.KernelArch + " " + infoStat.KernelVersion

	current, _ := user.Current()

	baseInfo := ""
	baseInfo += "    * OS VERSION:         " + platform + "\n" +
		"    * KERNEL VERSION:     " + OsKernel + "\n" +
		"    * CURRENT USER:       " + current.Username + "\n"

	return baseInfo
}
