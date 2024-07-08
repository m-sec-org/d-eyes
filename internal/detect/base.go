//go:build linux || windows || darwin

package detect

import (
	"fmt"
	"os/user"

	"github.com/shirou/gopsutil/v4/host"
	"github.com/urfave/cli/v2"

	"github.com/m-sec-org/d-eyes/internal"
	"github.com/m-sec-org/d-eyes/pkg/color"
)

var HostOption *HostOptions

func init() {
	HostOption = NewDetectPluginHost()
	internal.RegisterDetectSubcommands(HostOption)
}

type HostOptions struct {
	internal.BaseOption
}

func NewDetectPluginHost() *HostOptions {
	return &HostOptions{
		BaseOption: internal.BaseOption{
			// 主机基本信息
			Name:        "host check",
			Author:      "msec",
			Description: "Command for displaying basic host information",
		},
	}
}
func (hostOption *HostOptions) InitCommand() []*cli.Command {
	return []*cli.Command{
		{
			Name:   "host",
			Usage:  "Command for displaying basic host information",
			Action: hostOption.Action,
		},
	}
}

func (hostOption *HostOptions) Action(c *cli.Context) error {
	infoStat, _ := host.Info()
	platform := infoStat.Platform + " " + infoStat.PlatformVersion
	OsKernel := infoStat.KernelArch + " " + infoStat.KernelVersion
	CurrentUser, _ := user.Current()
	fmt.Print(color.Green.Sprint("* "))
	fmt.Println("OS VERSION:     ", platform)
	fmt.Print(color.Green.Sprint("* "))
	fmt.Println("KERNEL VERSION: ", OsKernel)
	fmt.Print(color.Green.Sprint("* "))
	fmt.Println("CURRENT USER:   ", CurrentUser.Username)
	return nil
}
