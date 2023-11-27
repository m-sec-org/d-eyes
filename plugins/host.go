package plugins

import (
	"fmt"
	"os/user"

	"github.com/gookit/color"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/urfave/cli/v2"

	"d-eyes/cmd"
)

type PluginHost struct{}

func init() {
	cmd.Register(new(PluginHost).InitCommands())
}

func (p *PluginHost) InitCommands() *cli.Command {
	return &cli.Command{
		Name:   "host",
		Usage:  "Command for displaying basic host information",
		Action: p.Run,
	}
}

func (p *PluginHost) Run(c *cli.Context) error {
	infoStat, _ := host.Info()
	platform := infoStat.Platform + " " + infoStat.PlatformVersion
	OsKernel := infoStat.KernelArch + " " + infoStat.KernelVersion

	CurrentUser, _ := user.Current()

	color.Greenp("* ")
	fmt.Println("OS VERSION:     ", platform)

	color.Greenp("* ")
	fmt.Println("KERNEL VERSION: ", OsKernel)

	color.Greenp("* ")
	fmt.Println("CURRENT USER:   ", CurrentUser.Username)
	return nil
}
