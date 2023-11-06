package info

import (
	"fmt"
	"os/user"

	"github.com/gookit/color"
	"github.com/shirou/gopsutil/v3/host"
)

func DisplayBaseInfo() {
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

}
