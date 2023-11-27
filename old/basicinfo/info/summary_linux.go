package info

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"

	"github.com/shirou/gopsutil/v3/host"
)

func SaveSummaryBaseInfo() {
	f, err := os.Create("SummaryBaseInfo.txt")
	if err != nil {
		fmt.Println(err)
		return
	}

	baseInfo := GetBaseInfo()
	_, err = f.WriteString("HostInfo: \n" + baseInfo)

	users := GetLinuxUser()
	_, err = f.WriteString("AllUsers: \n")
	for _, user := range users {
		_, err = f.WriteString("    * " + user + "\n")
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
		fmt.Println("Summary file to ", path+"/SummaryBaseInfo")
		fmt.Println("Summary Base Info file created!")
	} else {
		fmt.Errorf(err.Error())
	}
	f.Close()
	c := exec.Command("/bin/bash", "-c", "ifconfig -a>>SummaryBaseInfo")

	if err := c.Run(); err != nil {
		fmt.Println("Error: ", err)
	}

}

func GetBaseInfo() string {
	infoStat, _ := host.Info()
	platform := infoStat.Platform + " " + infoStat.PlatformVersion
	OsKernel := infoStat.KernelArch + " " + infoStat.KernelVersion

	user, _ := user.Current()

	baseInfo := ""
	baseInfo += "    * OS VERSION:         " + platform + "\n" +
		"    * KERNEL VERSION:     " + OsKernel + "\n" +
		"    * CURRENT USER:       " + user.Username + "\n"

	return baseInfo
}
