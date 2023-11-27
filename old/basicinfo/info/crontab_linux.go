package info

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/gookit/color"
)

var resultData []string

func DisplayPlanTask() {
	Crontab_file()
	Crontab_dir()
	DisplayCronTab(resultData)
}

// single crontab file
func Crontab_file() {
	dat, err := ioutil.ReadFile("/etc/crontab")
	if err != nil {
		return
	}
	cronList := strings.Split(string(dat), "\n")
	for _, info := range cronList {
		if strings.HasPrefix(info, "#") || strings.Count(info, " ") < 6 {
			continue
		}
		resultData = append(resultData, info)
	}
}

// dir crontab files
func Crontab_dir() {
	dir_list := []string{"/var/spool/cron/", "/var/spool/cron/crontabs/"}
	for _, dirTmp := range dir_list {
		dir, err := ioutil.ReadDir(dirTmp)
		if err != nil {
			continue
		}
		for _, f := range dir {
			if f.IsDir() {
				continue
			}
			dat, err := ioutil.ReadFile(dirTmp + f.Name())
			if err != nil {
				continue
			}
			cronList := strings.Split(string(dat), "\n")
			for _, info := range cronList {
				if strings.HasPrefix(info, "#") || strings.Count(info, " ") < 5 {
					continue
				}
				info = info + "              (user '" + f.Name() + "' created this task.)"
				resultData = append(resultData, info)
			}
		}
	}
}

func DisplayCronTab(cronTab []string) {
	color.Greenp("==============================================================================================\n")
	if len(cronTab) == 0 {
		fmt.Println("There is no crontab task in this host.")
		return
	}
	taskSum := 0
	for _, item := range cronTab {
		taskSum++
		color.Greenp("* task", taskSum)
		fmt.Println()
		fmt.Println(item)
		color.Greenp("==============================================================================================\n")
	}
}
func GetCronTab() []string {
	Crontab_file()
	Crontab_dir()
	return resultData
}
