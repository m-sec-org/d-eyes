package check

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/gookit/color"

	"d-eyes/configcheck/common"
)

var suspiciousContents [][2]string

func CrontabCheck() {
	CrontabFile()
	CrontabDir()
	if len(suspiciousContents) == 0 {
		color.Infoln("主机计划任务检测: [safe]")
	} else {
		fmt.Println("主机计划任务存在可疑内容, 请确认:")
		for _, detail := range suspiciousContents {
			fmt.Printf("[*]File: %s  Detail: %s\n", detail[0], detail[1])
		}
	}

}

// check single file
func CrontabFile() {
	dat, err := ioutil.ReadFile("/etc/crontab")
	if err != nil {
		return
	}
	cronList := strings.Split(string(dat), "\n")
	for _, info := range cronList {
		if strings.HasPrefix(info, "#") {
			continue
		}
		contents := common.CheckShell(info)
		if contents == true {
			suspiciousContents = append(suspiciousContents, [2]string{"/etc/crontab", info})
		}
	}

}

// check dir files
func CrontabDir() {
	dirList := []string{
		"/var/spool/cron/", "/var/spool/cron/crontabs/", "/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/", "/etc/cron.weekly/", "/etc/cron.monthly/",
	}
	for _, dirTmp := range dirList {
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
				if strings.HasPrefix(info, "#") {
					continue
				}
				contents := common.CheckShell(info)
				if contents == true {
					suspiciousContents = append(suspiciousContents, [2]string{dirTmp + f.Name(), info})
				}
			}
		}
	}
}
