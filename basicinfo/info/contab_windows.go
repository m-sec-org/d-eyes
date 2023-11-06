//go:build windows

package info

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"runtime"
	"strings"

	"github.com/gookit/color"

	"github.com/axgle/mahonia"
)

type task struct {
	RegistrationInfo struct {
		Description string
	}
	Actions struct {
		Exec struct {
			Command   string
			Arguments string
		}
	}
	Triggers struct {
		CalendarTrigger struct {
			StartBoundary string
		}
	}
	Principals struct {
		Principal struct {
			UserId string
		}
	}
}

type CronTab struct {
	Name        string `json:"name,omitempty"`
	Command     string `json:"command,omitempty"`
	Arg         string `json:"arg,omitempty"`
	User        string `json:"user,omitempty"`
	Rule        string `json:"rule,omitempty"`
	Description string `json:"description,omitempty"`
}

func DisplayPlanTask() {
	crontab := GetCronTab()
	DisplayCronTab(crontab)
}

// GetCronTab 获取计划任务
func GetCronTab() (resultData []CronTab) {
	var taskPath string
	if runtime.GOARCH == "386" {
		taskPath = `C:\Windows\SysNative\Tasks\`
	} else {
		taskPath = `C:\Windows\System32\Tasks\`
	}
	dir, err := ioutil.ReadDir(taskPath)
	if err != nil {
		return resultData
	}
	for _, f := range dir {
		if f.IsDir() {
			continue
		}
		dat, err := ioutil.ReadFile(taskPath + f.Name())
		if err != nil {
			continue
		}
		v := task{}
		dec := mahonia.NewDecoder("utf-16")
		data := dec.ConvertString(string(dat))
		err = xml.Unmarshal([]byte(strings.Replace(data, "UTF-16", "UTF-8", 1)), &v)
		if err != nil {
			log.Println("Windows crontab info xml Unmarshal error: ", err.Error())
			continue
		}
		m := CronTab{}
		m.Name = f.Name()
		m.Command = v.Actions.Exec.Command
		m.Arg = v.Actions.Exec.Arguments
		m.User = v.Principals.Principal.UserId
		m.Rule = v.Triggers.CalendarTrigger.StartBoundary
		m.Description = v.RegistrationInfo.Description
		resultData = append(resultData, m)
	}
	return resultData
}

func DisplayCronTab(cronTab []CronTab) {
	color.Greenp("==============================================================================================\n")
	for _, item := range cronTab {
		color.Greenp("* ")
		fmt.Println("NAME:        ", item.Name)
		color.Greenp("* ")
		fmt.Println("COMMAND:     ", item.Command)
		color.Greenp("* ")
		fmt.Println("ARG:         ", item.Arg)
		color.Greenp("* ")
		fmt.Println("USER:        ", item.User)
		color.Greenp("* ")
		fmt.Println("RULE:        ", item.Rule)
		color.Greenp("* ")
		fmt.Println("DESCRIPTION: ", item.Description)
		color.Greenp("==============================================================================================\n")
	}
}
