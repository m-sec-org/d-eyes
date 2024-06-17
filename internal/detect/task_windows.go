//go:build windows

package detect

import (
	"encoding/xml"
	"fmt"
	"github.com/axgle/mahonia"
	"github.com/m-sec-org/d-eyes/internal"
	"github.com/m-sec-org/d-eyes/pkg/color"
	"github.com/urfave/cli/v2"
	"io/ioutil"
	"log"
	"runtime"
	"strings"
)

var TaskOption *TaskOptions

type TaskOptions struct {
	internal.BaseOption
}

func init() {
	TaskOption = NewDetectPluginTask()
	internal.RegisterDetectSubcommands(TaskOption)

}
func NewDetectPluginTask() *TaskOptions {
	return &TaskOptions{
		internal.BaseOption{
			// 任务
			Name:        "check host tasks",
			Author:      "msec",
			Description: "Command for displaying all the tasks on the host",
		},
	}
}
func (task *TaskOptions) InitCommand() []*cli.Command {
	return []*cli.Command{
		&cli.Command{
			Name:  "task",
			Usage: "Command for displaying all the tasks on the host",
			// 这是执行命令只会激活的函数
			Action: task.Action,
		},
	}
}

func (task *TaskOptions) Action(c *cli.Context) error {
	fmt.Println(color.Green.Sprint("Task:"))
	displayPlanTask()
	return nil
}

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

type cronTab struct {
	Name        string `json:"name,omitempty"`
	Command     string `json:"command,omitempty"`
	Arg         string `json:"arg,omitempty"`
	User        string `json:"user,omitempty"`
	Rule        string `json:"rule,omitempty"`
	Description string `json:"description,omitempty"`
}

func displayPlanTask() {
	crontab := GetCronTab()
	displayCronTab(crontab)
}

// GetCronTab 获取计划任务
func GetCronTab() (resultData []cronTab) {
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
		m := cronTab{}
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

// displayCronTab 打印结果
func displayCronTab(cronTab []cronTab) {
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	for _, item := range cronTab {
		fmt.Print(color.Green.Sprint("* "))
		fmt.Println("NAME:        ", item.Name)
		fmt.Print(color.Green.Sprint("* "))
		fmt.Println("COMMAND:     ", item.Command)
		fmt.Print(color.Green.Sprint("* "))
		fmt.Println("ARG:         ", item.Arg)
		fmt.Print(color.Green.Sprint("* "))
		fmt.Println("USER:        ", item.User)
		fmt.Print(color.Green.Sprint("* "))
		fmt.Println("RULE:        ", item.Rule)
		fmt.Print(color.Green.Sprint("* "))
		fmt.Println("DESCRIPTION: ", item.Description)
		fmt.Println(color.Green.Sprint("=============================================================================================="))
	}
}
