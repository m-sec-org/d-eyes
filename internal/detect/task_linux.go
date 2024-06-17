//go:build linux

package detect

import (
	"fmt"
	"github.com/m-sec-org/d-eyes/internal"
	"github.com/m-sec-org/d-eyes/pkg/color"
	"github.com/urfave/cli/v2"
	"io/ioutil"
	"strings"
)

// 结果
var resultData []string

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
	GetCronTab()
	displayCronTab(resultData)
	return nil
}

// single crontab file
func crontabFile() {
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
func crontabDir() {
	dirList := []string{"/var/spool/cron/", "/var/spool/cron/crontabs/"}
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
				if strings.HasPrefix(info, "#") || strings.Count(info, " ") < 5 {
					continue
				}
				info = info + "              (user '" + f.Name() + "' created this task.)"
				resultData = append(resultData, info)
			}
		}
	}
}

func displayCronTab(cronTab []string) {
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	if len(cronTab) == 0 {
		fmt.Println("There is no crontab task in this host.")
		return
	}
	taskSum := 0
	for _, item := range cronTab {
		taskSum++
		fmt.Println(color.Green.Sprint("* task", taskSum))
		fmt.Println()
		fmt.Println(item)
		fmt.Println(color.Green.Sprint("=============================================================================================="))
	}
}
func GetCronTab() []string {
	crontabFile()
	crontabDir()
	return resultData
}
