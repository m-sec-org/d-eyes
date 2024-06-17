//go:build linux || windows

package detect

import (
	"fmt"
	"github.com/m-sec-org/d-eyes/internal"
	"github.com/m-sec-org/d-eyes/pkg/color"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/urfave/cli/v2"
	"os"
	"sort"
	"time"
)

type (
	Process struct {
		Process []*process.Process
	}
)

var TopOption *TopOptions

type TopOptions struct {
	internal.BaseOption
}

func init() {
	TopOption = NewPluginWindowsTop()
	internal.RegisterDetectSubcommands(TopOption)

}
func NewPluginWindowsTop() *TopOptions {
	return &TopOptions{
		internal.BaseOption{
			// 用于查询CPU占用率排名前15的进程
			Name:        "show CPU top 15",
			Author:      "msec",
			Description: "Command for displaying the top 15 processes in CPU usage",
		},
	}
}
func (top *TopOptions) InitCommand() []*cli.Command {
	return []*cli.Command{
		&cli.Command{
			Name: "top",
			// 命令用于查询CPU占用率排名前15的进程
			Usage: "Command for displaying the top 15 processes in CPU usage",
			// 这是执行命令只会激活的函数
			Action: top.Action,
		}}
}

func (top *TopOptions) Action(c *cli.Context) error {
	ps, err := process.Processes()
	if err != nil {
		fmt.Println(color.Red.Sprint(err.Error()))
		return nil
	}

	sort.Slice(
		ps, func(i, j int) bool {
			pic, _ := ps[i].CPUPercent()
			pjc, _ := ps[j].CPUPercent()
			return pic > pjc
		},
	)
	pss := Process{Process: ps}
	CPUSum := 0
	fmt.Println(color.Green.Sprint("=============================================================================================="))
	for _, ps := range pss.Process {
		pid := os.Getpid()
		if pid == int(ps.Pid) {
			continue
		}
		CPUSum++
		fmt.Println(color.Green.Sprint("* CPU Top ", CPUSum))
		fmt.Println()
		_pct, _ := ps.CreateTime()
		_pPath, _ := ps.Exe()
		_pCpuP, _ := ps.CPUPercent()
		startDate := time.Unix(_pct, 0).Format("2006-01-02 15:04:05")
		username, _ := ps.Username()
		MemPer, _ := ps.MemoryPercent()
		fmt.Printf(
			"[User]:%s | [Pid]:%d  | [Path]:%s | [CPU]:%.5f | [Memory]:%.5f | [Createdtime]:%v \n",
			username, ps.Pid, _pPath, _pCpuP, MemPer, startDate,
		)
		//network
		_ps, _ := ps.Connections()
		if len(_ps) == 0 {
			fmt.Println("[netstat]: null")
		} else {
			netSum := 0

			for _, conn := range _ps {
				if conn.Family == 1 {
					continue
				}
				netSum++
				fmt.Printf(
					"[netstat %d]: %v:%v<->%v:%v(%v)\n",
					netSum, conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port, conn.Status,
				)
			}
		}
		fmt.Println(color.Green.Sprint("=============================================================================================="))
		if CPUSum == 15 {
			break
		}
	}
	return nil
}
