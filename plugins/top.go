package plugins

import (
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	"github.com/gookit/color"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/urfave/cli/v2"

	"d-eyes/cmd"
)

type PluginTop struct{}

func init() {
	cmd.Register(new(PluginTop).InitCommands())
}

func (p *PluginTop) InitCommands() *cli.Command {
	return &cli.Command{
		Name:   "top",
		Usage:  "Command for displaying the top 15 processes in CPU usage",
		Action: p.Run,
	}
}

func (p *PluginTop) Run(c *cli.Context) error {
	psList, err := process.Processes()
	if err != nil {
		fmt.Println(err)
		return err
	}
	log.Println("共", len(psList), "个进程, 获取其资源占用情况...")
	cpuPercentMap := make(map[int32]float64)
	for i := range psList {
		fmt.Printf("\r正在获取 pid: %d (%d/%d)", psList[i].Pid, i, len(psList))
		p, _ := psList[i].CPUPercent()
		cpuPercentMap[psList[i].Pid] = p
	}
	sort.Slice(
		psList, func(i, j int) bool {
			return cpuPercentMap[psList[i].Pid] > cpuPercentMap[psList[j].Pid]
		},
	)
	CPUSum := 0
	color.Greenp("\r==============================================================================================\n")
	for _, ps := range psList {
		log.Printf(ps.String())
		pid := os.Getpid()
		if pid == int(ps.Pid) {
			continue
		}
		CPUSum++
		color.Greenp("* CPU Top ", CPUSum)
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
		color.Greenp("==============================================================================================\n")
		if CPUSum == 15 {
			break
		}
	}
	return nil
}
