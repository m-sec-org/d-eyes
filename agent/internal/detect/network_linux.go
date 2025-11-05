//go:build linux

package detect

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/urfave/cli/v2"

	"github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/utils"
	"github.com/m-sec-org/d-eyes/agent/pkg/color"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

var NetworkOption *NetworkOptions

type NetworkOptions struct {
	internal.BaseOption
}

func init() {
	NetworkOption = NewDetectPluginNetwork()
	internal.RegisterDetectSubcommands(NetworkOption)

}
func NewDetectPluginNetwork() *NetworkOptions {
	return &NetworkOptions{
		internal.BaseOption{
			// 外联检查
			Name:        "check  Network",
			Author:      "msec",
			Description: "Check the network connection",
		},
	}
}
func (network *NetworkOptions) InitCommand() []*cli.Command {
	return []*cli.Command{{
		Name:    "netstat",
		Aliases: []string{"net"},
		Usage:   "Command for displaying host network information",
		Action:  network.Action,
	}}
}

func (network *NetworkOptions) Action(_ *cli.Context) error {
	start := time.Now()
	fmt.Println(color.Green.Sprint("Network Info:"))
	outputs, err := displayNetStat()
	if err != nil {
		return err
	}
	internal.GetReportManager().PrintSummary(reporting.Summary{
		Command:  "detect netstat",
		Duration: time.Since(start),
		Outputs:  outputs,
		Status:   "完成",
	})
	return nil
}

// displayNetStat remote connection ip
func displayNetStat() ([]reporting.OutputRecord, error) {
	networkData := make([][]string, 0)
	var remoteIp []string
	ps, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("enumerate processes: %w", err)
	}

	for _, p := range ps {

		pid := os.Getpid()
		if pid == int(p.Pid) || p.Pid == 0 {
			continue
		}

		connList := make([]string, 0)
		connection := make([]string, 0)
		_pc, _ := p.Connections()
		for _, conn := range _pc {
			if conn.Family == 1 {
				continue
			}
			c := fmt.Sprintf(
				"%v:%v<->%v:%v(%v)\n",
				conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port, conn.Status,
			)
			remoteIp = append(remoteIp, conn.Raddr.IP)
			connection = append(connection, c)
		}
		_pUname, _ := p.Username()
		if len(connection) > 0 && _pUname != "" {
			network := strings.Join(connection, "")
			_exe, _ := p.Exe()
			path := utils.StringNewLine(_exe, 25)
			connList = append(connList, fmt.Sprintf("%v", p.Pid), fmt.Sprintf("%v", p.Username), network, path)
			networkData = append(networkData, connList)
		}
	}

	//output the information of current netstat
	tableConn := tablewriter.NewWriter(os.Stdout)
	tableConn.SetHeader([]string{"pid", "user", "local/remote(TCP Status)", "program name"})
	tableConn.SetBorder(true)
	tableConn.SetRowLine(true)
	tableConn.AppendBulk(networkData)
	tableConn.Render()
	remoteIpNew := RemoveRepeatedElement(remoteIp)
	outputs := make([]reporting.OutputRecord, 0, 1)

	if len(remoteIpNew) > 0 {
		manager := internal.GetReportManager()
		f, path, err := manager.CreateFile("detect/netstat", "remote-connection-ip", "csv")
		if err != nil {
			return nil, err
		}
		defer f.Close()

		if _, err := f.WriteString("\xEF\xBB\xBF"); err != nil {
			return nil, fmt.Errorf("write BOM: %w", err)
		}
		writer := csv.NewWriter(f)
		length := len(remoteIpNew)
		for i := 0; i < length; i++ {
			err := writer.Write([]string{remoteIpNew[i]})
			if err != nil {
				return nil, fmt.Errorf("write csv: %w", err)
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			return nil, fmt.Errorf("flush csv: %w", err)
		}
		fmt.Printf("远程连接IP列表已保存: %s\n", path)
		outputs = append(outputs, reporting.OutputRecord{
			Label: "远程连接IP",
			Path:  path,
		})
	} else {
		fmt.Println("\n当前主机不存在外联连接。")
	}
	return outputs, nil
}

func RemoveRepeatedElement(arr []string) (newArr []string) {
	newArr = make([]string, 0)
	for i := 0; i < len(arr); i++ {
		if arr[i] == "127.0.0.1" || arr[i] == "0.0.0.0" || arr[i] == "::" || arr[i] == "::1" || arr[i] == "" {
			continue
		}
		repeat := false
		for j := i + 1; j < len(arr); j++ {
			if arr[i] == arr[j] {
				repeat = true
				break
			}
		}
		if !repeat {
			newArr = append(newArr, arr[i])
		}
	}
	return
}
