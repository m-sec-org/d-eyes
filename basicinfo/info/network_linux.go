package info

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/shirou/gopsutil/v3/process"

	"d-eyes/basicinfo/utils"
)

// remote connection ip
func DisplayNetStat() {
	networkData := make([][]string, 0)
	var remoteIp []string
	ps, err := process.Processes()
	if err != nil {
		fmt.Println("Error:", err)
		return
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

	if len(remoteIpNew) > 0 {

		f, err := os.Create("RemoteConnectionIP.csv")
		if err != nil {
			panic(err)
		}
		_, err = f.WriteString("\xEF\xBB\xBF")
		if err != nil {
			panic(err)
		}
		writer := csv.NewWriter(f)
		length := len(remoteIpNew)
		for i := 0; i < length; i++ {
			err := writer.Write([]string{remoteIpNew[i]})
			if err != nil {
				panic(err)
			}
		}
		writer.Flush()
		f.Close()
		fmt.Println("The IP of the local remote connection has been exported to 'RemoteConnectionIP.csv'.")
	} else {
		fmt.Println("\nThere is no remote connection IP on this host.")
	}
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
