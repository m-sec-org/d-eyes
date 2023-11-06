package models

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/gookit/color"
	"github.com/hillu/go-yara/v4"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

type (
	Process struct {
		Process []*process.Process
	}

	ProcessScanResult struct {
		CheckIP     bool
		Connection  []string
		Ps          *process.Process
		PidMatches  yara.MatchRules
		PathMatches yara.MatchRules
		CheckArgs   bool
		Args        string
	}

	ProcessResult struct {
		Pid         int
		Path        string
		Namespace   string
		Rule        string
		Description string
	}
)

func SaveProcessResult(results []*ProcessScanResult) {

	red := color.FgRed.Render
	green := color.FgGreen.Render
	riskSum := 0
	color.Warn.Println("\nD-Eyes Detection Result : \n")
	for _, psr := range results {

		lenPidMatches := len(psr.PidMatches)
		lenPathMatches := len(psr.PathMatches)

		psrPath, _ := psr.Ps.Exe()
		if lenPidMatches != 0 && lenPathMatches != 0 {
			riskSum++
			data1 := psr.PidMatches[0].Metas[0]
			dataType1, _ := json.Marshal(data1)
			dataString1 := string(dataType1)
			meta1 := strings.Split(dataString1, ":")[2]
			metaTmp1 := strings.Trim(meta1, "\"}")

			data2 := psr.PathMatches[0].Metas[0]
			dataType2, _ := json.Marshal(data2)
			dataString2 := string(dataType2)
			met2a := strings.Split(dataString2, ":")[2]
			metaTmp2 := strings.Trim(met2a, "\"}")
			color.Error.Println("[ Risk ", riskSum, " ]")
			fmt.Printf(
				"[pid]:%d [%s]:%s | [path]:%s [%s]:%s | ",
				psr.Ps.Pid, red("status"), red(metaTmp1), psrPath, red("status"),
				red(metaTmp2),
			)

			if psr.CheckArgs {
				fmt.Printf("[args]:%s | ", red(psr.Args))
			} else {
				fmt.Printf("[args]:%s | ", green(psr.Args))
			}

			if len(psr.Connection) == 0 {
				fmt.Println("[network]:", green("null"))
			} else {
				fmt.Println("[network]:", psr.Connection)
			}
			continue
		}

		if lenPidMatches != 0 && lenPathMatches == 0 {

			riskSum++
			data := psr.PidMatches[0].Metas[0]
			dataType, _ := json.Marshal(data)
			dataString := string(dataType)
			meta := strings.Split(dataString, ":")[2]
			metaTmp := strings.Trim(meta, "\"}")

			color.Error.Println("[ Risk ", riskSum, " ]")
			fmt.Printf(
				"[pid]:%d [%s]:%s | [path]:%s [%s]:%s | ",
				psr.Ps.Pid, red("status"), red(metaTmp), psrPath, green("status"), green("safe"),
			)

			if psr.CheckArgs {
				fmt.Printf("[args]:%s | ", red(psr.Args))
			} else {
				fmt.Printf("[args]:%s | ", green(psr.Args))
			}

			if len(psr.Connection) == 0 {
				fmt.Println("[network]:", green("null"))
			} else {
				fmt.Println("[network]:", psr.Connection)
			}
			continue
		}

		if lenPidMatches == 0 && lenPathMatches != 0 {

			riskSum++
			data := psr.PathMatches[0].Metas[0]
			dataType, _ := json.Marshal(data)
			dataString := string(dataType)
			meta := strings.Split(dataString, ":")[2]
			metaTmp := strings.Trim(meta, "\"}")

			color.Error.Println("[ Risk ", riskSum, " ]")
			fmt.Printf(
				"[pid]:%d [%s]:%s | [path]:%s [%s]:%s | ",
				psr.Ps.Pid, green("status"), green("safe"), psrPath, red("status"), red(metaTmp),
			)

			if psr.CheckArgs {
				fmt.Printf("[args]:%s | ", red(psr.Args))
			} else {
				fmt.Printf("[args]:%s | ", green(psr.Args))
			}

			if len(psr.Connection) == 0 {
				fmt.Println("[network]:", green("null"))
			} else {
				fmt.Println("[network]:", psr.Connection)
			}
			continue
		}

		if psr.CheckIP {
			riskSum++
			color.Error.Println("[ Risk ", riskSum, " ]")
			fmt.Printf(
				"[pid]:%d [%s]:%s | [path]:%s [%s]:%s | ",
				psr.Ps.Pid, green("status"), green("safe"), psrPath, green("status"), green("safe"),
			)

			if psr.CheckArgs {
				fmt.Printf("[args]:%s | ", red(psr.Args))
			} else {
				fmt.Printf("[args]:%s | ", green(psr.Args))
			}
			fmt.Println("[network]:", psr.Connection)

			continue
		}

		if psr.CheckArgs {
			riskSum++
			color.Error.Println("[ Risk ", riskSum, " ]")
			fmt.Printf(
				"[pid]:%d [%s]:%s | [path]:%s [%s]:%s | ",
				psr.Ps.Pid, green("status"), green("safe"), psrPath, green("status"), green("safe"),
			)

			fmt.Printf("[args]:%s | ", red(psr.Args))

			if len(psr.Connection) == 0 {
				fmt.Println("[network]:", green("null"))
			} else {
				fmt.Println("[network]:", psr.Connection)
			}
		}
	}
	if riskSum == 0 {
		fmt.Println("\nNo suspicious process found. Your computer is safe with the rules you choose.")
	}

}

func DisplayNetworkInfo(connects []net.ConnectionStat) {

	green := color.FgGreen.Render
	blue := color.FgBlue.Render
	red := color.FgRed.Render

	if len(connects) == 0 {
		fmt.Println("[network]:", green("null"))
		return
	}

	ipf, _ := ioutil.TempFile("", "hostip")

	connection := make([]string, 0)
	for _, conn := range connects {
		if conn.Family == 1 {
			continue
		}
		raddrip := red(conn.Raddr.IP)
		c := fmt.Sprintf(
			"%v:%v<->%v:%v(%v)",
			blue(conn.Laddr.IP), blue(conn.Laddr.Port), raddrip, blue(conn.Raddr.Port), blue(conn.Status),
		)
		connection = append(connection, c)
		ipf.Write([]byte(raddrip))

	}
	ipf.Close()
	fmt.Println("[network]:", connection)

}
