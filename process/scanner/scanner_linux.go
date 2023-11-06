package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/gookit/color"
	"github.com/hillu/go-yara/v4"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/toolkits/slice"

	"d-eyes/process/models"
	"d-eyes/process/utils"
	"d-eyes/yaraobj"
)

var resultListTMP []*models.ProcessScanResult

type Scanner struct {
	Rules *yara.Rules
}

type (
	Process struct {
		Process []*process.Process
	}
)

func (i Process) Iterator() *Iterator {
	return &Iterator{
		data:  i,
		index: 0,
	}
}

type Iterator struct {
	data  Process
	index int
}

func (i *Iterator) HasNext() bool {
	return i.index < len(i.data.Process)
}

func (i *Iterator) Next() *process.Process {
	pro := i.data.Process[i.index]
	i.index++
	return pro
}

// Open the rule file and add it to the Yara compiler.
func NewScanner(rulepath string) (*Scanner, error) {
	f, err := os.ReadFile(rulepath)
	if err != nil {
		color.Redln("GetErr: Can't open the rule file: ", rulepath)
		os.Exit(1)
		return nil, err
	}
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, err
	}
	err = compiler.AddString(string(f), "")
	if err != nil {
		return nil, err
	}
	rules, err := compiler.GetRules()
	if err != nil {
		return nil, err
	}
	return &Scanner{Rules: rules}, err
}

func NewScannerAllRules() (*Scanner, error) {
	rulesPath := "yaraRules"
	_, err := os.Stat(rulesPath)
	if os.IsNotExist(err) {
		color.Redln("GetErr: The './yaraRules' directory does not exist.")
		os.Exit(1)
	}
	rules, err := yaraobj.LoadAllYaraRules(rulesPath)
	if err != nil {
		color.Redln("LoadCompiledRules goes error !!!")
		color.Redln("GetRules err: ", err)
		os.Exit(1)
	}
	return &Scanner{Rules: rules}, err
}

func (s *Scanner) ScanProcesses(pid int, ipList []string, Npattern []string) ([]*models.ProcessScanResult, error) {

	whiteList := []string{"ruby", "sagent", "crond", "mysqld", "rsyslogd"}
	var resultList []*models.ProcessScanResult

	if pid != -1 {

		var pidMatches yara.MatchRules
		var pathMatches yara.MatchRules
		err := s.Rules.ScanProc(pid, 0, 10, &pidMatches)
		if err != nil {
			return nil, fmt.Errorf("pid: %d is not exist! (%s)", pid, err)
		}
		ps, _ := process.NewProcess(int32(pid))
		path, _ := ps.Exe()
		err = s.Rules.ScanFile(path, 0, 10, &pathMatches)
		if err != nil {
			return nil, fmt.Errorf("ScanFile err: %s", err)
		}

		var checkarg bool
		var args string
		// todo
		//for _, i := range Npattern {
		//	reg := regexp.MustCompile(i)
		//	if reg.FindString(ps.Arguments) != "" {
		//		checkarg = true
		//		args = ps.Arguments
		//	} else {
		//		checkarg = false
		//		args = "safe"
		//	}
		//}

		connection, ok := DisplayScanResult(ps, pidMatches, pathMatches, ipList)
		resultList = append(
			resultList, &models.ProcessScanResult{
				CheckIP: ok, Connection: connection,
				Ps: ps, PidMatches: pidMatches, PathMatches: pathMatches, CheckArgs: checkarg, Args: args,
			},
		)

		return resultList, nil
	}

	ps, err := process.Processes()
	if err != nil {
		return nil, err
	}

	pss := Process{Process: ps}
	it := pss.Iterator()
	wg := &sync.WaitGroup{}
	wg.Add(5)
	for i := 0; i < 5; i++ {
		go s.ProScan(it, wg, whiteList, ipList, Npattern)
	}
	wg.Wait()

	resultList = resultListTMP
	return resultList, nil
}

func (s *Scanner) ProScan(it *Iterator, wg *sync.WaitGroup, whiteList []string, ipList []string, Npattern []string) {
	defer wg.Done()
	for {
		var err error
		if it.HasNext() {
			ps := it.Next()
			var pidMatches yara.MatchRules
			var pathMatches yara.MatchRules

			pid := os.Getpid()
			if pid == int(ps.Pid) {
				continue
			}

			_psPath, _ := ps.Exe()
			t := strings.Split(_psPath, "/")
			filename := t[len(t)-1]
			if !slice.ContainsString(whiteList, filename) {

				err = s.Rules.ScanProc(int(ps.Pid), 0, 10, &pidMatches)
				if err != nil {
					err = nil
					continue
				}
				err = s.Rules.ScanFile(_psPath, 0, 10, &pathMatches)

				if err != nil {
					err = nil
					continue
				}

				var checkarg bool
				var args string
				// todo
				//for _, i := range Npattern {
				//	reg := regexp.MustCompile(i)
				//	if reg.FindString(ps.Arguments) != "" {
				//		checkarg = true
				//		args = ps.Arguments
				//	} else {
				//		checkarg = false
				//		args = "safe"
				//	}
				//}

				connection, ok := DisplayScanResult(ps, pidMatches, pathMatches, ipList)

				resultListTMP = append(
					resultListTMP, &models.ProcessScanResult{
						CheckIP: ok, Connection: connection,
						Ps: ps, PidMatches: pidMatches, PathMatches: pathMatches, CheckArgs: checkarg, Args: args,
					},
				)

			}
		} else {
			break
		}
	}
}

func DisplayScanResult(ps *process.Process, pidMatches yara.MatchRules, pathMatches yara.MatchRules, ipList []string) ([]string, bool) {

	var pid_matches string
	var path_matches string
	var pid_rules string
	var path_rules string
	var ipexist bool

	red := color.FgRed.Render
	green := color.FgGreen.Render
	blue := color.FgBlue.Render

	color.Info.Printf("D-Eyes progress scanning: ")

	if len(pidMatches) == 0 {
		pid_matches = green("status")
		pid_rules = green("safe")
	} else {
		pid_matches = red("status")
		data := pidMatches[0].Metas[0]
		dataType, _ := json.Marshal(data)
		dataString := string(dataType)
		meta := strings.Split(dataString, ":")[2]
		metaTmp := strings.Trim(meta, "\"}")
		pid_rules = red(metaTmp)
	}

	if len(pathMatches) == 0 {
		path_matches = green("status")
		path_rules = green("safe")
	} else {
		path_matches = red("status")

		data := pathMatches[0].Metas[0]
		dataType, _ := json.Marshal(data)
		dataString := string(dataType)
		meta := strings.Split(dataString, ":")[2]
		metaTmp := strings.Trim(meta, "\"}")

		path_rules = red(metaTmp)
	}
	_pUname, _ := ps.Username()
	_exe, _ := ps.Exe()
	fmt.Printf(
		"[username]:%s | [pid]:%d [%s]:%s | [path]:%s [%s]:%s | ",
		_pUname, ps.Pid, pid_matches, pid_rules, _exe, path_matches, path_rules,
	)

	// 显示网络连接信息
	connection := make([]string, 0)
	_psConn, _ := ps.Connections()
	for _, conn := range _psConn {
		if conn.Family == 1 {
			continue
		}
		ok := utils.CheckIpInipconfig(ipList, conn.Raddr.IP)
		if !ok {
			c := fmt.Sprintf(
				"%v:%v<->%v:%v(%v)",
				conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port, conn.Status,
			)
			connection = append(connection, blue(c))
		} else {
			c := fmt.Sprintf(
				"%v:%v<->%v:%v(%v)",
				blue(conn.Laddr.IP), blue(conn.Laddr.Port), red(conn.Raddr.IP), blue(conn.Raddr.Port), blue(conn.Status),
			)
			connection = append(connection, c)
			ipexist = true
		}

	}

	if len(connection) == 0 {
		fmt.Println("[network]:", green("null"))
	} else {
		fmt.Println("[network]:", connection)
	}

	return connection, ipexist

}
