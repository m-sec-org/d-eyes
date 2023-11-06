package controller

import (
	"github.com/gookit/color"
	"github.com/shirou/gopsutil/v3/process"

	"d-eyes/process/models"
	"d-eyes/process/scanner"
	"d-eyes/process/utils"
)

func GetProcess() models.Process {
	ps, err := process.Processes()
	if err != nil {
		return models.Process{}
	}
	return models.Process{Process: ps}
}

func ScanProcess(pid int, rule string) {
	var scannerEngine *scanner.Scanner
	var err error

	if rule == "" {
		scannerEngine, err = scanner.NewScannerAllRules()
	} else {
		rulePath := "yaraRules\\" + rule + ".yar"
		scannerEngine, err = scanner.NewScanner(rulePath)
		if err != nil {
			color.Redln(err.Error())
			return
		}
	}

	ipList, err := utils.ReadLindIp("ip.config")
	Npattern := []string{"ms-msdt:/id\\s+PCWDiagnostic\\s+/skip force\\s+/param"}

	if err == nil {
		scanResults, err := scannerEngine.ScanProcesses(pid, ipList, Npattern)
		if err == nil {
			models.SaveProcessResult(scanResults)
		} else {
			color.Redln(err.Error())
		}
	} else {
		color.Redln(err.Error())
		return
	}
	//scannerEngine.Rules.Destroy()
}
