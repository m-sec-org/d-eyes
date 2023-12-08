package windows_log

import (
	"d-eyes/pkg/windows_log/winlogbeat/eventlog"
	"fmt"
	"github.com/gookit/color"
	"time"
)

const (
	winEvtApplication = "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx"
	winEvtSecurity = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
	winEvtSystem = "C:\\Windows\\System32\\winevt\\Logs\\System.evtx"
)

const (
	IgnoreOneHour  	= time.Hour   					// 取最近1小时之内事件
	Ignore12Hour  	= IgnoreOneHour * 12			// 取最近12小时事件
	Ignore24Hour  	= Ignore12Hour * 2				// 取最近24小时之内事件
	IgnoreWeek  	= Ignore24Hour * 7				// 取最近一周之内事件
	IgnoreMonth		= Ignore24Hour * 30				// 取最近一个月之内事件
)

func DisplayWindowsLogs(logType, ignore string, size int) {

	var filePath string
	var ignoreTime time.Duration
	switch logType {
	case "system": filePath = winEvtSystem
	case "application": filePath = winEvtApplication
	case "security": filePath = winEvtSecurity
	default:
		filePath = winEvtSystem
	}

	switch ignore {
	case "1h": ignoreTime = IgnoreOneHour
	case "12h": ignoreTime = Ignore12Hour
	case "24h": ignoreTime = Ignore24Hour
	case "week": ignoreTime = IgnoreWeek
	case "month": ignoreTime = IgnoreMonth
	default:
		ignoreTime = IgnoreOneHour
	}

	// 默认获取最新的前200条事件记录： ignoreOlder参数设置为0
	logs, _ := eventlog.GetEventLogByFile(filePath, ignoreTime, size)

	for _, log := range logs {
		color.Greenp("==============================================================================================\n")
		fmt.Println("LEVEL: 		", 	log.Level)
		fmt.Println("DATE: 			", 	log.TimeCreated.Format("2006-01-02 15:04:05"))
		fmt.Println("SOURCE: 		", 	log.ProviderName)
		fmt.Println("EVENT ID: 		",	log.Id)
		fmt.Println("TASK TYPE: 	",	log.Task)
		fmt.Println("EVENT MESSAGE: ",	log.Message)
		fmt.Println("XML: 			", 	log.Xml)
	}
}

