package eventlog

import (
	"d-eyes/pkg/windows_log/common"
	"d-eyes/pkg/windows_log/winlogbeat/checkpoint"
	"fmt"
	"path/filepath"
	"time"
)

// 日志事件结果信息
type WinEventLogResult struct {
	Level 			string			// 等级
	TimeCreated 	time.Time		// 时间
	ProviderName 	string			// 来源
	Id				uint32			// 事件ID
	Task 			string			// 任务类别
	Message 		string			// 日志信息
	Xml 			string			// Xml字符串
}

// GetEventLogByFile 获取对应filePath的事件记录， ignoreOlder为忽略此时间段之前的事件记录;
//  ignoreOlder 为 0 时获取当前最新事件记录; batchSize 为  ignoreOlder 参数为 0 时获取到当前最新事件记录条数,
// 当 ignoreOlder 参数不为 0 时获取到的事件记录条数不以 batchSize 为准。
func GetEventLogByFile(filePath string, ignoreOlder time.Duration, batchSize int) ([]WinEventLogResult, error) {

	if ignoreOlder != 0 { // 按时间获取事件句柄, 获取到事件数量不以batchSize为准!
		batchSize = 0
	}

	openLog := func(config map[string]interface{}) EventLog {
		return openLog(nil, config)
	}

	path, err := filepath.Abs(filePath)
	if err != nil {
		return nil, err
	}

	log := openLog(map[string]interface{}{
		"name":           	path,
		"no_more_events": 	"stop",
		"batch_read_size":  batchSize,
		"ignore_older":   	ignoreOlder,
		"include_xml":		true,
	})
	defer log.Close()

	records, err := log.Read()
	if err != nil {
		return nil, err
	}

	var resultEventLogs []WinEventLogResult

	for _, record := range records {
		resultEventLogs = append(resultEventLogs, WinEventLogResult{
			Level: 			record.Level,
			TimeCreated: 	record.TimeCreated.SystemTime.In(time.Local), // 将时间转换成当地时间
			ProviderName: 	record.Provider.Name,
			Id: 			record.EventIdentifier.ID,
			Task: 			record.Task,
			Message: 		record.Message,
			Xml: 			record.XML,
		})
	}

	return resultEventLogs, nil
}

func openLog(state *checkpoint.EventLogState, config map[string]interface{}) EventLog {
	cfg, err := common.NewConfigFrom(config)
	if err != nil {
		fmt.Println(err.Error())
	}

	var log EventLog

	log, err = newWinEventLog(cfg)

	if err != nil {
		fmt.Println(err.Error())
	}

	var eventLogState checkpoint.EventLogState
	if state != nil {
		eventLogState = *state
	}

	if err = log.Open(eventLogState); err != nil {
		log.Close()
		fmt.Println(err.Error())
	}

	return log
}

