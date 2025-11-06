package alerts

import (
	"log/slog"
	"time"
)

// Notifier 提供 BAS 告警触发能力。
type Notifier interface {
	NotifyBAS(event Event)
}

// Event 描述 BAS 告警所需的关键信息。
type Event struct {
	TaskID           string
	RunID            string
	ScenarioID       string
	ScenarioName     string
	Status           string
	ErrorMessage     string
	SandboxFallback  bool
	SandboxUsed      bool
	ApprovalRequired bool
	ApprovalGranted  bool
	Timestamp        time.Time
}

// LoggerNotifier 将告警写入 slog。
type LoggerNotifier struct {
	log              *slog.Logger
	enabled          bool
	notifyOnFailure  bool
	notifyOnFallback bool
}

// NewLoggerNotifier 构造基于日志的告警器。
func NewLoggerNotifier(log *slog.Logger, enabled bool, notifyOnFailure, notifyOnFallback bool) *LoggerNotifier {
	return &LoggerNotifier{
		log:              log,
		enabled:          enabled,
		notifyOnFailure:  notifyOnFailure,
		notifyOnFallback: notifyOnFallback,
	}
}

// NotifyBAS 根据事件状态输出告警。
func (n *LoggerNotifier) NotifyBAS(event Event) {
	if n == nil || !n.enabled || n.log == nil {
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Status == "failed" && n.notifyOnFailure {
		n.log.Warn("BAS 场景失败", "task_id", event.TaskID, "run_id", event.RunID, "scenario_id", event.ScenarioID, "scenario_name", event.ScenarioName, "error", event.ErrorMessage, "sandbox_fallback", event.SandboxFallback, "approval_required", event.ApprovalRequired, "approval_granted", event.ApprovalGranted, "timestamp", event.Timestamp)
		return
	}
	if event.SandboxFallback && n.notifyOnFallback {
		n.log.Warn("BAS 沙箱回退为宿主执行", "task_id", event.TaskID, "run_id", event.RunID, "scenario_id", event.ScenarioID, "scenario_name", event.ScenarioName, "approval_required", event.ApprovalRequired, "approval_granted", event.ApprovalGranted, "timestamp", event.Timestamp)
	}
}

// NopNotifier 为关闭状态提供空实现。
type NopNotifier struct{}

func (NopNotifier) NotifyBAS(Event) {}
