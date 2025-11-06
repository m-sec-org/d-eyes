package audit

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Recorder defines the contract for writing audit events.
type Recorder interface {
	Record(event Event) error
}

// Event captures BAS 审计事件的关键字段。
type Event struct {
	Timestamp        time.Time         `json:"timestamp"`
	TaskID           string            `json:"task_id"`
	RunID            string            `json:"run_id"`
	AgentID          string            `json:"agent_id,omitempty"`
	ScenarioID       string            `json:"scenario_id,omitempty"`
	ScenarioName     string            `json:"scenario_name,omitempty"`
	Status           string            `json:"status"`
	ExitCode         int32             `json:"exit_code"`
	ErrorMessage     string            `json:"error_message,omitempty"`
	SandboxEnabled   bool              `json:"sandbox_enabled"`
	SandboxUsed      bool              `json:"sandbox_used"`
	SandboxFallback  bool              `json:"sandbox_fallback"`
	ApprovalRequired bool              `json:"approval_required"`
	ApprovalGranted  bool              `json:"approval_granted"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	Notes            []string          `json:"notes,omitempty"`
	Risks            map[string]int    `json:"risks,omitempty"`
}

// Logger 将审计事件以 JSON Lines 形式写入指定文件。
type Logger struct {
	path string
	mu   sync.Mutex
}

// NewLogger 构造文件型审计记录器。
func NewLogger(path string) (*Logger, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("audit: log path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return &Logger{path: path}, nil
}

// Record 将事件追加到审计日志文件。
func (l *Logger) Record(event Event) error {
	if l == nil {
		return errors.New("audit: logger is nil")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(payload, '\n')); err != nil {
		return err
	}
	return nil
}
