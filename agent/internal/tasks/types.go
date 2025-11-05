package tasks

import (
	"context"
	"time"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

// TaskRunner 定义任务执行器接口
type TaskRunner interface {
	Run(ctx context.Context, req TaskRequest) (TaskResult, error)
}

// TaskRequest 表示任务执行所需的上下文
type TaskRequest struct {
	Profile    string
	OutputDir  string
	Format     string
	Name       string
	Timeout    time.Duration
	Flags      map[string]any
	Config     config.Config
	Manager    *reporting.Manager
	Quiet      bool
	JSONOutput bool
}

// TaskResult 表示任务执行后的返回数据
type TaskResult struct {
	Outputs []reporting.OutputRecord
	Risks   map[string]int
	Notes   []string
}

// ApplyDefaults 根据全局配置补充缺省值
func (r *TaskRequest) ApplyDefaults(fallbackName string) {
	cfg := r.Config
	if cfg == (config.Config{}) {
		cfg = config.Default()
	}
	if r.Profile == "" {
		r.Profile = "default"
	}
	if r.Flags == nil {
		r.Flags = make(map[string]any)
	}
	if r.OutputDir == "" {
		r.OutputDir = cfg.Output.Dir
	}
	if r.Format == "" {
		r.Format = cfg.Output.Format
	}
	if r.Timeout <= 0 {
		timeout := cfg.Performance.Timeout
		if timeout <= 0 {
			timeout = config.Default().Performance.Timeout
		}
		r.Timeout = timeout
	}
	if r.Name == "" {
		name := fallbackName
		if r.Profile != "" && r.Profile != "default" {
			name = name + "-" + r.Profile
		}
		r.Name = name
	}
	if r.Manager == nil {
		r.Manager = reporting.NewManager(cfg)
	}
}
