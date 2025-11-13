package tasks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
	"github.com/m-sec-org/d-eyes/agent/pkg/threatintel"
)

// TaskRunner 定义任务执行器接口
type TaskRunner interface {
	Run(ctx context.Context, req TaskRequest) (TaskResult, error)
}

// TaskRequest 表示任务执行所需的上下文
type TaskRequest struct {
	Profile         string
	OutputDir       string
	Format          string
	Name            string
	Timeout         time.Duration
	Flags           map[string]any
	Metadata        map[string]string
	Config          config.Config
	Manager         *reporting.Manager
	ThreatIntel     *threatintel.Manager
	Quiet           bool
	JSONOutput      bool
	Notices         []string
	SandboxApproved bool
}

// TaskResult 表示任务执行后的返回数据
type TaskResult struct {
	Outputs  []reporting.OutputRecord
	Risks    map[string]int
	Notes    []string
	Metadata map[string]string
}

// ApplyDefaults 根据全局配置补充缺省值
func (r *TaskRequest) ApplyDefaults(fallbackName string) {
	cfg := r.Config
	if cfg.Output.Dir == "" && cfg.Output.Format == "" {
		cfg = config.Default()
	}
	if r.Profile == "" {
		r.Profile = "default"
	}
	if r.Flags == nil {
		r.Flags = make(map[string]any)
	}
	if r.Metadata == nil {
		r.Metadata = make(map[string]string)
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
	if r.Notices == nil {
		r.Notices = make([]string, 0)
	}
	r.Config = cfg
	r.initThreatIntel()
	if r.Config.Sandbox.RequireApproval {
		if val, ok := r.Metadata["sandbox_approved"]; ok && strings.EqualFold(strings.TrimSpace(val), "true") {
			r.SandboxApproved = true
		}
	} else if !r.SandboxApproved {
		r.SandboxApproved = true
	}
}

func (r *TaskRequest) initThreatIntel() {
	mode := r.Config.ThreatIntel.Mode
	if mode == "" {
		mode = threatintel.ModeHybrid
		r.Config.ThreatIntel.Mode = mode
	}
	if mode == threatintel.ModeServer || r.ThreatIntel != nil {
		return
	}
	cfg := r.Config.ThreatIntel
	if cfg.CacheDir == "" {
		cfg.CacheDir = defaultThreatIntelCacheDir()
	}
	manager, err := threatintel.NewManager(cfg)
	if err != nil {
		var note string
		switch err {
		case threatintel.ErrNoActiveConnector:
			note = "威胁情报：未配置可用的 API Key，本地查询已禁用"
		default:
			note = fmt.Sprintf("威胁情报：初始化失败（%v），已降级为 server 模式", err)
		}
		r.Notices = append(r.Notices, note)
		return
	}
	r.ThreatIntel = manager
}

func defaultThreatIntelCacheDir() string {
	if dir := os.Getenv("D_EYES_CACHE"); strings.TrimSpace(dir) != "" {
		return filepath.Join(dir, "threatintel")
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".d-eyes", "cache", "threatintel")
	}
	return filepath.Join(os.TempDir(), "d-eyes", "cache", "threatintel")
}
