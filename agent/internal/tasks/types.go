package tasks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/debugger"
	"github.com/m-sec-org/d-eyes/agent/pkg/artifacts"
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
	ArtifactClient  ArtifactClient
	Quiet           bool
	JSONOutput      bool
	Notices         []string
	SandboxApproved bool
	Debug           bool
	Debugger        *debugger.Emitter
}

// ArtifactClient 抽象远程 artifact 上传行为，便于测试时注入。
type ArtifactClient interface {
	Upload(ctx context.Context, input artifacts.UploadInput) (*artifacts.UploadResult, error)
}

// TaskResult 表示任务执行后的返回数据
type TaskResult struct {
	Outputs  []reporting.OutputRecord
	Risks    map[string]int
	Notes    []string
	Metadata map[string]string
}

type threatIntelManagerProvider interface {
	NewManager(cfg threatintel.Config) (*threatintel.Manager, error)
}

var (
	tiProvider     threatIntelManagerProvider = defaultThreatIntelManagerProvider{}
	tiProviderLock sync.RWMutex
)

// SetThreatIntelProvider allows tests to override ThreatIntel manager creation.
func SetThreatIntelProvider(p threatIntelManagerProvider) {
	tiProviderLock.Lock()
	defer tiProviderLock.Unlock()
	if p == nil {
		tiProvider = defaultThreatIntelManagerProvider{}
		return
	}
	tiProvider = p
}

func getThreatIntelProvider() threatIntelManagerProvider {
	tiProviderLock.RLock()
	defer tiProviderLock.RUnlock()
	return tiProvider
}

type defaultThreatIntelManagerProvider struct{}

func (defaultThreatIntelManagerProvider) NewManager(cfg threatintel.Config) (*threatintel.Manager, error) {
	return threatintel.NewManager(cfg)
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
	if !r.Debug {
		if val := strings.TrimSpace(r.Metadata["debug"]); val != "" {
			r.Debug = parseBoolString(val)
		}
	}
	if r.Debug {
		r.Metadata["debug"] = "true"
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

func parseBoolString(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "y", "enabled":
		return true
	default:
		return false
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
	provider := getThreatIntelProvider()
	manager, err := provider.NewManager(cfg)
	if err != nil {
		if r.Metadata == nil {
			r.Metadata = make(map[string]string)
		}
		r.Metadata["threatintel.notice"] = threatintel.NoticeCodeInitFailed
		switch {
		case errors.Is(err, threatintel.ErrNoActiveConnector):
			r.Metadata["threatintel.notice_detail"] = "未配置可用的情报数据源，已降级为 local（仅启发式）"
		default:
			r.Metadata["threatintel.notice_detail"] = "初始化失败，已降级为 local（仅启发式）"
		}
		r.Notices = append(r.Notices, fmt.Sprintf("威胁情报：%s", r.Metadata["threatintel.notice_detail"]))
		fallbackCfg := cfg
		fallbackCfg.Mode = threatintel.ModeLocal
		if fallback, fallbackErr := threatintel.NewManager(fallbackCfg); fallbackErr == nil {
			r.ThreatIntel = fallback
		}
		return
	}
	r.ThreatIntel = manager
	for _, notice := range manager.Notices() {
		r.Notices = append(r.Notices, fmt.Sprintf("威胁情报：%s", notice))
	}
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
