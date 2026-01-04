package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/agent/pkg/threatintel"
	"gopkg.in/yaml.v3"
)

// OutputConfig controls report generation defaults.
type OutputConfig struct {
	Dir    string
	Format string
}

// UIConfig defines interactive output preferences.
type UIConfig struct {
	Color bool
	Quiet bool
}

// LoggingConfig controls verbosity.
type LoggingConfig struct {
	Verbose bool
	Debug   bool
}

// PolicyConfig sets risk handling defaults.
type PolicyConfig struct {
	FailOn      string
	SeverityMin string
}

// PerformanceConfig tunes runtime behaviour.
type PerformanceConfig struct {
	Threads int
	Timeout time.Duration
	Rate    int
}

// ResourcesConfig groups external resource settings.
type ResourcesConfig struct {
	RulesPath    string
	SBOMRegistry string
}

// NetworkConfig defines scanning defaults.
type NetworkConfig struct {
	Discovery   string
	ResolveHost bool
}

// RemoteConfig 定义与 Server 联动所需的配置。
type RemoteConfig struct {
	Enabled           bool
	ServerGRPCAddr    string
	ServerAPIBase     string
	AgentToken        string
	AgentName         string
	HeartbeatInterval time.Duration
	TaskPollInterval  time.Duration
	CacheDir          string
	TLS               RemoteTLSConfig
	Sandbox           SandboxConfig
	Adaptive          AdaptiveConfig
	Labels            map[string]string
}

type RemoteTLSConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
	CAFile   string
}

type SandboxConfig struct {
	Enabled         bool
	Runtime         string
	SharedPaths     []string
	TempDir         string
	RuntimeBinary   string
	AllowedCommands []string
	DeniedCommands  []string
	RequireApproval bool
	LogPath         string
	FallbackToHost  bool
}

// AdaptiveConfig 定义自适应调度与资源策略。
type AdaptiveConfig struct {
	CPUCeilPercent      float64
	BackoffInitial      time.Duration
	BackoffMax          time.Duration
	PriorityBoostLow    float64
	PriorityBoostHigh   float64
	MinPollInterval     time.Duration
	MaxPollInterval     time.Duration
	MinCPUResumePercent float64
}

type DiscoveryConfig struct {
	Targets []string
}

// TaskConfig groups module-level defaults shared by CLI & remote执行.
type TaskConfig struct {
	Respond     RespondTaskConfig
	Audit       AuditTaskConfig
	Inventory   InventoryTaskConfig
	SupplyChain SupplyChainTaskConfig
	Baseline    BaselineTaskConfig
	BAS         BASTaskConfig
}

// RespondTaskConfig provides defaults for respond 命令.
type RespondTaskConfig struct {
	Profile string
	Targets []string
}

// AuditTaskConfig provides defaults for audit 命令.
type AuditTaskConfig struct {
	Scope   string
	Targets []string
}

// InventoryTaskConfig provides defaults for inventory 命令.
type InventoryTaskConfig struct {
	Targets []string
	Ports   string
	Profile string
}

// SupplyChainTaskConfig provides defaults for supplychain 命令.
type SupplyChainTaskConfig struct {
	Mode  string
	Paths []string
	File  string
	Type  string
}

// BaselineTaskConfig provides defaults for baseline 命令.
type BaselineTaskConfig struct {
	Scope  string
	Config string
}

// BASTaskConfig provides defaults for BAS 子任务。
type BASTaskConfig struct {
	SandboxEnabled bool
	ScenarioDir    string
}

// CollectorConfig defines CLI/Probe shared system event collectors.
type CollectorConfig struct {
	Name      string
	Kind      string
	Disabled  bool
	Providers []string
	Probes    []string
	Parser    CollectorParserConfig
	Filters   CollectorFilterConfig
	Sampling  CollectorSamplingConfig
	Output    CollectorOutputConfig
	Settings  map[string]any
}

// CollectorFilterConfig defines include/exclude selectors.
type CollectorFilterConfig struct {
	Include map[string][]string
	Exclude map[string][]string
	Rules   []CollectorFilterRuleConfig
}

// CollectorSamplingConfig controls sampling behaviour.
type CollectorSamplingConfig struct {
	Rate              float64
	Interval          time.Duration
	Burst             int
	MaxEventsPerBatch int
	Strategies        []CollectorSamplingStrategyConfig
}

// CollectorOutputConfig defines output sink parameters.
type CollectorOutputConfig struct {
	Mode       string
	Path       string
	BufferSize int
	BatchSize  int
	Stream     CollectorStreamConfig
}

type CollectorStreamConfig struct {
	URL           string
	APIKey        string
	AgentID       string
	AgentName     string
	MaxBatch      int
	FlushInterval time.Duration
}

// CollectorParserConfig describes which parsers are enabled.
type CollectorParserConfig struct {
	Enabled  []string
	Disabled []string
	Plugins  []CollectorParserPluginConfig
	Settings map[string]any
}

// CollectorParserPluginConfig defines a parser plugin entry.
type CollectorParserPluginConfig struct {
	Name     string
	Path     string
	Type     string
	Checksum string
	Config   map[string]any
	Enabled  bool
	Metadata map[string]string
}

// CollectorFilterRuleConfig describes advanced filter expressions.
type CollectorFilterRuleConfig struct {
	Name       string
	Action     string
	Conditions []CollectorFilterConditionConfig
	Tags       map[string]string
	Threshold  CollectorFilterThresholdConfig
	Enabled    bool
}

// CollectorFilterConditionConfig represents a single clause.
type CollectorFilterConditionConfig struct {
	Field    string
	Operator string
	Value    string
	Values   []string
	Regex    string
}

// CollectorFilterThresholdConfig configures frequency gating.
type CollectorFilterThresholdConfig struct {
	Count  int
	Window time.Duration
}

// CollectorSamplingStrategyConfig defines per-event sampling overrides.
type CollectorSamplingStrategyConfig struct {
	Name       string
	EventTypes []string
	Match      map[string][]string
	Rate       float64
	Burst      int
	Window     time.Duration
	Enabled    bool
}

// Config contains global defaults for D-Eyes.
type Config struct {
	Output      OutputConfig
	UI          UIConfig
	Logging     LoggingConfig
	Policy      PolicyConfig
	Performance PerformanceConfig
	Resources   ResourcesConfig
	Network     NetworkConfig
	Remote      RemoteConfig
	Sandbox     SandboxConfig
	Discovery   DiscoveryConfig
	Tasks       TaskConfig
	ThreatIntel threatintel.Config
	Collectors  []CollectorConfig
}

// Default returns a Config populated with built-in defaults.
func Default() Config {
	home, err := os.UserHomeDir()
	var baseDir string
	if err == nil && home != "" {
		baseDir = filepath.Join(home, ".d-eyes", "reports")
	} else {
		baseDir = filepath.Join(os.TempDir(), "d-eyes", "reports")
	}
	return Config{
		Output: OutputConfig{
			Dir:    baseDir,
			Format: "json",
		},
		UI: UIConfig{
			Color: true,
			Quiet: false,
		},
		Logging: LoggingConfig{
			Verbose: false,
			Debug:   false,
		},
		Policy: PolicyConfig{
			FailOn:      "critical",
			SeverityMin: "medium",
		},
		Performance: PerformanceConfig{
			Threads: 0,
			Timeout: 10 * time.Minute,
			Rate:    0,
		},
		Resources: ResourcesConfig{
			RulesPath:    "",
			SBOMRegistry: "https://maven.aliyun.com/repository/public/",
		},
		Network: NetworkConfig{
			Discovery:   "",
			ResolveHost: false,
		},
		Remote: RemoteConfig{
			Enabled:           false,
			ServerGRPCAddr:    "",
			ServerAPIBase:     "",
			AgentToken:        "",
			AgentName:         "",
			HeartbeatInterval: 10 * time.Second,
			TaskPollInterval:  2 * time.Second,
			CacheDir:          filepath.Join(os.TempDir(), "d-eyes", "remote-cache"),
			Sandbox: SandboxConfig{
				Enabled:         false,
				Runtime:         "gvisor",
				SharedPaths:     nil,
				TempDir:         filepath.Join(os.TempDir(), "d-eyes", "sandbox"),
				RuntimeBinary:   "runsc",
				AllowedCommands: nil,
				DeniedCommands:  nil,
				RequireApproval: false,
				LogPath:         "",
				FallbackToHost:  true,
			},
			Adaptive: AdaptiveConfig{
				CPUCeilPercent:      75,
				MinCPUResumePercent: 55,
				BackoffInitial:      2 * time.Second,
				BackoffMax:          15 * time.Second,
				MinPollInterval:     1 * time.Second,
				MaxPollInterval:     10 * time.Second,
				PriorityBoostLow:    0.5,
				PriorityBoostHigh:   1.5,
			},
			Labels: map[string]string{
				"mode": "remote",
			},
		},
		Sandbox: SandboxConfig{
			Enabled:         false,
			Runtime:         "gvisor",
			SharedPaths:     nil,
			TempDir:         filepath.Join(os.TempDir(), "d-eyes", "sandbox"),
			RuntimeBinary:   "runsc",
			AllowedCommands: nil,
			DeniedCommands:  nil,
			RequireApproval: false,
			LogPath:         "",
			FallbackToHost:  true,
		},
		Discovery: DiscoveryConfig{
			Targets: nil,
		},
		Tasks: TaskConfig{
			Respond: RespondTaskConfig{
				Profile: "default",
				Targets: nil,
			},
			Audit: AuditTaskConfig{
				Scope:   "system",
				Targets: nil,
			},
			Inventory: InventoryTaskConfig{
				Targets: nil,
				Ports:   "",
				Profile: "fast",
			},
			SupplyChain: SupplyChainTaskConfig{
				Mode:  "generate",
				Paths: nil,
				File:  "",
				Type:  "json",
			},
			Baseline: BaselineTaskConfig{
				Scope:  "all",
				Config: "",
			},
			BAS: BASTaskConfig{
				SandboxEnabled: true,
				ScenarioDir:    "",
			},
		},
		ThreatIntel: threatintel.Config{
			Mode:                 threatintel.ModeHybrid,
			CacheTTL:             24 * time.Hour,
			CacheSize:            512,
			CacheDir:             "",
			HTTPTimeout:          15 * time.Second,
			MaxParallelPerSource: 4,
			OpenTIPBaseURL:       threatintel.DefaultOpenTIPBaseURL,
			MetaDefenderBaseURL:  threatintel.DefaultMetaDefenderBaseURL,
		},
	}
}

// Load reads configuration from the provided path. When the file does not exist
// the default configuration is returned.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read config: %w", err)
	}
	var parsed fileConfig
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	return mergeConfig(cfg, parsed), nil
}

type fileConfig struct {
	Output      *fileOutputConfig      `yaml:"output"`
	UI          *fileUIConfig          `yaml:"ui"`
	Logging     *fileLoggingConfig     `yaml:"logging"`
	Policy      *filePolicyConfig      `yaml:"policy"`
	Performance *filePerformanceConfig `yaml:"performance"`
	Resources   *fileResourcesConfig   `yaml:"resources"`
	Network     *fileNetworkConfig     `yaml:"network"`
	Remote      *fileRemoteConfig      `yaml:"remote"`
	Sandbox     *fileSandboxConfig     `yaml:"sandbox"`
	Discovery   *fileDiscoveryConfig   `yaml:"discovery"`
	Tasks       *fileTaskConfig        `yaml:"tasks"`
	ThreatIntel *fileThreatIntelConfig `yaml:"threat_intel"`
	Collectors  []*fileCollectorConfig `yaml:"collectors"`
}

type fileOutputConfig struct {
	Dir    *string `yaml:"dir"`
	Format *string `yaml:"format"`
}

type fileUIConfig struct {
	Color *bool `yaml:"color"`
	Quiet *bool `yaml:"quiet"`
}

type fileLoggingConfig struct {
	Verbose *bool `yaml:"verbose"`
	Debug   *bool `yaml:"debug"`
}

type filePolicyConfig struct {
	FailOn      *string `yaml:"fail_on"`
	SeverityMin *string `yaml:"severity_min"`
}

type filePerformanceConfig struct {
	Threads *int           `yaml:"threads"`
	Timeout *time.Duration `yaml:"timeout"`
	Rate    *int           `yaml:"rate"`
}

type fileResourcesConfig struct {
	RulesPath    *string `yaml:"rules_path"`
	SBOMRegistry *string `yaml:"sbom_registry"`
}

type fileNetworkConfig struct {
	Discovery   *string `yaml:"discovery"`
	ResolveHost *bool   `yaml:"resolve_host"`
}

type fileRemoteConfig struct {
	Enabled           *bool               `yaml:"enabled"`
	ServerGRPCAddr    *string             `yaml:"server_grpc_addr"`
	ServerAPIBase     *string             `yaml:"server_api_base"`
	AgentToken        *string             `yaml:"agent_token"`
	AgentName         *string             `yaml:"agent_name"`
	HeartbeatInterval *time.Duration      `yaml:"heartbeat_interval"`
	TaskPollInterval  *time.Duration      `yaml:"task_poll_interval"`
	CacheDir          *string             `yaml:"cache_dir"`
	TLS               *fileRemoteTLS      `yaml:"tls"`
	Sandbox           *fileSandboxConfig  `yaml:"sandbox"`
	Adaptive          *fileAdaptiveConfig `yaml:"adaptive"`
	Labels            map[string]string   `yaml:"labels"`
}

type fileRemoteTLS struct {
	Enabled  *bool   `yaml:"enabled"`
	CertFile *string `yaml:"cert_file"`
	KeyFile  *string `yaml:"key_file"`
	CAFile   *string `yaml:"ca_file"`
}

type fileAdaptiveConfig struct {
	CPUCeilPercent      *float64       `yaml:"cpu_ceil_percent"`
	MinCPUResumePercent *float64       `yaml:"min_cpu_resume_percent"`
	BackoffInitial      *time.Duration `yaml:"backoff_initial"`
	BackoffMax          *time.Duration `yaml:"backoff_max"`
	MinPollInterval     *time.Duration `yaml:"min_poll_interval"`
	MaxPollInterval     *time.Duration `yaml:"max_poll_interval"`
	PriorityBoostLow    *float64       `yaml:"priority_boost_low"`
	PriorityBoostHigh   *float64       `yaml:"priority_boost_high"`
}

type fileDiscoveryConfig struct {
	Targets []string `yaml:"targets"`
}

type fileTaskConfig struct {
	Respond     *fileRespondTaskConfig     `yaml:"respond"`
	Audit       *fileAuditTaskConfig       `yaml:"audit"`
	Inventory   *fileInventoryTaskConfig   `yaml:"inventory"`
	SupplyChain *fileSupplyChainTaskConfig `yaml:"supplychain"`
	Baseline    *fileBaselineTaskConfig    `yaml:"baseline"`
	BAS         *fileBASTaskConfig         `yaml:"bas"`
}

type fileRespondTaskConfig struct {
	Profile *string  `yaml:"profile"`
	Targets []string `yaml:"targets"`
}

type fileAuditTaskConfig struct {
	Scope   *string  `yaml:"scope"`
	Targets []string `yaml:"targets"`
}

type fileInventoryTaskConfig struct {
	Targets []string `yaml:"targets"`
	Ports   *string  `yaml:"ports"`
	Profile *string  `yaml:"profile"`
}

type fileSupplyChainTaskConfig struct {
	Mode  *string  `yaml:"mode"`
	Paths []string `yaml:"paths"`
	File  *string  `yaml:"file"`
	Type  *string  `yaml:"type"`
}

type fileBaselineTaskConfig struct {
	Scope  *string `yaml:"scope"`
	Config *string `yaml:"config"`
}

type fileBASTaskConfig struct {
	SandboxEnabled *bool   `yaml:"sandbox_enabled"`
	ScenarioDir    *string `yaml:"scenario_dir"`
}

type fileSandboxConfig struct {
	Enabled         *bool    `yaml:"enabled"`
	Runtime         *string  `yaml:"runtime"`
	SharedPaths     []string `yaml:"shared_paths"`
	TempDir         *string  `yaml:"temp_dir"`
	RuntimeBinary   *string  `yaml:"runtime_binary"`
	AllowedCommands []string `yaml:"allowed_commands"`
	DeniedCommands  []string `yaml:"denied_commands"`
	RequireApproval *bool    `yaml:"require_approval"`
	LogPath         *string  `yaml:"log_path"`
	FallbackToHost  *bool    `yaml:"fallback_to_host"`
}

type fileThreatIntelConfig struct {
	Mode                 *string        `yaml:"mode"`
	CacheTTL             *time.Duration `yaml:"cache_ttl"`
	CacheSize            *int           `yaml:"cache_size"`
	CacheDir             *string        `yaml:"cache_dir"`
	HTTPTimeout          *time.Duration `yaml:"http_timeout"`
	MaxParallelPerSource *int           `yaml:"max_parallel_per_source"`
	OpenTIPAPIKey        *string        `yaml:"opentip_api_key"`
	OpenTIPBaseURL       *string        `yaml:"opentip_base_url"`
	MetaDefenderAPIKey   *string        `yaml:"metadefender_api_key"`
	MetaDefenderBaseURL  *string        `yaml:"metadefender_base_url"`
}

type fileCollectorConfig struct {
	Name      *string                      `yaml:"name"`
	Kind      *string                      `yaml:"kind"`
	Disabled  *bool                        `yaml:"disabled"`
	Providers []string                     `yaml:"providers"`
	Probes    []string                     `yaml:"probes"`
	Parser    *fileCollectorParserConfig   `yaml:"parser"`
	Filters   *fileCollectorFilterConfig   `yaml:"filters"`
	Sampling  *fileCollectorSamplingConfig `yaml:"sampling"`
	Output    *fileCollectorOutputConfig   `yaml:"output"`
	Settings  map[string]any               `yaml:"settings"`
}

type fileCollectorFilterConfig struct {
	Include map[string][]string              `yaml:"include"`
	Exclude map[string][]string              `yaml:"exclude"`
	Rules   []*fileCollectorFilterRuleConfig `yaml:"rules"`
}

type fileCollectorSamplingConfig struct {
	Rate              *float64                               `yaml:"rate"`
	Interval          *time.Duration                         `yaml:"interval"`
	Burst             *int                                   `yaml:"burst"`
	MaxEventsPerBatch *int                                   `yaml:"max_events_per_batch"`
	Strategies        []*fileCollectorSamplingStrategyConfig `yaml:"strategies"`
}

type fileCollectorOutputConfig struct {
	Mode       *string                    `yaml:"mode"`
	Path       *string                    `yaml:"path"`
	BufferSize *int                       `yaml:"buffer_size"`
	BatchSize  *int                       `yaml:"batch_size"`
	Stream     *fileCollectorStreamConfig `yaml:"stream"`
}

type fileCollectorStreamConfig struct {
	URL           *string        `yaml:"url"`
	APIKey        *string        `yaml:"api_key"`
	AgentID       *string        `yaml:"agent_id"`
	AgentName     *string        `yaml:"agent_name"`
	MaxBatch      *int           `yaml:"max_batch"`
	FlushInterval *time.Duration `yaml:"flush_interval"`
}

type fileCollectorParserConfig struct {
	Enabled  []string                           `yaml:"enabled"`
	Disabled []string                           `yaml:"disabled"`
	Plugins  []*fileCollectorParserPluginConfig `yaml:"plugins"`
	Settings map[string]any                     `yaml:"settings"`
}

type fileCollectorParserPluginConfig struct {
	Name     *string           `yaml:"name"`
	Path     *string           `yaml:"path"`
	Type     *string           `yaml:"type"`
	Checksum *string           `yaml:"checksum"`
	Config   map[string]any    `yaml:"config"`
	Enabled  *bool             `yaml:"enabled"`
	Metadata map[string]string `yaml:"metadata"`
}

type fileCollectorFilterRuleConfig struct {
	Name       *string                               `yaml:"name"`
	Action     *string                               `yaml:"action"`
	Conditions []*fileCollectorFilterConditionConfig `yaml:"conditions"`
	Tags       map[string]string                     `yaml:"tags"`
	Threshold  *fileCollectorFilterThresholdConfig   `yaml:"threshold"`
	Enabled    *bool                                 `yaml:"enabled"`
}

type fileCollectorFilterConditionConfig struct {
	Field    *string  `yaml:"field"`
	Operator *string  `yaml:"operator"`
	Value    *string  `yaml:"value"`
	Values   []string `yaml:"values"`
	Regex    *string  `yaml:"regex"`
}

type fileCollectorFilterThresholdConfig struct {
	Count  *int           `yaml:"count"`
	Window *time.Duration `yaml:"window"`
}

type fileCollectorSamplingStrategyConfig struct {
	Name       *string             `yaml:"name"`
	EventTypes []string            `yaml:"event_types"`
	Match      map[string][]string `yaml:"match"`
	Rate       *float64            `yaml:"rate"`
	Burst      *int                `yaml:"burst"`
	Window     *time.Duration      `yaml:"window"`
	Enabled    *bool               `yaml:"enabled"`
}

func mergeConfig(base Config, overrides fileConfig) Config {
	if overrides.Output != nil {
		if overrides.Output.Dir != nil {
			base.Output.Dir = *overrides.Output.Dir
		}
		if overrides.Output.Format != nil {
			base.Output.Format = *overrides.Output.Format
		}
	}
	if overrides.UI != nil {
		if overrides.UI.Color != nil {
			base.UI.Color = *overrides.UI.Color
		}
		if overrides.UI.Quiet != nil {
			base.UI.Quiet = *overrides.UI.Quiet
		}
	}
	if overrides.Logging != nil {
		if overrides.Logging.Verbose != nil {
			base.Logging.Verbose = *overrides.Logging.Verbose
		}
		if overrides.Logging.Debug != nil {
			base.Logging.Debug = *overrides.Logging.Debug
		}
	}
	if overrides.Policy != nil {
		if overrides.Policy.FailOn != nil {
			base.Policy.FailOn = *overrides.Policy.FailOn
		}
		if overrides.Policy.SeverityMin != nil {
			base.Policy.SeverityMin = *overrides.Policy.SeverityMin
		}
	}
	if overrides.Performance != nil {
		if overrides.Performance.Threads != nil {
			base.Performance.Threads = *overrides.Performance.Threads
		}
		if overrides.Performance.Timeout != nil {
			base.Performance.Timeout = *overrides.Performance.Timeout
		}
		if overrides.Performance.Rate != nil {
			base.Performance.Rate = *overrides.Performance.Rate
		}
	}
	if overrides.Resources != nil {
		if overrides.Resources.RulesPath != nil {
			base.Resources.RulesPath = *overrides.Resources.RulesPath
		}
		if overrides.Resources.SBOMRegistry != nil {
			base.Resources.SBOMRegistry = *overrides.Resources.SBOMRegistry
		}
	}
	if overrides.Network != nil {
		if overrides.Network.Discovery != nil {
			base.Network.Discovery = *overrides.Network.Discovery
		}
		if overrides.Network.ResolveHost != nil {
			base.Network.ResolveHost = *overrides.Network.ResolveHost
		}
	}
	if overrides.Sandbox != nil {
		if overrides.Sandbox.Enabled != nil {
			base.Sandbox.Enabled = *overrides.Sandbox.Enabled
		}
		if overrides.Sandbox.Runtime != nil && strings.TrimSpace(*overrides.Sandbox.Runtime) != "" {
			base.Sandbox.Runtime = *overrides.Sandbox.Runtime
		}
		if overrides.Sandbox.SharedPaths != nil {
			base.Sandbox.SharedPaths = append([]string(nil), overrides.Sandbox.SharedPaths...)
		}
		if overrides.Sandbox.TempDir != nil && strings.TrimSpace(*overrides.Sandbox.TempDir) != "" {
			base.Sandbox.TempDir = *overrides.Sandbox.TempDir
		}
		if overrides.Sandbox.RuntimeBinary != nil && strings.TrimSpace(*overrides.Sandbox.RuntimeBinary) != "" {
			base.Sandbox.RuntimeBinary = *overrides.Sandbox.RuntimeBinary
		}
		if overrides.Sandbox.AllowedCommands != nil {
			base.Sandbox.AllowedCommands = append([]string(nil), overrides.Sandbox.AllowedCommands...)
		}
		if overrides.Sandbox.DeniedCommands != nil {
			base.Sandbox.DeniedCommands = append([]string(nil), overrides.Sandbox.DeniedCommands...)
		}
		if overrides.Sandbox.RequireApproval != nil {
			base.Sandbox.RequireApproval = *overrides.Sandbox.RequireApproval
		}
		if overrides.Sandbox.LogPath != nil && strings.TrimSpace(*overrides.Sandbox.LogPath) != "" {
			base.Sandbox.LogPath = *overrides.Sandbox.LogPath
		}
		if overrides.Sandbox.FallbackToHost != nil {
			base.Sandbox.FallbackToHost = *overrides.Sandbox.FallbackToHost
		}
	}
	if overrides.Discovery != nil {
		if overrides.Discovery.Targets != nil {
			base.Discovery.Targets = append([]string(nil), overrides.Discovery.Targets...)
		}
	}
	if overrides.Remote != nil {
		if overrides.Remote.Enabled != nil {
			base.Remote.Enabled = *overrides.Remote.Enabled
		}
		if overrides.Remote.ServerGRPCAddr != nil {
			base.Remote.ServerGRPCAddr = *overrides.Remote.ServerGRPCAddr
		}
		if overrides.Remote.ServerAPIBase != nil && strings.TrimSpace(*overrides.Remote.ServerAPIBase) != "" {
			base.Remote.ServerAPIBase = strings.TrimSpace(*overrides.Remote.ServerAPIBase)
		}
		if overrides.Remote.AgentToken != nil {
			base.Remote.AgentToken = *overrides.Remote.AgentToken
		}
		if overrides.Remote.AgentName != nil {
			base.Remote.AgentName = *overrides.Remote.AgentName
		}
		if overrides.Remote.HeartbeatInterval != nil {
			base.Remote.HeartbeatInterval = *overrides.Remote.HeartbeatInterval
		}
		if overrides.Remote.TaskPollInterval != nil {
			base.Remote.TaskPollInterval = *overrides.Remote.TaskPollInterval
		}
		if overrides.Remote.CacheDir != nil {
			base.Remote.CacheDir = *overrides.Remote.CacheDir
		}
		if overrides.Remote.Labels != nil {
			base.Remote.Labels = make(map[string]string, len(overrides.Remote.Labels))
			for k, v := range overrides.Remote.Labels {
				base.Remote.Labels[k] = v
			}
		}
		if overrides.Remote.TLS != nil {
			if overrides.Remote.TLS.Enabled != nil {
				base.Remote.TLS.Enabled = *overrides.Remote.TLS.Enabled
			}
			if overrides.Remote.TLS.CertFile != nil {
				base.Remote.TLS.CertFile = *overrides.Remote.TLS.CertFile
			}
			if overrides.Remote.TLS.KeyFile != nil {
				base.Remote.TLS.KeyFile = *overrides.Remote.TLS.KeyFile
			}
			if overrides.Remote.TLS.CAFile != nil {
				base.Remote.TLS.CAFile = *overrides.Remote.TLS.CAFile
			}
		}
		if overrides.Remote.Sandbox != nil {
			if overrides.Remote.Sandbox.Enabled != nil {
				base.Remote.Sandbox.Enabled = *overrides.Remote.Sandbox.Enabled
			}
			if overrides.Remote.Sandbox.Runtime != nil && strings.TrimSpace(*overrides.Remote.Sandbox.Runtime) != "" {
				base.Remote.Sandbox.Runtime = *overrides.Remote.Sandbox.Runtime
			}
			if overrides.Remote.Sandbox.SharedPaths != nil {
				base.Remote.Sandbox.SharedPaths = append([]string(nil), overrides.Remote.Sandbox.SharedPaths...)
			}
			if overrides.Remote.Sandbox.TempDir != nil && strings.TrimSpace(*overrides.Remote.Sandbox.TempDir) != "" {
				base.Remote.Sandbox.TempDir = *overrides.Remote.Sandbox.TempDir
			}
			if overrides.Remote.Sandbox.RuntimeBinary != nil && strings.TrimSpace(*overrides.Remote.Sandbox.RuntimeBinary) != "" {
				base.Remote.Sandbox.RuntimeBinary = *overrides.Remote.Sandbox.RuntimeBinary
			}
			if overrides.Remote.Sandbox.AllowedCommands != nil {
				base.Remote.Sandbox.AllowedCommands = append([]string(nil), overrides.Remote.Sandbox.AllowedCommands...)
			}
			if overrides.Remote.Sandbox.DeniedCommands != nil {
				base.Remote.Sandbox.DeniedCommands = append([]string(nil), overrides.Remote.Sandbox.DeniedCommands...)
			}
			if overrides.Remote.Sandbox.RequireApproval != nil {
				base.Remote.Sandbox.RequireApproval = *overrides.Remote.Sandbox.RequireApproval
			}
			if overrides.Remote.Sandbox.LogPath != nil && strings.TrimSpace(*overrides.Remote.Sandbox.LogPath) != "" {
				base.Remote.Sandbox.LogPath = *overrides.Remote.Sandbox.LogPath
			}
			if overrides.Remote.Sandbox.FallbackToHost != nil {
				base.Remote.Sandbox.FallbackToHost = *overrides.Remote.Sandbox.FallbackToHost
			}
		}
		if overrides.Remote.Adaptive != nil {
			if overrides.Remote.Adaptive.CPUCeilPercent != nil {
				base.Remote.Adaptive.CPUCeilPercent = *overrides.Remote.Adaptive.CPUCeilPercent
			}
			if overrides.Remote.Adaptive.MinCPUResumePercent != nil {
				base.Remote.Adaptive.MinCPUResumePercent = *overrides.Remote.Adaptive.MinCPUResumePercent
			}
			if overrides.Remote.Adaptive.BackoffInitial != nil {
				base.Remote.Adaptive.BackoffInitial = *overrides.Remote.Adaptive.BackoffInitial
			}
			if overrides.Remote.Adaptive.BackoffMax != nil {
				base.Remote.Adaptive.BackoffMax = *overrides.Remote.Adaptive.BackoffMax
			}
			if overrides.Remote.Adaptive.MinPollInterval != nil {
				base.Remote.Adaptive.MinPollInterval = *overrides.Remote.Adaptive.MinPollInterval
			}
			if overrides.Remote.Adaptive.MaxPollInterval != nil {
				base.Remote.Adaptive.MaxPollInterval = *overrides.Remote.Adaptive.MaxPollInterval
			}
			if overrides.Remote.Adaptive.PriorityBoostLow != nil {
				base.Remote.Adaptive.PriorityBoostLow = *overrides.Remote.Adaptive.PriorityBoostLow
			}
			if overrides.Remote.Adaptive.PriorityBoostHigh != nil {
				base.Remote.Adaptive.PriorityBoostHigh = *overrides.Remote.Adaptive.PriorityBoostHigh
			}
		}
	}
	if overrides.Tasks != nil {
		if overrides.Tasks.Respond != nil {
			if overrides.Tasks.Respond.Profile != nil {
				base.Tasks.Respond.Profile = *overrides.Tasks.Respond.Profile
			}
			if overrides.Tasks.Respond.Targets != nil {
				base.Tasks.Respond.Targets = append([]string(nil), overrides.Tasks.Respond.Targets...)
			}
		}
		if overrides.Tasks.Audit != nil {
			if overrides.Tasks.Audit.Scope != nil {
				base.Tasks.Audit.Scope = *overrides.Tasks.Audit.Scope
			}
			if overrides.Tasks.Audit.Targets != nil {
				base.Tasks.Audit.Targets = append([]string(nil), overrides.Tasks.Audit.Targets...)
			}
		}
		if overrides.Tasks.Inventory != nil {
			if overrides.Tasks.Inventory.Targets != nil {
				base.Tasks.Inventory.Targets = append([]string(nil), overrides.Tasks.Inventory.Targets...)
			}
			if overrides.Tasks.Inventory.Ports != nil {
				base.Tasks.Inventory.Ports = *overrides.Tasks.Inventory.Ports
			}
			if overrides.Tasks.Inventory.Profile != nil {
				base.Tasks.Inventory.Profile = *overrides.Tasks.Inventory.Profile
			}
		}
		if overrides.Tasks.SupplyChain != nil {
			if overrides.Tasks.SupplyChain.Mode != nil {
				base.Tasks.SupplyChain.Mode = *overrides.Tasks.SupplyChain.Mode
			}
			if overrides.Tasks.SupplyChain.Paths != nil {
				base.Tasks.SupplyChain.Paths = append([]string(nil), overrides.Tasks.SupplyChain.Paths...)
			}
			if overrides.Tasks.SupplyChain.File != nil {
				base.Tasks.SupplyChain.File = *overrides.Tasks.SupplyChain.File
			}
			if overrides.Tasks.SupplyChain.Type != nil {
				base.Tasks.SupplyChain.Type = *overrides.Tasks.SupplyChain.Type
			}
		}
		if overrides.Tasks.Baseline != nil {
			if overrides.Tasks.Baseline.Scope != nil {
				base.Tasks.Baseline.Scope = *overrides.Tasks.Baseline.Scope
			}
			if overrides.Tasks.Baseline.Config != nil {
				base.Tasks.Baseline.Config = *overrides.Tasks.Baseline.Config
			}
		}
		if overrides.Tasks.BAS != nil {
			if overrides.Tasks.BAS.SandboxEnabled != nil {
				base.Tasks.BAS.SandboxEnabled = *overrides.Tasks.BAS.SandboxEnabled
			}
			if overrides.Tasks.BAS.ScenarioDir != nil && strings.TrimSpace(*overrides.Tasks.BAS.ScenarioDir) != "" {
				base.Tasks.BAS.ScenarioDir = *overrides.Tasks.BAS.ScenarioDir
			}
		}
	}
	if overrides.ThreatIntel != nil {
		if overrides.ThreatIntel.Mode != nil {
			base.ThreatIntel.Mode = threatintel.ParseMode(*overrides.ThreatIntel.Mode)
		}
		if overrides.ThreatIntel.CacheTTL != nil && overrides.ThreatIntel.CacheTTL.Seconds() > 0 {
			base.ThreatIntel.CacheTTL = *overrides.ThreatIntel.CacheTTL
		}
		if overrides.ThreatIntel.CacheSize != nil && *overrides.ThreatIntel.CacheSize > 0 {
			base.ThreatIntel.CacheSize = *overrides.ThreatIntel.CacheSize
		}
		if overrides.ThreatIntel.CacheDir != nil {
			base.ThreatIntel.CacheDir = strings.TrimSpace(*overrides.ThreatIntel.CacheDir)
		}
		if overrides.ThreatIntel.HTTPTimeout != nil && overrides.ThreatIntel.HTTPTimeout.Seconds() > 0 {
			base.ThreatIntel.HTTPTimeout = *overrides.ThreatIntel.HTTPTimeout
		}
		if overrides.ThreatIntel.MaxParallelPerSource != nil && *overrides.ThreatIntel.MaxParallelPerSource > 0 {
			base.ThreatIntel.MaxParallelPerSource = *overrides.ThreatIntel.MaxParallelPerSource
		}
		if overrides.ThreatIntel.OpenTIPAPIKey != nil {
			base.ThreatIntel.OpenTIPAPIKey = strings.TrimSpace(*overrides.ThreatIntel.OpenTIPAPIKey)
		}
		if overrides.ThreatIntel.MetaDefenderAPIKey != nil {
			base.ThreatIntel.MetaDefenderAPIKey = strings.TrimSpace(*overrides.ThreatIntel.MetaDefenderAPIKey)
		}
		if overrides.ThreatIntel.OpenTIPBaseURL != nil && strings.TrimSpace(*overrides.ThreatIntel.OpenTIPBaseURL) != "" {
			base.ThreatIntel.OpenTIPBaseURL = strings.TrimRight(strings.TrimSpace(*overrides.ThreatIntel.OpenTIPBaseURL), "/")
		}
		if overrides.ThreatIntel.MetaDefenderBaseURL != nil && strings.TrimSpace(*overrides.ThreatIntel.MetaDefenderBaseURL) != "" {
			base.ThreatIntel.MetaDefenderBaseURL = strings.TrimRight(strings.TrimSpace(*overrides.ThreatIntel.MetaDefenderBaseURL), "/")
		}
	}
	if len(overrides.Collectors) > 0 {
		base.Collectors = normalizeCollectorConfigs(overrides.Collectors)
	}
	return base
}

func normalizeCollectorConfigs(overrides []*fileCollectorConfig) []CollectorConfig {
	result := make([]CollectorConfig, 0, len(overrides))
	for _, item := range overrides {
		if item == nil {
			continue
		}
		cfg := CollectorConfig{
			Name:      stringValue(item.Name),
			Kind:      stringValue(item.Kind),
			Disabled:  boolValue(item.Disabled),
			Providers: append([]string(nil), item.Providers...),
			Probes:    append([]string(nil), item.Probes...),
			Settings:  cloneAnyMap(item.Settings),
		}
		if item.Parser != nil {
			cfg.Parser = CollectorParserConfig{
				Enabled:  append([]string(nil), item.Parser.Enabled...),
				Disabled: append([]string(nil), item.Parser.Disabled...),
				Settings: cloneAnyMap(item.Parser.Settings),
				Plugins:  convertParserPlugins(item.Parser.Plugins),
			}
		}
		if item.Filters != nil {
			cfg.Filters = CollectorFilterConfig{
				Include: cloneStringSliceMap(item.Filters.Include),
				Exclude: cloneStringSliceMap(item.Filters.Exclude),
				Rules:   convertFilterRules(item.Filters.Rules),
			}
		}
		if item.Sampling != nil {
			cfg.Sampling = CollectorSamplingConfig{
				Rate:              floatValue(item.Sampling.Rate),
				Interval:          durationValue(item.Sampling.Interval),
				Burst:             intValue(item.Sampling.Burst),
				MaxEventsPerBatch: intValue(item.Sampling.MaxEventsPerBatch),
				Strategies:        convertSamplingStrategies(item.Sampling.Strategies),
			}
		}
		if item.Output != nil {
			cfg.Output = CollectorOutputConfig{
				Mode:       stringValue(item.Output.Mode),
				Path:       stringValue(item.Output.Path),
				BufferSize: intValue(item.Output.BufferSize),
				BatchSize:  intValue(item.Output.BatchSize),
			}
			if item.Output.Stream != nil {
				cfg.Output.Stream = CollectorStreamConfig{
					URL:           stringValue(item.Output.Stream.URL),
					APIKey:        stringValue(item.Output.Stream.APIKey),
					AgentID:       stringValue(item.Output.Stream.AgentID),
					AgentName:     stringValue(item.Output.Stream.AgentName),
					MaxBatch:      intValue(item.Output.Stream.MaxBatch),
					FlushInterval: durationValue(item.Output.Stream.FlushInterval),
				}
			}
		}
		result = append(result, cfg)
	}
	return result
}

func stringValue(ptr *string) string {
	if ptr == nil {
		return ""
	}
	return *ptr
}

func boolValue(ptr *bool) bool {
	if ptr == nil {
		return false
	}
	return *ptr
}

func intValue(ptr *int) int {
	if ptr == nil {
		return 0
	}
	return *ptr
}

func floatValue(ptr *float64) float64 {
	if ptr == nil {
		return 0
	}
	return *ptr
}

func durationValue(ptr *time.Duration) time.Duration {
	if ptr == nil {
		return 0
	}
	return *ptr
}

func cloneStringSliceMap(input map[string][]string) map[string][]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string][]string, len(input))
	for key, vals := range input {
		out[key] = append([]string(nil), vals...)
	}
	return out
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}

func convertParserPlugins(items []*fileCollectorParserPluginConfig) []CollectorParserPluginConfig {
	if len(items) == 0 {
		return nil
	}
	out := make([]CollectorParserPluginConfig, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		out = append(out, CollectorParserPluginConfig{
			Name:     stringValue(item.Name),
			Path:     stringValue(item.Path),
			Type:     stringValue(item.Type),
			Checksum: stringValue(item.Checksum),
			Config:   cloneAnyMap(item.Config),
			Enabled:  boolValue(item.Enabled),
			Metadata: cloneStringMap(item.Metadata),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func convertFilterRules(items []*fileCollectorFilterRuleConfig) []CollectorFilterRuleConfig {
	if len(items) == 0 {
		return nil
	}
	out := make([]CollectorFilterRuleConfig, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		rule := CollectorFilterRuleConfig{
			Name:       stringValue(item.Name),
			Action:     stringValue(item.Action),
			Conditions: convertFilterConditions(item.Conditions),
			Tags:       cloneStringMap(item.Tags),
			Enabled:    boolValue(item.Enabled),
		}
		if item.Threshold != nil {
			rule.Threshold = CollectorFilterThresholdConfig{
				Count:  intValue(item.Threshold.Count),
				Window: durationValue(item.Threshold.Window),
			}
		}
		out = append(out, rule)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func convertFilterConditions(items []*fileCollectorFilterConditionConfig) []CollectorFilterConditionConfig {
	if len(items) == 0 {
		return nil
	}
	out := make([]CollectorFilterConditionConfig, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		out = append(out, CollectorFilterConditionConfig{
			Field:    stringValue(item.Field),
			Operator: stringValue(item.Operator),
			Value:    stringValue(item.Value),
			Values:   append([]string(nil), item.Values...),
			Regex:    stringValue(item.Regex),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func convertSamplingStrategies(items []*fileCollectorSamplingStrategyConfig) []CollectorSamplingStrategyConfig {
	if len(items) == 0 {
		return nil
	}
	out := make([]CollectorSamplingStrategyConfig, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		out = append(out, CollectorSamplingStrategyConfig{
			Name:       stringValue(item.Name),
			EventTypes: append([]string(nil), item.EventTypes...),
			Match:      cloneStringSliceMap(item.Match),
			Rate:       floatValue(item.Rate),
			Burst:      intValue(item.Burst),
			Window:     durationValue(item.Window),
			Enabled:    boolValue(item.Enabled),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneAnyMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]any, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}
