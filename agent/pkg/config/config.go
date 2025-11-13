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
			CacheTTL:             6 * time.Hour,
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
	Enabled           *bool              `yaml:"enabled"`
	ServerGRPCAddr    *string            `yaml:"server_grpc_addr"`
	ServerAPIBase     *string            `yaml:"server_api_base"`
	AgentToken        *string            `yaml:"agent_token"`
	AgentName         *string            `yaml:"agent_name"`
	HeartbeatInterval *time.Duration     `yaml:"heartbeat_interval"`
	TaskPollInterval  *time.Duration     `yaml:"task_poll_interval"`
	CacheDir          *string            `yaml:"cache_dir"`
	TLS               *fileRemoteTLS     `yaml:"tls"`
	Sandbox           *fileSandboxConfig `yaml:"sandbox"`
}

type fileRemoteTLS struct {
	Enabled  *bool   `yaml:"enabled"`
	CertFile *string `yaml:"cert_file"`
	KeyFile  *string `yaml:"key_file"`
	CAFile   *string `yaml:"ca_file"`
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
	return base
}
