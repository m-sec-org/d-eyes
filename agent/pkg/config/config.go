package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

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
	AgentToken        string
	AgentName         string
	HeartbeatInterval time.Duration
	TaskPollInterval  time.Duration
	CacheDir          string
	TLS               RemoteTLSConfig
}

type RemoteTLSConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
	CAFile   string
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
			AgentToken:        "",
			AgentName:         "",
			HeartbeatInterval: 10 * time.Second,
			TaskPollInterval:  2 * time.Second,
			CacheDir:          filepath.Join(os.TempDir(), "d-eyes", "remote-cache"),
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
	Enabled           *bool          `yaml:"enabled"`
	ServerGRPCAddr    *string        `yaml:"server_grpc_addr"`
	AgentToken        *string        `yaml:"agent_token"`
	AgentName         *string        `yaml:"agent_name"`
	HeartbeatInterval *time.Duration `yaml:"heartbeat_interval"`
	TaskPollInterval  *time.Duration `yaml:"task_poll_interval"`
	CacheDir          *string        `yaml:"cache_dir"`
	TLS               *fileRemoteTLS `yaml:"tls"`
}

type fileRemoteTLS struct {
	Enabled  *bool   `yaml:"enabled"`
	CertFile *string `yaml:"cert_file"`
	KeyFile  *string `yaml:"key_file"`
	CAFile   *string `yaml:"ca_file"`
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
	if overrides.Remote != nil {
		if overrides.Remote.Enabled != nil {
			base.Remote.Enabled = *overrides.Remote.Enabled
		}
		if overrides.Remote.ServerGRPCAddr != nil {
			base.Remote.ServerGRPCAddr = *overrides.Remote.ServerGRPCAddr
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
	}
	return base
}
