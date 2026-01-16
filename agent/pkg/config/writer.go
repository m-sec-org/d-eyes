package config

import (
	"bytes"
	"sort"

	"gopkg.in/yaml.v3"
)

type orderedStringMap map[string]string

func (m orderedStringMap) MarshalYAML() (any, error) {
	node := &yaml.Node{
		Kind: yaml.MappingNode,
		Tag:  "!!map",
	}
	if len(m) == 0 {
		return node, nil
	}
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: m[key]},
		)
	}
	return node, nil
}

type yamlOutputConfig struct {
	Dir    string `yaml:"dir"`
	Format string `yaml:"format"`
}

type yamlUIConfig struct {
	Color bool `yaml:"color"`
	Quiet bool `yaml:"quiet"`
}

type yamlLoggingConfig struct {
	Verbose bool `yaml:"verbose"`
	Debug   bool `yaml:"debug"`
}

type yamlPolicyConfig struct {
	FailOn      string `yaml:"fail_on"`
	SeverityMin string `yaml:"severity_min"`
}

type yamlPerformanceConfig struct {
	Threads int    `yaml:"threads"`
	Timeout string `yaml:"timeout"`
	Rate    int    `yaml:"rate"`
}

type yamlResourcesConfig struct {
	RulesPath    string `yaml:"rules_path"`
	SBOMRegistry string `yaml:"sbom_registry"`
}

type yamlNetworkConfig struct {
	Discovery   string `yaml:"discovery"`
	ResolveHost bool   `yaml:"resolve_host"`
}

type yamlRemoteTLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
}

type yamlSandboxConfig struct {
	Enabled         bool     `yaml:"enabled"`
	Runtime         string   `yaml:"runtime"`
	SharedPaths     []string `yaml:"shared_paths"`
	TempDir         string   `yaml:"temp_dir"`
	RuntimeBinary   string   `yaml:"runtime_binary"`
	AllowedCommands []string `yaml:"allowed_commands"`
	DeniedCommands  []string `yaml:"denied_commands"`
	RequireApproval bool     `yaml:"require_approval"`
	LogPath         string   `yaml:"log_path"`
	FallbackToHost  bool     `yaml:"fallback_to_host"`
}

type yamlAdaptiveConfig struct {
	CPUCeilPercent      float64 `yaml:"cpu_ceil_percent"`
	BackoffInitial      string  `yaml:"backoff_initial"`
	BackoffMax          string  `yaml:"backoff_max"`
	PriorityBoostLow    float64 `yaml:"priority_boost_low"`
	PriorityBoostHigh   float64 `yaml:"priority_boost_high"`
	MinPollInterval     string  `yaml:"min_poll_interval"`
	MaxPollInterval     string  `yaml:"max_poll_interval"`
	MinCPUResumePercent float64 `yaml:"min_cpu_resume_percent"`
}

type yamlRemoteConfig struct {
	Enabled           bool                `yaml:"enabled"`
	ServerGRPCAddr    string              `yaml:"server_grpc_addr"`
	ServerAPIBase     string              `yaml:"server_api_base"`
	AgentToken        string              `yaml:"agent_token"`
	AgentName         string              `yaml:"agent_name"`
	HeartbeatInterval string              `yaml:"heartbeat_interval"`
	TaskPollInterval  string              `yaml:"task_poll_interval"`
	CacheDir          string              `yaml:"cache_dir"`
	TLS               yamlRemoteTLSConfig `yaml:"tls"`
	Sandbox           yamlSandboxConfig   `yaml:"sandbox"`
	Adaptive          yamlAdaptiveConfig  `yaml:"adaptive"`
	Labels            orderedStringMap    `yaml:"labels"`
}

type yamlDiscoveryConfig struct {
	Targets []string `yaml:"targets"`
}

type yamlRespondTaskConfig struct {
	Profile string   `yaml:"profile"`
	Targets []string `yaml:"targets"`
}

type yamlAuditTaskConfig struct {
	Scope   string   `yaml:"scope"`
	Targets []string `yaml:"targets"`
}

type yamlInventoryTaskConfig struct {
	Targets []string `yaml:"targets"`
	Ports   string   `yaml:"ports"`
	Profile string   `yaml:"profile"`
}

type yamlSupplyChainTaskConfig struct {
	Mode  string   `yaml:"mode"`
	Paths []string `yaml:"paths"`
	File  string   `yaml:"file"`
	Type  string   `yaml:"type"`
}

type yamlBaselineTaskConfig struct {
	Scope  string `yaml:"scope"`
	Config string `yaml:"config"`
}

type yamlBASTaskConfig struct {
	SandboxEnabled bool   `yaml:"sandbox_enabled"`
	ScenarioDir    string `yaml:"scenario_dir"`
}

type yamlTaskConfig struct {
	Respond     yamlRespondTaskConfig     `yaml:"respond"`
	Audit       yamlAuditTaskConfig       `yaml:"audit"`
	Inventory   yamlInventoryTaskConfig   `yaml:"inventory"`
	SupplyChain yamlSupplyChainTaskConfig `yaml:"supplychain"`
	Baseline    yamlBaselineTaskConfig    `yaml:"baseline"`
	BAS         yamlBASTaskConfig         `yaml:"bas"`
}

type yamlThreatIntelConfig struct {
	Mode                 string `yaml:"mode"`
	CacheTTL             string `yaml:"cache_ttl"`
	CacheSize            int    `yaml:"cache_size"`
	CacheDir             string `yaml:"cache_dir"`
	HTTPTimeout          string `yaml:"http_timeout"`
	MaxParallelPerSource int    `yaml:"max_parallel_per_source"`
	OpenTIPAPIKey        string `yaml:"opentip_api_key"`
	OpenTIPBaseURL       string `yaml:"opentip_base_url"`
	MetaDefenderAPIKey   string `yaml:"metadefender_api_key"`
	MetaDefenderBaseURL  string `yaml:"metadefender_base_url"`
}

type yamlConfig struct {
	Output      yamlOutputConfig      `yaml:"output"`
	UI          yamlUIConfig          `yaml:"ui"`
	Logging     yamlLoggingConfig     `yaml:"logging"`
	Policy      yamlPolicyConfig      `yaml:"policy"`
	Performance yamlPerformanceConfig `yaml:"performance"`
	Resources   yamlResourcesConfig   `yaml:"resources"`
	Network     yamlNetworkConfig     `yaml:"network"`
	Remote      yamlRemoteConfig      `yaml:"remote"`
	Sandbox     yamlSandboxConfig     `yaml:"sandbox"`
	Discovery   yamlDiscoveryConfig   `yaml:"discovery"`
	Tasks       yamlTaskConfig        `yaml:"tasks"`
	ThreatIntel yamlThreatIntelConfig `yaml:"threat_intel"`
	Collectors  []any                 `yaml:"collectors"`
}

func EncodeDefaultYAML() ([]byte, error) {
	return EncodeYAML(Default())
}

func EncodeYAML(cfg Config) ([]byte, error) {
	payload := yamlConfig{
		Output: yamlOutputConfig{
			Dir:    cfg.Output.Dir,
			Format: cfg.Output.Format,
		},
		UI: yamlUIConfig{
			Color: cfg.UI.Color,
			Quiet: cfg.UI.Quiet,
		},
		Logging: yamlLoggingConfig{
			Verbose: cfg.Logging.Verbose,
			Debug:   cfg.Logging.Debug,
		},
		Policy: yamlPolicyConfig{
			FailOn:      cfg.Policy.FailOn,
			SeverityMin: cfg.Policy.SeverityMin,
		},
		Performance: yamlPerformanceConfig{
			Threads: cfg.Performance.Threads,
			Timeout: cfg.Performance.Timeout.String(),
			Rate:    cfg.Performance.Rate,
		},
		Resources: yamlResourcesConfig{
			RulesPath:    cfg.Resources.RulesPath,
			SBOMRegistry: cfg.Resources.SBOMRegistry,
		},
		Network: yamlNetworkConfig{
			Discovery:   cfg.Network.Discovery,
			ResolveHost: cfg.Network.ResolveHost,
		},
		Remote: yamlRemoteConfig{
			Enabled:           cfg.Remote.Enabled,
			ServerGRPCAddr:    cfg.Remote.ServerGRPCAddr,
			ServerAPIBase:     cfg.Remote.ServerAPIBase,
			AgentToken:        cfg.Remote.AgentToken,
			AgentName:         cfg.Remote.AgentName,
			HeartbeatInterval: cfg.Remote.HeartbeatInterval.String(),
			TaskPollInterval:  cfg.Remote.TaskPollInterval.String(),
			CacheDir:          cfg.Remote.CacheDir,
			TLS: yamlRemoteTLSConfig{
				Enabled:  cfg.Remote.TLS.Enabled,
				CertFile: cfg.Remote.TLS.CertFile,
				KeyFile:  cfg.Remote.TLS.KeyFile,
				CAFile:   cfg.Remote.TLS.CAFile,
			},
			Sandbox: yamlSandboxConfig{
				Enabled:         cfg.Remote.Sandbox.Enabled,
				Runtime:         cfg.Remote.Sandbox.Runtime,
				SharedPaths:     append([]string(nil), cfg.Remote.Sandbox.SharedPaths...),
				TempDir:         cfg.Remote.Sandbox.TempDir,
				RuntimeBinary:   cfg.Remote.Sandbox.RuntimeBinary,
				AllowedCommands: append([]string(nil), cfg.Remote.Sandbox.AllowedCommands...),
				DeniedCommands:  append([]string(nil), cfg.Remote.Sandbox.DeniedCommands...),
				RequireApproval: cfg.Remote.Sandbox.RequireApproval,
				LogPath:         cfg.Remote.Sandbox.LogPath,
				FallbackToHost:  cfg.Remote.Sandbox.FallbackToHost,
			},
			Adaptive: yamlAdaptiveConfig{
				CPUCeilPercent:      cfg.Remote.Adaptive.CPUCeilPercent,
				BackoffInitial:      cfg.Remote.Adaptive.BackoffInitial.String(),
				BackoffMax:          cfg.Remote.Adaptive.BackoffMax.String(),
				PriorityBoostLow:    cfg.Remote.Adaptive.PriorityBoostLow,
				PriorityBoostHigh:   cfg.Remote.Adaptive.PriorityBoostHigh,
				MinPollInterval:     cfg.Remote.Adaptive.MinPollInterval.String(),
				MaxPollInterval:     cfg.Remote.Adaptive.MaxPollInterval.String(),
				MinCPUResumePercent: cfg.Remote.Adaptive.MinCPUResumePercent,
			},
			Labels: cloneOrderedStringMap(cfg.Remote.Labels),
		},
		Sandbox: yamlSandboxConfig{
			Enabled:         cfg.Sandbox.Enabled,
			Runtime:         cfg.Sandbox.Runtime,
			SharedPaths:     append([]string(nil), cfg.Sandbox.SharedPaths...),
			TempDir:         cfg.Sandbox.TempDir,
			RuntimeBinary:   cfg.Sandbox.RuntimeBinary,
			AllowedCommands: append([]string(nil), cfg.Sandbox.AllowedCommands...),
			DeniedCommands:  append([]string(nil), cfg.Sandbox.DeniedCommands...),
			RequireApproval: cfg.Sandbox.RequireApproval,
			LogPath:         cfg.Sandbox.LogPath,
			FallbackToHost:  cfg.Sandbox.FallbackToHost,
		},
		Discovery: yamlDiscoveryConfig{
			Targets: append([]string(nil), cfg.Discovery.Targets...),
		},
		Tasks: yamlTaskConfig{
			Respond: yamlRespondTaskConfig{
				Profile: cfg.Tasks.Respond.Profile,
				Targets: append([]string(nil), cfg.Tasks.Respond.Targets...),
			},
			Audit: yamlAuditTaskConfig{
				Scope:   cfg.Tasks.Audit.Scope,
				Targets: append([]string(nil), cfg.Tasks.Audit.Targets...),
			},
			Inventory: yamlInventoryTaskConfig{
				Targets: append([]string(nil), cfg.Tasks.Inventory.Targets...),
				Ports:   cfg.Tasks.Inventory.Ports,
				Profile: cfg.Tasks.Inventory.Profile,
			},
			SupplyChain: yamlSupplyChainTaskConfig{
				Mode:  cfg.Tasks.SupplyChain.Mode,
				Paths: append([]string(nil), cfg.Tasks.SupplyChain.Paths...),
				File:  cfg.Tasks.SupplyChain.File,
				Type:  cfg.Tasks.SupplyChain.Type,
			},
			Baseline: yamlBaselineTaskConfig{
				Scope:  cfg.Tasks.Baseline.Scope,
				Config: cfg.Tasks.Baseline.Config,
			},
			BAS: yamlBASTaskConfig{
				SandboxEnabled: cfg.Tasks.BAS.SandboxEnabled,
				ScenarioDir:    cfg.Tasks.BAS.ScenarioDir,
			},
		},
		ThreatIntel: yamlThreatIntelConfig{
			Mode:                 string(cfg.ThreatIntel.Mode),
			CacheTTL:             cfg.ThreatIntel.CacheTTL.String(),
			CacheSize:            cfg.ThreatIntel.CacheSize,
			CacheDir:             cfg.ThreatIntel.CacheDir,
			HTTPTimeout:          cfg.ThreatIntel.HTTPTimeout.String(),
			MaxParallelPerSource: cfg.ThreatIntel.MaxParallelPerSource,
			OpenTIPAPIKey:        cfg.ThreatIntel.OpenTIPAPIKey,
			OpenTIPBaseURL:       cfg.ThreatIntel.OpenTIPBaseURL,
			MetaDefenderAPIKey:   cfg.ThreatIntel.MetaDefenderAPIKey,
			MetaDefenderBaseURL:  cfg.ThreatIntel.MetaDefenderBaseURL,
		},
		Collectors: nil,
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(payload); err != nil {
		_ = enc.Close()
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func cloneOrderedStringMap(in map[string]string) orderedStringMap {
	if len(in) == 0 {
		return nil
	}
	out := make(orderedStringMap, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
