package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config captures all runtime configuration for the server process.
type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Security    SecurityConfig    `yaml:"security"`
	Database    DatabaseConfig    `yaml:"database"`
	Redis       RedisConfig       `yaml:"redis"`
	Scheduler   SchedulerConfig   `yaml:"scheduler"`
	Search      SearchConfig      `yaml:"search"`
	Metrics     MetricsConfig     `yaml:"metrics"`
	Audit       AuditConfig       `yaml:"audit"`
	Alerts      AlertsConfig      `yaml:"alerts"`
	Templates   TemplateConfig    `yaml:"templates"`
	TaskCatalog TaskCatalogConfig `yaml:"task_catalog"`
	BAS         BASConfig         `yaml:"bas"`
	RBAC        RBACConfig        `yaml:"rbac"`
	Reports     ReportConfig      `yaml:"reports"`
}

type ServerConfig struct {
	HTTPAddr string    `yaml:"http_addr"`
	GRPCAddr string    `yaml:"grpc_addr"`
	TLS      TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type SecurityConfig struct {
	AgentToken string   `yaml:"agent_token"`
	APIKeys    []string `yaml:"api_keys"`
}

type DatabaseConfig struct {
	DSN          string `yaml:"dsn"`
	MaxOpenConns int    `yaml:"max_open_conns"`
	MaxIdleConns int    `yaml:"max_idle_conns"`
	InMemory     bool   `yaml:"in_memory"`
}

type RedisConfig struct {
	Addr         string        `yaml:"addr"`
	Password     string        `yaml:"password"`
	DB           int           `yaml:"db"`
	Enabled      bool          `yaml:"enabled"`
	QueueKey     string        `yaml:"queue_key"`
	DialTimeout  time.Duration `yaml:"dial_timeout"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

type SchedulerConfig struct {
	LeaseTTL             time.Duration `yaml:"lease_ttl"`
	MaxRetries           int           `yaml:"max_retries"`
	HeartbeatTimeout     time.Duration `yaml:"heartbeat_timeout"`
	QueueCapacity        int           `yaml:"queue_capacity"`
	LeasePollInterval    time.Duration `yaml:"lease_poll_interval"`
	MaxAgentConcurrency  int           `yaml:"max_agent_concurrency"`
	GlobalMaxConcurrency int           `yaml:"global_max_concurrency"`
	ResultRetention      time.Duration `yaml:"result_retention"`
	BASMaxConcurrency    int           `yaml:"bas_max_concurrency"`
}

type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

type AuditConfig struct {
	Enabled   bool   `yaml:"enabled"`
	LogPath   string `yaml:"log_path"`
	StorePath string `yaml:"store_path"`
}

type AlertsConfig struct {
	Enabled          bool   `yaml:"enabled"`
	Channel          string `yaml:"channel"`
	NotifyBASFailure bool   `yaml:"notify_bas_failure"`
	NotifyFallback   bool   `yaml:"notify_sandbox_fallback"`
}

type TemplateConfig struct {
	PersistPath string `yaml:"persist_path"`
}

type BASConfig struct {
	ScenarioPersistPath      string            `yaml:"scenario_persist_path"`
	DefaultNetworkBoundaries []string          `yaml:"default_network_boundaries"`
	DefaultResourceLimits    BASResourceLimits `yaml:"default_resource_limits"`
}

type BASResourceLimits struct {
	MaxTargets         int `yaml:"max_targets"`
	MaxParallelSteps   int `yaml:"max_parallel_steps"`
	MaxDurationMinutes int `yaml:"max_duration_minutes"`
	MaxCPUPercent      int `yaml:"max_cpu_percent"`
}

type TaskCatalogConfig struct {
	PersistPath string `yaml:"persist_path"`
}

type ReportConfig struct {
	TemplatePath string `yaml:"template_path"`
}

type RBACConfig struct {
	Policies []RBACPolicy `yaml:"policies"`
}

type RBACPolicy struct {
	Role        string   `yaml:"role"`
	Permissions []string `yaml:"permissions"`
}

type SearchConfig struct {
	Enabled   bool          `yaml:"enabled"`
	Addresses []string      `yaml:"addresses"`
	Username  string        `yaml:"username"`
	Password  string        `yaml:"password"`
	Index     string        `yaml:"index"`
	Timeout   time.Duration `yaml:"timeout"`
}

// Default returns a Config populated with sensible defaults.
func Default() Config {
	return Config{
		Server: ServerConfig{
			HTTPAddr: ":8080",
			GRPCAddr: ":9090",
			TLS: TLSConfig{
				Enabled:  false,
				CertFile: "",
				KeyFile:  "",
			},
		},
		Security: SecurityConfig{
			AgentToken: "changeme",
			APIKeys:    []string{"changeme"},
		},
		Database: DatabaseConfig{
			DSN:          "",
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			InMemory:     true,
		},
		Redis: RedisConfig{
			Addr:         "localhost:6379",
			DB:           0,
			Enabled:      false,
			QueueKey:     "d-eyes:task-queue",
			DialTimeout:  5 * time.Second,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		Scheduler: SchedulerConfig{
			LeaseTTL:             2 * time.Minute,
			MaxRetries:           3,
			HeartbeatTimeout:     15 * time.Second,
			QueueCapacity:        1024,
			LeasePollInterval:    5 * time.Second,
			MaxAgentConcurrency:  2,
			GlobalMaxConcurrency: 0,
			ResultRetention:      24 * time.Hour,
			BASMaxConcurrency:    1,
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Path:    "/metrics",
		},
		Audit: AuditConfig{
			Enabled:   false,
			LogPath:   "",
			StorePath: "",
		},
		Alerts: AlertsConfig{
			Enabled:          false,
			Channel:          "log",
			NotifyBASFailure: true,
			NotifyFallback:   true,
		},
		Templates: TemplateConfig{
			PersistPath: "",
		},
		TaskCatalog: TaskCatalogConfig{
			PersistPath: "",
		},
		BAS: BASConfig{
			ScenarioPersistPath:      "",
			DefaultNetworkBoundaries: []string{"dmz"},
			DefaultResourceLimits: BASResourceLimits{
				MaxTargets:         64,
				MaxParallelSteps:   2,
				MaxDurationMinutes: 60,
				MaxCPUPercent:      80,
			},
		},
		Search: SearchConfig{
			Enabled:   false,
			Addresses: []string{"http://127.0.0.1:9200"},
			Index:     "d-eyes-task-results",
			Timeout:   5 * time.Second,
		},
		RBAC: RBACConfig{
			Policies: []RBACPolicy{
				{Role: "operator", Permissions: []string{"tasks.view", "reports.view", "audit.view"}},
				{Role: "auditor", Permissions: []string{"audit.view", "reports.view"}},
				{Role: "admin", Permissions: []string{"*"}},
			},
		},
		Reports: ReportConfig{
			TemplatePath: "",
		},
	}
}

// Load reads configuration from the provided file path. If path is empty, defaults are returned.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config file: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("unmarshal config yaml: %w", err)
	}
	applyEnvOverrides(&cfg)
	return cfg, nil
}

// applyEnvOverrides allows overriding sensitive values from environment variables.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("D_EYES_SERVER_HTTP_ADDR"); v != "" {
		cfg.Server.HTTPAddr = v
	}
	if v := os.Getenv("D_EYES_SERVER_GRPC_ADDR"); v != "" {
		cfg.Server.GRPCAddr = v
	}
	if v := os.Getenv("D_EYES_SERVER_AGENT_TOKEN"); v != "" {
		cfg.Security.AgentToken = v
	}
	if v := os.Getenv("D_EYES_SERVER_DSN"); v != "" {
		cfg.Database.DSN = v
		cfg.Database.InMemory = false
	}
	if v := os.Getenv("D_EYES_SERVER_REDIS_ADDR"); v != "" {
		cfg.Redis.Enabled = true
		cfg.Redis.Addr = v
	}
	if v := os.Getenv("D_EYES_SERVER_REDIS_PASSWORD"); v != "" {
		cfg.Redis.Password = v
	}
	if v := os.Getenv("D_EYES_SERVER_REDIS_DB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Redis.DB = n
		}
	}
	if v := os.Getenv("D_EYES_SERVER_REDIS_QUEUE"); v != "" {
		cfg.Redis.QueueKey = v
	}
	if v := os.Getenv("D_EYES_SERVER_SEARCH_ADDR"); v != "" {
		cfg.Search.Enabled = true
		cfg.Search.Addresses = []string{v}
	}
	if v := os.Getenv("D_EYES_SERVER_SEARCH_INDEX"); v != "" {
		cfg.Search.Index = v
	}
	if v := os.Getenv("D_EYES_SERVER_BAS_MAX_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.Scheduler.BASMaxConcurrency = n
		}
	}
	if v := os.Getenv("D_EYES_SERVER_AUDIT_LOG"); v != "" {
		cfg.Audit.Enabled = true
		cfg.Audit.LogPath = v
	}
	if v := os.Getenv("D_EYES_SERVER_ALERTS_CHANNEL"); v != "" {
		cfg.Alerts.Enabled = true
		cfg.Alerts.Channel = v
	}
	if v := os.Getenv("D_EYES_SERVER_TEMPLATES_PATH"); v != "" {
		cfg.Templates.PersistPath = v
	}
	if v := os.Getenv("D_EYES_BAS_SCENARIO_PATH"); v != "" {
		cfg.BAS.ScenarioPersistPath = v
	}
	if v := os.Getenv("D_EYES_REPORT_TEMPLATE_PATH"); v != "" {
		cfg.Reports.TemplatePath = v
	}
	if v := os.Getenv("D_EYES_AUDIT_STORE_PATH"); v != "" {
		cfg.Audit.StorePath = v
	}
}

// Validate ensures required fields are present.
func (c Config) Validate() error {
	if c.Security.AgentToken == "" {
		return errors.New("security.agent_token must be set")
	}
	if !c.Database.InMemory && c.Database.DSN == "" {
		return errors.New("database.dsn must be set when in_memory=false")
	}
	if c.Audit.Enabled && strings.TrimSpace(c.Audit.LogPath) == "" {
		return errors.New("audit.log_path must be set when audit enabled")
	}
	return nil
}
