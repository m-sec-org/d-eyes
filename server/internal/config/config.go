package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Config captures all runtime configuration for the server process.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Security  SecurityConfig  `yaml:"security"`
	Database  DatabaseConfig  `yaml:"database"`
	Redis     RedisConfig     `yaml:"redis"`
	Scheduler SchedulerConfig `yaml:"scheduler"`
	Metrics   MetricsConfig   `yaml:"metrics"`
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
	LeaseTTL          time.Duration `yaml:"lease_ttl"`
	MaxRetries        int           `yaml:"max_retries"`
	HeartbeatTimeout  time.Duration `yaml:"heartbeat_timeout"`
	QueueCapacity     int           `yaml:"queue_capacity"`
	LeasePollInterval time.Duration `yaml:"lease_poll_interval"`
}

type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
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
			LeaseTTL:          2 * time.Minute,
			MaxRetries:        3,
			HeartbeatTimeout:  15 * time.Second,
			QueueCapacity:     1024,
			LeasePollInterval: 5 * time.Second,
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Path:    "/metrics",
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
}

// Validate ensures required fields are present.
func (c Config) Validate() error {
	if c.Security.AgentToken == "" {
		return errors.New("security.agent_token must be set")
	}
	if !c.Database.InMemory && c.Database.DSN == "" {
		return errors.New("database.dsn must be set when in_memory=false")
	}
	return nil
}
