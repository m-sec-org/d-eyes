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
	Server      ServerConfig           `yaml:"server"`
	Security    SecurityConfig         `yaml:"security"`
	Database    DatabaseConfig         `yaml:"database"`
	Redis       RedisConfig            `yaml:"redis"`
	Scheduler   SchedulerConfig        `yaml:"scheduler"`
	Search      SearchConfig           `yaml:"search"`
	Metrics     MetricsConfig          `yaml:"metrics"`
	Events      EventsConfig           `yaml:"events"`
	Audit       AuditConfig            `yaml:"audit"`
	Alerts      AlertsConfig           `yaml:"alerts"`
	Templates   TemplateConfig         `yaml:"templates"`
	TaskCatalog TaskCatalogConfig      `yaml:"task_catalog"`
	Collectors  CollectorControlConfig `yaml:"collectors"`
	BAS         BASConfig              `yaml:"bas"`
	RBAC        RBACConfig             `yaml:"rbac"`
	Reports     ReportConfig           `yaml:"reports"`
	Artifact    ArtifactConfig         `yaml:"artifact"`
	ThreatIntel ThreatIntelConfig      `yaml:"threat_intel"`
	Behavior    BehaviorConfig         `yaml:"behavior"`
	Playbook    PlaybookConfig         `yaml:"playbook"`
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
	AgentToken string    `yaml:"agent_token"`
	APIKeys    []string  `yaml:"api_keys"`
	PKI        PKIConfig `yaml:"pki"`
	MFA        MFAConfig `yaml:"mfa"`
}

type PKIConfig struct {
	Enabled           bool          `yaml:"enabled"`
	StorageDir        string        `yaml:"storage_dir"`
	CommonName        string        `yaml:"common_name"`
	Organization      string        `yaml:"organization"`
	ServerDNSNames    []string      `yaml:"server_dns_names"`
	ServerIPs         []string      `yaml:"server_ips"`
	ServerCertTTL     time.Duration `yaml:"server_cert_ttl"`
	AgentCertTTL      time.Duration `yaml:"agent_cert_ttl"`
	RequireClientCert bool          `yaml:"require_client_cert"`
}

type MFAConfig struct {
	Enabled       bool              `yaml:"enabled"`
	Header        string            `yaml:"header"`
	RequiredRoles []string          `yaml:"required_roles"`
	Secrets       map[string]string `yaml:"secrets"`
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
	SelfHealInterval     time.Duration `yaml:"self_heal_interval"`
	SelfHealBatch        int           `yaml:"self_heal_batch"`
}

type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

type CollectorControlConfig struct {
	AllowedProviders      []string      `yaml:"allowed_providers"`
	AllowedProbes         []string      `yaml:"allowed_probes"`
	HeartbeatLagThreshold time.Duration `yaml:"heartbeat_lag_threshold"`
	RolloutGracePeriod    time.Duration `yaml:"rollout_grace_period"`
}
type EventsConfig struct {
	Enabled         bool                                `yaml:"enabled"`
	QueueCapacity   int                                 `yaml:"queue_capacity"`
	MaxBatch        int                                 `yaml:"max_batch"`
	FlushInterval   time.Duration                       `yaml:"flush_interval"`
	MaxPayloadSize  int64                               `yaml:"max_payload_size"`
	DefaultPriority string                              `yaml:"default_priority"`
	PriorityQueues  map[string]EventPriorityQueueConfig `yaml:"priority_queues"`
	Retention       EventRetentionConfig                `yaml:"retention"`
	Parsers         []EventParserConfig                 `yaml:"parsers"`
	Detection       DetectionConfig                     `yaml:"detection"`
}

type EventPriorityQueueConfig struct {
	QueueCapacity         int           `yaml:"queue_capacity"`
	MaxBatch              int           `yaml:"max_batch"`
	Spillover             string        `yaml:"spillover"`
	DropPolicy            string        `yaml:"drop_policy"`
	BackpressureThreshold float64       `yaml:"backpressure_threshold"`
	AlertCooldown         time.Duration `yaml:"alert_cooldown"`
}

type EventRetentionConfig struct {
	Hot  time.Duration `yaml:"hot"`
	Warm time.Duration `yaml:"warm"`
	Cold time.Duration `yaml:"cold"`
}

type EventParserConfig struct {
	Name             string   `yaml:"name"`
	Enabled          bool     `yaml:"enabled"`
	EventTypes       []string `yaml:"event_types"`
	Sources          []string `yaml:"sources"`
	CollectorKinds   []string `yaml:"collector_kinds"`
	RequiredPayload  []string `yaml:"required_payload"`
	RequiredMetadata []string `yaml:"required_metadata"`
	RequiredTags     []string `yaml:"required_tags"`
	StrictPayload    bool     `yaml:"strict_payload"`
}

type DetectionConfig struct {
	Enabled     bool                       `yaml:"enabled"`
	MaxWorkers  int                        `yaml:"max_workers"`
	QueueSize   int                        `yaml:"queue_size"`
	Rules       []DetectionRuleConfig      `yaml:"rules"`
	MLModels    []DetectionMLModelConfig   `yaml:"ml_models"`
	AutoRespond DetectionAutoRespondConfig `yaml:"auto_respond"`
	StreamEvent bool                       `yaml:"stream_events"`
}

type DetectionAutoRespondConfig struct {
	Enabled         bool              `yaml:"enabled"`
	DefaultProfile  string            `yaml:"default_profile"`
	DefaultPriority int               `yaml:"default_priority"`
	CreatedBy       string            `yaml:"created_by"`
	Metadata        map[string]string `yaml:"metadata"`
}

type DetectionRuleConfig struct {
	Name                string            `yaml:"name"`
	Description         string            `yaml:"description"`
	Enabled             bool              `yaml:"enabled"`
	Severity            string            `yaml:"severity"`
	EventTypes          []string          `yaml:"event_types"`
	Sources             []string          `yaml:"sources"`
	Metadata            map[string]string `yaml:"metadata"`
	Tags                map[string]string `yaml:"tags"`
	PayloadContains     []string          `yaml:"payload_contains"`
	Indicators          []string          `yaml:"indicators"`
	AutoRespondProfile  string            `yaml:"auto_respond_profile"`
	AutoRespondPriority int               `yaml:"auto_respond_priority"`
	SubmitToThreatIntel bool              `yaml:"submit_to_threat_intel"`
	RespondMetadata     map[string]string `yaml:"respond_metadata"`
}

type DetectionMLModelConfig struct {
	Name                string             `yaml:"name"`
	Enabled             bool               `yaml:"enabled"`
	Severity            string             `yaml:"severity"`
	Threshold           float64            `yaml:"threshold"`
	FeatureWeights      map[string]float64 `yaml:"feature_weights"`
	AutoRespondProfile  string             `yaml:"auto_respond_profile"`
	AutoRespondPriority int                `yaml:"auto_respond_priority"`
	SubmitToThreatIntel bool               `yaml:"submit_to_threat_intel"`
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
	DefaultNetworkBoundaries []string          `yaml:"default_network_boundaries"`
	DefaultResourceLimits    BASResourceLimits `yaml:"default_resource_limits"`
	DefaultExecutionPlan     BASExecutionPlan  `yaml:"default_execution_plan"`
	DefaultApprovalPolicy    []BASApprovalRule `yaml:"default_approval_policy"`
	CacheTTL                 time.Duration     `yaml:"cache_ttl"`
}

type BASResourceLimits struct {
	MaxTargets         int `yaml:"max_targets"`
	MaxParallelSteps   int `yaml:"max_parallel_steps"`
	MaxDurationMinutes int `yaml:"max_duration_minutes"`
	MaxCPUPercent      int `yaml:"max_cpu_percent"`
}

type BASExecutionPlan struct {
	Mode               string `yaml:"mode"`
	MaxParallel        int    `yaml:"max_parallel"`
	RetryLimit         int    `yaml:"retry_limit"`
	StepTimeoutSeconds int    `yaml:"step_timeout_seconds"`
	CrossAgent         bool   `yaml:"cross_agent"`
}

type BASApprovalRule struct {
	Role           string `yaml:"role"`
	TimeoutSeconds int    `yaml:"timeout_seconds"`
}

type TaskCatalogConfig struct {
	PersistPath string `yaml:"persist_path"`
}

type ReportConfig struct {
	TemplatePath string `yaml:"template_path"`
}

type ArtifactConfig struct {
	StorageDir string        `yaml:"storage_dir"`
	UploadTTL  time.Duration `yaml:"upload_ttl"`
	MaxSize    int64         `yaml:"max_size_bytes"`
}

type ThreatIntelConfig struct {
	Enabled             bool          `yaml:"enabled"`
	WorkerConcurrency   int           `yaml:"worker_concurrency"`
	QueuePollInterval   time.Duration `yaml:"queue_poll_interval"`
	MaxAttempts         int           `yaml:"max_attempts"`
	RetryBackoff        time.Duration `yaml:"retry_backoff"`
	VerdictTTL          time.Duration `yaml:"verdict_ttl"`
	OpenTIPAPIKey       string        `yaml:"opentip_api_key"`
	OpenTIPBaseURL      string        `yaml:"opentip_base_url"`
	MetaDefenderAPIKey  string        `yaml:"metadefender_api_key"`
	MetaDefenderBaseURL string        `yaml:"metadefender_base_url"`
}

type BehaviorConfig struct {
	Enabled             bool                `yaml:"enabled"`
	HeartbeatStream     string              `yaml:"heartbeat_stream"`
	EventStream         string              `yaml:"event_stream"`
	AnomalyCPUThreshold float64             `yaml:"anomaly_cpu_threshold"`
	Graph               BehaviorGraphConfig `yaml:"graph"`
}

type BehaviorGraphConfig struct {
	Enabled                  bool          `yaml:"enabled"`
	Window                   time.Duration `yaml:"window"`
	SampleRate               float64       `yaml:"sample_rate"`
	MaxBatch                 int           `yaml:"max_batch"`
	RedisGroup               string        `yaml:"redis_group"`
	RedisConsumer            string        `yaml:"redis_consumer"`
	FlushInterval            time.Duration `yaml:"flush_interval"`
	CPUScoreWeight           float64       `yaml:"cpu_score_weight"`
	BlockedActionWeight      float64       `yaml:"blocked_action_weight"`
	ConnectionBurstThreshold int           `yaml:"connection_burst_threshold"`
	ResourceAnomalyWeight    float64       `yaml:"resource_anomaly_weight"`
	ConnectionAnomalyWeight  float64       `yaml:"connection_anomaly_weight"`
	UserSessionAnomalyWeight float64       `yaml:"user_session_anomaly_weight"`
}

type PlaybookConfig struct {
	Enabled           bool          `yaml:"enabled"`
	WorkerConcurrency int           `yaml:"worker_concurrency"`
	ApprovalTimeout   time.Duration `yaml:"approval_timeout"`
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
			PKI: PKIConfig{
				Enabled:           false,
				StorageDir:        "./tmp/pki",
				CommonName:        "d-eyes.local",
				Organization:      "d-eyes",
				ServerDNSNames:    []string{"localhost"},
				ServerCertTTL:     90 * 24 * time.Hour,
				AgentCertTTL:      30 * 24 * time.Hour,
				RequireClientCert: false,
			},
			MFA: MFAConfig{
				Enabled:       false,
				Header:        "X-MFA-Code",
				RequiredRoles: []string{"admin"},
				Secrets:       map[string]string{},
			},
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
			SelfHealInterval:     time.Minute,
			SelfHealBatch:        200,
		},
		Events: EventsConfig{
			Enabled:         true,
			QueueCapacity:   8192,
			MaxBatch:        512,
			FlushInterval:   50 * time.Millisecond,
			MaxPayloadSize:  4 * 1024 * 1024, // 4 MiB
			DefaultPriority: "normal",
			PriorityQueues: map[string]EventPriorityQueueConfig{
				"high":   {QueueCapacity: 2048, MaxBatch: 256},
				"normal": {QueueCapacity: 4096, MaxBatch: 512},
				"low":    {QueueCapacity: 2048, MaxBatch: 256},
			},
			Retention: EventRetentionConfig{
				Hot:  7 * 24 * time.Hour,
				Warm: 30 * 24 * time.Hour,
				Cold: 180 * 24 * time.Hour,
			},
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
			DefaultNetworkBoundaries: []string{"dmz"},
			DefaultResourceLimits: BASResourceLimits{
				MaxTargets:         64,
				MaxParallelSteps:   2,
				MaxDurationMinutes: 60,
				MaxCPUPercent:      80,
			},
			DefaultExecutionPlan: BASExecutionPlan{
				Mode:               "serial",
				MaxParallel:        1,
				RetryLimit:         1,
				StepTimeoutSeconds: 300,
				CrossAgent:         false,
			},
			DefaultApprovalPolicy: []BASApprovalRule{
				{Role: "admin", TimeoutSeconds: 3600},
			},
			CacheTTL: 30 * time.Second,
		},
		Search: SearchConfig{
			Enabled:   false,
			Addresses: []string{"http://127.0.0.1:9200"},
			Index:     "d-eyes-task-results",
			Timeout:   5 * time.Second,
		},
		RBAC: RBACConfig{
			Policies: []RBACPolicy{
				{Role: "operator", Permissions: []string{"tasks.read", "tasks.create", "tasks.retry", "tasks.cancel", "tasks.actions", "reports.view", "audit.view", "playbook.execute", "bas.view", "collector.status.read", "events.read"}},
				{Role: "sre", Permissions: []string{"collector.config.read", "collector.config.write", "collector.status.read", "collector.status.write", "events.read"}},
				{Role: "auditor", Permissions: []string{"audit.view", "reports.view", "playbook.execute", "collector.status.read", "events.read"}},
				{Role: "admin", Permissions: []string{"*"}},
			},
		},
		Collectors: CollectorControlConfig{
			AllowedProviders:      []string{"Kernel", "Security"},
			AllowedProbes:         []string{"diag-ebpf", "diag-sysmon"},
			HeartbeatLagThreshold: 30 * time.Second,
			RolloutGracePeriod:    2 * time.Minute,
		},
		Reports: ReportConfig{
			TemplatePath: "",
		},
		Artifact: ArtifactConfig{
			StorageDir: "./tmp/artifacts",
			UploadTTL:  15 * time.Minute,
			MaxSize:    25 * 1024 * 1024,
		},
		ThreatIntel: ThreatIntelConfig{
			Enabled:             false,
			WorkerConcurrency:   2,
			QueuePollInterval:   5 * time.Second,
			MaxAttempts:         3,
			RetryBackoff:        30 * time.Second,
			VerdictTTL:          24 * time.Hour,
			OpenTIPBaseURL:      "https://opentip.kaspersky.com/api/v1",
			MetaDefenderBaseURL: "https://api.metadefender.com/v4",
		},
		Behavior: BehaviorConfig{
			Enabled:             false,
			HeartbeatStream:     "behavior.heartbeats",
			EventStream:         "behavior.events",
			AnomalyCPUThreshold: 90,
			Graph: BehaviorGraphConfig{
				Enabled:                  true,
				Window:                   5 * time.Minute,
				SampleRate:               1.0,
				MaxBatch:                 256,
				RedisGroup:               "behavior-graph",
				RedisConsumer:            "behavior-graph-consumer",
				FlushInterval:            5 * time.Second,
				CPUScoreWeight:           0.4,
				BlockedActionWeight:      0.2,
				ConnectionBurstThreshold: 25,
				ResourceAnomalyWeight:    0.2,
				ConnectionAnomalyWeight:  0.15,
				UserSessionAnomalyWeight: 0.05,
			},
		},
		Playbook: PlaybookConfig{
			Enabled:           false,
			WorkerConcurrency: 2,
			ApprovalTimeout:   30 * time.Minute,
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
	if v := os.Getenv("D_EYES_BAS_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 0 {
			cfg.BAS.CacheTTL = d
		}
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
	if v := os.Getenv("D_EYES_REPORT_TEMPLATE_PATH"); v != "" {
		cfg.Reports.TemplatePath = v
	}
	if v := os.Getenv("D_EYES_AUDIT_STORE_PATH"); v != "" {
		cfg.Audit.StorePath = v
	}
	if v := os.Getenv("D_EYES_ARTIFACT_DIR"); v != "" {
		cfg.Artifact.StorageDir = v
	}
	if v := os.Getenv("D_EYES_ARTIFACT_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Artifact.UploadTTL = d
		}
	}
	if v := os.Getenv("D_EYES_ARTIFACT_MAX_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			cfg.Artifact.MaxSize = n
		}
	}
	if v := os.Getenv("D_EYES_MFA_ENABLED"); v != "" {
		cfg.Security.MFA.Enabled = strings.EqualFold(v, "true") || v == "1"
	}
	if v := os.Getenv("D_EYES_MFA_HEADER"); v != "" {
		cfg.Security.MFA.Header = strings.TrimSpace(v)
	}
	if v := os.Getenv("D_EYES_MFA_REQUIRED_ROLES"); v != "" {
		parts := strings.Split(v, ",")
		cfg.Security.MFA.RequiredRoles = cfg.Security.MFA.RequiredRoles[:0]
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				cfg.Security.MFA.RequiredRoles = append(cfg.Security.MFA.RequiredRoles, trimmed)
			}
		}
	}
	if v := os.Getenv("D_EYES_MFA_SECRETS"); v != "" {
		if cfg.Security.MFA.Secrets == nil {
			cfg.Security.MFA.Secrets = make(map[string]string)
		}
		for _, pair := range strings.Split(v, ",") {
			if pair = strings.TrimSpace(pair); pair == "" {
				continue
			}
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(parts[0]))
			secret := strings.TrimSpace(parts[1])
			if key != "" && secret != "" {
				cfg.Security.MFA.Secrets[key] = secret
			}
		}
	}
	if v := os.Getenv("D_EYES_PKI_ENABLED"); v != "" {
		cfg.Security.PKI.Enabled = strings.EqualFold(v, "true") || v == "1"
	}
	if v := os.Getenv("D_EYES_PKI_DIR"); v != "" {
		cfg.Security.PKI.StorageDir = strings.TrimSpace(v)
	}
	if v := os.Getenv("D_EYES_PKI_COMMON_NAME"); v != "" {
		cfg.Security.PKI.CommonName = strings.TrimSpace(v)
	}
	if v := os.Getenv("D_EYES_PKI_ORG"); v != "" {
		cfg.Security.PKI.Organization = strings.TrimSpace(v)
	}
	if v := os.Getenv("D_EYES_PKI_SERVER_DNS"); v != "" {
		parts := strings.Split(v, ",")
		cfg.Security.PKI.ServerDNSNames = cfg.Security.PKI.ServerDNSNames[:0]
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				cfg.Security.PKI.ServerDNSNames = append(cfg.Security.PKI.ServerDNSNames, trimmed)
			}
		}
	}
	if v := os.Getenv("D_EYES_PKI_SERVER_IPS"); v != "" {
		parts := strings.Split(v, ",")
		cfg.Security.PKI.ServerIPs = cfg.Security.PKI.ServerIPs[:0]
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				cfg.Security.PKI.ServerIPs = append(cfg.Security.PKI.ServerIPs, trimmed)
			}
		}
	}
	if v := os.Getenv("D_EYES_PKI_REQUIRE_CLIENT_CERT"); v != "" {
		cfg.Security.PKI.RequireClientCert = strings.EqualFold(v, "true") || v == "1"
	}
	if v := os.Getenv("D_EYES_PKI_SERVER_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.Security.PKI.ServerCertTTL = d
		}
	}
	if v := os.Getenv("D_EYES_PKI_AGENT_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.Security.PKI.AgentCertTTL = d
		}
	}
	if v := os.Getenv("D_EYES_TI_ENABLED"); v != "" {
		cfg.ThreatIntel.Enabled = strings.EqualFold(v, "true") || v == "1"
	}
	if v := os.Getenv("D_EYES_TI_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.ThreatIntel.WorkerConcurrency = n
		}
	}
	if v := os.Getenv("D_EYES_TI_QUEUE_POLL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.ThreatIntel.QueuePollInterval = d
		}
	}
	if v := os.Getenv("D_EYES_TI_MAX_ATTEMPTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.ThreatIntel.MaxAttempts = n
		}
	}
	if v := os.Getenv("D_EYES_TI_RETRY_BACKOFF"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.ThreatIntel.RetryBackoff = d
		}
	}
	if v := os.Getenv("D_EYES_TI_VERDICT_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.ThreatIntel.VerdictTTL = d
		}
	}
	if v := os.Getenv("D_EYES_TI_OPENTIP_API_KEY"); v != "" {
		cfg.ThreatIntel.OpenTIPAPIKey = v
	}
	if v := os.Getenv("D_EYES_TI_OPENTIP_BASE_URL"); v != "" {
		cfg.ThreatIntel.OpenTIPBaseURL = strings.TrimRight(strings.TrimSpace(v), "/")
	}
	if v := os.Getenv("D_EYES_TI_METADEFENDER_API_KEY"); v != "" {
		cfg.ThreatIntel.MetaDefenderAPIKey = v
	}
	if v := os.Getenv("D_EYES_TI_METADEFENDER_BASE_URL"); v != "" {
		cfg.ThreatIntel.MetaDefenderBaseURL = strings.TrimRight(strings.TrimSpace(v), "/")
	}
	if v := os.Getenv("D_EYES_BEHAVIOR_CPU_THRESHOLD"); v != "" {
		if pct, err := strconv.ParseFloat(v, 64); err == nil && pct > 0 {
			cfg.Behavior.AnomalyCPUThreshold = pct
		}
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
	if strings.TrimSpace(c.Artifact.StorageDir) == "" {
		return errors.New("artifact.storage_dir must be set")
	}
	if c.Artifact.UploadTTL <= 0 {
		return errors.New("artifact.upload_ttl must be positive")
	}
	if c.Artifact.MaxSize <= 0 {
		return errors.New("artifact.max_size_bytes must be positive")
	}
	mode := strings.ToLower(strings.TrimSpace(c.BAS.DefaultExecutionPlan.Mode))
	if mode != "serial" && mode != "parallel" {
		return errors.New("bas.default_execution_plan.mode must be serial or parallel")
	}
	if mode == "parallel" && c.BAS.DefaultExecutionPlan.MaxParallel <= 0 {
		return errors.New("bas.default_execution_plan.max_parallel must be > 0 for parallel mode")
	}
	if c.BAS.CacheTTL < 0 {
		return errors.New("bas.cache_ttl must be >= 0")
	}
	if c.Security.PKI.Enabled {
		if strings.TrimSpace(c.Security.PKI.StorageDir) == "" {
			return errors.New("security.pki.storage_dir must be set when pki enabled")
		}
		if c.Security.PKI.ServerCertTTL <= 0 {
			return errors.New("security.pki.server_cert_ttl must be positive")
		}
		if c.Security.PKI.AgentCertTTL <= 0 {
			return errors.New("security.pki.agent_cert_ttl must be positive")
		}
		if len(c.Security.PKI.ServerDNSNames) == 0 {
			return errors.New("security.pki.server_dns_names must have at least one entry")
		}
	}
	if c.Security.MFA.Enabled {
		if strings.TrimSpace(c.Security.MFA.Header) == "" {
			return errors.New("security.mfa.header must be set when mfa enabled")
		}
		if len(c.Security.MFA.RequiredRoles) == 0 {
			return errors.New("security.mfa.required_roles must include at least one role when mfa enabled")
		}
		if len(c.Security.MFA.Secrets) == 0 {
			return errors.New("security.mfa.secrets must include at least one entry when mfa enabled")
		}
	}
	for i, provider := range c.Collectors.AllowedProviders {
		c.Collectors.AllowedProviders[i] = strings.TrimSpace(provider)
	}
	for i, probe := range c.Collectors.AllowedProbes {
		c.Collectors.AllowedProbes[i] = strings.TrimSpace(probe)
	}
	if c.Collectors.HeartbeatLagThreshold <= 0 {
		c.Collectors.HeartbeatLagThreshold = 30 * time.Second
	}
	if c.Collectors.RolloutGracePeriod <= 0 {
		c.Collectors.RolloutGracePeriod = time.Minute
	}
	if c.Events.Enabled {
		if c.Events.QueueCapacity <= 0 {
			return errors.New("events.queue_capacity must be positive")
		}
		if c.Events.MaxBatch <= 0 {
			return errors.New("events.max_batch must be positive")
		}
		if c.Events.FlushInterval <= 0 {
			return errors.New("events.flush_interval must be positive")
		}
		if c.Events.MaxPayloadSize <= 0 {
			return errors.New("events.max_payload_size must be positive")
		}
		if c.Events.DefaultPriority == "" {
			c.Events.DefaultPriority = "normal"
		}
		if len(c.Events.PriorityQueues) == 0 {
			c.Events.PriorityQueues = map[string]EventPriorityQueueConfig{
				c.Events.DefaultPriority: {
					QueueCapacity: c.Events.QueueCapacity,
					MaxBatch:      c.Events.MaxBatch,
				},
			}
		}
		if _, ok := c.Events.PriorityQueues[c.Events.DefaultPriority]; !ok {
			c.Events.PriorityQueues[c.Events.DefaultPriority] = EventPriorityQueueConfig{
				QueueCapacity: c.Events.QueueCapacity,
				MaxBatch:      c.Events.MaxBatch,
			}
		}
		normalized := make(map[string]EventPriorityQueueConfig, len(c.Events.PriorityQueues))
		for name, lane := range c.Events.PriorityQueues {
			trimmed := strings.ToLower(strings.TrimSpace(name))
			if trimmed == "" {
				return fmt.Errorf("events.priority_queues contains empty name")
			}
			if lane.QueueCapacity <= 0 {
				return fmt.Errorf("events.priority_queues[%s].queue_capacity must be positive", name)
			}
			if lane.MaxBatch <= 0 {
				return fmt.Errorf("events.priority_queues[%s].max_batch must be positive", name)
			}
			normalized[trimmed] = lane
		}
		c.Events.PriorityQueues = normalized
		c.Events.DefaultPriority = strings.ToLower(strings.TrimSpace(c.Events.DefaultPriority))
		if _, ok := c.Events.PriorityQueues[c.Events.DefaultPriority]; !ok {
			return fmt.Errorf("events.default_priority %q not defined in priority_queues", c.Events.DefaultPriority)
		}
		if c.Events.Retention.Hot <= 0 || c.Events.Retention.Warm <= 0 || c.Events.Retention.Cold <= 0 {
			return errors.New("events.retention hot/warm/cold must be positive durations")
		}
		if c.Events.Retention.Hot > c.Events.Retention.Warm || c.Events.Retention.Warm > c.Events.Retention.Cold {
			return errors.New("events.retention must satisfy hot <= warm <= cold")
		}
		if c.Events.Detection.Enabled {
			if c.Events.Detection.MaxWorkers <= 0 {
				c.Events.Detection.MaxWorkers = 4
			}
			if c.Events.Detection.QueueSize <= 0 {
				c.Events.Detection.QueueSize = 1024
			}
			if c.Events.Detection.AutoRespond.Enabled {
				if strings.TrimSpace(c.Events.Detection.AutoRespond.DefaultProfile) == "" {
					c.Events.Detection.AutoRespond.DefaultProfile = "respond_profile_v1"
				}
				if c.Events.Detection.AutoRespond.DefaultPriority <= 0 {
					c.Events.Detection.AutoRespond.DefaultPriority = 1
				}
				if strings.TrimSpace(c.Events.Detection.AutoRespond.CreatedBy) == "" {
					c.Events.Detection.AutoRespond.CreatedBy = "detection-engine"
				}
			}
			seenRules := make(map[string]struct{})
			for _, rule := range c.Events.Detection.Rules {
				name := strings.ToLower(strings.TrimSpace(rule.Name))
				if name == "" {
					return errors.New("events.detection.rules name must be set")
				}
				if _, exists := seenRules[name]; exists {
					return fmt.Errorf("events.detection.rules contains duplicate name %q", rule.Name)
				}
				seenRules[name] = struct{}{}
			}
			seenModels := make(map[string]struct{})
			for _, model := range c.Events.Detection.MLModels {
				name := strings.ToLower(strings.TrimSpace(model.Name))
				if name == "" {
					return errors.New("events.detection.ml_models name must be set")
				}
				if model.Threshold <= 0 {
					return fmt.Errorf("events.detection.ml_models[%s].threshold must be positive", model.Name)
				}
				if _, exists := seenModels[name]; exists {
					return fmt.Errorf("events.detection.ml_models contains duplicate name %q", model.Name)
				}
				seenModels[name] = struct{}{}
			}
		}
	}
	return nil
}
