package remote

import (
	"time"
)

// RemoteConfig 定义 Agent 在连接 Server 时所需的配置。
type RemoteConfig struct {
	ServerGRPCAddr    string        `yaml:"server_grpc_addr"`
	AgentToken        string        `yaml:"agent_token"`
	AgentName         string        `yaml:"agent_name"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	TaskPollInterval  time.Duration `yaml:"task_poll_interval"`
	CacheDir          string        `yaml:"cache_dir"`
	TLS               TLSConfig     `yaml:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
}
