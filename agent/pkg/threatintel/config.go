package threatintel

import (
	"strings"
	"time"
)

// Mode 表示威胁情报运行模式。
type Mode string

const (
	// ModeAuto 自动根据配置选择执行策略。
	ModeAuto Mode = "auto"
	// ModeLocal 仅使用本地启发式。
	ModeLocal Mode = "local"
	// ModeHybrid 同时使用本地与外部数据源。
	ModeHybrid Mode = "hybrid"
	// ModeServer 完全依赖 Server 侧情报（Agent 不主动查询）。
	ModeServer Mode = "server"
)

// Config 控制威胁情报组件行为。
type Config struct {
	Mode                 Mode
	CacheTTL             time.Duration
	CacheSize            int
	CacheDir             string
	HTTPTimeout          time.Duration
	MaxParallelPerSource int
	OpenTIPAPIKey        string
	OpenTIPBaseURL       string
	MetaDefenderAPIKey   string
	MetaDefenderBaseURL  string
}

// 默认情报接口地址，用于避免硬编码 Magic String。
const (
	DefaultOpenTIPBaseURL      = "https://tip.nsfocus.com/api"
	DefaultMetaDefenderBaseURL = "https://api.metadefender.com/v4"
)

// ParseMode 根据用户输入解析 Mode。
func ParseMode(raw string) Mode {
	raw = strings.TrimSpace(strings.ToLower(raw))
	switch Mode(raw) {
	case ModeLocal, ModeHybrid, ModeServer, ModeAuto:
		return Mode(raw)
	default:
		return ModeHybrid
	}
}
