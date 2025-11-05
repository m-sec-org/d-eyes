package internal

import (
	"sync"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

var (
	globalConfig     = config.Default()
	globalConfigLock sync.RWMutex

	reportManager     = reporting.NewManager(globalConfig)
	reportManagerLock sync.RWMutex

	quietMode     bool
	quietModeLock sync.RWMutex
)

// SetGlobalConfig stores the application-wide configuration.
func SetGlobalConfig(cfg config.Config) {
	globalConfigLock.Lock()
	defer globalConfigLock.Unlock()
	globalConfig = cfg
	SetReportManager(reporting.NewManager(cfg))
}

// GetGlobalConfig retrieves the active configuration.
func GetGlobalConfig() config.Config {
	globalConfigLock.RLock()
	defer globalConfigLock.RUnlock()
	return globalConfig
}

// SetReportManager stores the global reporting manager.
func SetReportManager(m *reporting.Manager) {
	reportManagerLock.Lock()
	defer reportManagerLock.Unlock()
	reportManager = m
}

// GetReportManager returns the active reporting manager.
func GetReportManager() *reporting.Manager {
	reportManagerLock.RLock()
	defer reportManagerLock.RUnlock()
	return reportManager
}

// SetQuietMode 更新全局静默模式标志
func SetQuietMode(q bool) {
	quietModeLock.Lock()
	defer quietModeLock.Unlock()
	quietMode = q
}

// IsQuietMode 判断是否启用了静默模式
func IsQuietMode() bool {
	quietModeLock.RLock()
	defer quietModeLock.RUnlock()
	return quietMode
}
