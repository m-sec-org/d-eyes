package internal

import (
	"sync"

	"github.com/m-sec-org/d-eyes/agent/internal/cmdexec"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

type ConfigWatcher func(config.Config)

var (
	globalConfig     = config.Default()
	globalConfigLock sync.RWMutex

	reportManager     = reporting.NewManager(globalConfig)
	reportManagerLock sync.RWMutex

	quietMode     bool
	quietModeLock sync.RWMutex

	configWatchers     []ConfigWatcher
	configWatchersLock sync.RWMutex
)

// SetGlobalConfig stores the application-wide configuration.
func SetGlobalConfig(cfg config.Config) {
	globalConfigLock.Lock()
	defer globalConfigLock.Unlock()
	globalConfig = cfg
	SetReportManager(reporting.NewManager(cfg))
	cmdexec.Configure(cfg)
	notifyConfigWatchers(cfg)
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

// RegisterConfigWatcher attaches a callback invoked whenever SetGlobalConfig is called.
// It returns a function that removes the watcher.
func RegisterConfigWatcher(w ConfigWatcher) func() {
	if w == nil {
		return func() {}
	}
	configWatchersLock.Lock()
	defer configWatchersLock.Unlock()
	configWatchers = append(configWatchers, w)
	idx := len(configWatchers) - 1
	return func() {
		configWatchersLock.Lock()
		defer configWatchersLock.Unlock()
		if idx >= 0 && idx < len(configWatchers) {
			configWatchers[idx] = nil
		}
	}
}

func notifyConfigWatchers(cfg config.Config) {
	configWatchersLock.RLock()
	watchers := make([]ConfigWatcher, 0, len(configWatchers))
	for _, w := range configWatchers {
		if w != nil {
			watchers = append(watchers, w)
		}
	}
	configWatchersLock.RUnlock()
	for _, watcher := range watchers {
		go watcher(cfg)
	}
}
