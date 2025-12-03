//go:build !windows && !linux

package collector

func registerDefaultFactories(m *Manager) {
	_ = m.RegisterFactory(KindETW, func(cfg Config) (EventCollector, error) {
		return newETWCollector(cfg)
	})
}
