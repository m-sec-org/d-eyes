//go:build linux

package collector

func registerDefaultFactories(m *Manager) {
	_ = m.RegisterFactory(KindETW, func(cfg Config) (EventCollector, error) {
		return newETWCollector(cfg)
	})
	_ = m.RegisterFactory(KindEBPF, func(cfg Config) (EventCollector, error) {
		return newEBPFCollector(cfg)
	})
}
