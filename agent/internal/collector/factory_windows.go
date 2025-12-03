//go:build windows

package collector

func registerDefaultFactories(m *Manager) {
	_ = m.RegisterFactory(KindETW, newETWCollector)
}
