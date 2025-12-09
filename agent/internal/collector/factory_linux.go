//go:build linux

package collector

func registerDefaultFactories(s *Service) {
	if s == nil || s.manager == nil {
		return
	}
	_ = s.manager.RegisterFactory(KindETW, func(cfg Config) (EventCollector, error) {
		instance, err := newETWCollector(cfg)
		if err != nil {
			return nil, err
		}
		s.applyDetectionSink(instance)
		return instance, nil
	})
	_ = s.manager.RegisterFactory(KindEBPF, func(cfg Config) (EventCollector, error) {
		return newEBPFCollector(cfg)
	})
}
