package collector

import (
	"context"
	"errors"
	"fmt"
)

// Service wires configuration-driven collectors onto a shared Manager.
type Service struct {
	manager *Manager
	configs []Config
	outputs map[string]func()
}

// ServiceOption customises a Service.
type ServiceOption func(*Service)

// WithManager injects a custom Manager instance (mainly for testing).
func WithManager(m *Manager) ServiceOption {
	return func(s *Service) {
		s.manager = m
	}
}

// NewService constructs a Service for the supplied collector configs.
func NewService(configs []Config, opts ...ServiceOption) *Service {
	svc := &Service{
		configs: configs,
		manager: NewManager(),
		outputs: make(map[string]func()),
	}
	registerDefaultFactories(svc.manager)
	for _, opt := range opts {
		if opt != nil {
			opt(svc)
		}
	}
	if svc.manager == nil {
		svc.manager = NewManager()
	}
	return svc
}

// HasCollectors reports whether at least one collector is configured.
func (s *Service) HasCollectors() bool {
	return len(s.configs) > 0
}

// Start instantiates collectors via the Manager.
func (s *Service) Start(ctx context.Context, handler EventHandler) error {
	if len(s.configs) == 0 {
		return nil
	}
	if handler == nil {
		handler = EventHandlerFunc(func(context.Context, *SystemEvent) error { return nil })
	}
	var multi error
	for _, cfg := range s.configs {
		if cfg.Disabled {
			continue
		}
		decorated, cleanup, err := s.decorateHandler(cfg, handler)
		decorated = s.wrapCollectorMetadata(cfg, decorated)
		if err != nil {
			multi = errors.Join(multi, fmt.Errorf("%s: %w", cfg.Name, err))
			continue
		}
		if cleanup != nil {
			s.outputs[cfg.Name] = cleanup
		}
		if err := s.manager.Start(ctx, cfg, decorated); err != nil {
			if cleanup != nil {
				cleanup()
				delete(s.outputs, cfg.Name)
			}
			multi = errors.Join(multi, fmt.Errorf("%s: %w", cfg.Name, err))
		}
	}
	return multi
}

// Stop halts all managed collectors.
func (s *Service) Stop(ctx context.Context) error {
	if s.manager == nil {
		return nil
	}
	defer s.cleanupOutputs()
	return s.manager.StopAll(ctx)
}

// Status aggregates runtime state across collectors.
func (s *Service) Status() []CollectorStatus {
	if s.manager == nil {
		return nil
	}
	return s.manager.Status()
}

func (s *Service) decorateHandler(cfg Config, base EventHandler) (EventHandler, func(), error) {
	return buildOutputHandler(cfg, base)
}

func (s *Service) wrapCollectorMetadata(cfg Config, handler EventHandler) EventHandler {
	if handler == nil {
		return nil
	}
	return EventHandlerFunc(func(ctx context.Context, event *SystemEvent) error {
		if event != nil {
			if event.Metadata == nil {
				event.Metadata = make(map[string]string, 2)
			}
			if _, ok := event.Metadata["collector"]; !ok && cfg.Name != "" {
				event.Metadata["collector"] = cfg.Name
			}
			if _, ok := event.Metadata["collector_kind"]; !ok && string(cfg.Kind) != "" {
				event.Metadata["collector_kind"] = string(cfg.Kind)
			}
		}
		return handler.HandleEvent(ctx, event)
	})
}

func (s *Service) cleanupOutputs() {
	for name, cleanup := range s.outputs {
		if cleanup != nil {
			cleanup()
		}
		delete(s.outputs, name)
	}
}
