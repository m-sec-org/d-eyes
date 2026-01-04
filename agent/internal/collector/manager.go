package collector

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/m-sec-org/d-eyes/agent/internal/debugger"
)

// Manager orchestrates the lifecycle of multiple collectors (ETW/eBPF, etc.).
type Manager struct {
	mu         sync.Mutex
	factories  map[Kind]Factory
	collectors map[string]*managedCollector
	emitter    *debugger.Emitter
}

type managedCollector struct {
	cfg       Config
	instance  EventCollector
	handler   EventHandler
	cancel    context.CancelFunc
	started   bool
	startOnce sync.Once
}

// NewManager constructs an empty Manager.
func NewManager() *Manager {
	return &Manager{
		factories:  make(map[Kind]Factory),
		collectors: make(map[string]*managedCollector),
	}
}

// NewManagerWithEmitter constructs a Manager with debug emitter.
func NewManagerWithEmitter(emitter *debugger.Emitter) *Manager {
	m := NewManager()
	m.emitter = emitter
	return m
}

// SetEmitter wires a debug emitter for lifecycle events.
func (m *Manager) SetEmitter(emitter *debugger.Emitter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.emitter = emitter
}

// RegisterFactory binds a collector kind to a factory.
func (m *Manager) RegisterFactory(kind Kind, factory Factory) error {
	if factory == nil {
		return errors.New("collector: factory cannot be nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.factories[kind]; ok {
		return fmt.Errorf("collector: factory for kind %q already registered", kind)
	}
	m.factories[kind] = factory
	return nil
}

// Start initializes (or replaces) a collector matching cfg.Name/cfg.Kind.
func (m *Manager) Start(ctx context.Context, cfg Config, handler EventHandler) error {
	if cfg.Disabled {
		return fmt.Errorf("collector %s is disabled", cfg.Name)
	}
	factory, err := m.factoryFor(cfg.Kind)
	if err != nil {
		return err
	}
	instance, err := factory(cfg)
	if err != nil {
		m.emitState(cfg.Name, cfg.Kind, "error", err)
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	mc := &managedCollector{
		cfg:      cfg,
		instance: instance,
		handler:  handler,
		cancel:   cancel,
	}

	m.mu.Lock()
	if existing, ok := m.collectors[cfg.Name]; ok {
		_ = existing.stop(context.Background())
	}
	m.collectors[cfg.Name] = mc
	m.mu.Unlock()
	m.emitState(cfg.Name, cfg.Kind, "starting", nil)

	go func() {
		if err := instance.Start(runCtx, handler); err != nil {
			m.emitState(cfg.Name, cfg.Kind, "error", err)
			cancel()
		} else {
			mc.startOnce.Do(func() { mc.started = true })
			m.emitState(cfg.Name, cfg.Kind, "running", nil)
		}
	}()
	return nil
}

// Stop halts a named collector.
func (m *Manager) Stop(ctx context.Context, name string) error {
	m.mu.Lock()
	mc, ok := m.collectors[name]
	if ok {
		delete(m.collectors, name)
	}
	m.mu.Unlock()
	if !ok {
		return nil
	}
	m.emitState(mc.cfg.Name, mc.cfg.Kind, "stopping", nil)
	return mc.stop(ctx)
}

// StopAll stops every running collector.
func (m *Manager) StopAll(ctx context.Context) error {
	m.mu.Lock()
	collectors := make([]*managedCollector, 0, len(m.collectors))
	for name, mc := range m.collectors {
		collectors = append(collectors, mc)
		delete(m.collectors, name)
	}
	m.mu.Unlock()

	var multi error
	for _, mc := range collectors {
		m.emitState(mc.cfg.Name, mc.cfg.Kind, "stopping", nil)
		if err := mc.stop(ctx); err != nil {
			multi = errors.Join(multi, err)
			m.emitState(mc.cfg.Name, mc.cfg.Kind, "error", err)
		}
	}
	return multi
}

// Status snapshots all collector states.
func (m *Manager) Status() []CollectorStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	statuses := make([]CollectorStatus, 0, len(m.collectors))
	for _, mc := range m.collectors {
		statuses = append(statuses, mc.instance.Status())
	}
	return statuses
}

func (m *Manager) factoryFor(kind Kind) (Factory, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	factory, ok := m.factories[kind]
	if !ok {
		return nil, fmt.Errorf("collector: no factory registered for kind %q", kind)
	}
	return factory, nil
}

func (mc *managedCollector) stop(ctx context.Context) error {
	if mc.cancel != nil {
		mc.cancel()
	}
	return mc.instance.Stop(ctx)
}

func (m *Manager) emitState(name string, kind Kind, state string, err error) {
	m.mu.Lock()
	emitter := m.emitter
	m.mu.Unlock()
	if emitter == nil {
		return
	}
	msg := state
	if err != nil {
		msg = fmt.Sprintf("%s: %v", state, err)
		emitter.Error(string(kind), msg)
		return
	}
	emitter.Notice(string(kind), fmt.Sprintf("collector %s %s", name, state))
}
