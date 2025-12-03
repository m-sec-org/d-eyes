package collector

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestManagerRegistersAndStartsCollector(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := NewManager()
	if err := m.RegisterFactory(Kind("stub"), func(cfg Config) (EventCollector, error) {
		return newStubCollector(cfg), nil
	}); err != nil {
		t.Fatalf("register factory: %v", err)
	}

	cfg := Config{Name: "test", Kind: Kind("stub")}
	var mu sync.Mutex
	var handled int
	handler := EventHandlerFunc(func(_ context.Context, _ *SystemEvent) error {
		mu.Lock()
		defer mu.Unlock()
		handled++
		return nil
	})
	if err := m.Start(ctx, cfg, handler); err != nil {
		t.Fatalf("start collector: %v", err)
	}

	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return handled > 0
	})

	status := m.Status()
	if len(status) != 1 {
		t.Fatalf("expected one status, got %d", len(status))
	}
	if status[0].Name != "stub-test" {
		t.Fatalf("unexpected collector name %q", status[0].Name)
	}

	if err := m.StopAll(context.Background()); err != nil {
		t.Fatalf("stop all: %v", err)
	}
}

func TestManagerStopsUnknownCollectorGracefully(t *testing.T) {
	m := NewManager()
	if err := m.Stop(context.Background(), "unknown"); err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
}

func TestManagerFactoryValidation(t *testing.T) {
	m := NewManager()
	if err := m.RegisterFactory(Kind("invalid"), nil); err == nil {
		t.Fatalf("expected error for nil factory")
	}
	if err := m.RegisterFactory(Kind("dup"), func(Config) (EventCollector, error) { return nil, nil }); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := m.RegisterFactory(Kind("dup"), func(Config) (EventCollector, error) { return nil, nil }); err == nil {
		t.Fatalf("expected duplicate error")
	}
}

type stubCollector struct {
	cfg     Config
	mu      sync.Mutex
	stopped bool
}

func newStubCollector(cfg Config) *stubCollector {
	return &stubCollector{cfg: cfg}
}

func (s *stubCollector) Name() string {
	return "stub-" + s.cfg.Name
}

func (s *stubCollector) Start(ctx context.Context, handler EventHandler) error {
	if handler != nil {
		_ = handler.HandleEvent(ctx, &SystemEvent{
			Timestamp: time.Now(),
			EventType: "stub",
			Source:    "test",
		})
	}
	return nil
}

func (s *stubCollector) Stop(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return errors.New("already stopped")
	}
	s.stopped = true
	return nil
}

func (s *stubCollector) Status() CollectorStatus {
	return CollectorStatus{
		Name:      s.Name(),
		Kind:      s.cfg.Kind,
		State:     "running",
		StartedAt: time.Now(),
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met before deadline")
}
