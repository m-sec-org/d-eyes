package collector

import (
	"context"
	"testing"
	"time"
)

func TestServiceStartStop(t *testing.T) {
	cfgs := []Config{
		{Name: "test", Kind: Kind("stub"), Output: Output{Mode: "stdout"}},
	}
	m := NewManager()
	if err := m.RegisterFactory(Kind("stub"), func(cfg Config) (EventCollector, error) {
		return &serviceStubCollector{cfg: cfg}, nil
	}); err != nil {
		t.Fatalf("register factory: %v", err)
	}
	svc := NewService(cfgs, WithManager(m))
	if !svc.HasCollectors() {
		t.Fatalf("expected collectors")
	}
	if err := svc.Start(context.Background(), nil); err != nil {
		t.Fatalf("start collectors: %v", err)
	}
	status := svc.Status()
	if len(status) != 1 || status[0].Name == "" {
		t.Fatalf("unexpected status: %+v", status)
	}
	if err := svc.Stop(context.Background()); err != nil {
		t.Fatalf("stop collectors: %v", err)
	}
}

func TestServiceStartAggregatesErrors(t *testing.T) {
	cfgs := []Config{
		{Name: "broken", Kind: Kind("missing")},
	}
	svc := NewService(cfgs)
	if err := svc.Start(context.Background(), nil); err == nil {
		t.Fatalf("expected error when factory missing")
	}
}

func TestWrapCollectorMetadata(t *testing.T) {
	cfg := Config{Name: "diag-ebpf", Kind: KindEBPF}
	svc := NewService(nil)
	base := EventHandlerFunc(func(ctx context.Context, event *SystemEvent) error {
		if event.Metadata["collector"] != "diag-ebpf" {
			t.Fatalf("expected collector metadata, got %+v", event.Metadata)
		}
		if event.Metadata["collector_kind"] != string(KindEBPF) {
			t.Fatalf("expected collector kind metadata, got %+v", event.Metadata)
		}
		return nil
	})
	handler := svc.wrapCollectorMetadata(cfg, base)
	if handler == nil {
		t.Fatalf("expected handler")
	}
	err := handler.HandleEvent(context.Background(), &SystemEvent{Metadata: map[string]string{}})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
}

type serviceStubCollector struct {
	cfg Config
}

func (s *serviceStubCollector) Name() string { return s.cfg.Name }

func (s *serviceStubCollector) Start(context.Context, EventHandler) error { return nil }

func (s *serviceStubCollector) Stop(context.Context) error { return nil }

func (s *serviceStubCollector) Status() CollectorStatus {
	return CollectorStatus{
		Name:      s.cfg.Name,
		Kind:      s.cfg.Kind,
		State:     "running",
		StartedAt: time.Now(),
	}
}
