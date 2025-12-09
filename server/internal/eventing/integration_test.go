package eventing

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	memqueue "github.com/m-sec-org/d-eyes/server/internal/queue/memory"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	"github.com/m-sec-org/d-eyes/server/internal/streams"
	"github.com/m-sec-org/d-eyes/server/internal/threatintel"
)

func TestIntegrationETWEBPFIngestionDetection(t *testing.T) {
	h := newIngestionHarness(t)
	t.Cleanup(h.Close)

	ctx, cancel := context.WithCancel(context.Background())
	streamCh, unsubscribe := h.hub.Subscribe(ctx)
	defer func() {
		cancel()
		unsubscribe()
	}()

	var sseCount atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for event := range streamCh {
			if event.Event == "detection.triggered" {
				sseCount.Add(1)
			}
		}
	}()

	h.enqueue(t, newCollectorEvent("etw", "etw.security.suspicious_process", map[string]any{
		"process": "powershell.exe",
		"args":    "-nop -enc ...",
	}))
	h.enqueue(t, newCollectorEvent("ebpf", "ebpf.network.exfiltration", map[string]any{
		"dest_ip":   "203.0.113.24",
		"dest_port": 4444,
	}))

	waitForCondition(t, 5*time.Second, 25*time.Millisecond, func() bool {
		results, err := h.store.QuerySystemEvents(context.Background(), store.SystemEventQuery{
			EventType: "detection.alert",
			Limit:     10,
		})
		if err != nil {
			return false
		}
		return len(results) >= 2
	})

	if count := h.threat.CallCount(); count == 0 {
		t.Fatalf("expected threat intel lookups, got 0")
	}

	etwTriggered := readCounter(t, h.metrics.DetectionsTriggered.WithLabelValues("etw-rule", "high"))
	if etwTriggered < 1 {
		t.Fatalf("expected etw-rule detections >=1, got %f", etwTriggered)
	}
	ebpfTriggered := readCounter(t, h.metrics.DetectionsTriggered.WithLabelValues("ebpf-rule", "medium"))
	if ebpfTriggered < 1 {
		t.Fatalf("expected ebpf-rule detections >=1, got %f", ebpfTriggered)
	}

	waitForCondition(t, time.Second, 25*time.Millisecond, func() bool {
		return sseCount.Load() >= 2
	})

	cancel()
	<-done
}

func TestIntegrationIngestionPerfBaseline(t *testing.T) {
	h := newIngestionHarness(t)
	t.Cleanup(h.Close)

	const totalEvents = 200
	start := time.Now()
	for i := 0; i < totalEvents; i++ {
		eventType := "ebpf.network.exfiltration"
		if i%2 == 0 {
			eventType = "etw.security.suspicious_process"
		}
		h.enqueue(t, newCollectorEvent(mapEventKind(eventType), eventType, map[string]any{
			"sequence": i,
			"message":  "integration-perf-baseline",
		}))
	}
	waitForCondition(t, 5*time.Second, 25*time.Millisecond, func() bool {
		count, err := h.store.CountSystemEvents(context.Background(), time.Time{})
		if err != nil {
			return false
		}
		return count >= int64(totalEvents)
	})
	totalDuration := time.Since(start)
	avgPerEvent := totalDuration / totalEvents
	t.Logf("[perf] ingestion_total=%d duration=%s avg_per_event=%s", totalEvents, totalDuration, avgPerEvent)
	if avgPerEvent > 25*time.Millisecond {
		t.Fatalf("ingestion average per event too slow: %s", avgPerEvent)
	}
}

type ingestionHarness struct {
	cfg      config.EventsConfig
	store    store.Store
	metrics  *metrics.Metrics
	service  *Service
	engine   *DetectionEngine
	hub      *streams.Hub
	sched    *scheduler.Scheduler
	threat   *fakeThreatLookup
	logger   *slog.Logger
	registry *prometheus.Registry
}

func newIngestionHarness(t *testing.T) *ingestionHarness {
	t.Helper()
	cfg := integrationEventsConfig()
	st := store.NewInMemoryStore()
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service := NewService(cfg, st, m, logger)
	if service == nil {
		t.Fatalf("expected event service to be initialised")
	}
	queue := memqueue.New()
	sched := scheduler.New(st, queue, config.SchedulerConfig{
		LeaseTTL:      time.Minute,
		QueueCapacity: 256,
	})
	sched.SetMetrics(m)
	hub := streams.NewTaskHub()
	threat := &fakeThreatLookup{}
	engine := NewDetectionEngine(cfg, st, sched, threat, logger, m, hub)
	if engine == nil {
		t.Fatalf("expected detection engine to be initialised")
	}
	service.RegisterConsumer(engine)
	return &ingestionHarness{
		cfg:      cfg,
		store:    st,
		metrics:  m,
		service:  service,
		engine:   engine,
		hub:      hub,
		sched:    sched,
		threat:   threat,
		logger:   logger,
		registry: reg,
	}
}

func (h *ingestionHarness) Close() {
	if h.service != nil {
		h.service.Close()
	}
	if h.engine != nil {
		h.engine.Close()
	}
	if h.hub != nil {
		h.hub.Close()
	}
}

func (h *ingestionHarness) enqueue(t *testing.T, event model.SystemEventRecord) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.service.Enqueue(ctx, "high", []model.SystemEventRecord{event}); err != nil {
		t.Fatalf("enqueue failed: %v", err)
	}
}

type fakeThreatLookup struct {
	mu       sync.Mutex
	requests []threatintel.LookupRequest
}

func (f *fakeThreatLookup) SubmitLookup(_ context.Context, req threatintel.LookupRequest) ([]uuid.UUID, []*model.ThreatIntelVerdict, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
	return []uuid.UUID{uuid.New()}, nil, nil
}

func (f *fakeThreatLookup) CallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func integrationEventsConfig() config.EventsConfig {
	return config.EventsConfig{
		Enabled:         true,
		QueueCapacity:   256,
		MaxBatch:        64,
		FlushInterval:   10 * time.Millisecond,
		DefaultPriority: "high",
		PriorityQueues: map[string]config.EventPriorityQueueConfig{
			"high": {
				QueueCapacity: 256,
				MaxBatch:      64,
			},
		},
		Retention: config.EventRetentionConfig{
			Hot: 24 * time.Hour,
		},
		Detection: config.DetectionConfig{
			Enabled:    true,
			MaxWorkers: 2,
			QueueSize:  256,
			Rules: []config.DetectionRuleConfig{
				{
					Name:                "etw-rule",
					Enabled:             true,
					Severity:            "high",
					EventTypes:          []string{"etw.security.suspicious_process"},
					Tags:                map[string]string{"collector_kind": "etw"},
					Indicators:          []string{"payload.process"},
					SubmitToThreatIntel: true,
				},
				{
					Name:       "ebpf-rule",
					Enabled:    true,
					Severity:   "medium",
					EventTypes: []string{"ebpf.network.exfiltration"},
					Tags:       map[string]string{"collector_kind": "ebpf"},
				},
			},
			AutoRespond: config.DetectionAutoRespondConfig{
				Enabled: false,
			},
		},
	}
}

func newCollectorEvent(kind, eventType string, payload map[string]any) model.SystemEventRecord {
	body, _ := json.Marshal(payload)
	now := time.Now().UTC()
	return model.SystemEventRecord{
		ID:            uuid.New(),
		AgentID:       uuid.New(),
		AgentName:     kind + "-agent",
		Collector:     kind + "-collector",
		CollectorKind: kind,
		EventType:     eventType,
		Source:        kind + ".source",
		Priority:      "high",
		StorageTier:   "hot",
		Timestamp:     now,
		Sequence:      uint64(time.Now().UnixNano()),
		Payload:       body,
		Metadata: map[string]string{
			"collector_kind": kind,
		},
		Tags: map[string]string{
			"collector_kind": kind,
		},
		ReceivedAt: now,
	}
}

func waitForCondition(t *testing.T, timeout, interval time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(interval)
	}
	t.Fatalf("condition not met within %s", timeout)
}

func mapEventKind(eventType string) string {
	if eventType == "etw.security.suspicious_process" {
		return "etw"
	}
	return "ebpf"
}
