package eventing

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

func TestServiceSpillover(t *testing.T) {
	cfg := config.EventsConfig{
		Enabled:         true,
		FlushInterval:   time.Second,
		DefaultPriority: "normal",
		PriorityQueues: map[string]config.EventPriorityQueueConfig{
			"high": {
				QueueCapacity: 1,
				MaxBatch:      10,
				DropPolicy:    "spillover",
				Spillover:     "normal",
			},
			"normal": {
				QueueCapacity: 8,
				MaxBatch:      8,
			},
		},
	}
	st := store.NewInMemoryStore()
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := NewService(cfg, st, m, log)
	if svc == nil {
		t.Fatalf("service should be instantiated")
	}
	t.Cleanup(func() {
		if svc != nil {
			svc.Close()
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	event := model.SystemEventRecord{Priority: "high", EventType: "test"}
	firstErr := make(chan error, 1)
	go func() {
		firstErr <- svc.Enqueue(ctx, "high", []model.SystemEventRecord{event})
	}()
	time.Sleep(20 * time.Millisecond)
	if err := svc.Enqueue(ctx, "high", []model.SystemEventRecord{event}); err != nil {
		t.Fatalf("spillover enqueue failed: %v", err)
	}
	svc.Close()
	svc = nil
	select {
	case err := <-firstErr:
		if err != nil {
			t.Fatalf("first enqueue failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("first enqueue did not complete")
	}
	results, err := st.QuerySystemEvents(context.Background(), store.SystemEventQuery{Limit: 10})
	if err != nil {
		t.Fatalf("QuerySystemEvents: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 events persisted, got %d", len(results))
	}
}

func TestBackpressureMetrics(t *testing.T) {
	cfg := config.EventsConfig{
		Enabled:         true,
		FlushInterval:   time.Second,
		DefaultPriority: "high",
		PriorityQueues: map[string]config.EventPriorityQueueConfig{
			"high": {
				QueueCapacity:         10,
				MaxBatch:              10,
				BackpressureThreshold: 0.5,
				AlertCooldown:         10 * time.Millisecond,
			},
		},
	}
	st := store.NewInMemoryStore()
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := NewService(cfg, st, m, log)
	if svc == nil {
		t.Fatalf("service should be instantiated")
	}
	defer svc.Close()
	// Stop background loop to avoid interference.
	svc.Close()
	pending := map[string][]model.SystemEventRecord{
		"high": make([]model.SystemEventRecord, 6),
	}
	svc.updateQueueMetrics(pending)
	value := readCounter(t, m.SystemEventsBackpressure.WithLabelValues("high", "saturation"))
	if value != 1 {
		t.Fatalf("expected backpressure counter 1, got %f", value)
	}
	svc.updateQueueMetrics(map[string][]model.SystemEventRecord{"high": nil})
	svc.updateQueueMetrics(pending)
	value = readCounter(t, m.SystemEventsBackpressure.WithLabelValues("high", "saturation"))
	if value != 2 {
		t.Fatalf("expected backpressure counter 2 after re-trigger, got %f", value)
	}
}

func readCounter(t *testing.T, counter prometheus.Counter) float64 {
	t.Helper()
	metric := &dto.Metric{}
	if err := counter.Write(metric); err != nil {
		t.Fatalf("counter write failed: %v", err)
	}
	if metric.Counter == nil {
		return 0
	}
	return metric.Counter.GetValue()
}

func TestBlockPolicyReturnsError(t *testing.T) {
	cfg := config.EventsConfig{
		Enabled:         true,
		FlushInterval:   time.Second,
		DefaultPriority: "high",
		PriorityQueues: map[string]config.EventPriorityQueueConfig{
			"high": {
				QueueCapacity: 1,
				MaxBatch:      10,
				DropPolicy:    "block",
			},
		},
	}
	st := store.NewInMemoryStore()
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := NewService(cfg, st, m, log)
	if svc == nil {
		t.Fatalf("service should be instantiated")
	}
	defer svc.Close()
	svc.Close()
	lane := svc.laneFor("high")
	if lane == nil {
		t.Fatalf("expected lane lookup")
	}
	lane.queue <- batchRequest{events: []model.SystemEventRecord{{EventType: "pending"}}}
	err := svc.handleBackpressure(lane, batchRequest{events: []model.SystemEventRecord{{EventType: "incoming"}}})
	if err != ErrBackpressure {
		t.Fatalf("expected ErrBackpressure for block policy, got %v", err)
	}
}
