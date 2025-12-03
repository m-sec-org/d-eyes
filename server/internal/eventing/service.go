package eventing

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

var (
	// ErrBackpressure indicates the ingestion queue is full.
	ErrBackpressure = errors.New("event queue is saturated")
)

type batchRequest struct {
	events []model.SystemEventRecord
	done   chan error
}

// Service buffers incoming events and persists them asynchronously.
type Service struct {
	cfg     config.EventsConfig
	store   store.Store
	metrics *metrics.Metrics
	log     *slog.Logger

	queue chan batchRequest
	stop  chan struct{}
	once  sync.Once
	wg    sync.WaitGroup
}

// NewService constructs the ingestion pipeline when enabled.
func NewService(cfg config.EventsConfig, st store.Store, metricsCollector *metrics.Metrics, log *slog.Logger) *Service {
	if !cfg.Enabled {
		return nil
	}
	queueSize := cfg.QueueCapacity
	if queueSize <= 0 {
		queueSize = 8192
	}
	svc := &Service{
		cfg:     cfg,
		store:   st,
		metrics: metricsCollector,
		log:     log,
		queue:   make(chan batchRequest, queueSize),
		stop:    make(chan struct{}),
	}
	svc.wg.Add(1)
	go svc.run()
	return svc
}

func (s *Service) run() {
	defer s.wg.Done()
	flushInterval := s.cfg.FlushInterval
	if flushInterval <= 0 {
		flushInterval = 50 * time.Millisecond
	}
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	var pending []model.SystemEventRecord
	var pendingReqs []batchRequest
	flush := func() {
		if len(pending) == 0 {
			return
		}
		events := pending
		reqs := pendingReqs
		pending = nil
		pendingReqs = nil
		if err := s.store.InsertSystemEvents(context.Background(), events); err != nil {
			if s.log != nil {
				s.log.Error("persist system events failed", "error", err, "count", len(events))
			}
			if s.metrics != nil {
				s.metrics.SystemEventsDropped.Add(float64(len(events)))
				s.metrics.SystemEventsQueue.Set(float64(len(s.queue)))
			}
			for _, req := range reqs {
				req.done <- err
			}
			return
		}
		now := time.Now().UTC()
		if s.metrics != nil {
			for _, evt := range events {
				s.metrics.SystemEventsIngested.Inc()
				if !evt.ReceivedAt.IsZero() {
					s.metrics.SystemEventsLatency.Observe(now.Sub(evt.ReceivedAt).Seconds())
				}
			}
			s.metrics.SystemEventsQueue.Set(float64(len(s.queue)))
		}
		for _, req := range reqs {
			req.done <- nil
		}
	}

	for {
		select {
		case req := <-s.queue:
			pendingReqs = append(pendingReqs, req)
			pending = append(pending, req.events...)
			if len(pending) >= s.cfg.MaxBatch {
				flush()
			}
			if s.metrics != nil {
				s.metrics.SystemEventsQueue.Set(float64(len(s.queue)))
			}
		case <-ticker.C:
			flush()
		case <-s.stop:
			flush()
			return
		}
	}
}

// Close stops the background workers and flushes inflight events.
func (s *Service) Close() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		close(s.stop)
		s.wg.Wait()
	})
}

// Enqueue persists the provided events, blocking until flushed or the context cancels.
func (s *Service) Enqueue(ctx context.Context, events []model.SystemEventRecord) error {
	if s == nil || len(events) == 0 {
		return nil
	}
	req := batchRequest{
		events: cloneEvents(events),
		done:   make(chan error, 1),
	}
	select {
	case s.queue <- req:
	default:
		if s.metrics != nil {
			s.metrics.SystemEventsDropped.Add(float64(len(events)))
		}
		return ErrBackpressure
	}
	select {
	case err := <-req.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func cloneEvents(events []model.SystemEventRecord) []model.SystemEventRecord {
	if len(events) == 0 {
		return nil
	}
	out := make([]model.SystemEventRecord, len(events))
	for i, evt := range events {
		cp := evt
		if cp.ID == uuid.Nil {
			cp.ID = uuid.New()
		}
		if cp.ReceivedAt.IsZero() {
			cp.ReceivedAt = time.Now().UTC()
		}
		if cp.Timestamp.IsZero() {
			cp.Timestamp = cp.ReceivedAt
		}
		out[i] = cp
	}
	return out
}
