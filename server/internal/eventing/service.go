package eventing

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sort"
	"strings"
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

// Consumer receives flushed events for downstream processing (detections, analytics, etc.).
type Consumer interface {
	Consume(ctx context.Context, events []model.SystemEventRecord)
}

type batchRequest struct {
	priority string
	events   []model.SystemEventRecord
	done     chan error
}

type priorityLane struct {
	name        string
	queue       chan batchRequest
	config      config.EventPriorityQueueConfig
	spillover   *priorityLane
	dropPolicy  string
	threshold   float64
	alertActive bool
	lastAlert   time.Time
	cooldown    time.Duration
}

// Service buffers incoming events and persists them asynchronously.
type Service struct {
	cfg             config.EventsConfig
	store           store.Store
	metrics         *metrics.Metrics
	log             *slog.Logger
	lanes           []*priorityLane
	laneIndex       map[string]int
	defaultPriority string
	stop            chan struct{}
	once            sync.Once
	wg              sync.WaitGroup
	consumers       []Consumer
}

// NewService constructs the ingestion pipeline when enabled.
func NewService(cfg config.EventsConfig, st store.Store, metricsCollector *metrics.Metrics, log *slog.Logger) *Service {
	if !cfg.Enabled {
		return nil
	}
	if len(cfg.PriorityQueues) == 0 {
		defaultLane := strings.ToLower(strings.TrimSpace(cfg.DefaultPriority))
		if defaultLane == "" {
			defaultLane = "normal"
		}
		cfg.PriorityQueues = map[string]config.EventPriorityQueueConfig{
			defaultLane: {
				QueueCapacity: cfg.QueueCapacity,
				MaxBatch:      cfg.MaxBatch,
			},
		}
		cfg.DefaultPriority = defaultLane
	}
	order := orderedPriorities(cfg)
	lanes := make([]*priorityLane, 0, len(order))
	laneIndex := make(map[string]int, len(order))
	for idx, name := range order {
		laneCfg := cfg.PriorityQueues[name]
		threshold := laneCfg.BackpressureThreshold
		if threshold <= 0 || threshold > 1 {
			threshold = 0.8
		}
		dropPolicy := strings.ToLower(strings.TrimSpace(laneCfg.DropPolicy))
		if dropPolicy == "" {
			dropPolicy = "block"
		}
		cooldown := laneCfg.AlertCooldown
		if cooldown <= 0 {
			cooldown = 30 * time.Second
		}
		lane := &priorityLane{
			name:       name,
			queue:      make(chan batchRequest, laneCfg.QueueCapacity),
			config:     laneCfg,
			dropPolicy: dropPolicy,
			threshold:  threshold,
			cooldown:   cooldown,
		}
		laneIndex[name] = len(lanes)
		lanes = append(lanes, lane)
		if spill := strings.ToLower(strings.TrimSpace(laneCfg.Spillover)); spill != "" {
			if pos, ok := laneIndex[spill]; ok {
				lane.spillover = lanes[pos]
			}
		}
		if lane.spillover == nil && idx+1 < len(order) {
			// default spillover to next lane (lower priority).
			// we will set actual pointer after all lanes initialised.
		}
	}
	for i, lane := range lanes {
		if lane.spillover != nil {
			continue
		}
		if spill := strings.ToLower(strings.TrimSpace(lane.config.Spillover)); spill != "" {
			if idx, ok := laneIndex[spill]; ok && idx != i {
				lane.spillover = lanes[idx]
			}
			continue
		}
		if i+1 < len(lanes) {
			lane.spillover = lanes[i+1]
		}
	}
	defaultPriority := strings.ToLower(strings.TrimSpace(cfg.DefaultPriority))
	if defaultPriority == "" {
		defaultPriority = "normal"
	}
	svc := &Service{
		cfg:             cfg,
		store:           st,
		metrics:         metricsCollector,
		log:             log,
		lanes:           lanes,
		laneIndex:       laneIndex,
		defaultPriority: defaultPriority,
		stop:            make(chan struct{}),
	}
	svc.wg.Add(1)
	go svc.run()
	return svc
}

func (s *Service) run() {
	defer s.wg.Done()
	if len(s.lanes) == 0 {
		return
	}
	flushInterval := s.cfg.FlushInterval
	if flushInterval <= 0 {
		flushInterval = 50 * time.Millisecond
	}
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	cases := make([]reflect.SelectCase, len(s.lanes)+2)
	for i, lane := range s.lanes {
		cases[i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(lane.queue)}
	}
	cases[len(s.lanes)] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ticker.C)}
	cases[len(s.lanes)+1] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(s.stop)}
	pending := make(map[string][]model.SystemEventRecord, len(s.lanes))
	pendingReqs := make(map[string][]batchRequest, len(s.lanes))
	flushPriority := func(name string) {
		events := pending[name]
		if len(events) == 0 {
			return
		}
		reqs := pendingReqs[name]
		pending[name] = nil
		pendingReqs[name] = nil
		s.flushBatch(events, reqs)
		s.updateQueueMetrics(pending)
	}
	flushAll := func() {
		for _, lane := range s.lanes {
			flushPriority(lane.name)
		}
	}
	for {
		chosen, recv, ok := reflect.Select(cases)
		switch {
		case chosen < len(s.lanes):
			if !ok {
				continue
			}
			req := recv.Interface().(batchRequest)
			lane := s.lanes[chosen]
			pending[lane.name] = append(pending[lane.name], req.events...)
			pendingReqs[lane.name] = append(pendingReqs[lane.name], req)
			if len(pending[lane.name]) >= lane.config.MaxBatch {
				flushPriority(lane.name)
			} else {
				s.updateQueueMetrics(pending)
			}
		case chosen == len(s.lanes):
			flushAll()
		case chosen == len(s.lanes)+1:
			flushAll()
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

func (s *Service) flushBatch(events []model.SystemEventRecord, reqs []batchRequest) {
	if len(events) == 0 {
		return
	}
	if err := s.store.InsertSystemEvents(context.Background(), events); err != nil {
		if s.log != nil {
			s.log.Error("persist system events failed", "error", err, "count", len(events))
		}
		if s.metrics != nil {
			s.metrics.SystemEventsDropped.Add(float64(len(events)))
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
			priority := priorityLabel(evt.Priority)
			tier := tierLabel(evt.StorageTier)
			s.metrics.SystemEventsIngestedByTier.WithLabelValues(priority, tier).Inc()
			if !evt.ReceivedAt.IsZero() {
				s.metrics.SystemEventsLatency.Observe(now.Sub(evt.ReceivedAt).Seconds())
			}
		}
	}
	s.dispatchToConsumers(events)
	for _, req := range reqs {
		req.done <- nil
	}
}

func (s *Service) updateQueueMetrics(pending map[string][]model.SystemEventRecord) {
	if s.metrics == nil {
		return
	}
	total := 0
	for _, lane := range s.lanes {
		depth := len(lane.queue) + len(pending[lane.name])
		s.metrics.SystemEventsQueueByPriority.WithLabelValues(lane.name).Set(float64(depth))
		s.checkBackpressure(lane, depth)
		total += depth
	}
	s.metrics.SystemEventsQueue.Set(float64(total))
}

func (s *Service) checkBackpressure(lane *priorityLane, depth int) {
	if lane == nil || lane.config.QueueCapacity <= 0 {
		return
	}
	ratio := float64(depth) / float64(lane.config.QueueCapacity)
	if ratio >= lane.threshold {
		now := time.Now()
		if !lane.alertActive || now.Sub(lane.lastAlert) >= lane.cooldown {
			lane.alertActive = true
			lane.lastAlert = now
			if s.metrics != nil {
				s.metrics.SystemEventsBackpressure.WithLabelValues(lane.name, "saturation").Inc()
			}
			if s.log != nil {
				s.log.Warn("system events queue reaching capacity", "priority", lane.name, "depth", depth, "capacity", lane.config.QueueCapacity)
			}
		}
		return
	}
	if lane.alertActive && ratio <= lane.threshold*0.8 {
		lane.alertActive = false
	}
}

// Enqueue persists the provided events, blocking until flushed or the context cancels.
func (s *Service) Enqueue(ctx context.Context, priority string, events []model.SystemEventRecord) error {
	if s == nil || len(events) == 0 {
		return nil
	}
	lane := s.laneFor(priority)
	if lane == nil {
		return errors.New("event queue unavailable")
	}
	req := batchRequest{
		priority: lane.name,
		events:   cloneEvents(events),
		done:     make(chan error, 1),
	}
	select {
	case lane.queue <- req:
	default:
		if err := s.handleBackpressure(lane, req); err != nil {
			return err
		}
	}
	select {
	case err := <-req.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) handleBackpressure(lane *priorityLane, req batchRequest) error {
	if lane == nil {
		return ErrBackpressure
	}
	switch lane.dropPolicy {
	case "spillover":
		if lane.spillover != nil {
			if s.metrics != nil {
				s.metrics.SystemEventsBackpressure.WithLabelValues(lane.name, "spillover").Inc()
			}
			return s.enqueueSpillover(lane.spillover, req)
		}
	}
	if s.metrics != nil {
		s.metrics.SystemEventsBackpressure.WithLabelValues(lane.name, "block").Inc()
		s.metrics.SystemEventsDropped.Add(float64(len(req.events)))
	}
	if s.log != nil {
		s.log.Warn("system events queue backpressure", "priority", lane.name, "reason", lane.dropPolicy, "events", len(req.events))
	}
	return ErrBackpressure
}

func (s *Service) enqueueSpillover(lane *priorityLane, req batchRequest) error {
	if lane == nil {
		return ErrBackpressure
	}
	select {
	case lane.queue <- req:
		return nil
	default:
		return s.handleBackpressure(lane, req)
	}
}

func (s *Service) laneFor(priority string) *priorityLane {
	if len(s.lanes) == 0 {
		return nil
	}
	name := strings.ToLower(strings.TrimSpace(priority))
	if idx, ok := s.laneIndex[name]; ok {
		return s.lanes[idx]
	}
	if idx, ok := s.laneIndex[s.defaultPriority]; ok {
		return s.lanes[idx]
	}
	return s.lanes[0]
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

// RegisterConsumer attaches an asynchronous consumer that is notified after successful flushes.
func (s *Service) RegisterConsumer(consumer Consumer) {
	if s == nil || consumer == nil {
		return
	}
	s.consumers = append(s.consumers, consumer)
}

func (s *Service) dispatchToConsumers(events []model.SystemEventRecord) {
	if len(s.consumers) == 0 || len(events) == 0 {
		return
	}
	for _, consumer := range s.consumers {
		if consumer == nil {
			continue
		}
		batch := make([]model.SystemEventRecord, len(events))
		copy(batch, events)
		go consumer.Consume(context.Background(), batch)
	}
}

func orderedPriorities(cfg config.EventsConfig) []string {
	if len(cfg.PriorityQueues) == 0 {
		return []string{strings.ToLower(strings.TrimSpace(cfg.DefaultPriority))}
	}
	seen := make(map[string]struct{}, len(cfg.PriorityQueues))
	appendIf := func(list []string, name string) []string {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return list
		}
		if _, ok := cfg.PriorityQueues[name]; !ok {
			return list
		}
		if _, ok := seen[name]; ok {
			return list
		}
		seen[name] = struct{}{}
		return append(list, name)
	}
	order := make([]string, 0, len(cfg.PriorityQueues))
	order = appendIf(order, "high")
	order = appendIf(order, cfg.DefaultPriority)
	order = appendIf(order, "normal")
	order = appendIf(order, "low")
	var rest []string
	for name := range cfg.PriorityQueues {
		name = strings.ToLower(strings.TrimSpace(name))
		if _, ok := seen[name]; ok {
			continue
		}
		rest = append(rest, name)
	}
	sort.Strings(rest)
	order = append(order, rest...)
	return order
}

func priorityLabel(v string) string {
	name := strings.ToLower(strings.TrimSpace(v))
	if name == "" {
		return "normal"
	}
	return name
}

func tierLabel(v string) string {
	name := strings.ToLower(strings.TrimSpace(v))
	if name == "" {
		return "hot"
	}
	return name
}
