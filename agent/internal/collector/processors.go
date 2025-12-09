package collector

import (
	"context"
	"strings"
	"sync/atomic"
)

// EventProcessor mutates or short-circuits events before they are forwarded downstream.
type EventProcessor interface {
	Name() string
	Process(ctx context.Context, event *SystemEvent) (bool, error)
	Close() error
}

type processorStats struct {
	processed atomic.Uint64
	dropped   atomic.Uint64
}

func (s *processorStats) RecordProcessed() {
	if s == nil {
		return
	}
	s.processed.Add(1)
}

func (s *processorStats) RecordDropped() {
	if s == nil {
		return
	}
	s.dropped.Add(1)
}

func (s *processorStats) Snapshot(prefix string) map[string]uint64 {
	if s == nil {
		return nil
	}
	prefix = strings.TrimSuffix(prefix, ".")
	stats := map[string]uint64{
		prefix + ".processed": s.processed.Load(),
		prefix + ".dropped":   s.dropped.Load(),
	}
	return stats
}
