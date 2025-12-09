package collector

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
)

// DetectionAction declares how the collector should react to a detection.
type DetectionAction string

const (
	// DetectionActionAlert records the detection and forwards it downstream without auto response.
	DetectionActionAlert DetectionAction = "alert"
	// DetectionActionRespond triggers the Respond automation pipeline.
	DetectionActionRespond DetectionAction = "respond"
)

// DetectionResult captures metadata about a detector hit emitted by collectors.
type DetectionResult struct {
	ID             string
	RuleID         string
	Name           string
	Category       string
	Severity       string
	Action         DetectionAction
	Description    string
	Confidence     float64
	RespondProfile string
	Tags           map[string]string
	Metadata       map[string]string
}

// DetectionSink consumes detector hits (e.g. to trigger Respond tasks or record telemetry).
type DetectionSink interface {
	OnDetection(ctx context.Context, event *SystemEvent, result DetectionResult)
}

type detectionStats struct {
	total   atomic.Uint64
	byRule  sync.Map
	lastIDs sync.Map
}

func (s *detectionStats) Record(rule string, id string) {
	if s == nil {
		return
	}
	s.total.Add(1)
	if rule == "" {
		rule = "unknown"
	}
	counter, _ := s.byRule.LoadOrStore(rule, &atomic.Uint64{})
	counter.(*atomic.Uint64).Add(1)
	if id != "" {
		s.lastIDs.Store(rule, id)
	}
}

func (s *detectionStats) Snapshot() (total uint64, perRule map[string]uint64, ids map[string]string) {
	if s == nil {
		return 0, nil, nil
	}
	total = s.total.Load()
	perRule = make(map[string]uint64)
	s.byRule.Range(func(key, value any) bool {
		name := strings.ReplaceAll(key.(string), " ", "_")
		perRule[name] = value.(*atomic.Uint64).Load()
		return true
	})
	ids = make(map[string]string)
	s.lastIDs.Range(func(key, value any) bool {
		name := strings.ReplaceAll(key.(string), " ", "_")
		if v, ok := value.(string); ok {
			ids[name] = v
		}
		return true
	})
	return total, perRule, ids
}

// detectionAwareCollector allows injection of detection sinks.
type detectionAwareCollector interface {
	SetDetectionSink(sink DetectionSink)
}

func cloneSystemEvent(event *SystemEvent) *SystemEvent {
	if event == nil {
		return nil
	}
	out := &SystemEvent{
		Timestamp: event.Timestamp,
		EventType: event.EventType,
		Source:    event.Source,
		Sequence:  event.Sequence,
	}
	if len(event.Metadata) > 0 {
		out.Metadata = make(map[string]string, len(event.Metadata))
		for k, v := range event.Metadata {
			out.Metadata[k] = v
		}
	}
	if len(event.Tags) > 0 {
		out.Tags = make(map[string]string, len(event.Tags))
		for k, v := range event.Tags {
			out.Tags[k] = v
		}
	}
	if len(event.Payload) > 0 {
		out.Payload = make(map[string]any, len(event.Payload))
		for k, v := range event.Payload {
			out.Payload[k] = v
		}
	}
	if len(event.Raw) > 0 {
		out.Raw = make(map[string]interface{}, len(event.Raw))
		for k, v := range event.Raw {
			out.Raw[k] = v
		}
	}
	return out
}
