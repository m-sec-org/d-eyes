package collector

import (
	"context"
	"time"
)

// Kind identifies a collector type (e.g. etw, ebpf).
type Kind string

// Common collector kinds.
const (
	KindETW  Kind = "etw"
	KindEBPF Kind = "ebpf"
)

// SystemEvent represents a normalized system-level event emitted by ETW/eBPF collectors.
type SystemEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	EventType string                 `json:"event_type"`
	Source    string                 `json:"source"`
	Payload   map[string]any         `json:"payload,omitempty"`
	Metadata  map[string]string      `json:"metadata,omitempty"`
	Sequence  uint64                 `json:"sequence,omitempty"`
	Tags      map[string]string      `json:"tags,omitempty"`
	Raw       map[string]interface{} `json:"raw,omitempty"`
}

// EventHandler consumes events produced by a collector.
type EventHandler interface {
	HandleEvent(ctx context.Context, event *SystemEvent) error
}

// EventHandlerFunc adapts a function to the EventHandler interface.
type EventHandlerFunc func(context.Context, *SystemEvent) error

// HandleEvent invokes f(ctx, event).
func (f EventHandlerFunc) HandleEvent(ctx context.Context, event *SystemEvent) error {
	if f == nil {
		return nil
	}
	return f(ctx, event)
}

// CollectorStatus conveys runtime state for diagnostics.
type CollectorStatus struct {
	Name      string            `json:"name"`
	Kind      Kind              `json:"kind"`
	State     string            `json:"state"`
	StartedAt time.Time         `json:"started_at"`
	LastError string            `json:"last_error,omitempty"`
	Stats     map[string]any    `json:"stats,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// EventCollector defines lifecycle and status hooks that platform-specific collectors must implement.
type EventCollector interface {
	Name() string
	Start(ctx context.Context, handler EventHandler) error
	Stop(ctx context.Context) error
	Status() CollectorStatus
}

// Factory creates collectors for the supplied configuration.
type Factory func(cfg Config) (EventCollector, error)

// Config describes a collector instance.
type Config struct {
	Name      string            `json:"name"`
	Kind      Kind              `json:"kind"`
	Disabled  bool              `json:"disabled,omitempty"`
	Providers []string          `json:"providers,omitempty"`
	Probes    []string          `json:"probes,omitempty"`
	Filters   Filters           `json:"filters"`
	Sampling  Sampling          `json:"sampling"`
	Output    Output            `json:"output"`
	Settings  map[string]any    `json:"settings,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
}

// Filters controls include/exclude rules for events.
type Filters struct {
	Include map[string][]string `json:"include,omitempty"`
	Exclude map[string][]string `json:"exclude,omitempty"`
}

// Sampling tunes rate/interval controls.
type Sampling struct {
	Rate              float64       `json:"rate,omitempty"`
	Interval          time.Duration `json:"interval,omitempty"`
	Burst             int           `json:"burst,omitempty"`
	MaxEventsPerBatch int           `json:"max_events_per_batch,omitempty"`
}

// Output determines how events are emitted (stream/file/etc).
type Output struct {
	Mode       string                `json:"mode,omitempty"`
	Path       string                `json:"path,omitempty"`
	BufferSize int                   `json:"buffer_size,omitempty"`
	BatchSize  int                   `json:"batch_size,omitempty"`
	Stream     CollectorStreamConfig `json:"stream"`
}

// CollectorStreamConfig describes HTTP streaming output.
type CollectorStreamConfig struct {
	URL           string        `json:"url,omitempty"`
	APIKey        string        `json:"api_key,omitempty"`
	AgentID       string        `json:"agent_id,omitempty"`
	AgentName     string        `json:"agent_name,omitempty"`
	MaxBatch      int           `json:"max_batch,omitempty"`
	FlushInterval time.Duration `json:"flush_interval,omitempty"`
}
