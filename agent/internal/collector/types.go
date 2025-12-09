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

// ConfigurableCollector can apply runtime config updates without restart.
type ConfigurableCollector interface {
	UpdateConfig(cfg Config)
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
	Parser    ParserConfig      `json:"parser"`
	Filters   Filters           `json:"filters"`
	Sampling  Sampling          `json:"sampling"`
	Output    Output            `json:"output"`
	Settings  map[string]any    `json:"settings,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
}

// ParserConfig configures builtin/plug-in parsers.
type ParserConfig struct {
	Enabled  []string             `json:"enabled,omitempty"`
	Disabled []string             `json:"disabled,omitempty"`
	Plugins  []ParserPluginConfig `json:"plugins,omitempty"`
	Settings map[string]any       `json:"settings,omitempty"`
}

// ParserPluginConfig declares an external parser module.
type ParserPluginConfig struct {
	Name     string            `json:"name"`
	Path     string            `json:"path,omitempty"`
	Type     string            `json:"type,omitempty"`
	Checksum string            `json:"checksum,omitempty"`
	Config   map[string]any    `json:"config,omitempty"`
	Enabled  bool              `json:"enabled"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Filters controls include/exclude rules for events.
type Filters struct {
	Include map[string][]string `json:"include,omitempty"`
	Exclude map[string][]string `json:"exclude,omitempty"`
	Rules   []FilterRule        `json:"rules,omitempty"`
}

// FilterRule describes a rule-based filter evaluation.
type FilterRule struct {
	Name       string            `json:"name,omitempty"`
	Action     string            `json:"action,omitempty"`
	Conditions []FilterCondition `json:"conditions,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	Threshold  FilterThreshold   `json:"threshold,omitempty"`
	Enabled    bool              `json:"enabled"`
}

// FilterCondition describes an individual clause.
type FilterCondition struct {
	Field    string   `json:"field,omitempty"`
	Operator string   `json:"operator,omitempty"`
	Value    string   `json:"value,omitempty"`
	Values   []string `json:"values,omitempty"`
	Regex    string   `json:"regex,omitempty"`
}

// FilterThreshold controls frequency-based gating.
type FilterThreshold struct {
	Count  int           `json:"count,omitempty"`
	Window time.Duration `json:"window,omitempty"`
}

// Sampling tunes rate/interval controls.
type Sampling struct {
	Rate              float64        `json:"rate,omitempty"`
	Interval          time.Duration  `json:"interval,omitempty"`
	Burst             int            `json:"burst,omitempty"`
	MaxEventsPerBatch int            `json:"max_events_per_batch,omitempty"`
	Rules             []SamplingRule `json:"rules,omitempty"`
}

// SamplingRule adjusts rates for subsets of events.
type SamplingRule struct {
	Name       string              `json:"name,omitempty"`
	EventTypes []string            `json:"event_types,omitempty"`
	Match      map[string][]string `json:"match,omitempty"`
	Rate       float64             `json:"rate,omitempty"`
	Burst      int                 `json:"burst,omitempty"`
	Window     time.Duration       `json:"window,omitempty"`
	Enabled    bool                `json:"enabled"`
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
