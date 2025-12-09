package collector

// EventFilterEngine evaluates rule-based filters against normalized events.
type EventFilterEngine interface {
	ShouldProcess(event *SystemEvent) bool
	UpdateConfig(cfg Filters) error
	Stats() FilterEngineStats
}

// FilterEngineStats exposes counters for diagnostics.
type FilterEngineStats struct {
	Evaluated uint64 `json:"evaluated"`
	Dropped   uint64 `json:"dropped"`
	UpdatedAt int64  `json:"updated_at"`
}

// EventSampler applies sampling policies before downstream processing.
type EventSampler interface {
	ShouldSample(eventType string, metadata map[string]string) bool
	UpdateConfig(cfg Sampling) error
	Stats() SamplerStats
}

// SamplerStats tracks sampling decisions.
type SamplerStats struct {
	Sampled   uint64  `json:"sampled"`
	Skipped   uint64  `json:"skipped"`
	UpdatedAt int64   `json:"updated_at"`
	Scale     float64 `json:"scale,omitempty"`
}
