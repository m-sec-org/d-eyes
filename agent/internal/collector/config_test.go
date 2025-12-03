package collector

import (
	"testing"
	"time"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

func TestFromAppConfigConvertsCollectors(t *testing.T) {
	appCfg := config.Config{
		Collectors: []config.CollectorConfig{
			{
				Name:      "etw",
				Kind:      "etw",
				Providers: []string{"Kernel"},
				Filters: config.CollectorFilterConfig{
					Include: map[string][]string{"event_type": {"process"}},
				},
				Sampling: config.CollectorSamplingConfig{
					Rate:     0.5,
					Interval: time.Second,
					Burst:    5,
				},
				Output: config.CollectorOutputConfig{
					Mode:       "file",
					Path:       "events.jsonl",
					BufferSize: 1024,
					Stream: config.CollectorStreamConfig{
						URL:           "https://example/api/v1/events",
						APIKey:        "secret",
						AgentID:       "agent-123",
						AgentName:     "edge-node-01",
						MaxBatch:      10,
						FlushInterval: 2 * time.Second,
					},
				},
				Settings: map[string]any{"session": "default"},
			},
		},
	}
	cfgs := FromAppConfig(appCfg)
	if len(cfgs) != 1 {
		t.Fatalf("expected one config, got %d", len(cfgs))
	}
	got := cfgs[0]
	if got.Name != "etw" || got.Kind != KindETW {
		t.Fatalf("unexpected config: %+v", got)
	}
	if got.Sampling.Interval != time.Second || got.Sampling.Rate != 0.5 {
		t.Fatalf("sampling mismatch: %+v", got.Sampling)
	}
	if got.Output.Path != "events.jsonl" || got.Output.BufferSize != 1024 {
		t.Fatalf("output mismatch: %+v", got.Output)
	}
	if got.Output.Stream.URL != "https://example/api/v1/events" || got.Output.Stream.APIKey != "secret" {
		t.Fatalf("stream config mismatch: %+v", got.Output.Stream)
	}
	if got.Output.Stream.AgentID != "agent-123" || got.Output.Stream.AgentName != "edge-node-01" {
		t.Fatalf("stream metadata mismatch: %+v", got.Output.Stream)
	}
	if got.Output.Stream.MaxBatch != 10 || got.Output.Stream.FlushInterval != 2*time.Second {
		t.Fatalf("stream batching mismatch: %+v", got.Output.Stream)
	}
	if got.Filters.Include["event_type"][0] != "process" {
		t.Fatalf("filters mismatch: %+v", got.Filters)
	}
	if got.Settings["session"] != "default" {
		t.Fatalf("settings mismatch: %+v", got.Settings)
	}
}
