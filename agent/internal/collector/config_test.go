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
				Parser: config.CollectorParserConfig{
					Enabled:  []string{"security"},
					Disabled: []string{"legacy"},
					Plugins: []config.CollectorParserPluginConfig{
						{
							Name:    "defender-ext",
							Path:    "plugins/defender.so",
							Enabled: true,
							Config:  map[string]any{"severity": "high"},
						},
					},
					Settings: map[string]any{"max_stack": 8},
				},
				Filters: config.CollectorFilterConfig{
					Include: map[string][]string{"event_type": {"process"}},
					Rules: []config.CollectorFilterRuleConfig{
						{
							Name:   "drop-debug",
							Action: "drop",
							Conditions: []config.CollectorFilterConditionConfig{
								{Field: "level", Operator: "equals", Value: "debug"},
							},
							Threshold: config.CollectorFilterThresholdConfig{
								Count:  10,
								Window: 5 * time.Second,
							},
							Enabled: true,
						},
					},
				},
				Sampling: config.CollectorSamplingConfig{
					Rate:     0.5,
					Interval: time.Second,
					Burst:    5,
					Strategies: []config.CollectorSamplingStrategyConfig{
						{
							Name:       "high-priority",
							EventTypes: []string{"process"},
							Match:      map[string][]string{"level": {"5"}},
							Rate:       0.2,
							Burst:      1,
							Window:     3 * time.Second,
							Enabled:    true,
						},
					},
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
	if len(got.Filters.Rules) != 1 || got.Filters.Rules[0].Name != "drop-debug" {
		t.Fatalf("filter rules mismatch: %+v", got.Filters.Rules)
	}
	if len(got.Parser.Plugins) != 1 || !got.Parser.Plugins[0].Enabled {
		t.Fatalf("parser plugins mismatch: %+v", got.Parser)
	}
	if got.Settings["session"] != "default" {
		t.Fatalf("settings mismatch: %+v", got.Settings)
	}
	if len(got.Sampling.Rules) != 1 || got.Sampling.Rules[0].Name != "high-priority" {
		t.Fatalf("sampling rules mismatch: %+v", got.Sampling.Rules)
	}
}
