package agent

import (
	"testing"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/collector"
)

func TestFilterCollectorsByKind(t *testing.T) {
	configs := []collector.Config{
		{Name: "etw1", Kind: collector.KindETW},
		{Name: "ebpf1", Kind: collector.KindEBPF},
	}
	filtered := filterCollectorsByKind(configs, []string{"ebpf"})
	if len(filtered) != 1 {
		t.Fatalf("expected 1 config, got %d", len(filtered))
	}
	if filtered[0].Kind != collector.KindEBPF {
		t.Fatalf("unexpected kind: %s", filtered[0].Kind)
	}
}

func TestBuildAdhocCollectorsCreatesEBPF(t *testing.T) {
	overrides := collectCLIOverrides{
		probes: []string{"sys_enter_execve"},
		output: collector.Output{
			Mode: "stream",
			Stream: collector.CollectorStreamConfig{
				URL:           "https://example",
				APIKey:        "token",
				MaxBatch:      5,
				FlushInterval: time.Second,
			},
		},
	}
	configs := buildAdhocCollectors(overrides, []string{"ebpf", "EBPF"})
	if len(configs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(configs))
	}
	cfg := configs[0]
	if cfg.Kind != collector.KindEBPF {
		t.Fatalf("unexpected kind: %s", cfg.Kind)
	}
	if len(cfg.Probes) != 1 || cfg.Probes[0] != "sys_enter_execve" {
		t.Fatalf("unexpected probes: %+v", cfg.Probes)
	}
	if cfg.Output.Stream.URL != "https://example" {
		t.Fatalf("unexpected stream url: %s", cfg.Output.Stream.URL)
	}
	if cfg.Output.Stream.MaxBatch != 5 {
		t.Fatalf("unexpected max batch: %d", cfg.Output.Stream.MaxBatch)
	}
}

func TestCountEnabledCollectors(t *testing.T) {
	configs := []collector.Config{
		{Name: "c1"},
		{Name: "c2", Disabled: true},
	}
	if got := countEnabledCollectors(configs); got != 1 {
		t.Fatalf("expected 1 enabled collector, got %d", got)
	}
}

func TestWaitForCollectorStartup(t *testing.T) {
	statuses := [][]collector.CollectorStatus{
		{{Name: "c1", State: "stopped"}},
		{{Name: "c1", State: "running"}},
	}
	var calls int
	fn := func() []collector.CollectorStatus {
		defer func() { calls++ }()
		if calls >= len(statuses) {
			return statuses[len(statuses)-1]
		}
		return statuses[calls]
	}
	got := waitForCollectorStartup(fn, 1, time.Second, nil)
	if countRunningCollectors(got) != 1 {
		t.Fatalf("expected running collector after wait, got %+v", got)
	}
	if calls < 2 {
		t.Fatalf("expected at least two status polls, got %d", calls)
	}
}
