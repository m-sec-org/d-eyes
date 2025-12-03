package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultAssignsFallbacks(t *testing.T) {
	cfg := Default()
	if cfg.Output.Format != "json" {
		t.Fatalf("expected default json format, got %s", cfg.Output.Format)
	}
	if cfg.Policy.FailOn == "" || cfg.Policy.SeverityMin == "" {
		t.Fatalf("policy defaults should be populated")
	}
}

func TestLoadMergesOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `output:
  dir: "` + filepath.Join(dir, "reports") + `"
policy:
  fail_on: high
performance:
  timeout: 5s
sandbox:
  enabled: true
  runtime: "docker"
remote:
  labels:
    network_boundary: dmz
tasks:
  respond:
    profile: quick
collectors:
  - name: win-etw
    kind: etw
    providers: ["Kernel", "Security"]
    filters:
      include:
        event_type: ["process"]
    sampling:
      rate: 0.5
      interval: 2s
      burst: 10
    output:
      mode: file
      path: "` + filepath.Join(dir, "etw.jsonl") + `"
      buffer_size: 2048
    settings:
      session: win-default
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if cfg.Output.Dir != filepath.Join(dir, "reports") {
		t.Fatalf("output dir not merged: %s", cfg.Output.Dir)
	}
	if cfg.Policy.FailOn != "high" {
		t.Fatalf("policy not merged")
	}
	if cfg.Performance.Timeout != 5*time.Second {
		t.Fatalf("timeout not merged: %s", cfg.Performance.Timeout)
	}
	if !cfg.Sandbox.Enabled || cfg.Sandbox.Runtime != "docker" {
		t.Fatalf("sandbox overrides missing")
	}
	if cfg.Tasks.Respond.Profile != "quick" {
		t.Fatalf("tasks overrides missing")
	}
	if cfg.Remote.Labels["network_boundary"] != "dmz" {
		t.Fatalf("remote labels not merged")
	}
	if len(cfg.Collectors) != 1 {
		t.Fatalf("expected one collector, got %d", len(cfg.Collectors))
	}
	col := cfg.Collectors[0]
	if col.Name != "win-etw" || col.Kind != "etw" {
		t.Fatalf("collector fields not parsed: %+v", col)
	}
	if col.Sampling.Interval != 2*time.Second || col.Sampling.Rate != 0.5 {
		t.Fatalf("collector sampling not parsed: %+v", col.Sampling)
	}
	if col.Output.Path != filepath.Join(dir, "etw.jsonl") || col.Output.BufferSize != 2048 {
		t.Fatalf("collector output not parsed: %+v", col.Output)
	}
	if col.Filters.Include["event_type"][0] != "process" {
		t.Fatalf("collector filters not parsed: %+v", col.Filters)
	}
	if col.Settings["session"] != "win-default" {
		t.Fatalf("collector settings missing: %+v", col.Settings)
	}
}

func TestLoadMissingFileReturnsDefault(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatalf("Load should not error: %v", err)
	}
	if cfg.Output.Format != "json" {
		t.Fatalf("unexpected default format: %s", cfg.Output.Format)
	}
}
