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
