package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
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
    parser:
      enabled: ["security", "defender"]
      disabled: ["legacy"]
      plugins:
        - name: defender-ext
          path: "` + filepath.Join(dir, "plugins", "defender.so") + `"
          type: go
          enabled: true
          metadata:
            arch: amd64
          config:
            severity: high
    filters:
      include:
        event_type: ["process"]
      rules:
        - name: drop-debug
          action: drop
          enabled: true
          tags:
            severity: low
          threshold:
            count: 50
            window: 5s
          conditions:
            - field: event_type
              operator: equals
              value: debug
    sampling:
      rate: 0.5
      interval: 2s
      burst: 10
      strategies:
        - name: proc-create
          event_types: ["process"]
          match:
            level: ["5"]
          rate: 0.2
          burst: 2
          window: 10s
          enabled: true
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
	if len(col.Sampling.Strategies) != 1 || col.Sampling.Strategies[0].Name != "proc-create" {
		t.Fatalf("sampling strategies missing: %+v", col.Sampling.Strategies)
	}
	if col.Output.Path != filepath.Join(dir, "etw.jsonl") || col.Output.BufferSize != 2048 {
		t.Fatalf("collector output not parsed: %+v", col.Output)
	}
	if col.Filters.Include["event_type"][0] != "process" {
		t.Fatalf("collector filters not parsed: %+v", col.Filters)
	}
	if len(col.Filters.Rules) != 1 || col.Filters.Rules[0].Name != "drop-debug" {
		t.Fatalf("collector filter rules missing: %+v", col.Filters.Rules)
	}
	if col.Parser.Enabled[0] != "security" || col.Parser.Disabled[0] != "legacy" {
		t.Fatalf("collector parser config missing: %+v", col.Parser)
	}
	if len(col.Parser.Plugins) != 1 || col.Parser.Plugins[0].Name != "defender-ext" {
		t.Fatalf("collector parser plugins missing: %+v", col.Parser.Plugins)
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

func TestEnsureDefaultConfigDoesNotOverwriteExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := []byte("output:\n  format: html\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	stamp := time.Date(2000, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatalf("set config timestamp: %v", err)
	}

	if err := EnsureDefaultConfig(path); err != nil {
		t.Fatalf("EnsureDefaultConfig error: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(after) != string(content) {
		t.Fatalf("expected existing config to be preserved, got:\n%s", string(after))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if !info.ModTime().Equal(stamp) {
		t.Fatalf("expected mod time %s, got %s", stamp, info.ModTime())
	}
}

func TestEnsureDefaultConfigConcurrentBootstrapDoesNotCorruptFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	path := filepath.Join(home, ".d-eyes", "config.yaml")
	expectedYAML, err := EncodeDefaultYAML()
	if err != nil {
		t.Fatalf("EncodeDefaultYAML error: %v", err)
	}

	if err := EnsureDefaultConfig(path); err != nil {
		t.Fatalf("EnsureDefaultConfig preflight error: %v", err)
	}
	requireEqualBytes(t, expectedYAML, path)
	requireNoTempFiles(t, filepath.Dir(path))

	_ = os.Remove(path)
	_ = os.Remove(filepath.Dir(path))

	const workers = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)

	errCh := make(chan error, 1)

	done := make(chan struct{})
	var observerWG sync.WaitGroup
	observerWG.Add(1)
	go func() {
		defer observerWG.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					time.Sleep(500 * time.Microsecond)
					continue
				}
				select {
				case errCh <- err:
				default:
				}
				return
			}
			if !bytes.Equal(raw, expectedYAML) {
				select {
				case errCh <- fmt.Errorf("observed corrupt or partial config content"):
				default:
				}
				return
			}
			time.Sleep(500 * time.Microsecond)
		}
	}()

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			<-start
			if err := EnsureDefaultConfig(path); err != nil {
				select {
				case errCh <- err:
				default:
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(done)
	observerWG.Wait()

	select {
	case err := <-errCh:
		t.Fatalf("concurrent bootstrap failed: %v", err)
	default:
	}

	requireEqualBytes(t, expectedYAML, path)
	requireNoTempFiles(t, filepath.Dir(path))

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if !reflect.DeepEqual(cfg, Default()) {
		t.Fatalf("loaded config mismatch after concurrent bootstrap")
	}
}

func TestEncodeDefaultYAMLStableAndLoadable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	expected := Default()
	first, err := EncodeDefaultYAML()
	if err != nil {
		t.Fatalf("EncodeDefaultYAML error: %v", err)
	}
	second, err := EncodeDefaultYAML()
	if err != nil {
		t.Fatalf("EncodeDefaultYAML error: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("expected deterministic yaml output")
	}
	if !strings.HasPrefix(string(first), "output:\n") {
		t.Fatalf("expected yaml to include output section, got:\n%s", string(first))
	}
	if strings.Contains(string(first), "Output:") {
		t.Fatalf("expected yaml to use file schema keys, not Go struct fields")
	}

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if loaded.Output.Dir != expected.Output.Dir {
		t.Fatalf("output dir mismatch: %s != %s", loaded.Output.Dir, expected.Output.Dir)
	}
	if loaded.Policy.FailOn != expected.Policy.FailOn {
		t.Fatalf("policy fail_on mismatch: %s != %s", loaded.Policy.FailOn, expected.Policy.FailOn)
	}
	if loaded.Remote.HeartbeatInterval != expected.Remote.HeartbeatInterval {
		t.Fatalf("remote heartbeat_interval mismatch: %s != %s", loaded.Remote.HeartbeatInterval, expected.Remote.HeartbeatInterval)
	}
	if loaded.ThreatIntel.Mode != expected.ThreatIntel.Mode {
		t.Fatalf("threat intel mode mismatch: %s != %s", loaded.ThreatIntel.Mode, expected.ThreatIntel.Mode)
	}
	if loaded.Remote.Labels["mode"] != "remote" {
		t.Fatalf("expected remote labels to include mode=remote, got: %#v", loaded.Remote.Labels)
	}
}

func requireEqualBytes(t *testing.T, expected []byte, path string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatalf("unexpected file content at %s", path)
	}
}

func requireNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "config.yaml.") {
			t.Fatalf("unexpected leftover temp config: %s", entry.Name())
		}
	}
}
