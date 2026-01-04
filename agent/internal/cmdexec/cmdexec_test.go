package cmdexec

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

func TestConfigureDefaultPolicyEnforcesAllowlistAndLogs(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	cfg.Sandbox.AllowedCommands = nil
	cfg.Sandbox.LogPath = ""

	Configure(cfg)

	p := GetPolicy()
	expectedLog := filepath.Join(cfg.Output.Dir, "audit", "command-exec.jsonl")
	if p.LogPath != expectedLog {
		t.Fatalf("expected log path %q, got %q", expectedLog, p.LogPath)
	}
	if len(p.Allowed) == 0 {
		t.Fatalf("expected default allowlist to be non-empty")
	}

	_, err := Run(context.Background(), Request{Command: "definitely-not-a-command"})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "command denied") {
		t.Fatalf("expected command denied error, got %v", err)
	}

	raw, err := os.ReadFile(expectedLog)
	if err != nil {
		t.Fatalf("expected audit log file to exist: %v", err)
	}
	if !strings.Contains(string(raw), `"command":"definitely-not-a-command"`) {
		t.Fatalf("expected audit log to contain command entry, got %q", string(raw))
	}

	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 0 {
		t.Fatalf("expected audit log to contain records")
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &record); err != nil {
		t.Fatalf("expected audit record to be valid json: %v", err)
	}
	for _, key := range []string{
		"timestamp",
		"id",
		"command",
		"args",
		"working_dir",
		"use_sandbox",
		"sandboxed",
		"fallback_to_host",
		"exit_code",
		"duration_seconds",
		"error",
	} {
		if _, ok := record[key]; !ok {
			t.Fatalf("expected audit record to contain %q, got %#v", key, record)
		}
	}
}

func TestConfigureAllowsAllWithWildcard(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	cfg.Sandbox.AllowedCommands = []string{"*"}
	cfg.Sandbox.LogPath = "off"

	Configure(cfg)

	p := GetPolicy()
	if len(p.Allowed) != 0 {
		t.Fatalf("expected allow-all policy to have empty allowlist, got %#v", p.Allowed)
	}

	_, err := Run(context.Background(), Request{Command: "definitely-not-a-command"})
	if err == nil {
		t.Fatalf("expected execution error, got nil")
	}
	if strings.Contains(strings.ToLower(err.Error()), "command denied") {
		t.Fatalf("expected non-policy error, got %v", err)
	}
}

func TestConfigureDisablesLogging(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	cfg.Sandbox.LogPath = "off"

	Configure(cfg)

	p := GetPolicy()
	if p.LogPath != "" {
		t.Fatalf("expected logging disabled, got log path %q", p.LogPath)
	}

	defaultLogPath := filepath.Join(cfg.Output.Dir, "audit", "command-exec.jsonl")
	_, _ = Run(context.Background(), Request{Command: "definitely-not-a-command"})
	if _, err := os.Stat(defaultLogPath); err == nil {
		t.Fatalf("expected no audit log file, found %s", defaultLogPath)
	}
}
