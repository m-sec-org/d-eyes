package tasks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/m-sec-org/d-eyes/agent/internal/cmdexec"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

func TestSupplyChainCaptureAuditsCommandExecution(t *testing.T) {
	binDir := t.TempDir()
	writeDummyCommand(t, binDir, "pip", []string{"requests==2.0.0"}, nil)
	prependPath(t, binDir)

	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	cfg.Sandbox.AllowedCommands = []string{"pip"}
	cfg.Sandbox.LogPath = ""
	cmdexec.Configure(cfg)

	req := TaskRequest{Config: cfg, Flags: map[string]any{"mode": "capture"}}
	req.ApplyDefaults("supplychain")
	runner := supplyChainRunner{}

	_, err := runner.Run(context.Background(), req)
	if err != nil {
		t.Fatalf("supplychain capture: %v", err)
	}

	record := findAuditRecord(t, filepath.Join(cfg.Output.Dir, "audit", "command-exec.jsonl"), "tasks.supplychain capture pip list")
	assertAuditRecordFields(t, record)
	if record["command"] != "pip" {
		t.Fatalf("expected audit command pip, got %#v", record["command"])
	}
}

func prependPath(t *testing.T, dir string) {
	t.Helper()
	existing := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+existing)
}

func writeDummyCommand(t *testing.T, dir, name string, stdoutLines, stderrLines []string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, name+".bat")
		lines := []string{"@echo off"}
		for _, line := range stdoutLines {
			lines = append(lines, "echo "+line)
		}
		for _, line := range stderrLines {
			lines = append(lines, "echo "+line+" 1>&2")
		}
		content := strings.Join(lines, "\r\n") + "\r\n"
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write dummy command: %v", err)
		}
		return
	}

	path := filepath.Join(dir, name)
	var builder strings.Builder
	builder.WriteString("#!/bin/sh\n")
	for _, line := range stdoutLines {
		builder.WriteString("echo ")
		builder.WriteString(shellQuote(line))
		builder.WriteString("\n")
	}
	for _, line := range stderrLines {
		builder.WriteString("echo ")
		builder.WriteString(shellQuote(line))
		builder.WriteString(" 1>&2\n")
	}
	builder.WriteString("exit 0\n")
	if err := os.WriteFile(path, []byte(builder.String()), 0o755); err != nil {
		t.Fatalf("write dummy command: %v", err)
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func findAuditRecord(t *testing.T, logPath, identifier string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(lines[i]), &record); err != nil {
			t.Fatalf("unmarshal audit record: %v", err)
		}
		if record["id"] == identifier {
			return record
		}
	}
	t.Fatalf("audit record not found for id %q", identifier)
	return nil
}

func assertAuditRecordFields(t *testing.T, record map[string]any) {
	t.Helper()
	required := []string{
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
	}
	for _, key := range required {
		if _, ok := record[key]; !ok {
			t.Fatalf("missing audit field %q in %#v", key, record)
		}
	}
}
