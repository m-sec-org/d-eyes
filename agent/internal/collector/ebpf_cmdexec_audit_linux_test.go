//go:build linux

package collector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/m-sec-org/d-eyes/agent/internal/cmdexec"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

func TestCompileEmbeddedProgramAuditsClangExecution(t *testing.T) {
	toolDir := t.TempDir()
	clangPath := filepath.Join(toolDir, "clang")
	script := `#!/bin/sh
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-o" ]; then
    out="$arg"
    break
  fi
  prev="$arg"
done
if [ -z "$out" ]; then
  echo "missing -o" 1>&2
  exit 1
fi
echo "dummy-object" > "$out"
echo "clang-stderr" 1>&2
exit 0
`
	if err := os.WriteFile(clangPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write clang stub: %v", err)
	}

	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	cfg.Sandbox.AllowedCommands = []string{"clang"}
	cfg.Sandbox.LogPath = ""
	cmdexec.Configure(cfg)

	env := ebpfEnvironment{
		ClangPath: clangPath,
		Target:    "bpf",
		ArchMacro: "x86",
	}
	data, meta, err := compileEmbeddedProgram(context.Background(), env, nil)
	if err != nil {
		t.Fatalf("compileEmbeddedProgram: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("expected compiled object bytes to be non-empty")
	}
	if meta.Clang != clangPath {
		t.Fatalf("expected meta clang %q, got %q", clangPath, meta.Clang)
	}
	if meta.BuildLog != "clang-stderr" {
		t.Fatalf("expected build log clang-stderr, got %q", meta.BuildLog)
	}

	record := findAuditRecord(t, filepath.Join(cfg.Output.Dir, "audit", "command-exec.jsonl"), "collector.ebpf clang compile")
	assertAuditRecordFields(t, record)
	if record["command"] != clangPath {
		t.Fatalf("expected audit command %q, got %#v", clangPath, record["command"])
	}
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
