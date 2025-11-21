package logs

import (
	"log"
	"os"
	"path/filepath"
	"testing"
)

func TestInitLogCreatesFileNextToExecutable(t *testing.T) {
	dir := t.TempDir()
	fakeExec := filepath.Join(dir, "agent-test")
	if err := os.WriteFile(fakeExec, []byte("#!/bin/sh"), 0o755); err != nil {
		t.Fatalf("prepare fake exec: %v", err)
	}
	executable = func() (string, error) { return fakeExec, nil }
	defer func() { executable = os.Executable }()

	defer log.SetOutput(os.Stderr)
	InitLog()

	target := filepath.Join(dir, "d-eyes.logs")
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("expected log file: %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("expected empty log by default")
	}
}
