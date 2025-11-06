package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func requirePosix(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("sandbox manager tests rely on POSIX shell")
	}
}

func TestManagerHostExecution(t *testing.T) {
	requirePosix(t)
	mgr := NewManager(Config{})

	res, err := mgr.Run(context.Background(), RunRequest{
		Command: "/bin/sh",
		Args:    []string{"-c", "echo sandbox"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", res.ExitCode)
	}
	if res.Sandboxed {
		t.Fatalf("expected sandboxed=false for host execution")
	}
}

func TestManagerDeniedCommand(t *testing.T) {
	requirePosix(t)
	mgr := NewManager(Config{
		Denied: []string{"echo"},
	})
	_, err := mgr.Run(context.Background(), RunRequest{
		Command: "/bin/echo",
		Args:    []string{"forbidden"},
	})
	if err == nil {
		t.Fatalf("expected command to be denied")
	}
}

func TestManagerSandboxApprovalRequired(t *testing.T) {
	requirePosix(t)
	mgr := NewManager(Config{
		Enabled: true,
		Runtime: "gvisor",
	})
	_, err := mgr.Run(context.Background(), RunRequest{
		Command:    "/bin/sh",
		Args:       []string{"-c", "echo pending"},
		UseSandbox: true,
		// SandboxApproved defaults to false, expect approval error.
	})
	if !errors.Is(err, errSandboxApprovalRequired) {
		t.Fatalf("expected approval error, got %v", err)
	}
}

func TestManagerSandboxFallback(t *testing.T) {
	requirePosix(t)
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "sandbox.log")
	mgr := NewManager(Config{
		Enabled:        true,
		Runtime:        "gvisor",
		RuntimeBinary:  "non-existent-runtime",
		FallbackToHost: true,
		LogPath:        logPath,
	})
	res, err := mgr.Run(context.Background(), RunRequest{
		Command:         "/bin/sh",
		Args:            []string{"-c", "echo fallback"},
		UseSandbox:      true,
		SandboxApproved: true,
	})
	if err != nil {
		t.Fatalf("unexpected error with fallback: %v", err)
	}
	if !res.Fallback {
		t.Fatalf("expected fallback to host execution when sandbox runtime missing")
	}
	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("expected log file to be created, got %v", err)
	}
}
