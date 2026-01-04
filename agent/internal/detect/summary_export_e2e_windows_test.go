//go:build windows

package detect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

func TestDetectExportWindowsE2E(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := config.Default()
	cfg.Output.Dir = filepath.Join(tmpDir, "reports")
	manager := reporting.NewManager(cfg)

	record, _, err := SaveSummaryBaseInfo(manager)
	if err != nil {
		t.Fatalf("SaveSummaryBaseInfo failed: %v", err)
	}
	if record.Path == "" {
		t.Fatalf("expected report path, got empty")
	}

	raw, err := os.ReadFile(record.Path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	out := string(raw)
	if !strings.Contains(out, "InterfaceInfo:\n") {
		t.Fatalf("expected InterfaceInfo section, got %q", out)
	}
	if !strings.Contains(out, "dns_server:") {
		t.Fatalf("expected dns_server output, got %q", out)
	}
	if !strings.Contains(out, "gateway:") {
		t.Fatalf("expected gateway output, got %q", out)
	}
}
