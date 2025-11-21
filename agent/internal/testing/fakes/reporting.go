package fakes

import (
	"testing"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

// NewReportManager returns a reporting.Manager whose base directory lives under t.TempDir().
func NewReportManager(t *testing.T) (*reporting.Manager, config.Config) {
	t.Helper()
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	return reporting.NewManager(cfg), cfg
}
