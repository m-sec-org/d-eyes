package tasks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/testing/fakes"
	"github.com/m-sec-org/d-eyes/agent/pkg/threatintel"
)

func TestExtractIndicatorsDeduplicates(t *testing.T) {
	text := `visit https://example.com/login from 8.8.8.8 using hash deadbeefdeadbeefdeadbeefdeadbeef`
	matches := extractIndicators(text)
	require.Len(t, matches, 4)
	kinds := make(map[threatintel.IndicatorKind]bool)
	for _, m := range matches {
		kinds[m.Kind] = true
	}
	require.True(t, kinds[threatintel.IndicatorURL])
	require.True(t, kinds[threatintel.IndicatorIP])
	require.True(t, kinds[threatintel.IndicatorHash])
}

func TestTICollectorCreatesReport(t *testing.T) {
	mgr, cfg := fakes.NewReportManager(t)
	ti, err := threatintel.NewManager(threatintel.Config{Mode: threatintel.ModeLocal})
	require.NoError(t, err)

	req := TaskRequest{Profile: "default", Config: cfg, Manager: mgr, ThreatIntel: ti}
	collector := newTICollector(req)
	require.NotNil(t, collector)

	collector.LookupIndicator(context.Background(), threatintel.IndicatorIP, "8.8.8.8", nil)
	outputs, notes := collector.Flush("respond", "ti", "TI Report")
	require.Len(t, outputs, 1)
	require.Len(t, notes, 0)
	if _, err := os.Stat(outputs[0].Path); err != nil {
		t.Fatalf("expected output file: %v", err)
	}
}

func TestTICollectorRecordsErrors(t *testing.T) {
	mgr, cfg := fakes.NewReportManager(t)
	ti, err := threatintel.NewManager(threatintel.Config{Mode: threatintel.ModeLocal})
	require.NoError(t, err)

	req := TaskRequest{Profile: "default", Config: cfg, Manager: mgr, ThreatIntel: ti}
	collector := newTICollector(req)

	collector.LookupFile(context.Background(), "missing-file.bin", nil)
	outputs, notes := collector.Flush("respond", "ti-errors", "TI Errors")
	require.Len(t, outputs, 1)
	require.NotEmpty(t, notes)
	require.True(t, strings.Contains(notes[0], "威胁情报查询产生"))
}
