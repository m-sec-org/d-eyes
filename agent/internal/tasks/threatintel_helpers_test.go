package tasks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/testing/fakes"
	"github.com/m-sec-org/d-eyes/agent/pkg/artifacts"
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

func TestTICollectorIncludesThreatIntelMetadataWithoutRepeatingNotice(t *testing.T) {
	mgr, cfg := fakes.NewReportManager(t)
	ti, err := threatintel.NewManager(threatintel.Config{Mode: threatintel.ModeHybrid})
	require.NoError(t, err)

	req := TaskRequest{Profile: "default", Config: cfg, Manager: mgr, ThreatIntel: ti}
	collector := newTICollector(req)
	require.NotNil(t, collector)

	collector.LookupIndicator(context.Background(), threatintel.IndicatorIP, "8.8.8.8", nil)
	outputs, notes := collector.Flush("respond", "ti-meta", "TI Report")
	require.Len(t, outputs, 1)
	require.Len(t, notes, 0)

	raw, err := os.ReadFile(outputs[0].Path)
	require.NoError(t, err)

	var report struct {
		Metadata map[string]string `json:"metadata"`
		Findings []map[string]any  `json:"findings"`
		Errors   []string          `json:"errors"`
		Command  string            `json:"command"`
		Profile  string            `json:"profile"`
	}
	require.NoError(t, json.Unmarshal(raw, &report))
	require.Equal(t, "respond", report.Command)
	require.Equal(t, "default", report.Profile)
	require.Equal(t, "hybrid", report.Metadata["threatintel.mode_requested"])
	require.Equal(t, "local", report.Metadata["threatintel.mode_effective"])
	require.Equal(t, "false", report.Metadata["threatintel.remote_configured"])
	require.Equal(t, "false", report.Metadata["threatintel.remote_enabled"])
	require.Equal(t, "", report.Metadata["threatintel.remote_sources"])
	require.Equal(t, threatintel.NoticeCodeFallbackLocalNoAPIKey, report.Metadata["threatintel.notice"])
	require.Contains(t, report.Metadata["threatintel.notice_detail"], "已降级为 local")
	require.Len(t, report.Findings, 1)
	if _, ok := report.Findings[0]["notice"]; ok {
		t.Fatalf("expected finding notice to be omitted from report: %#v", report.Findings[0])
	}
	require.Empty(t, report.Errors)
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

func TestTICollectorUploadsArtifactsInServerMode(t *testing.T) {
	mgr, cfg := fakes.NewReportManager(t)
	cfg.ThreatIntel.Mode = threatintel.ModeServer
	req := TaskRequest{
		Profile:        "default",
		Config:         cfg,
		Manager:        mgr,
		Metadata:       map[string]string{},
		ArtifactClient: &stubArtifactClient{},
	}
	file := filepath.Join(t.TempDir(), "sample.bin")
	require.NoError(t, os.WriteFile(file, []byte("payload"), 0o644))

	collector := newTICollector(req)
	require.NotNil(t, collector)
	collector.LookupFile(context.Background(), file, nil)
	require.Contains(t, req.Metadata, artifactTokensMetadataKey)
	client := req.ArtifactClient.(*stubArtifactClient)
	require.Len(t, client.uploads, 1)
	require.Equal(t, "none", client.uploads[0].Encryption)
}

func TestTICollectorReportMetadataIncludesNoticeInServerMode(t *testing.T) {
	mgr, cfg := fakes.NewReportManager(t)
	cfg.ThreatIntel.Mode = threatintel.ModeServer
	req := TaskRequest{
		Profile:        "default",
		Config:         cfg,
		Manager:        mgr,
		Metadata:       map[string]string{},
		ArtifactClient: &errorArtifactClient{},
	}
	file := filepath.Join(t.TempDir(), "sample.bin")
	require.NoError(t, os.WriteFile(file, []byte("payload"), 0o644))

	collector := newTICollector(req)
	require.NotNil(t, collector)
	collector.LookupFile(context.Background(), file, nil)
	outputs, notes := collector.Flush("respond", "ti-server-meta", "TI Report")
	require.Len(t, outputs, 1)
	require.NotEmpty(t, notes)

	raw, err := os.ReadFile(outputs[0].Path)
	require.NoError(t, err)

	var report struct {
		Metadata map[string]string `json:"metadata"`
		Errors   []string          `json:"errors"`
	}
	require.NoError(t, json.Unmarshal(raw, &report))
	require.Equal(t, "server", report.Metadata["threatintel.mode_requested"])
	require.Equal(t, "server", report.Metadata["threatintel.mode_effective"])
	require.Equal(t, threatintel.NoticeCodeServerMode, report.Metadata["threatintel.notice"])
	require.NotEmpty(t, report.Errors)
}

type stubArtifactClient struct {
	uploads []artifacts.UploadInput
}

func (s *stubArtifactClient) Upload(ctx context.Context, input artifacts.UploadInput) (*artifacts.UploadResult, error) {
	s.uploads = append(s.uploads, input)
	return &artifacts.UploadResult{Token: "token-stub"}, nil
}

type errorArtifactClient struct{}

func (errorArtifactClient) Upload(context.Context, artifacts.UploadInput) (*artifacts.UploadResult, error) {
	return nil, os.ErrPermission
}
