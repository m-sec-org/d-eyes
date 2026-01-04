package tasks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/benchmark"
	"github.com/m-sec-org/d-eyes/agent/internal/benchmarkexec"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
	"github.com/m-sec-org/d-eyes/agent/pkg/threatintel"
)

func TestThreatIntelServerModeUploadsArtifactsAndSkipsRemoteRespondFileScan(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	target := t.TempDir()
	file := createTestFile(t, target, "malware.exe")

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	cfg.ThreatIntel.Mode = threatintel.ModeServer
	cfg.ThreatIntel.OpenTIPAPIKey = "key"
	cfg.ThreatIntel.OpenTIPBaseURL = server.URL

	req := TaskRequest{
		Config:         cfg,
		Flags:          map[string]any{"targets": target},
		Metadata:       map[string]string{},
		ArtifactClient: &fakeArtifactClient{},
	}
	req.Manager = reporting.NewManager(cfg)
	req.ApplyDefaults("respond")

	result, err := runFileScan(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, int32(0), calls.Load())
	require.NotEmpty(t, req.Metadata[artifactTokensMetadataKey])

	client := req.ArtifactClient.(*fakeArtifactClient)
	require.Len(t, client.uploads, 1)
	require.Equal(t, file, client.uploads[0].Path)
	require.NotEmpty(t, result.Metadata[artifactTokensMetadataKey])
}

func TestThreatIntelServerModeUploadsArtifactsAndSkipsRemoteBaseline(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	file := createTestFile(t, dir, "sample.exe")

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	cfg.ThreatIntel.Mode = threatintel.ModeServer
	cfg.ThreatIntel.OpenTIPAPIKey = "key"
	cfg.ThreatIntel.OpenTIPBaseURL = server.URL

	exec := &fakeBaselineExecutor{
		result: benchmarkexec.Result{
			Checks: []benchmark.CheckResult{{
				ID:          "C-1",
				Name:        "sample file",
				Severity:    benchmark.SeverityHigh,
				ActualValue:  file,
				Description: "for ti server mode",
			}},
			SeverityCount: map[string]int{"high": 1},
			Duration:      10 * time.Millisecond,
		},
	}
	runner := BaselineRunnerWithExecutor(exec)

	req := TaskRequest{
		Config:         cfg,
		Flags:          map[string]any{"scope": "os"},
		Metadata:       map[string]string{},
		ArtifactClient: &fakeArtifactClient{},
	}
	req.Manager = reporting.NewManager(cfg)
	req.ApplyDefaults("baseline")

	result, err := runner.Run(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, int32(0), calls.Load())
	require.NotEmpty(t, req.Metadata[artifactTokensMetadataKey])

	client := req.ArtifactClient.(*fakeArtifactClient)
	require.Len(t, client.uploads, 1)
	require.Equal(t, file, client.uploads[0].Path)
	require.NotEmpty(t, result.Metadata[artifactTokensMetadataKey])
}

