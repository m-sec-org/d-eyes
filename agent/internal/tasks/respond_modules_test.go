package tasks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/pkg/artifacts"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
	"github.com/m-sec-org/d-eyes/agent/pkg/threatintel"
)

func TestRunFileScanCachesByFingerprint(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	target := t.TempDir()
	createTestFile(t, target, "sample.exe")

	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	req := TaskRequest{
		Config: cfg,
		Flags:  map[string]any{"targets": target},
	}
	req.Manager = reporting.NewManager(cfg)
	req.ApplyDefaults("respond")

	res1, err := runFileScan(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "false", res1.Metadata["cache.hit"])

	res2, err := runFileScan(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "true", res2.Metadata["cache.hit"])
}

func TestRunFileScanUploadsArtifactsInServerMode(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	target := t.TempDir()
	file := createTestFile(t, target, "malware.exe")

	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	cfg.ThreatIntel.Mode = threatintel.ModeServer
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
	require.NotEmpty(t, req.Metadata[artifactTokensMetadataKey])
	client := req.ArtifactClient.(*fakeArtifactClient)
	require.Len(t, client.uploads, 1)
	require.Equal(t, file, client.uploads[0].Path)
	require.Contains(t, result.Metadata, "scanned_files")
}

func createTestFile(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte("data"), 0o644))
	return path
}

type fakeArtifactClient struct {
	uploads []artifacts.UploadInput
}

func (f *fakeArtifactClient) Upload(ctx context.Context, input artifacts.UploadInput) (*artifacts.UploadResult, error) {
	f.uploads = append(f.uploads, input)
	return &artifacts.UploadResult{Token: "token-1"}, nil
}
