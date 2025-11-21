package tasks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
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

func createTestFile(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte("data"), 0o644))
	return path
}
