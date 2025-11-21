package tasks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

func TestSupplyChainRunnerSelectsMode(t *testing.T) {
	collector := &fakeSupplyChainCollector{}
	runner := SupplyChainRunnerWithCollector(collector)
	cfg := config.Default()
	req := TaskRequest{Config: cfg, Flags: map[string]any{"path": "/project"}}
	req.ApplyDefaults("supplychain")

	result, err := runner.Run(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "generate", collector.lastMode)
	require.Equal(t, "generate", result.Metadata["mode"])
}

func TestSupplyChainRunnerCaptureMode(t *testing.T) {
	collector := &fakeSupplyChainCollector{}
	runner := SupplyChainRunnerWithCollector(collector)
	cfg := config.Default()
	req := TaskRequest{Config: cfg, Flags: map[string]any{"mode": "capture", "path": "/tmp"}}
	req.ApplyDefaults("supplychain")

	_, err := runner.Run(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "capture", collector.lastMode)
}

type fakeSupplyChainCollector struct {
	lastMode string
}

func (f *fakeSupplyChainCollector) Generate(ctx context.Context, req TaskRequest) (TaskResult, error) {
	f.lastMode = "generate"
	return TaskResult{Metadata: map[string]string{"mode": "generate"}}, nil
}

func (f *fakeSupplyChainCollector) Capture(ctx context.Context, req TaskRequest) (TaskResult, error) {
	f.lastMode = "capture"
	return TaskResult{Metadata: map[string]string{"mode": "capture"}}, nil
}

func TestSupplyChainGenerateCachesResults(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	projectDir := createFixtureProject(t)

	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	req := TaskRequest{Config: cfg, Flags: map[string]any{"path": projectDir}}
	req.ApplyDefaults("supplychain")

	runner := supplyChainRunner{}
	res1, err := runner.generateSBOM(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "false", res1.Metadata["cache.hit"])

	res2, err := runner.generateSBOM(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "true", res2.Metadata["cache.hit"])
	require.Contains(t, res2.Notes[0], "命中供应链缓存")
}

func TestSupplyChainIncrementalReuse(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	projectDir := createFixtureProject(t)

	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	req := TaskRequest{Config: cfg, Flags: map[string]any{"path": projectDir}}
	req.ApplyDefaults("supplychain")

	origTTL := supplyChainCacheTTL
	origManifestTTL := supplyChainManifestCacheTTL
	supplyChainCacheTTL = time.Nanosecond
	supplyChainManifestCacheTTL = time.Hour
	t.Cleanup(func() {
		supplyChainCacheTTL = origTTL
		supplyChainManifestCacheTTL = origManifestTTL
	})

	runner := supplyChainRunner{}
	_, err := runner.generateSBOM(context.Background(), req)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)
	requirementsPath := filepath.Join(projectDir, "requirements.txt")
	require.NoError(t, os.WriteFile(requirementsPath, []byte("flask==2.0.0\n"), 0o644))

	res2, err := runner.generateSBOM(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "false", res2.Metadata["cache.hit"])
	require.Equal(t, "1", res2.Metadata["cache.manifest_reused"])
	require.Equal(t, "1", res2.Metadata["cache.manifest_refreshed"])
}

func createFixtureProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	packageJSON := `{
  "dependencies": {
    "axios": "1.4.0"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}`
	require.NoError(t, os.WriteFile(filepath.Join(root, "package.json"), []byte(packageJSON), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("requests==2.0.0\n"), 0o644))
	return root
}
