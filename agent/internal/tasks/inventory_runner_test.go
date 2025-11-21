package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/assets"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

func TestInventoryRunnerRequiresTargets(t *testing.T) {
	runner := InventoryRunnerWithExecutor(&fakeInventoryExecutor{})
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	req := TaskRequest{Config: cfg}
	req.Manager = reporting.NewManager(cfg)
	req.ApplyDefaults("inventory")

	_, err := runner.Run(context.Background(), req)
	require.ErrorContains(t, err, "至少一个")
}

func TestInventoryRunnerAggregatesReportsAndSummary(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	exec := &fakeInventoryExecutor{}
	runner := InventoryRunnerWithExecutor(exec)
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	req := TaskRequest{
		Config: cfg,
		Flags:  map[string]any{"targets": "10.0.0.1,10.0.0.2"},
	}
	req.Manager = reporting.NewManager(cfg)
	req.ApplyDefaults("inventory")
	req.Profile = ""

	result, err := runner.Run(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 2, exec.calls)
	require.Equal(t, "fast", result.Metadata["profile"])
	require.Equal(t, "2", result.Metadata["target_count"])
	require.Len(t, result.Outputs, 3) // two reports + summary
	require.Equal(t, "资产扫描：10.0.0.1", result.Outputs[0].Label)
	require.Equal(t, 2, result.Risks["high"])
}

func TestInventoryCacheHit(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	exec := &fakeInventoryExecutor{}
	runner := InventoryRunnerWithExecutor(exec)
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	req := TaskRequest{
		Config: cfg,
		Flags:  map[string]any{"targets": "10.0.0.1"},
	}
	req.Manager = reporting.NewManager(cfg)
	req.ApplyDefaults("inventory")
	req.Profile = "fast"

	res1, err := runner.Run(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "false", res1.Metadata["cache.hit"])

	res2, err := runner.Run(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "true", res2.Metadata["cache.hit"])
	require.Equal(t, "1", res2.Metadata["target_count"])
}

type fakeInventoryExecutor struct {
	calls int
}

func (f *fakeInventoryExecutor) ScanTarget(_ context.Context, target string, _ assets.ScanOptions, req TaskRequest) (inventoryReport, error) {
	f.calls++
	file, path, err := req.Manager.CreateFile("inventory", fmt.Sprintf("%s-%s", req.Name, sanitizeFileComponent(target)), "json")
	if err != nil {
		return inventoryReport{}, err
	}
	defer file.Close()
	if err := json.NewEncoder(file).Encode(map[string]string{"target": target}); err != nil {
		return inventoryReport{}, err
	}
	return inventoryReport{
		Target: target,
		Hosts:  []assets.HostInfo{{Hostname: target}},
		Ports:  []assets.PortInfo{{Port: 3389}},
		OutputRecord: reporting.OutputRecord{
			Label: "资产扫描：" + target,
			Path:  path,
		},
		Risks: map[string]int{"high": 1},
		Path:  path,
	}, nil
}
