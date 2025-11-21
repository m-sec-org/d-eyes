package tasks

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/benchmark"
	"github.com/m-sec-org/d-eyes/agent/internal/benchmarkexec"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

func TestBaselineRunnerWritesReportAndMetadata(t *testing.T) {
	exec := &fakeBaselineExecutor{
		result: benchmarkexec.Result{
			Checks:        []benchmark.CheckResult{{ID: "C-1", Severity: benchmark.SeverityHigh}},
			SeverityCount: map[string]int{"high": 1},
			Duration:      time.Second,
			Warnings:      []string{"missing config"},
		},
	}
	runner := BaselineRunnerWithExecutor(exec)
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	req := TaskRequest{
		Config: cfg,
		Flags: map[string]any{
			"scope":           "os",
			"baseline-config": "/tmp/baseline.yaml",
		},
	}
	req.Manager = reporting.NewManager(cfg)
	req.ApplyDefaults("baseline")

	result, err := runner.Run(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "os", exec.lastReq.Scope)
	require.Equal(t, "/tmp/baseline.yaml", exec.lastReq.ConfigPath)
	require.Contains(t, result.Metadata["report_path"], "baseline")
	require.Contains(t, result.Notes, "missing config")
}

type fakeBaselineExecutor struct {
	result  benchmarkexec.Result
	err     error
	lastReq benchmarkexec.Request
}

func (f *fakeBaselineExecutor) Execute(_ context.Context, req benchmarkexec.Request) (benchmarkexec.Result, error) {
	f.lastReq = req
	if f.err != nil {
		return benchmarkexec.Result{}, f.err
	}
	return f.result, nil
}
