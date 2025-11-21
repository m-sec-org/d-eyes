package tasks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

func TestRespondRunnerFallsBackToDefaultProfile(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	req := TaskRequest{
		Profile:  "custom",
		Config:   cfg,
		Metadata: map[string]string{"origin": "cli"},
	}
	req.Manager = reporting.NewManager(cfg)
	req.ApplyDefaults("respond")

	called := make([]string, 0)
	runner := RespondRunnerWithSelector(func(profile string) []respondModule {
		called = append(called, profile)
		if profile == "default" {
			return []respondModule{{
				Name: "stub",
				Run: func(context.Context, TaskRequest) (moduleResult, error) {
					return moduleResult{
						Outputs: []reporting.OutputRecord{{Label: "stub", Path: "stub.json"}},
						Notes:   []string{"note"},
						Risks:   map[string]int{"high": 2},
					}, nil
				},
			}}
		}
		return nil
	})

	result, err := runner.Run(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, []string{"custom", "default"}, called)
	require.Len(t, result.Outputs, 1)
	require.Equal(t, 2, result.Risks["high"])
	require.Contains(t, result.Notes, "note")
	require.Equal(t, "cli", result.Metadata["origin"])
}

func TestRespondRunnerRecordsModuleErrors(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	req := TaskRequest{Profile: "quick", Config: cfg}
	req.Manager = reporting.NewManager(cfg)
	req.ApplyDefaults("respond")

	runner := RespondRunnerWithSelector(func(profile string) []respondModule {
		require.Equal(t, "quick", profile)
		return []respondModule{
			{
				Name: "failing",
				Run: func(context.Context, TaskRequest) (moduleResult, error) {
					return moduleResult{}, context.DeadlineExceeded
				},
			},
			{
				Name: "success",
				Run: func(context.Context, TaskRequest) (moduleResult, error) {
					return moduleResult{Notes: []string{"fin"}}, nil
				},
			},
		}
	})

	result, err := runner.Run(context.Background(), req)
	require.NoError(t, err)
	require.Contains(t, result.Notes[0], "failing 执行失败")
	require.Contains(t, result.Notes, "fin")
}
