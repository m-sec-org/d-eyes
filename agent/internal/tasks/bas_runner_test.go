package tasks

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/sandbox"
	telemetrypkg "github.com/m-sec-org/d-eyes/agent/internal/telemetry"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
	sharedtelemetry "github.com/m-sec-org/d-eyes/server/pkg/telemetry"
)

func TestBASRunnerWithInjectedDependencies(t *testing.T) {
	scenario := Scenario{
		ID:   "scenario-1",
		Name: "Test",
		Steps: []ScenarioStep{
			{ID: "s1", Name: "first", Command: "echo"},
			{ID: "s2", Name: "second", Command: "echo"},
		},
	}
	loader := &fakeScenarioLoader{scenario: scenario}
	exec := &fakeSandboxExecutor{
		outcomes: map[string]stepOutcome{
			"s1": {ID: "s1", Name: "first", Status: "succeeded", Sandbox: true},
			"s2": {ID: "s2", Name: "second", Status: "succeeded", Sandbox: true},
		},
	}
	telemetry := &fakeTelemetryEncoder{stepsToken: "steps-token", statsToken: "stats-token"}
	runner := BASRunnerWithDeps(loader, fakeSandboxFactory{exec: exec}, telemetry)

	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	req := TaskRequest{Config: cfg, Manager: reporting.NewManager(cfg)}

	result, err := runner.Run(context.Background(), req)
	require.NoError(t, err)
	require.Contains(t, result.Metadata, sharedtelemetry.MetadataBASteps)
	require.Equal(t, "steps-token", result.Metadata[sharedtelemetry.MetadataBASteps])
	require.Equal(t, "stats-token", result.Metadata[sharedtelemetry.MetadataSandboxStats])
}

func TestBASRunnerHandlesFailuresAndFallback(t *testing.T) {
	scenario := Scenario{
		ID:   "scenario-2",
		Name: "Failing",
		Steps: []ScenarioStep{
			{ID: "s1", Name: "first", Command: "echo", Severity: "critical", UseSandbox: true},
			{ID: "s2", Name: "second", Command: "echo"},
		},
	}
	loader := &fakeScenarioLoader{scenario: scenario}
	exec := &fakeSandboxExecutor{
		outcomes: map[string]stepOutcome{
			"s1": {ID: "s1", Name: "first", Status: "failed", Fallback: true, Sandboxed: true, Message: "boom"},
			"s2": {ID: "s2", Name: "second", Status: "skipped"},
		},
	}
	telemetry := &fakeTelemetryEncoder{}
	runner := BASRunnerWithDeps(loader, fakeSandboxFactory{exec: exec}, telemetry)

	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	cfg.Sandbox.Enabled = true
	req := TaskRequest{Config: cfg, Manager: reporting.NewManager(cfg)}

	result, err := runner.Run(context.Background(), req)
	require.Error(t, err)
	require.Equal(t, "s1", result.Metadata["failed_steps"])
	require.Contains(t, result.Notes[len(result.Notes)-1], "失败")
	require.Equal(t, "true", result.Metadata["sandbox_fallback"])
	require.Equal(t, "true", result.Metadata["sandbox_executed"])
}

func TestBASRunnerAddsTelemetryErrorNote(t *testing.T) {
	scenario := Scenario{
		ID:   "scenario-3",
		Name: "Telemetry",
		Steps: []ScenarioStep{
			{ID: "s1", Name: "sandbox-step", Command: "echo", UseSandbox: true},
		},
	}
	loader := &fakeScenarioLoader{scenario: scenario}
	exec := &fakeSandboxExecutor{
		outcomes: map[string]stepOutcome{
			"s1": {ID: "s1", Name: "sandbox-step", Status: "succeeded", Sandboxed: true, Fallback: true},
		},
	}
	telemetry := &failingTelemetryEncoder{encodeErr: errors.New("boom"), statsToken: "stats-json"}
	runner := BASRunnerWithDeps(loader, fakeSandboxFactory{exec: exec}, telemetry)

	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	cfg.Sandbox.Enabled = true
	req := TaskRequest{Config: cfg, Manager: reporting.NewManager(cfg)}
	req.SandboxApproved = true

	result, err := runner.Run(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "stats-json", result.Metadata[sharedtelemetry.MetadataSandboxStats])
	require.True(t, noteContains(result.Notes, "BAS 步骤遥测编码失败"))
	require.Equal(t, "true", result.Metadata["sandbox_fallback"])
	require.Equal(t, "true", result.Metadata["sandbox_executed"])
}

type fakeScenarioLoader struct {
	scenario Scenario
	err      error
}

func (f *fakeScenarioLoader) Load(TaskRequest) (Scenario, error) {
	if f.err != nil {
		return Scenario{}, f.err
	}
	return f.scenario, nil
}

type fakeSandboxFactory struct {
	exec sandboxExecutor
}

func (f fakeSandboxFactory) New(sandbox.Config, bool) sandboxExecutor {
	return f.exec
}

type fakeSandboxExecutor struct {
	outcomes map[string]stepOutcome
}

func (f *fakeSandboxExecutor) Execute(ctx context.Context, _ Scenario, step ScenarioStep, _ bool) stepOutcome {
	if outcome, ok := f.outcomes[step.ID]; ok {
		if outcome.StartedAt.IsZero() {
			outcome.StartedAt = time.Now().Add(-time.Second)
		}
		if outcome.EndedAt.IsZero() {
			outcome.EndedAt = time.Now()
		}
		return outcome
	}
	return stepOutcome{ID: step.ID, Name: step.Name, Status: "skipped"}
}

type fakeTelemetryEncoder struct {
	stepsToken string
	statsToken string
}

func (f *fakeTelemetryEncoder) BuildSteps(Scenario, []stepOutcome) ([]telemetrypkg.BAStepTelemetry, int, int) {
	return []telemetrypkg.BAStepTelemetry{}, 0, 0
}

func (f *fakeTelemetryEncoder) EncodeSteps([]telemetrypkg.BAStepTelemetry) (string, error) {
	if f.stepsToken == "" {
		return "steps-default", nil
	}
	return f.stepsToken, nil
}

func (f *fakeTelemetryEncoder) EncodeStats(telemetrypkg.SandboxStats) (string, error) {
	if f.statsToken == "" {
		return "stats-default", nil
	}
	return f.statsToken, nil
}

type failingTelemetryEncoder struct {
	encodeErr  error
	statsToken string
}

func (f *failingTelemetryEncoder) BuildSteps(Scenario, []stepOutcome) ([]telemetrypkg.BAStepTelemetry, int, int) {
	return []telemetrypkg.BAStepTelemetry{{ID: "s1", Name: "sandbox-step", Status: "succeeded"}}, 1, 1
}

func (f *failingTelemetryEncoder) EncodeSteps([]telemetrypkg.BAStepTelemetry) (string, error) {
	return "", f.encodeErr
}

func (f *failingTelemetryEncoder) EncodeStats(telemetrypkg.SandboxStats) (string, error) {
	return f.statsToken, nil
}

func noteContains(notes []string, needle string) bool {
	for _, note := range notes {
		if strings.Contains(note, needle) {
			return true
		}
	}
	return false
}
