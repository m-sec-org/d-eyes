package tasks

import (
	"context"
	"testing"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

type stubTaskRunner struct {
	result TaskResult
	err    error

	lastReq TaskRequest
}

func (s *stubTaskRunner) Run(ctx context.Context, req TaskRequest) (TaskResult, error) {
	s.lastReq = req
	if s.err != nil {
		return TaskResult{}, s.err
	}
	return s.result, nil
}

func TestAuditRunnerUsesInjectedBaselineRunner(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Output.Dir = tempDir
	manager := reporting.NewManager(cfg)

	baseline := &stubTaskRunner{
		result: TaskResult{
			Outputs: []reporting.OutputRecord{{Label: "baseline", Path: "/tmp/baseline"}},
			Risks:   map[string]int{"high": 1},
			Notes:   []string{"baseline-note"},
		},
	}

	runner := &auditRunner{
		baseline: baseline,
		hostSummary: func(ctx context.Context, req TaskRequest) (moduleResult, error) {
			return moduleResult{
				Outputs: []reporting.OutputRecord{{Label: "host", Path: "/tmp/host"}},
				Risks:   map[string]int{"medium": 2},
			}, nil
		},
		userInspection: func(ctx context.Context, req TaskRequest) (moduleResult, error) {
			return moduleResult{
				Outputs: []reporting.OutputRecord{{Label: "user", Path: "/tmp/user"}},
				Risks:   map[string]int{"low": 3},
			}, nil
		},
	}

	req := TaskRequest{
		Name:    "audit-task",
		Profile: "compliance",
		Manager: manager,
		Config:  cfg,
	}

	result, err := runner.Run(context.Background(), req)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if baseline.lastReq.Name != "audit-task-baseline" {
		t.Fatalf("baseline request name = %s, want audit-task-baseline", baseline.lastReq.Name)
	}
	if scope, ok := baseline.lastReq.Flags["scope"]; !ok || scope != "all" {
		t.Fatalf("baseline scope = %v, want all", scope)
	}
	if result.Risks["high"] != 1 || result.Risks["medium"] != 2 || result.Risks["low"] != 3 {
		t.Fatalf("unexpected risks aggregation: %#v", result.Risks)
	}
	if len(result.Notes) == 0 || result.Notes[0] != "baseline-note" {
		t.Fatalf("baseline notes not propagated: %v", result.Notes)
	}
	if len(result.Outputs) != 4 {
		t.Fatalf("expected 4 outputs (baseline, host, user, summary), got %d", len(result.Outputs))
	}
	summary := result.Outputs[len(result.Outputs)-1]
	if summary.Label != "审计汇总" || summary.Path == "" {
		t.Fatalf("missing summary output: %+v", summary)
	}
}
