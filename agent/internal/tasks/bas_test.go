package tasks

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

func TestBASRunnerSuccessScenario(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("BAS 场景依赖 /bin/sh，Windows 环境下跳过")
	}

	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	req := TaskRequest{
		Config: cfg,
		Flags: map[string]any{
			"scenario-id": "initial-access",
		},
	}
	req.ApplyDefaults("bas")
	if err := ValidateRequest("bas", &req); err != nil {
		t.Fatalf("validate request failed: %v", err)
	}

	result, err := BASRunner().Run(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error executing success scenario: %v (metadata=%v stdout=%v)", err, result.Metadata, result.Outputs)
	}

	if result.Metadata["scenario_id"] != "initial-access" {
		t.Fatalf("expected scenario_id metadata to be initial-access, got %s", result.Metadata["scenario_id"])
	}
	if v := result.Metadata["failed_steps"]; v != "" {
		t.Fatalf("expected no failed steps, got %s", v)
	}
	if len(result.Outputs) == 0 {
		t.Fatalf("expected outputs to include scenario report")
	}
}

func TestBASRunnerFailureScenario(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("BAS 场景依赖 /bin/sh，Windows 环境下跳过")
	}

	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	req := TaskRequest{
		Config: cfg,
		Flags: map[string]any{
			"scenario-id": "privilege-escalation",
		},
	}
	req.ApplyDefaults("bas")
	if err := ValidateRequest("bas", &req); err != nil {
		t.Fatalf("validate request failed: %v", err)
	}

	result, err := BASRunner().Run(context.Background(), req)
	if err == nil {
		t.Fatalf("expected failure scenario to return error")
	}
	if !strings.Contains(err.Error(), "提权验证") && !strings.Contains(err.Error(), "执行失败") {
		t.Fatalf("unexpected error message: %v", err)
	}

	if result.Metadata["failed_steps"] != "exploit-attempt" {
		t.Fatalf("expected failed_steps metadata to be exploit-attempt, got %s", result.Metadata["failed_steps"])
	}
	if result.Metadata["error_code"] != "bas.step_failed" {
		t.Fatalf("expected error_code bas.step_failed, got %s", result.Metadata["error_code"])
	}

	summary := result.Metadata["scenario_summary"]
	if summary == "" {
		t.Fatalf("expected scenario_summary metadata")
	}
	var steps []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(summary), &steps); err != nil {
		t.Fatalf("failed to decode scenario_summary: %v", err)
	}
	if len(steps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(steps))
	}
	if steps[1].Status != "failed" {
		t.Fatalf("expected second step to fail, got %s", steps[1].Status)
	}
	if steps[2].Status != "skipped" {
		t.Fatalf("expected third step to be skipped, got %s", steps[2].Status)
	}
}
