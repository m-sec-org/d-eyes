package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type mockExecutor struct {
	outputs map[string]mockResponse
}

type mockResponse struct {
	stdout   string
	stderr   string
	exitCode int
	err      error
}

func (m *mockExecutor) Run(ctx context.Context, command string, args []string, shell bool, timeout time.Duration) (string, string, int, error) {
	key := command + " " + strings.Join(args, " ")
	resp, ok := m.outputs[key]
	if !ok {
		return "", "unknown command", 1, errors.New("cmd not found")
	}
	return resp.stdout, resp.stderr, resp.exitCode, resp.err
}

func TestRunnerRunPass(t *testing.T) {
	mock := &mockExecutor{
		outputs: map[string]mockResponse{
			"grep PASS_MAX_DAYS /etc/login.defs": {stdout: "PASS_MAX_DAYS 90\n", exitCode: 0},
		},
	}
	runner := NewRunner(WithExecutor(mock), WithNow(func() time.Time { return time.Unix(0, 0) }))

	rule := Rule{
		ID:          "test_rule",
		Title:       "Check PASS_MAX_DAYS",
		Severity:    "HIGH",
		Description: "Ensure PASS_MAX_DAYS <= 90",
		Checks: []CheckSpec{{
			Name:    "pass_max_days",
			Command: "grep",
			Args:    []string{"PASS_MAX_DAYS", "/etc/login.defs"},
			Expect: ExpectSpec{
				Operator: "contains",
				Value:    "PASS_MAX_DAYS 90",
			},
		}},
	}

	res := runner.Run(context.Background(), rule)
	if res.Status != StatusPass {
		t.Fatalf("expected PASS, got %s", res.Status)
	}
	if len(res.Details) != 1 || res.Details[0].Status != StatusPass {
		t.Fatalf("expected detail PASS")
	}
}

func TestRunnerRunFail(t *testing.T) {
	mock := &mockExecutor{
		outputs: map[string]mockResponse{
			"grep PASS_MAX_DAYS /etc/login.defs": {stdout: "PASS_MAX_DAYS 365\n", exitCode: 0},
		},
	}
	runner := NewRunner(WithExecutor(mock))

	rule := Rule{
		ID:    "test_rule",
		Title: "Check PASS_MAX_DAYS",
		Checks: []CheckSpec{{
			Command: "grep",
			Args:    []string{"PASS_MAX_DAYS", "/etc/login.defs"},
			Expect: ExpectSpec{
				Operator: "contains",
				Value:    "PASS_MAX_DAYS 90",
			},
		}},
	}

	res := runner.Run(context.Background(), rule)
	if res.Status != StatusFail {
		t.Fatalf("expected FAIL, got %s", res.Status)
	}
	if res.Details[0].Status != StatusFail {
		t.Fatalf("expected detail FAIL")
	}
}

func TestRunnerRunError(t *testing.T) {
	mock := &mockExecutor{
		outputs: map[string]mockResponse{
			"systemctl is-active firewalld": {stderr: "command not found", exitCode: 127, err: errors.New("missing command")},
		},
	}
	runner := NewRunner(WithExecutor(mock))

	rule := Rule{
		ID:    "firewall",
		Title: "Firewall active",
		Checks: []CheckSpec{{
			Command: "systemctl",
			Args:    []string{"is-active", "firewalld"},
			Expect: ExpectSpec{
				Operator: "equals",
				Value:    "active",
			},
		}},
	}

	res := runner.Run(context.Background(), rule)
	if res.Status != StatusError {
		t.Fatalf("expected ERROR, got %s", res.Status)
	}
}

func TestRunnerRunWarnOnOptional(t *testing.T) {
	mock := &mockExecutor{
		outputs: map[string]mockResponse{
			"redis-cli CONFIG GET requirepass": {stdout: "", exitCode: 0},
		},
	}
	runner := NewRunner(WithExecutor(mock))

	rule := Rule{
		ID:    "redis_auth",
		Title: "Redis auth configured",
		Checks: []CheckSpec{{
			Command:  "redis-cli",
			Args:     []string{"CONFIG", "GET", "requirepass"},
			Optional: true,
			Expect: ExpectSpec{
				Operator: "contains",
				Value:    "requirepass",
			},
		}},
	}

	res := runner.Run(context.Background(), rule)
	if res.Status != StatusWarn {
		t.Fatalf("expected WARN, got %s", res.Status)
	}
}
