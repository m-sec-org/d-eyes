package tasks

import (
	"path/filepath"
	"testing"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

func TestValidateRespondUsesConfigTargets(t *testing.T) {
	cfg := config.Default()
	cfg.Tasks.Respond.Targets = []string{"/var/log", "/tmp"}
	req := TaskRequest{
		Config: cfg,
		Flags:  map[string]any{},
	}
	req.ApplyDefaults("respond")
	if err := ValidateRequest("respond", &req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	targets, ok := req.Flags["targets"].(string)
	if !ok {
		t.Fatalf("expected targets flag to be set, got %#v", req.Flags["targets"])
	}
	if targets != "/var/log,/tmp" {
		t.Fatalf("unexpected targets: %s", targets)
	}
	if len(req.Notices) == 0 {
		t.Fatalf("expected notice to be recorded when falling back to config targets")
	}
}

func TestValidateInventoryRequiresTargets(t *testing.T) {
	cfg := config.Default()
	req := TaskRequest{
		Config: cfg,
		Flags:  map[string]any{},
	}
	req.ApplyDefaults("inventory")
	err := ValidateRequest("inventory", &req)
	if err == nil {
		t.Fatalf("expected error for missing targets")
	}
	if exitErr, ok := err.(interface{ ExitCode() int }); ok {
		if exitErr.ExitCode() != 64 {
			t.Fatalf("expected exit code 64, got %d", exitErr.ExitCode())
		}
	} else {
		t.Fatalf("expected exit error type, got %T", err)
	}
}

func TestValidateSupplyChainModeAndInputs(t *testing.T) {
	cfg := config.Default()
	req := TaskRequest{
		Config: cfg,
		Flags: map[string]any{
			"mode": "unknown",
		},
	}
	req.ApplyDefaults("supplychain")
	err := ValidateRequest("supplychain", &req)
	if err == nil {
		t.Fatalf("expected error for invalid mode")
	}
	req.Flags["mode"] = "generate"
	err = ValidateRequest("supplychain", &req)
	if err == nil {
		t.Fatalf("expected error when missing --path/--file")
	}

	req.Flags["path"] = "./"
	err = ValidateRequest("supplychain", &req)
	if err != nil {
		t.Fatalf("unexpected error when path provided: %v", err)
	}
}

func TestValidateBaselineConfigPath(t *testing.T) {
	cfg := config.Default()
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "baseline.yaml")
	req := TaskRequest{
		Config: cfg,
		Flags: map[string]any{
			"baseline-config": configPath,
		},
	}
	req.ApplyDefaults("baseline")
	err := ValidateRequest("baseline", &req)
	if err == nil {
		t.Fatalf("expected error for missing baseline config file")
	}
	if exitErr, ok := err.(interface{ ExitCode() int }); ok && exitErr.ExitCode() != 64 {
		t.Fatalf("expected exit code 64, got %d", exitErr.ExitCode())
	}
}

func TestValidateBASScenarioRequirement(t *testing.T) {
	cfg := config.Default()
	req := TaskRequest{
		Config: cfg,
		Flags:  map[string]any{},
	}
	req.ApplyDefaults("bas")
	err := ValidateRequest("bas", &req)
	if err == nil {
		t.Fatalf("expected error for missing scenario")
	}

	req.Flags["scenario"] = `{"id":"test","name":"scenario","steps":[{"id":"step1","name":"noop"}]}`
	err = ValidateRequest("bas", &req)
	if err != nil {
		t.Fatalf("unexpected error when scenario provided: %v", err)
	}
}

func TestValidateBASScenarioDefaultKeepsSandboxDisabled(t *testing.T) {
	cfg := config.Default()
	cfg.Sandbox.Enabled = false
	req := TaskRequest{
		Config: cfg,
		Flags: map[string]any{
			"scenario-id": "initial-access",
		},
	}
	req.ApplyDefaults("bas")
	err := ValidateRequest("bas", &req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Config.Sandbox.Enabled {
		t.Fatalf("expected sandbox to remain disabled when global sandbox is off")
	}
}

func TestValidateBASSandboxDisableFlag(t *testing.T) {
	cfg := config.Default()
	cfg.Sandbox.Enabled = true
	req := TaskRequest{
		Config: cfg,
		Flags: map[string]any{
			"scenario-id":   "initial-access",
			"no-sandbox":    true,
			"scenario-file": "",
		},
	}
	req.ApplyDefaults("bas")
	err := ValidateRequest("bas", &req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Config.Sandbox.Enabled {
		t.Fatalf("expected sandbox to be disabled when --no-sandbox flag provided")
	}
}

func TestValidateBASSandboxFlagEnables(t *testing.T) {
	cfg := config.Default()
	cfg.Sandbox.Enabled = false
	req := TaskRequest{
		Config: cfg,
		Flags: map[string]any{
			"scenario-id": "initial-access",
			"sandbox":     true,
		},
	}
	req.ApplyDefaults("bas")
	err := ValidateRequest("bas", &req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !req.Config.Sandbox.Enabled {
		t.Fatalf("expected sandbox to be enabled when --sandbox flag provided")
	}
}
