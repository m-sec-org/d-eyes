package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	internal "github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/threatintel"
)

func TestCLIRespondThreatIntelFlag(t *testing.T) {
	helper := &cliTestHelper{}
	cfg := config.Default()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "cli-config.yaml")
	configYAML := `tasks:
  respond:
    targets:
      - /var/log
`
	require.NoError(t, os.WriteFile(configPath, []byte(configYAML), 0o600))

	recorder := &recordingRunner{}
	restore := internal.OverrideTaskRunnerForTesting("respond", recorder)
	defer restore()

	exitCode, err := helper.run(context.Background(), cfg, "--config", configPath, "--ti-mode", "local", "--quiet", "respond")
	require.Equal(t, 0, exitCode)
	require.NoError(t, err)
	require.Equal(t, threatintel.ModeLocal, recorder.lastRequest.Config.ThreatIntel.Mode)
}

func TestCLIBASSandboxApproveFlag(t *testing.T) {
	helper := &cliTestHelper{}
	cfg := config.Default()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "bas-config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("tasks: {}"), 0o600))

	recorder := &recordingRunner{}
	restore := internal.OverrideTaskRunnerForTesting("bas", recorder)
	defer restore()

	scenario := map[string]any{
		"id":   "sandbox",
		"name": "Sandbox Scenario",
		"steps": []map[string]any{
			{"id": "s1", "name": "noop", "command": "echo"},
		},
	}
	raw, err := json.Marshal(scenario)
	require.NoError(t, err)

	exitCode, err := helper.run(context.Background(), cfg, "--config", configPath, "bas", "--scenario", string(raw), "--sandbox-approve")
	require.Equal(t, 0, exitCode)
	require.NoError(t, err)
	require.True(t, recorder.lastRequest.SandboxApproved)
}

type recordingRunner struct {
	lastRequest tasks.TaskRequest
}

func (r *recordingRunner) Run(ctx context.Context, req tasks.TaskRequest) (tasks.TaskResult, error) {
	r.lastRequest = req
	return tasks.TaskResult{}, nil
}
