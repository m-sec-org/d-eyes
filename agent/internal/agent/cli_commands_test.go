package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	internal "github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

func TestCLICommandSuite(t *testing.T) {
	helper := &cliTestHelper{}
	cfg := config.Default()

	tmpDir := t.TempDir()
	baselineCfg := filepath.Join(tmpDir, "baseline.yaml")
	require.NoError(t, os.WriteFile(baselineCfg, []byte("id: baseline"), 0o600))

	configPath := filepath.Join(tmpDir, "cli-config.yaml")
	configYAML := fmt.Sprintf(`tasks:
  respond:
    targets:
      - /var/log
    profile: quick
  audit:
    targets:
      - localhost
  inventory:
    targets:
      - 10.0.0.0/30
  supplychain:
    paths:
      - %s
  baseline:
    config: %s
remote:
  enabled: true
  server_grpc_addr: bufconn://cli
`, tmpDir, baselineCfg)
	require.NoError(t, os.WriteFile(configPath, []byte(configYAML), 0o600))

	cases := []struct {
		name    string
		runner  string
		cliArgs []string
	}{
		{"respond", "respond", []string{"--config", configPath, "--json", "--quiet", "respond"}},
		{"audit", "audit", []string{"--config", configPath, "audit"}},
		{"inventory", "inventory", []string{"--config", configPath, "inventory"}},
		{"supplychain", "supplychain", []string{"--config", configPath, "supplychain", "--mode", "generate"}},
		{"baseline", "baseline", []string{"--config", configPath, "baseline"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			restore := internal.OverrideTaskRunnerForTesting(tc.runner, stubTaskRunner{})
			defer restore()

			exitCode, err := helper.run(context.Background(), cfg, tc.cliArgs...)
			require.Equal(t, 0, exitCode)
			require.NoError(t, err)
		})
	}

	t.Run("bas command", func(t *testing.T) {
		restore := internal.OverrideTaskRunnerForTesting("bas", stubTaskRunner{})
		defer restore()

		scenario := map[string]any{
			"id":   "unit",
			"name": "Unit Scenario",
			"steps": []map[string]any{
				{"id": "s1", "name": "noop", "command": "echo", "args": []string{"hi"}},
			},
		}
		raw, err := json.Marshal(scenario)
		require.NoError(t, err)

		exitCode, err := helper.run(context.Background(), cfg, "--config", configPath, "bas", "--scenario", string(raw), "--sandbox-approve")
		require.Equal(t, 0, exitCode)
		require.NoError(t, err)
	})

	t.Run("remote command", func(t *testing.T) {
		cfg := config.Default()
		called := false
		orig := runRemoteFunc
		runRemoteFunc = func(ctx context.Context, rc config.RemoteConfig) error {
			called = true
			require.Equal(t, "bufconn://cli", rc.ServerGRPCAddr)
			return nil
		}
		defer func() { runRemoteFunc = orig }()

		exitCode, err := helper.run(context.Background(), cfg, "--config", configPath, "remote")
		require.Equal(t, 0, exitCode)
		require.NoError(t, err)
		require.True(t, called)
	})
}

func TestRuntimeRunnerFactoryOverridesRespond(t *testing.T) {
	helper := &cliTestHelper{}
	cfg := config.Default()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "runner-factory.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("tasks: {}"), 0o600))

	counter := &countingRunner{}
	factory := customRunnerFactory{
		base:    internal.DefaultRunnerFactory(),
		respond: counter,
	}

	runtime := NewRuntime(WithRunnerFactory(factory))
	exitCode, err := helper.runWithRuntime(context.Background(), runtime, cfg, "--config", configPath, "respond", "--targets", tmpDir)
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)
	require.Equal(t, 1, counter.Calls())
}

type stubTaskRunner struct{}

func (stubTaskRunner) Run(ctx context.Context, req tasks.TaskRequest) (tasks.TaskResult, error) {
	return tasks.TaskResult{}, nil
}
