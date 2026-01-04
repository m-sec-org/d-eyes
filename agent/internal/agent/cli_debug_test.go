package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	internal "github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/collector"
	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

func TestCLIDebugModeStreamsEvents(t *testing.T) {
	helper := &cliTestHelper{}
	cfg := config.Default()

	tmpDir := t.TempDir()
	configPath := writeDebugConfig(t, tmpDir)
	scenario := map[string]any{
		"id":   "unit",
		"name": "Unit Scenario",
		"steps": []map[string]any{
			{"id": "s1", "name": "noop", "command": "echo", "args": []string{"hi"}},
		},
	}
	rawScenario, err := json.Marshal(scenario)
	require.NoError(t, err)

	cases := []struct {
		name      string
		runner    string
		args      []string
		expectStr string
	}{
		{"respond", "respond", []string{"respond"}, "respond debug active"},
		{"audit", "audit", []string{"audit"}, "audit debug active"},
		{"inventory", "inventory", []string{"inventory"}, "inventory debug active"},
		{"supplychain", "supplychain", []string{"supplychain", "--mode", "generate"}, "supplychain debug active"},
		{"baseline", "baseline", []string{"baseline"}, "baseline debug active"},
		{"bas", "bas", []string{"bas", "--scenario", string(rawScenario), "--sandbox-approve"}, "bas debug active"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			runner := debugEventRunner{t: t, label: tc.runner}
			restore := internal.OverrideTaskRunnerForTesting(tc.runner, runner)
			defer restore()

			args := append([]string{"--config", configPath, "--debug"}, tc.args...)
			exitCode, err := helper.run(context.Background(), cfg, args...)
			require.Equal(t, 0, exitCode)
			require.NoError(t, err)

			stderr := helper.stderrString()
			require.Contains(t, stderr, tc.expectStr)
		})
	}
}

func TestCLIDebugModeJsonQuietOutput(t *testing.T) {
	helper := &cliTestHelper{}
	cfg := config.Default()

	tmpDir := t.TempDir()
	configPath := writeDebugConfig(t, tmpDir)
	runner := debugEventRunner{t: t, label: "respond"}
	restore := internal.OverrideTaskRunnerForTesting("respond", runner)
	defer restore()

	// JSON mode should emit machine-readable summary on stdout while keeping debug lines on stderr.
	exitCode, err := helper.run(context.Background(), cfg, "--config", configPath, "--json", "--debug", "respond")
	require.Equal(t, 0, exitCode)
	require.NoError(t, err)
	require.Contains(t, helper.stdoutString(), `"command": "respond"`)
	require.Contains(t, helper.stderrString(), "respond debug active")

	// Quiet mode suppresses stdout and disables emitter streaming.
	exitCode, err = helper.run(context.Background(), cfg, "--config", configPath, "--quiet", "--debug", "respond")
	require.Equal(t, 0, exitCode)
	require.NoError(t, err)
	require.Equal(t, "", strings.TrimSpace(helper.stdoutString()))
	require.Equal(t, "", strings.TrimSpace(helper.stderrString()))
}

func TestCollectCommandDebugOutput(t *testing.T) {
	helper := &cliTestHelper{}
	cfg := config.Default()

	tmpDir := t.TempDir()
	configPath := writeDebugConfig(t, tmpDir)

	mgr := collector.NewManager()
	require.NoError(t, mgr.RegisterFactory(collector.Kind("stub"), func(cfg collector.Config) (collector.EventCollector, error) {
		return &stubCollector{name: cfg.Name}, nil
	}))
	collectorServiceOptionsHook = func() []collector.ServiceOption {
		return []collector.ServiceOption{collector.WithManager(mgr)}
	}
	t.Cleanup(func() {
		collectorServiceOptionsHook = nil
	})

	args := []string{"--config", configPath, "--debug", "collect", "--duration", "20ms"}
	exitCode, err := helper.run(context.Background(), cfg, args...)
	require.Equal(t, 0, exitCode)
	require.NoError(t, err)
	require.Contains(t, helper.stderrString(), "collector stub-collector running")
}

type debugEventRunner struct {
	t     *testing.T
	label string
}

func (r debugEventRunner) Run(_ context.Context, req tasks.TaskRequest) (tasks.TaskResult, error) {
	if !req.Debug {
		r.t.Fatalf("expected debug flag for %s", r.label)
	}
	if req.Debugger == nil {
		r.t.Fatalf("expected debugger emitter for %s", r.label)
	}
	req.Debugger.Notice(r.label, fmt.Sprintf("%s debug active", r.label))
	req.Debugger.Progress(r.label, 1, 1, "complete")
	req.Debugger.PhaseEnd(r.label, "done")
	return tasks.TaskResult{}, nil
}

type stubCollector struct {
	name string
}

func (c *stubCollector) Name() string {
	return c.name
}

func (c *stubCollector) Start(ctx context.Context, handler collector.EventHandler) error {
	if handler != nil {
		_ = handler.HandleEvent(ctx, &collector.SystemEvent{
			EventType: "stub",
			Metadata:  map[string]string{"collector": c.name},
		})
	}
	go func() {
		<-ctx.Done()
	}()
	return nil
}

func (c *stubCollector) Stop(context.Context) error {
	return nil
}

func (c *stubCollector) Status() collector.CollectorStatus {
	return collector.CollectorStatus{
		Name:  c.name,
		Kind:  collector.Kind("stub"),
		State: "running",
	}
}

func writeDebugConfig(t *testing.T, dir string) string {
	t.Helper()
	baselineCfg := filepath.Join(dir, "baseline.yaml")
	require.NoError(t, os.WriteFile(baselineCfg, []byte("id: baseline"), 0o600))

	projectDir := filepath.Join(dir, "project")
	require.NoError(t, os.MkdirAll(projectDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "requirements.txt"), []byte("pkg==1.0.0"), 0o600))

	configPath := filepath.Join(dir, "cli-debug.yaml")
	content := fmt.Sprintf(`tasks:
  respond:
    targets:
      - /var/log
    profile: quick
  audit:
    targets:
      - localhost
  inventory:
    targets:
      - 10.0.0.1/32
  supplychain:
    paths:
      - %s
  baseline:
    config: %s
collectors:
  - name: stub-collector
    kind: stub
`, projectDir, baselineCfg)
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0o600))
	return configPath
}
