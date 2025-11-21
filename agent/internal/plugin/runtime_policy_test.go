package plugin

import (
	"context"
	"runtime"
	"testing"
	"time"

	pluginmanifest "github.com/m-sec-org/d-eyes/server/pkg/pluginmanifest"
	"github.com/stretchr/testify/require"
)

type recordingHook struct {
	events []Event
}

func (h *recordingHook) OnEvent(_ context.Context, evt Event) {
	h.events = append(h.events, evt)
}

func baselineManifest() pluginmanifest.Manifest {
	return pluginmanifest.Manifest{
		APIVersion:     pluginmanifest.SupportedAPIVersion,
		Name:           "respond-risk-score",
		Version:        "1.0.0",
		Entry:          "./plugin.so",
		ArtifactDigest: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		Tasks:          []pluginmanifest.Task{{Name: "respond-risk-score", Kind: "respond"}},
	}
}

func TestApplyRespectsLimitsAndSandboxFlag(t *testing.T) {
	hook := &recordingHook{}
	mgr := NewManager(Limits{MaxMilliCPU: 600, MaxMemoryMi: 512, MaxTimeout: 10 * time.Minute}, false, hook)

	m := baselineManifest()
	m.Targets = []pluginmanifest.Target{{OS: runtime.GOOS, Arch: runtime.GOARCH}}
	m.Resources = pluginmanifest.ResourceLimits{CPU: "500m", Memory: "256Mi", Timeout: "5m"}
	m.Metadata = map[string]string{"sandbox": "required"}

	policy, err := mgr.Apply(context.Background(), m)
	require.NoError(t, err)
	require.True(t, policy.SandboxRequired)
	require.Equal(t, 500, policy.ResourceLimits.MilliCPU)
	require.Equal(t, 256, policy.ResourceLimits.MemoryMi)
	require.Equal(t, 5*time.Minute, policy.ResourceLimits.Timeout)

	require.Len(t, hook.events, 1)
	require.Equal(t, "installed", hook.events[0].Type)
}

func TestApplyRejectsOverBudget(t *testing.T) {
	hook := &recordingHook{}
	mgr := NewManager(Limits{MaxMilliCPU: 400}, false, hook)

	m := baselineManifest()
	m.Resources = pluginmanifest.ResourceLimits{CPU: "500m"}

	_, err := mgr.Apply(context.Background(), m)
	require.Error(t, err)
	require.Len(t, hook.events, 1)
	require.Equal(t, "rejected", hook.events[0].Type)
}

func TestApplyWithRollbackRestoresPrevious(t *testing.T) {
	hook := &recordingHook{}
	mgr := NewManager(Limits{}, true, hook)
	m1 := baselineManifest()
	_, err := mgr.Apply(context.Background(), m1)
	require.NoError(t, err)

	m2 := baselineManifest()
	m2.Version = "2.0.0"
	m2.Metadata = map[string]string{"sandbox": "required"}

	policy2, rollback, err := mgr.ApplyWithRollback(context.Background(), m2)
	require.NoError(t, err)
	require.True(t, policy2.SandboxRequired)
	require.NotNil(t, rollback)

	rollback()
	require.True(t, len(hook.events) >= 2)
	require.Equal(t, "rollback", hook.events[len(hook.events)-1].Type)
}

func TestParseBudgetRejectsInvalidNumbers(t *testing.T) {
	_, err := parseMilliCPU("10x")
	require.Error(t, err)
	_, err = parseMemoryMi("20abc")
	require.Error(t, err)
}
