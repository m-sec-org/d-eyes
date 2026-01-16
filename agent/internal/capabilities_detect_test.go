package internal

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
)

type noopDetectRunner struct{}

func (noopDetectRunner) Run(context.Context, tasks.TaskRequest) (tasks.TaskResult, error) {
	return tasks.TaskResult{}, nil
}

func TestDetectCapabilitiesGatedByPlatformAndAllowMemscan(t *testing.T) {
	EnsureDefaultTaskRunners(nil)

	restoreDiag := OverrideTaskRunnerForTesting("detect.diag", noopDetectRunner{})
	defer restoreDiag()
	restoreMemscan := OverrideTaskRunnerForTesting("detect.memscan", noopDetectRunner{})
	defer restoreMemscan()

	capsLinux := AdvertisedCapabilities(CapabilityContext{Platform: "linux"})
	require.Contains(t, capsLinux, "detect.diag")
	require.NotContains(t, capsLinux, "detect.memscan")

	capsWindowsNoLabel := AdvertisedCapabilities(CapabilityContext{Platform: "windows"})
	require.NotContains(t, capsWindowsNoLabel, "detect.memscan")

	capsWindowsWrongLabel := AdvertisedCapabilities(CapabilityContext{
		Platform: "windows",
		Labels: map[string]string{
			LabelAllowMemscan: "TRUE",
		},
	})
	require.NotContains(t, capsWindowsWrongLabel, "detect.memscan")

	capsWindowsEnabled := AdvertisedCapabilities(CapabilityContext{
		Platform: "windows",
		Labels: map[string]string{
			LabelAllowMemscan: LabelValueTrue,
		},
	})
	require.Contains(t, capsWindowsEnabled, "detect.memscan")
}
