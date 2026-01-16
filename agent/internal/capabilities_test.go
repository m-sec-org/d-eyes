package internal

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
)

type noopTaskRunner struct{}

func (noopTaskRunner) Run(context.Context, tasks.TaskRequest) (tasks.TaskResult, error) {
	return tasks.TaskResult{}, nil
}

func TestAdvertisedCapabilitiesIncludeCoreTaskTypes(t *testing.T) {
	EnsureDefaultTaskRunners(nil)

	restore := OverrideTaskRunnerForTesting("experimental.task", noopTaskRunner{})
	defer restore()

	caps := AdvertisedCapabilities(CapabilityContext{Platform: "linux"})
	require.True(t, sort.StringsAreSorted(caps))
	require.NotContains(t, caps, "experimental.task")

	set := make(map[string]struct{}, len(caps))
	for _, cap := range caps {
		require.Equal(t, cap, strings.TrimSpace(cap))
		set[cap] = struct{}{}
	}

	for _, expected := range []string{"respond", "audit", "inventory", "supplychain", "baseline", "bas", "action"} {
		_, ok := set[expected]
		require.True(t, ok, "missing core capability %q", expected)
	}
}

func TestCapabilityCatalogSupportsMappingAndFilters(t *testing.T) {
	EnsureDefaultTaskRunners(nil)

	restoreMapped := RegisterAdvertisedCapabilityForTesting(NewCapabilityDefinition(
		"mapped.capability",
		WithRunner("respond"),
	))
	defer restoreMapped()

	restoreWindowsOnly := RegisterAdvertisedCapabilityForTesting(NewCapabilityDefinition(
		"windows.only",
		WithRunner("respond"),
		WithPlatforms("windows"),
	))
	defer restoreWindowsOnly()

	restoreLabel := RegisterAdvertisedCapabilityForTesting(NewCapabilityDefinition(
		"label.gated",
		WithRunner("respond"),
		WithRequiredLabel(LabelAllowMemscan, LabelValueTrue),
	))
	defer restoreLabel()

	capsLinux := AdvertisedCapabilities(CapabilityContext{Platform: "linux"})
	require.Contains(t, capsLinux, "mapped.capability")
	require.NotContains(t, capsLinux, "windows.only")
	require.NotContains(t, capsLinux, "label.gated")

	capsWindows := AdvertisedCapabilities(CapabilityContext{Platform: "windows"})
	require.Contains(t, capsWindows, "windows.only")

	capsWithLabel := AdvertisedCapabilities(CapabilityContext{
		Platform: "linux",
		Labels: map[string]string{
			LabelAllowMemscan: LabelValueTrue,
		},
	})
	require.Contains(t, capsWithLabel, "label.gated")
}

func TestCapabilityCatalogReservedRequiredLabelsOnly(t *testing.T) {
	EnsureDefaultTaskRunners(nil)

	catalog := NewCapabilityCatalog()
	require.NoError(t, catalog.Register(NewCapabilityDefinition(
		"reserved.good",
		WithRunner("respond"),
		WithRequiredLabel(LabelAllowMemscan, LabelValueTrue),
		WithRequiredLabelsReservedKeysOnly(),
	)))
	require.Error(t, catalog.Register(NewCapabilityDefinition(
		"reserved.bad",
		WithRunner("respond"),
		WithRequiredLabel("feature", "true"),
		WithRequiredLabelsReservedKeysOnly(),
	)))

	caps := catalog.Advertised(CapabilityContext{
		Platform: "windows",
		Labels: map[string]string{
			LabelAllowMemscan: LabelValueTrue,
		},
	})
	require.Contains(t, caps, "reserved.good")
}
