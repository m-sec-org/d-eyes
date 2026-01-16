package taskcatalog_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/taskcatalog"
)

func newTestCatalog(t *testing.T) *taskcatalog.Manager {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	catalog, err := taskcatalog.NewManager(taskcatalog.Config{}, log)
	require.NoError(t, err)
	return catalog
}

func TestImportSeedIfEmptyIsIdempotent(t *testing.T) {
	t.Parallel()
	catalog := newTestCatalog(t)
	ctx := context.Background()

	seeded, err := catalog.ImportSeedIfEmpty(ctx, taskcatalog.BuiltInSeed())
	require.NoError(t, err)
	require.True(t, seeded)

	types1, err := catalog.ListTaskTypes(ctx)
	require.NoError(t, err)
	profiles1, err := catalog.ListTaskProfiles(ctx, "")
	require.NoError(t, err)
	require.Len(t, types1, 9)
	require.Len(t, profiles1, 10)

	seeded, err = catalog.ImportSeedIfEmpty(ctx, taskcatalog.BuiltInSeed())
	require.NoError(t, err)
	require.False(t, seeded)

	types2, err := catalog.ListTaskTypes(ctx)
	require.NoError(t, err)
	profiles2, err := catalog.ListTaskProfiles(ctx, "")
	require.NoError(t, err)
	require.Equal(t, types1, types2)
	require.Equal(t, profiles1, profiles2)
}

func TestImportSeedIfEmptyPreservesExistingCatalog(t *testing.T) {
	t.Parallel()
	catalog := newTestCatalog(t)
	ctx := context.Background()

	_, err := catalog.CreateTaskType(ctx, taskcatalog.TaskType{
		Name:        "custom",
		DisplayName: "Custom",
		Description: "User-defined task type",
	})
	require.NoError(t, err)

	seeded, err := catalog.ImportSeedIfEmpty(ctx, taskcatalog.BuiltInSeed())
	require.NoError(t, err)
	require.False(t, seeded)

	types, err := catalog.ListTaskTypes(ctx)
	require.NoError(t, err)
	require.Len(t, types, 1)
	require.Equal(t, "custom", types[0].Name)

	_, err = catalog.GetTaskType(ctx, "respond")
	require.ErrorIs(t, err, taskcatalog.ErrUnknownTaskType)
}

func TestImportSeedIfEmptyPersistsAndIsIdempotentAcrossRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "catalog.json")

	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	catalog, err := taskcatalog.NewManager(taskcatalog.Config{PersistPath: persistPath}, log)
	require.NoError(t, err)

	seeded, err := catalog.ImportSeedIfEmpty(ctx, taskcatalog.BuiltInSeed())
	require.NoError(t, err)
	require.True(t, seeded)

	types1, err := catalog.ListTaskTypes(ctx)
	require.NoError(t, err)
	profiles1, err := catalog.ListTaskProfiles(ctx, "")
	require.NoError(t, err)
	memscan1, err := catalog.GetTaskProfile(ctx, "detect.memscan")
	require.NoError(t, err)

	reloaded, err := taskcatalog.NewManager(taskcatalog.Config{PersistPath: persistPath}, log)
	require.NoError(t, err)

	types2, err := reloaded.ListTaskTypes(ctx)
	require.NoError(t, err)
	profiles2, err := reloaded.ListTaskProfiles(ctx, "")
	require.NoError(t, err)
	memscan2, err := reloaded.GetTaskProfile(ctx, "detect.memscan")
	require.NoError(t, err)
	require.Equal(t, types1, types2)
	require.Len(t, profiles2, len(profiles1))
	seedProfileKeys := make([]string, 0, len(profiles1))
	for _, profile := range profiles1 {
		seedProfileKeys = append(seedProfileKeys, profile.ID+":"+profile.TaskType)
	}
	reloadedProfileKeys := make([]string, 0, len(profiles2))
	for _, profile := range profiles2 {
		reloadedProfileKeys = append(reloadedProfileKeys, profile.ID+":"+profile.TaskType)
	}
	require.Equal(t, seedProfileKeys, reloadedProfileKeys)

	assertDefaultInt64 := func(t *testing.T, profile *taskcatalog.TaskProfile, key string, expected int64) {
		t.Helper()
		var found any
		for _, param := range profile.Schema.Parameters {
			if param.Key == key {
				found = param.Default
				break
			}
		}
		require.NotNil(t, found, "missing default for %s", key)
		require.IsType(t, int64(0), found, "default type drift for %s", key)
		require.Equal(t, expected, found.(int64))
	}
	assertDefaultInt64(t, memscan1, "max_bytes", 33554432)
	assertDefaultInt64(t, memscan1, "max_regions", 128)
	assertDefaultInt64(t, memscan2, "max_bytes", 33554432)
	assertDefaultInt64(t, memscan2, "max_regions", 128)

	require.NoError(t, reloaded.ValidateTaskPayload("detect.diag", "detect.diag", map[string]any{"backend": "auto"}))
	require.Error(t, reloaded.ValidateTaskPayload("detect.diag", "detect.diag", map[string]any{"backend": "invalid"}))
	require.NoError(t, reloaded.ValidateTaskPayload("detect.memscan", "detect.memscan", map[string]any{"pid": 1}))
	require.Error(t, reloaded.ValidateTaskPayload("detect.memscan", "detect.memscan", map[string]any{"pid": 0}))

	seeded, err = reloaded.ImportSeedIfEmpty(ctx, taskcatalog.BuiltInSeed())
	require.NoError(t, err)
	require.False(t, seeded)
}

func TestTaskProfileFloatDefaultAvoidsScientificNotation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "catalog.json")

	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	catalog, err := taskcatalog.NewManager(taskcatalog.Config{PersistPath: persistPath}, log)
	require.NoError(t, err)

	_, err = catalog.CreateTaskType(ctx, taskcatalog.TaskType{
		Name:        "custom",
		DisplayName: "Custom",
	})
	require.NoError(t, err)

	created, err := catalog.CreateTaskProfile(ctx, taskcatalog.TaskProfile{
		ID:          "float-default",
		TaskType:    "custom",
		DisplayName: "Float Default",
		Version:     "1.0.0",
		Schema: taskcatalog.TaskProfileSchema{
			Parameters: []taskcatalog.ProfileParameter{
				{Key: "ratio", Label: "Ratio", Type: "number", Default: 0.000001},
			},
		},
	})
	require.NoError(t, err)

	var found any
	for _, param := range created.Schema.Parameters {
		if param.Key == "ratio" {
			found = param.Default
			break
		}
	}
	require.IsType(t, json.Number(""), found)
	require.Equal(t, json.Number("0.000001"), found.(json.Number))

	raw, err := os.ReadFile(persistPath)
	require.NoError(t, err)
	require.Contains(t, string(raw), "0.000001")
	require.NotContains(t, string(raw), "1e-06")

	reloaded, err := taskcatalog.NewManager(taskcatalog.Config{PersistPath: persistPath}, log)
	require.NoError(t, err)
	profile, err := reloaded.GetTaskProfile(ctx, "float-default")
	require.NoError(t, err)
	require.Len(t, profile.Schema.Parameters, 1)
	require.IsType(t, json.Number(""), profile.Schema.Parameters[0].Default)
	require.Equal(t, json.Number("0.000001"), profile.Schema.Parameters[0].Default.(json.Number))
}
