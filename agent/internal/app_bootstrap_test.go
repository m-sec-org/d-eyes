package internal

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	agentconfig "github.com/m-sec-org/d-eyes/agent/pkg/config"
)

func unsetEnv(t *testing.T, key string) {
	t.Helper()
	orig, ok := os.LookupEnv(key)
	require.NoError(t, os.Unsetenv(key))
	t.Cleanup(func() {
		if ok {
			_ = os.Setenv(key, orig)
			return
		}
		_ = os.Unsetenv(key)
	})
}

func setUserHomeForTest(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func TestBootstrapCreatesDefaultConfigWhenNotExplicit(t *testing.T) {
	unsetEnv(t, "D_EYES_CONFIG")

	home := t.TempDir()
	setUserHomeForTest(t, home)
	expected := agentconfig.Default()

	app := NewApp()
	require.NoError(t, app.Run([]string{"d-eyes", "version"}))

	path := filepath.Join(home, ".d-eyes", "config.yaml")
	_, err := os.Stat(path)
	require.NoError(t, err)

	loaded, err := agentconfig.Load(path)
	require.NoError(t, err)
	require.Equal(t, expected, loaded)
}

func TestBootstrapSkippedWhenConfigFlagIsSet(t *testing.T) {
	unsetEnv(t, "D_EYES_CONFIG")

	home := t.TempDir()
	setUserHomeForTest(t, home)

	custom := filepath.Join(t.TempDir(), "custom.yaml")
	app := NewApp()
	require.NoError(t, app.Run([]string{"d-eyes", "--config", custom, "version"}))

	defaultPath := filepath.Join(home, ".d-eyes", "config.yaml")
	_, err := os.Stat(defaultPath)
	require.ErrorIs(t, err, os.ErrNotExist)

	_, err = os.Stat(custom)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestBootstrapPermissionDeniedFallsBackToDefaults(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not portable on windows")
	}
	unsetEnv(t, "D_EYES_CONFIG")

	home := t.TempDir()
	setUserHomeForTest(t, home)

	configDir := filepath.Join(home, ".d-eyes")
	require.NoError(t, os.MkdirAll(configDir, 0o700))
	require.NoError(t, os.Chmod(configDir, 0o000))
	t.Cleanup(func() {
		_ = os.Chmod(configDir, 0o700)
	})

	app := NewApp()
	require.NoError(t, app.Run([]string{"d-eyes", "version"}))
}
