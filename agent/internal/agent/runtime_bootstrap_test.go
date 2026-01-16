package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func unsetEnvForTest(t *testing.T, key string) {
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

func TestRuntimeBootstrapsDefaultConfigOnHelp(t *testing.T) {
	unsetEnvForTest(t, "D_EYES_CONFIG")

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	runtime := NewRuntime()
	exitCode, err := runtime.Run([]string{"d-eyes", "--help"})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)

	path := filepath.Join(home, ".d-eyes", "config.yaml")
	_, err = os.Stat(path)
	require.NoError(t, err)
}

func TestRuntimeBootstrapsDefaultConfigOnVersionCommand(t *testing.T) {
	unsetEnvForTest(t, "D_EYES_CONFIG")

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	runtime := NewRuntime()
	exitCode, err := runtime.Run([]string{"d-eyes", "version"})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)

	path := filepath.Join(home, ".d-eyes", "config.yaml")
	_, err = os.Stat(path)
	require.NoError(t, err)
}
