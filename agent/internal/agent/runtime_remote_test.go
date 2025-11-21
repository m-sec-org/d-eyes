package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

func TestRemoteCLICommandUsesRunRemoteHook(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	configYAML := `
remote:
  enabled: true
  server_grpc_addr: bufconn://example
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(configYAML), 0o600))
	require.NoError(t, os.Setenv("D_EYES_CONFIG", cfgPath))
	t.Cleanup(func() {
		_ = os.Unsetenv("D_EYES_CONFIG")
	})

	runtime := NewRuntime()

	called := false
	orig := runRemoteFunc
	runRemoteFunc = func(ctx context.Context, rc config.RemoteConfig) error {
		called = true
		require.Equal(t, "bufconn://example", rc.ServerGRPCAddr)
		select {
		case <-ctx.Done():
			t.Fatal("context canceled unexpectedly")
		default:
		}
		return nil
	}
	t.Cleanup(func() {
		runRemoteFunc = orig
	})

	exitCode, err := runtime.Run([]string{"d-eyes", "remote"})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)
	require.True(t, called)
}
