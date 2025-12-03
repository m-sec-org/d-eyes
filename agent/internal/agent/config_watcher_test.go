package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	internal "github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

func TestConfigWatcherReloadsOnFileChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	initialConfig := `
collectors: []
`
	require.NoError(t, os.WriteFile(path, []byte(initialConfig), 0o644))

	internal.SetGlobalConfig(config.Default())

	cfgCh := make(chan config.Config, 4)
	stopWatcher := internal.RegisterConfigWatcher(func(cfg config.Config) {
		cfgCh <- cfg
	})
	defer stopWatcher()

	runner := &remoteRunner{
		configWatchInterval: 10 * time.Millisecond,
	}
	runner.startConfigWatcher(path)
	defer func() {
		if runner.configWatcherStop != nil {
			runner.configWatcherStop()
		}
	}()

	updatedConfig := `
collectors:
  - name: diag-ebpf
    kind: ebpf
`
	require.NoError(t, os.WriteFile(path, []byte(updatedConfig), 0o644))

	require.Eventually(t, func() bool {
		for {
			select {
			case cfg := <-cfgCh:
				if len(cfg.Collectors) == 1 && cfg.Collectors[0].Kind == "ebpf" {
					return true
				}
			default:
				return false
			}
		}
	}, time.Second, 20*time.Millisecond)
}
