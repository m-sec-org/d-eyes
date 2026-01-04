//go:build yara_native

package detect

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/backend"
)

func TestWriteYaraBackendSummaryAutoSelectsNativeWhenAvailable(t *testing.T) {
	dir := t.TempDir()
	rule := `
rule ok {
    strings:
        $a = "ok"
    condition:
        $a
}
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ok.yar"), []byte(rule), 0o600))

	res, err := backend.Load(backend.Options{
		RulePath: dir,
		Mode:     backend.ModeAuto,
	})
	require.NoError(t, err)
	require.Equal(t, backend.ModeNative, res.Backend)
	require.False(t, res.Fallback)

	var buf bytes.Buffer
	writeYaraBackendSummary(&buf, backend.ModeAuto, res)
	out := buf.String()

	require.Contains(t, out, "requested=auto")
	require.Contains(t, out, "backend=native")
	require.Contains(t, out, "engine=libyara")
	require.Contains(t, out, "Rule coverage:")
	require.NotContains(t, out, "Fallback reason:")
}
