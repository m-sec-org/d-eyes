package detect

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/backend"
)

func TestWriteYaraBackendSummaryPortableIncludesCoverageAndSkipReasons(t *testing.T) {
	dir := t.TempDir()

	valid := `
rule ok {
    strings:
        $a = "ok"
    condition:
        $a
}
`
	invalid := `
rule bad_rule {
    strings:
        $a = "x"
    condition:
        $a and
}
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "valid.yar"), []byte(valid), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "invalid.yar"), []byte(invalid), 0o600))

	res, err := backend.Load(backend.Options{
		RulePath: dir,
		Mode:     backend.ModePortable,
	})
	require.NoError(t, err)

	var buf bytes.Buffer
	writeYaraBackendSummary(&buf, backend.ModePortable, res)
	out := buf.String()

	require.Contains(t, out, "Loaded ")
	require.Contains(t, out, "requested=portable")
	require.Contains(t, out, "backend=portable")
	require.Contains(t, out, "Rule coverage:")
	require.Contains(t, out, "50.0%")
	require.Contains(t, out, "skipped=1")
	require.Contains(t, out, "Skip reasons:")
	require.Contains(t, out, "parse-error=1")
	require.NotContains(t, out, "Fallback reason:")
}
