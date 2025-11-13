package detect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/backend"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine"
)

func TestLoadRuleBundleWithCustomRuleDirectory(t *testing.T) {
	dir := t.TempDir()
	ruleContent := []byte(`
rule d_eyes_unit_test {
    strings:
        $a = "d-eyes-testing"
    condition:
        $a
}
`)
	rulePath := filepath.Join(dir, "custom_rule.yar")
	require.NoError(t, os.WriteFile(rulePath, ruleContent, 0o600))

	result, err := backend.Load(backend.Options{
		RulePath: dir,
		Mode:     backend.ModePortable,
	})
	require.NoError(t, err)
	require.NotNil(t, result.Bundle)
	require.NotNil(t, result.Manager)

	payload := []byte("hello d-eyes-testing payload")
	matches, err := result.Bundle.Scan(payload, engine.ScanOptions{FilePath: "payload.bin"})
	require.NoError(t, err)
	require.Len(t, matches, 1)
	require.Equal(t, "d_eyes_unit_test", matches[0].RuleName)
}

func TestRuleManagerRecordsStats(t *testing.T) {
	dir := t.TempDir()
	valid := `
rule valid_rule {
    strings:
        $a = "ok"
    condition:
        $a
}
`
	invalid := `
rule bad_rule {
    condition:
        pe.entry_point and not } // malformed
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "valid.yar"), []byte(valid), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "invalid.yar"), []byte(invalid), 0o644))

	result, err := backend.Load(backend.Options{
		RulePath: dir,
		Mode:     backend.ModePortable,
	})
	require.NoError(t, err)
	require.NotNil(t, result.Manager)
	stats := result.Manager.Snapshot().Stats
	require.Equal(t, 2, stats.TotalRuleFiles)
	require.Equal(t, 1, stats.LoadedRuleFiles)
	require.Equal(t, 1, stats.SkippedRuleFiles)
	require.Equal(t, 1, stats.SkipReasons["parse-error"]+stats.SkipReasons["unsupported-feature"]+stats.SkipReasons["syntax-error"])
}
