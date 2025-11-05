package detect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

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

	bundle, err := loadRuleBundle(dir)
	require.NoError(t, err)
	require.NotNil(t, bundle)

	payload := []byte("hello d-eyes-testing payload")
	matches, err := bundle.Scan(payload, engine.ScanOptions{FilePath: "payload.bin"})
	require.NoError(t, err)
	require.Len(t, matches, 1)
	require.Equal(t, "d_eyes_unit_test", matches[0].RuleName)
}
