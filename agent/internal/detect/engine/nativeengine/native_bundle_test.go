//go:build yara_native

package nativeengine

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine"
)

func TestCompileFromSourcesAndScanMapsFields(t *testing.T) {
	rules := []byte(`
rule DemoRule : ransomware testtag {
  meta:
    description = "demo description"
    category = "ransomware"
    severity = "critical"
    confidence = "0.8"
  strings:
    $a = "abc"
  condition:
    $a
}
`)
	bundle, stats, err := CompileFromSources(map[string][]byte{
		"demo.yar": rules,
	}, "v1")
	require.NoError(t, err)
	require.Equal(t, 1, stats.TotalRuleFiles)
	require.Equal(t, 1, stats.LoadedRuleFiles)
	require.Equal(t, 0, stats.SkippedRuleFiles)
	require.Equal(t, 1, bundle.RuleCount())

	matches, err := bundle.Scan([]byte("xxabcxx"), engine.ScanOptions{FilePath: "/tmp/sample.bin"})
	require.NoError(t, err)
	require.Len(t, matches, 1)

	match := matches[0]
	require.Equal(t, "DemoRule", match.RuleName)
	require.Equal(t, "demo description", match.Description)
	require.Contains(t, match.Tags, "ransomware")
	require.Contains(t, match.Tags, "testtag")
	require.Equal(t, "/tmp/sample.bin", match.FilePath)

	require.Equal(t, "ransomware", match.ScoreHints.Category)
	require.Equal(t, "critical", match.ScoreHints.Severity)
	require.InDelta(t, 0.8, match.ScoreHints.Confidence, 0.0001)

	require.Equal(t, "demo description", match.Metadata["description"])
	require.Equal(t, "ransomware", match.Metadata["category"])
	require.Equal(t, "critical", match.Metadata["severity"])
	require.Equal(t, "0.8", match.Metadata["confidence"])

	require.Len(t, match.Strings, 1)
	require.Equal(t, "$a", match.Strings[0].Identifier)
	require.Equal(t, []int{2}, match.Strings[0].Offsets)
}

func TestCompileFromSourcesSkipsInvalidRules(t *testing.T) {
	bundle, stats, err := CompileFromSources(map[string][]byte{
		"good.yar": []byte("rule ok { condition: true }"),
		"bad.yar":  []byte("rule bad { condition: }"),
	}, "v1")
	require.NoError(t, err)
	require.Equal(t, 2, stats.TotalRuleFiles)
	require.Equal(t, 1, stats.LoadedRuleFiles)
	require.Equal(t, 1, stats.SkippedRuleFiles)
	require.Equal(t, 1, bundle.RuleCount())
}

