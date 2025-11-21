package goengine

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine/goengine/metadata"
)

func TestParserExtractsMetadataAndPreconditions(t *testing.T) {
	src := `rule sample_rule {
        meta:
            description = "Example rule"
            tags = "ransom"
        strings:
            $a = "MZ"
        condition:
            filesize < 2KB and pe.is_pe and $a
    }`

	condition := "filesize < 2KB and pe.is_pe and $a"
	pcs, placeholder, partial := extractPreconditions(condition)
	if len(pcs) != 2 {
		t.Fatalf("unexpected precondition count: got %d placeholder=%q", len(pcs), placeholder)
	}
	require.NotContains(t, placeholder, "uint16")
	require.Contains(t, partial, "metadata:pe")

	parser := newParser("sample.yar", src)
	rules, err := parser.Parse()
	require.NoError(t, err)
	require.Len(t, rules, 1)

	rule := rules[0]
	require.Equal(t, "Example rule", rule.Description)
	require.ElementsMatch(t, []string{"ransom"}, rule.Tags)
	require.Len(t, rule.Strings, 1)
	require.Equal(t, "$a", rule.Strings[0].ID)
	require.NotNil(t, rule.Condition)
	require.Len(t, rule.Preconds, 2)
	require.True(t, rule.Partial)
	require.Contains(t, rule.PartialReasons, "metadata:pe")

	sample := []byte{0x4d, 0x5a, 0x00, 0x00, 0x00, 0x00}
	meta := metadata.Extract(sample)
	for _, pc := range rule.Preconds {
		require.True(t, pc.Eval(sample, meta))
	}
}
