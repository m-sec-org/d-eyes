package detect

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnalyzeSourcesPortableComputesMissingFamiliesAndReasons(t *testing.T) {
	files := map[string][]byte{
		"Ransom.Ok.yar": []byte(`
rule ok {
  strings:
    $a = "ok"
  condition:
    $a
}
`),
		"Botnet.Unsupported.yar": []byte(`
rule bad {
  strings:
    $a = "x"
  condition:
    uint16
}
`),
		"Malware.Parse.yar": []byte(`
rule bad {
  strings:
    $a = "x"
  condition:
    $a and
}
`),
		"notes.txt": []byte("not a rule file"),
	}

	analysis := analyzeSourcesPortable(files)
	require.Equal(t, 3, analysis.TotalFiles)
	require.Equal(t, 1, analysis.LoadedFiles)
	require.Equal(t, 2, analysis.SkippedFiles)

	require.Equal(t, 1, analysis.Families["Ransom"].LoadedFiles)

	require.Equal(t, 0, analysis.Families["Botnet"].LoadedFiles)
	require.Equal(t, 1, analysis.Families["Botnet"].SkippedFiles)
	require.Equal(t, 1, analysis.Families["Botnet"].SkipReasons["unsupported-feature"])

	require.Equal(t, 0, analysis.Families["Malware"].LoadedFiles)
	require.Equal(t, 1, analysis.Families["Malware"].SkippedFiles)
	require.Equal(t, 1, analysis.Families["Malware"].SkipReasons["parse-error"])

	missing := computeMissingFamilies(analysis.Families)
	require.Equal(t, []string{"Botnet", "Malware"}, missing)
}
