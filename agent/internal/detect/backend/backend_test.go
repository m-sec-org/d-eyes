package backend

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeRulePathHandlesFilesAndMissingEntries(t *testing.T) {
	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "custom.yar")
	require.NoError(t, os.WriteFile(file, []byte("rule test { condition: true }"), 0o600))

	require.Equal(t, tmpDir, sanitizeRulePath(file))
	require.Equal(t, tmpDir, sanitizeRulePath(tmpDir))
	require.Equal(t, "", sanitizeRulePath(filepath.Join(tmpDir, "missing")))
}

func TestNormalizeModeDefaultsToPortable(t *testing.T) {
	require.Equal(t, ModePortable, normalizeMode(""))
	require.Equal(t, ModeNative, normalizeMode(ModeNative))
	require.Equal(t, ModePortable, normalizeMode("unknown"))
}
