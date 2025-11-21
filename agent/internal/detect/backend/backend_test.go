package backend

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadNativeModeFallsBackToPortable(t *testing.T) {
	res, err := Load(Options{Mode: ModeNative})
	require.NoError(t, err)
	require.Equal(t, ModePortable, res.Backend)
	require.True(t, res.Fallback)
	require.Contains(t, res.FallbackReason, "falling back")
	require.NotNil(t, res.Manager)
	require.NotNil(t, res.Bundle)
}

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
