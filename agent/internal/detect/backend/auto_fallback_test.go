//go:build !yara_native

package backend

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadAutoModeFallsBackToPortableWhenTagMissing(t *testing.T) {
	res, err := Load(Options{Mode: ModeAuto})
	require.NoError(t, err)
	require.Equal(t, ModePortable, res.Backend)
	require.True(t, res.Fallback)
	require.Contains(t, res.FallbackReason, "falling back")
	require.NotNil(t, res.Manager)
	require.NotNil(t, res.Bundle)
	require.Equal(t, "embedded", res.Bundle.Name())
	require.Greater(t, res.Stats.TotalRuleFiles, 0)
}
