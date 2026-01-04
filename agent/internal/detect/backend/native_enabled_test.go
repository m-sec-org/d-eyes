//go:build yara_native

package backend

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadNativeModeUsesLibyara(t *testing.T) {
	res, err := Load(Options{Mode: ModeNative})
	require.NoError(t, err)
	require.Equal(t, ModeNative, res.Backend)
	require.False(t, res.Fallback)
	require.Empty(t, res.FallbackReason)
	require.NotNil(t, res.Manager)
	require.NotNil(t, res.Bundle)
	require.Greater(t, res.Bundle.RuleCount(), 0)
	require.Equal(t, ModeNative, res.Backend)
}

