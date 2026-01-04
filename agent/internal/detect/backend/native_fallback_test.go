//go:build !yara_native

package backend

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadNativeModeFallsBackToPortableWhenTagMissing(t *testing.T) {
	res, err := Load(Options{Mode: ModeNative})
	require.NoError(t, err)
	require.Equal(t, ModePortable, res.Backend)
	require.True(t, res.Fallback)
	require.Contains(t, res.FallbackReason, "falling back")
	require.NotNil(t, res.Manager)
	require.NotNil(t, res.Bundle)
}

