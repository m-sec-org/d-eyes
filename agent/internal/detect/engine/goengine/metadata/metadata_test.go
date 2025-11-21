package metadata

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractDetectsFamilies(t *testing.T) {
	pe := Extract([]byte{'M', 'Z', 0x00, 0x00})
	require.True(t, pe.SupportsFamily("PE"))
	require.False(t, pe.SupportsFamily("elf"))

	elf := Extract([]byte{0x7f, 'E', 'L', 'F'})
	require.True(t, elf.SupportsFamily("elf"))

	mach := Extract([]byte{0xFE, 0xED, 0xFA, 0xCE})
	require.True(t, mach.SupportsFamily("mach"))
}

func TestHashBytesEmptyInput(t *testing.T) {
	meta := Extract(nil)
	require.Equal(t, 0, meta.Size)
	require.Equal(t, "", meta.Hash)
	require.False(t, meta.SupportsFamily("pe"))
}
