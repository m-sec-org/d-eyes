package taskcache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSaveAndRestore(t *testing.T) {
	dir := t.TempDir()
	cacheRoot = dir

	src := filepath.Join(dir, "src.txt")
	require.NoError(t, os.WriteFile(src, []byte("hello"), 0o644))

	err := SaveFile("respond", "k1", src, map[string]string{"foo": "bar"})
	require.NoError(t, err)

	path, meta, ok, err := RestoreFile("respond", "k1", time.Hour)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "bar", meta["foo"])

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))
}

func TestTTLExpiry(t *testing.T) {
	dir := t.TempDir()
	cacheRoot = dir
	src := filepath.Join(dir, "src.txt")
	require.NoError(t, os.WriteFile(src, []byte("hello"), 0o644))
	require.NoError(t, SaveFile("respond", "k1", src, nil))

	PurgeExpired("respond", time.Nanosecond)
	_, _, ok, err := RestoreFile("respond", "k1", time.Second)
	require.NoError(t, err)
	require.False(t, ok)
}
