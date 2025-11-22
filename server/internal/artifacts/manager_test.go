package artifacts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/config"
)

func TestManagerUploadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewManager(config.ArtifactConfig{
		StorageDir: dir,
		UploadTTL:  time.Minute,
		MaxSize:    1024,
	})
	require.NoError(t, err)
	payload := []byte("sample-artifact")
	hash := sha256.Sum256(payload)
	meta := Metadata{
		Filename:    "sample.bin",
		ContentType: "application/octet-stream",
		Size:        int64(len(payload)),
		Hash:        hex.EncodeToString(hash[:]),
		Encryption:  "aes256-gcm",
	}
	id, _, err := mgr.CreateUpload(meta)
	require.NoError(t, err)
	require.NoError(t, mgr.WriteUpload(id, bytes.NewReader(payload)))
	stored, err := mgr.Consume(id)
	require.NoError(t, err)
	require.Equal(t, meta.Filename, stored.Filename)
	require.Equal(t, meta.ContentType, stored.ContentType)
	require.Equal(t, meta.Encryption, stored.Encryption)
	require.Equal(t, payload, stored.Data)
}

func TestManagerUploadSizeMismatch(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewManager(config.ArtifactConfig{
		StorageDir: dir,
		UploadTTL:  time.Minute,
		MaxSize:    10,
	})
	require.NoError(t, err)
	meta := Metadata{
		Filename: "size.bin",
		Size:     8,
		Hash:     strings.Repeat("0", 64),
	}
	id, _, err := mgr.CreateUpload(meta)
	require.NoError(t, err)
	err = mgr.WriteUpload(id, bytes.NewReader([]byte("short")))
	require.Error(t, err)
	require.Contains(t, err.Error(), "size mismatch")
}

func TestManagerUploadHashMismatch(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewManager(config.ArtifactConfig{
		StorageDir: dir,
		UploadTTL:  time.Minute,
		MaxSize:    1024,
	})
	require.NoError(t, err)
	payload := []byte("artifact")
	meta := Metadata{
		Filename: "hash.bin",
		Size:     int64(len(payload)),
		Hash:     strings.Repeat("a", 64),
	}
	id, _, err := mgr.CreateUpload(meta)
	require.NoError(t, err)
	require.NoError(t, mgr.WriteUpload(id, bytes.NewReader(payload)))
	_, err = mgr.Consume(id)
	require.Error(t, err)
	require.Contains(t, err.Error(), "hash mismatch")
}
