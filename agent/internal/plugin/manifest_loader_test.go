package plugin

import (
	crypto "crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	pluginmanifest "github.com/m-sec-org/d-eyes/server/pkg/pluginmanifest"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestLoadManifestFromPath(t *testing.T) {
	pub, priv, err := crypto.GenerateKey(rand.Reader)
	require.NoError(t, err)

	now := time.Now().UTC()
	m := pluginmanifest.Manifest{
		APIVersion:      pluginmanifest.SupportedAPIVersion,
		Name:            "inventory-fast-scan",
		Version:         "0.1.0",
		Entry:           "./plugin.so",
		ArtifactDigest:  "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		MinAgentVersion: "1.0.0",
		SignedAt:        &now,
		Tasks:           []pluginmanifest.Task{{Name: "inventory-fast-scan", Kind: "inventory"}},
	}
	payload, err := m.SigningBytes()
	require.NoError(t, err)
	sig := crypto.Sign(priv, payload)
	m.Signature = pluginmanifest.Signature{
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Value:     base64.StdEncoding.EncodeToString(sig),
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "plugin.yaml")
	contents, err := yaml.Marshal(&m)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, contents, 0o644))

	loaded, err := LoadManifestFromPath(path)
	require.NoError(t, err)
	require.Equal(t, m.Name, loaded.Name)
}

func TestValidateManifestBytesFails(t *testing.T) {
	_, err := ValidateManifestBytes([]byte("apiVersion: v1\nname: bad\nversion: invalid"))
	require.Error(t, err)
}
