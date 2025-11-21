package plugins

import (
	"context"
	crypto "crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	pluginmanifest "github.com/m-sec-org/d-eyes/server/pkg/pluginmanifest"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestInstallAndList(t *testing.T) {
	mgr := NewManager()
	manifestYAML := newSignedManifest(t, "respond-risk-score", "1.0.0")

	rec, err := mgr.Install(context.Background(), manifestYAML)
	require.NoError(t, err)
	require.Equal(t, StatusInstalled, rec.Status)

	list := mgr.List()
	require.Len(t, list, 1)
	require.Equal(t, "respond-risk-score", list[0].Manifest.Name)
}

func TestRollback(t *testing.T) {
	mgr := NewManager()
	// seed history
	mgr.records["test"] = Record{Manifest: recManifest("test", "1.0.0"), Status: StatusInstalled}
	mgr.history["test"] = []Record{{Manifest: recManifest("test", "0.9.0"), Status: StatusInstalled}}

	rec, err := mgr.Rollback(context.Background(), "test")
	require.NoError(t, err)
	require.Equal(t, StatusRollback, rec.Status)
}

func TestHookReceivesEvents(t *testing.T) {
	mgr := NewManager()
	var got Event
	mgr.UseHook(func(evt Event) { got = evt })

	_, _ = mgr.Install(context.Background(), newSignedManifest(t, "hook-plugin", "0.1.0"))
	require.Equal(t, "hook-plugin", got.Manifest.Name)
	require.Equal(t, string(StatusInstalled), got.Type)
}

func newSignedManifest(t *testing.T, name, version string) []byte {
	t.Helper()
	pub, priv, err := crypto.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now().UTC()
	m := pluginmanifest.Manifest{
		APIVersion:     pluginmanifest.SupportedAPIVersion,
		Name:           name,
		Version:        version,
		Entry:          "./plugin.so",
		ArtifactDigest: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		SignedAt:       &now,
		Tasks:          []pluginmanifest.Task{{Name: name, Kind: "respond"}},
	}
	payload, err := m.SigningBytes()
	require.NoError(t, err)
	sig := crypto.Sign(priv, payload)
	m.Signature = pluginmanifest.Signature{
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Value:     base64.StdEncoding.EncodeToString(sig),
	}
	out, err := yaml.Marshal(&m)
	require.NoError(t, err)
	return out
}

func recManifest(name, version string) pluginmanifest.Manifest {
	return pluginmanifest.Manifest{
		APIVersion:     pluginmanifest.SupportedAPIVersion,
		Name:           name,
		Version:        version,
		Entry:          "./plugin.so",
		ArtifactDigest: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		Tasks:          []pluginmanifest.Task{{Name: name, Kind: "respond"}},
		Signature: pluginmanifest.Signature{
			Algorithm: "ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(make([]byte, crypto.PublicKeySize)),
			Value:     base64.StdEncoding.EncodeToString(make([]byte, crypto.SignatureSize)),
		},
	}
}
